//! WAL 流式扫描：复用 sov_probe 的四重校验（Magic→Version→Length→CRC32）。
//! 脏尾退栈：一旦遇到不可恢复的脏数据立即停止（不尝试跨坏记录重同步），
//! 与 sov_probe 解码契约一致，避免把损坏区的"疑似合法"字节误当成记录。

use anyhow::Result;
use sov_probe::wal::header::{WalRecord, WAL_HEADER_SIZE, WAL_MAGIC, WAL_VERSION};
use std::io::Read;

/// 扫描统计。
#[derive(Debug, Default, Clone)]
pub struct ScanStats {
    pub records: u64,
    /// payload 总字节（不含 64B header）。
    pub payload_bytes: u64,
    /// 文件总字节（header + payload）。
    pub total_bytes: u64,
    /// 脏尾字节数（EOF 处无法解码的残段，≥1 表示文件被截断/损坏）。
    pub dirty_tail_bytes: u64,
    /// 遇脏即停：mid-stream 出现不可恢复脏数据（Magic/Version 不符）。
    pub stopped_early: bool,
}

/// 扫描结果。
#[derive(Debug)]
pub struct ScanResult {
    pub records: Vec<WalRecord>,
    pub stats: ScanStats,
}

/// 流式扫描一个 WAL 文件/字节流。
/// 大端语义由 sov_probe 内部保证；本层只负责分块缓冲与脏尾判定。
pub fn scan_reader<R: Read>(reader: &mut R) -> Result<ScanResult> {
    let mut pending: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut stats = ScanStats::default();
    let mut records = Vec::new();
    let mut tmp = [0u8; 64 * 1024];

    loop {
        let n = reader.read(&mut tmp)?;
        if n == 0 {
            break; // EOF
        }
        pending.extend_from_slice(&tmp[..n]);
        stats.total_bytes += n as u64;

        // 若已有完整 header 且 Magic/Version 不符 → 不可恢复脏尾，立即停止。
        if bad_header(&pending) {
            stats.stopped_early = true;
            stats.dirty_tail_bytes = pending.len() as u64;
            pending.clear();
            break;
        }

        let (recs, residual) = WalRecord::decode_stream(&pending);
        records.extend(recs);
        let keep = pending.len() - residual;
        pending.drain(..keep);
    }

    // EOF 残段判定：完整 header 但 Magic/Version 不符 → 脏尾；否则为未对齐截断残段。
    if !pending.is_empty() {
        if bad_header(&pending) {
            stats.stopped_early = true;
        }
        stats.dirty_tail_bytes = pending.len() as u64;
    }

    stats.records = records.len() as u64;
    stats.payload_bytes = records.iter().map(|r| r.payload.len() as u64).sum();
    Ok(ScanResult { records, stats })
}

/// 已有完整 header 时判断 Magic/Version 是否不符（不可恢复脏尾）。
fn bad_header(buf: &[u8]) -> bool {
    if buf.len() < WAL_HEADER_SIZE {
        return false;
    }
    let magic = u16::from_be_bytes([buf[0], buf[1]]);
    magic != WAL_MAGIC || buf[2] != WAL_VERSION
}

/// 将整段字节一次性解码（供已落盘 hot 文件回读对账使用）。
pub fn decode_bytes(buf: &[u8]) -> (Vec<WalRecord>, usize) {
    WalRecord::decode_stream(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sov_probe::wal::header::WalRecord;

    fn rec(seq: u32, payload: &[u8]) -> WalRecord {
        WalRecord {
            timestamp_ns: seq as u64,
            flags: 0,
            tcp_flags: 0x02,
            tcp_seq: seq,
            tcp_ack: 0,
            window_size: 65535,
            src_ip: [192, 168, 1, 10],
            dst_ip: [10, 0, 0, 1],
            src_port: 12345,
            dst_port: 443,
            proto: 6,
            orig_payload_len: payload.len() as u32,
            payload: payload.to_vec(),
        }
    }

    fn encode(recs: &[WalRecord]) -> Vec<u8> {
        let mut buf = Vec::new();
        for r in recs {
            r.encode(&mut buf);
        }
        buf
    }

    #[test]
    fn scan_clean_stream() {
        let bytes = encode(&[rec(1, b"GET /a"), rec(2, b"GET /bb"), rec(3, b"POST /ccc")]);
        let mut c = std::io::Cursor::new(bytes.clone());
        let r = scan_reader(&mut c).unwrap();
        assert_eq!(r.stats.records, 3);
        assert_eq!(r.stats.total_bytes, bytes.len() as u64);
        assert_eq!(r.stats.dirty_tail_bytes, 0);
        assert!(!r.stats.stopped_early);
        assert_eq!(r.records[1].payload, b"GET /bb");
    }

    #[test]
    fn dirty_tail_truncated() {
        let bytes = encode(&[rec(1, b"GET /a")]);
        // 截掉尾部 20 字节 → 未对齐残段
        let mut c = std::io::Cursor::new(&bytes[..bytes.len() - 20]);
        let r = scan_reader(&mut c).unwrap();
        assert_eq!(r.stats.records, 0);
        assert_eq!(r.stats.dirty_tail_bytes, (bytes.len() - 20) as u64);
    }

    #[test]
    fn mid_stream_corruption_stops() {
        let bytes = encode(&[rec(1, b"GET /a"), rec(2, b"GET /bb")]);
        let mut corrupted = bytes.clone();
        // 在第二条记录处破坏 Magic → 遇脏即停，不向后重同步。
        let off2 = 64 + rec(1, b"GET /a").payload.len();
        corrupted[off2] ^= 0xFF;
        let mut c = std::io::Cursor::new(corrupted);
        let r = scan_reader(&mut c).unwrap();
        assert_eq!(r.stats.records, 1);
        assert!(r.stats.stopped_early);
        assert!(r.stats.dirty_tail_bytes > 0);
    }

    #[test]
    fn split_record_across_reads() {
        // 用极小读块强制记录跨块：验证分块缓冲正确。
        let bytes = encode(&[rec(1, b"GET /a"), rec(2, b"GET /bb")]);
        let c = std::io::Cursor::new(bytes);
        // 逐字节读取（Read trait 可能一次只给 1 字节）→ 仍应完整解码。
        let mut single = SingleByteReader { inner: c };
        let r = scan_reader(&mut single).unwrap();
        assert_eq!(r.stats.records, 2);
        assert_eq!(r.stats.dirty_tail_bytes, 0);
    }

    struct SingleByteReader {
        inner: std::io::Cursor<Vec<u8>>,
    }
    impl Read for SingleByteReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let mut b = [0u8; 1];
            let n = self.inner.read(&mut b)?;
            if n > 0 && !buf.is_empty() {
                buf[0] = b[0];
            }
            Ok(n)
        }
    }
}
