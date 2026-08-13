//! P5 PCAP 司法级流式导出：DBI_RECORD_TS 游标 + 内存 BPF 过滤 + orig_len/incl_len 裁切还原。
//!
//! 设计依据：09 §九 P5（PCAP 导出）与 §12 验收（Wireshark 还原握手 + `[Packet size limited]`
//! 精准出现）、§8.2 export 集成测试。
//!
//! 链路：`DBI_RECORD_TS`（键序 `[ts_ns][packet_idx]`）游标翻页 → **内存 BPF** 在紧凑摘要
//! 上预过滤（proto/ip/port，命中才打开数据平面文件）→ `WalResolver` 按 `IDX=(file_id<<32)|offset`
//! 回读 WAL 原文（Magic→Version→Length→CRC32 四重校验，司法级保真）→ 合成
//! Ethernet+IPv4+TCP/UDP 帧 → `incl_len`（实际落盘帧长）/ `orig_len`（线上原始长度）精确落盘。
//!
//! 裁切还原：WAL 存 `payload_len`（incl）+ `orig_payload_len`（orig）；`incl < orig` 时
//! Wireshark 自动标 `[Packet size limited]`——不伪造字节，截断留白，司法口径严格。

use crate::db::{DbRegistry, RecordSummary};
use crate::id;
use crate::ledger::Ledger;
use crate::query::{ExportSink, RecordRow, replay_scan};
use anyhow::{Context, Result};
use pcap_file::pcap::{PcapPacket, PcapWriter};
use sov_probe::wal::header::WalRecord;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::time::Duration;

/// 链路层固定头长（Ethernet II）。
pub const L2_ETH: usize = 14;
/// IPv4 头长。
pub const L3_IPV4: usize = 20;
/// TCP 头长（无选项）。
pub const L4_TCP: usize = 20;
/// UDP 头长。
pub const L4_UDP: usize = 8;

/// 导出统计。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PcapStats {
    /// 实际写入 pcap 的报文数。
    pub packets: u64,
    /// 被 BPF 过滤剔除的报文数。
    pub filtered: u64,
    /// 数据平面回读失败（截断/损坏/缺失）数。
    pub unresolved: u64,
    /// 落盘字节（incl_len 合计）。
    pub incl_bytes: u64,
    /// 线上原始字节（orig_len 合计）。
    pub orig_bytes: u64,
}

/// 内存 BPF 过滤：先在 `RECORD_TS` 紧凑摘要上做预过滤（proto/ip/port），
/// flags 约束在回读 WAL 记录后判定（摘要 flags 位含 DEGRADED，与 TCP flags 冲突，不以摘要判 flags）。
#[derive(Debug, Clone, Default)]
pub struct BpfFilter {
    pub proto: Option<u8>,
    pub src_ip: Option<u32>,
    pub dst_ip: Option<u32>,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    /// TCP flags：置任一位即通过。
    pub flags_any: Option<u8>,
    /// TCP flags：全部置位才通过。
    pub flags_all: Option<u8>,
}

impl BpfFilter {
    /// 摘要级预过滤（不打开数据平面文件）。
    pub fn matches_summary(&self, s: &RecordSummary) -> bool {
        if let Some(p) = self.proto {
            if p != s.proto {
                return false;
            }
        }
        if let Some(ip) = self.src_ip {
            if ip != s.src_ip {
                return false;
            }
        }
        if let Some(ip) = self.dst_ip {
            if ip != s.dst_ip {
                return false;
            }
        }
        if let Some(port) = self.sport {
            if port != s.sport {
                return false;
            }
        }
        if let Some(port) = self.dport {
            if port != s.dport {
                return false;
            }
        }
        true
    }

    /// 记录级 flags 判定（在回读后执行）。
    pub fn matches_record(&self, rec: &WalRecord) -> bool {
        if let Some(any) = self.flags_any {
            if rec.tcp_flags & any == 0 {
                return false;
            }
        }
        if let Some(all) = self.flags_all {
            if rec.tcp_flags & all != all {
                return false;
            }
        }
        true
    }

    pub fn is_empty(&self) -> bool {
        self.proto.is_none()
            && self.src_ip.is_none()
            && self.dst_ip.is_none()
            && self.sport.is_none()
            && self.dport.is_none()
            && self.flags_any.is_none()
            && self.flags_all.is_none()
    }

    /// CLI flags 名 → 位（"syn,ack" → 0x02|0x10）。
    pub fn parse_flags(names: &[&str]) -> Option<u8> {
        let mut bits = 0u8;
        for n in names {
            let b = match *n {
                "fin" => sov_probe::wal::header::TCP_FIN,
                "syn" => sov_probe::wal::header::TCP_SYN,
                "rst" => sov_probe::wal::header::TCP_RST,
                "psh" => sov_probe::wal::header::TCP_PSH,
                "ack" => sov_probe::wal::header::TCP_ACK,
                "urg" => sov_probe::wal::header::TCP_URG,
                _ => return None,
            };
            bits |= b;
        }
        Some(bits)
    }
}

/// 数据平面回读器：`packet_idx → WalRecord`。按 file_id 缓存句柄与路径，`try_decode` 四重校验。
pub struct WalResolver<'a> {
    ledger: &'a Ledger,
    paths: HashMap<u32, Option<String>>,
    handles: HashMap<u32, File>,
}

impl<'a> WalResolver<'a> {
    pub fn new(ledger: &'a Ledger) -> WalResolver<'a> {
        WalResolver {
            ledger,
            paths: HashMap::new(),
            handles: HashMap::new(),
        }
    }

    /// 按 IDX 回读原始 WAL 记录（CRC32 校验失败/截断 → None，不计入导出）。
    pub fn load(&mut self, packet_idx: u64) -> Result<Option<WalRecord>> {
        let (file_id, offset) = id::decode(packet_idx);
        let Some(f) = self.handle(file_id)? else {
            return Ok(None);
        };
        f.seek(SeekFrom::Start(offset as u64))?;
        let mut hdr = [0u8; 64];
        let got = f.read(&mut hdr)?;
        if got != hdr.len() {
            return Ok(None); // 数据平面截断（崩溃尾部已按水位线截断，不应出现）
        }
        let payload_len = u32::from_be_bytes(hdr[56..60].try_into().unwrap()) as usize;
        let mut buf = Vec::with_capacity(hdr.len() + payload_len);
        buf.extend_from_slice(&hdr);
        let mut payload = vec![0u8; payload_len];
        if f.read_exact(&mut payload).is_err() {
            return Ok(None);
        }
        buf.extend_from_slice(&payload);
        // Magic → Version → Length → CRC32 四重校验；损坏丢弃。
        Ok(WalRecord::try_decode(&buf, 0).map(|(r, _)| r))
    }

    fn handle(&mut self, file_id: u32) -> Result<Option<&mut File>> {
        if self.handles.contains_key(&file_id) {
            return Ok(self.handles.get_mut(&file_id));
        }
        let path = self.path(file_id)?;
        let Some(path) = path else {
            self.handles.insert(file_id, File::open("/dev/null")?);
            return Ok(self.handles.get_mut(&file_id));
        };
        let f = OpenOptions::new()
            .read(true)
            .open(&path)
            .with_context(|| format!("打开数据平面文件失败: {}", path))?;
        self.handles.insert(file_id, f);
        Ok(self.handles.get_mut(&file_id))
    }

    fn path(&mut self, file_id: u32) -> Result<Option<String>> {
        if let Some(p) = self.paths.get(&file_id) {
            return Ok(p.clone());
        }
        let p = self.ledger.file_path(file_id as i64)?;
        self.paths.insert(file_id, p.clone());
        Ok(p)
    }
}

/// PCAP 流式写入器（拥有 writer，导出结束时显式 flush）。
pub struct PcapSink<'r, W: Write> {
    writer: PcapWriter<BufWriter<W>>,
    resolver: WalResolver<'r>,
    filter: &'r BpfFilter,
    stats: PcapStats,
}

impl<'r, W: Write> PcapSink<'r, W> {
    pub fn new(out: W, ledger: &'r Ledger, filter: &'r BpfFilter) -> Result<PcapSink<'r, W>> {
        let writer = PcapWriter::new(BufWriter::new(out))?;
        Ok(PcapSink {
            writer,
            resolver: WalResolver::new(ledger),
            filter,
            stats: PcapStats::default(),
        })
    }

    pub fn stats(&self) -> PcapStats {
        self.stats
    }

    /// 单条 RECORD_TS 行 → 过滤 → 回读 → 合成 → 落盘。
    pub fn record(&mut self, row: &RecordRow) -> Result<()> {
        if !self.filter.matches_summary(&row.summary) {
            self.stats.filtered += 1;
            return Ok(());
        }
        let Some(rec) = self.resolver.load(row.packet_idx)? else {
            self.stats.unresolved += 1;
            return Ok(());
        };
        if !self.filter.matches_record(&rec) {
            self.stats.filtered += 1;
            return Ok(());
        }
        let frame = synthesize(&rec);
        let l4 = if rec.proto == 6 { L4_TCP } else { L4_UDP };
        let orig = (L2_ETH + L3_IPV4 + l4 + rec.orig_payload_len as usize) as u32;
        self.writer.write_packet(&PcapPacket::new(
            Duration::from_nanos(rec.timestamp_ns),
            orig,
            &frame,
        ))?;
        self.stats.packets += 1;
        self.stats.incl_bytes += frame.len() as u64;
        self.stats.orig_bytes += orig as u64;
        Ok(())
    }

    /// 消费自身，flush 底层缓冲并返回统计。
    pub fn finish(self) -> Result<PcapStats> {
        let inner = self.writer.into_writer();
        let mut buf = inner;
        buf.flush()?;
        Ok(self.stats)
    }
}

/// ExportSink 适配：PCAP 消费 RECORD_TS 行（BPF 过滤 + 数据平面回读 + 帧合成），
/// `qr` 维度不适用（PCAP 无 Q 行）→ 恒 Ok。
impl<'r, W: Write> ExportSink for PcapSink<'r, W> {
    fn qr(&mut self, _row: &crate::query::QrIndexRow) -> Result<()> {
        Ok(())
    }
    fn record(&mut self, row: &RecordRow) -> Result<()> {
        PcapSink::record(self, row)
    }
}

/// 流式导出：`DBI_RECORD_TS` 游标翻页打满（has_more 键级判定，天然防断流），
/// 全量时间窗可选；返回写入的报文数。
/// L1+L3：带时间窗时按 epoch 边界索引裁剪历史 epoch（只挑窗口内命中的），
/// 每个 epoch 单次 range 流式喂给 sink（REPLAY 热路径不随历史总量衰减）。
pub fn export_pcap<W: Write>(
    reg: &DbRegistry,
    ledger: &Ledger,
    filter: &BpfFilter,
    start_ts: Option<u64>,
    end_ts: Option<u64>,
    out: W,
) -> Result<PcapStats> {
    let mut sink = PcapSink::new(out, ledger, filter)?;
    replay_scan(reg, ledger, start_ts, end_ts, &mut sink)?;
    sink.finish()
}

/// 合成一条完整帧：Ethernet II + IPv4 + TCP/UDP + payload（v0.4 起仅 IPv4）。
/// 语义与 sov-probe `sov2pcap` 完全对齐（校验和置 0，Wireshark 自算；seq/ack/window 填真实线上值）。
pub fn synthesize(rec: &WalRecord) -> Vec<u8> {
    let src_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let dst_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    let l4_len = (if rec.proto == 6 { L4_TCP } else { L4_UDP }) + rec.payload.len();

    let mut out = Vec::with_capacity(L2_ETH + L3_IPV4 + l4_len);
    out.extend_from_slice(&dst_mac);
    out.extend_from_slice(&src_mac);
    out.extend_from_slice(&[0x08, 0x00]);

    let total = L3_IPV4 + l4_len;
    let (t_hi, t_lo) = (((total >> 8) & 0xFF) as u8, (total & 0xFF) as u8);
    out.extend_from_slice(&[0x45, 0x00, t_hi, t_lo]);
    out.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 0x40, rec.proto as u8, 0x00, 0x00]);
    out.extend_from_slice(&rec.src_ip);
    out.extend_from_slice(&rec.dst_ip);

    let (sp_hi, sp_lo) = ((rec.src_port >> 8) as u8, (rec.src_port & 0xFF) as u8);
    let (dp_hi, dp_lo) = ((rec.dst_port >> 8) as u8, (rec.dst_port & 0xFF) as u8);
    if rec.proto == 6 {
        let flags = rec.tcp_flags;
        let (seq_b, ack_b) = (rec.tcp_seq.to_be_bytes(), rec.tcp_ack.to_be_bytes());
        let (win_hi, win_lo) = ((rec.window_size >> 8) as u8, (rec.window_size & 0xFF) as u8);
        out.extend_from_slice(&[
            sp_hi, sp_lo, dp_hi, dp_lo, seq_b[0], seq_b[1], seq_b[2], seq_b[3], ack_b[0],
            ack_b[1], ack_b[2], ack_b[3], 0x50, flags, win_hi, win_lo, 0, 0, 0, 0,
        ]);
    } else {
        let ulen = ((8 + rec.payload.len()) as u16).to_be_bytes();
        out.extend_from_slice(&[sp_hi, sp_lo, dp_hi, dp_lo, ulen[0], ulen[1], 0, 0]);
    }
    out.extend_from_slice(&rec.payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcap_file::pcap::PcapReader;
    use std::io::BufReader;
    use sov_probe::wal::header::{TCP_ACK, TCP_SYN};

    fn record(proto: u16, tcp_flags: u8, orig_len: u32, payload: &[u8]) -> WalRecord {
        WalRecord {
            timestamp_ns: 1_700_000_000_000,
            flags: 0,
            tcp_flags,
            tcp_seq: 0x1122_3344,
            tcp_ack: 0x5566_7788,
            window_size: 8192,
            src_ip: [192, 168, 1, 10],
            dst_ip: [10, 0, 0, 1],
            src_port: 12345,
            dst_port: 443,
            proto,
            orig_payload_len: orig_len,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn synthesize_tcp_ipv4_layout() {
        let rec = record(6, TCP_SYN | TCP_ACK, 5, b"hello");
        let packet = synthesize(&rec);
        let expect_len = L2_ETH + L3_IPV4 + (L4_TCP + rec.payload.len());
        assert_eq!(packet.len(), expect_len);
        assert_eq!(&packet[0..6], &[0x02, 0, 0, 0, 0, 2]);
        assert_eq!(&packet[6..12], &[0x02, 0, 0, 0, 0, 1]);
        assert_eq!(&packet[12..14], &[0x08, 0x00]);
        assert_eq!(packet[14], 0x45);
        assert_eq!(packet[14 + 9], 6);
        assert_eq!(&packet[14 + 12..14 + 16], &[192, 168, 1, 10]);
        assert_eq!(&packet[14 + 16..14 + 20], &[10, 0, 0, 1]);
        let tcp = L2_ETH + L3_IPV4;
        assert_eq!(&packet[tcp..tcp + 2], &[48, 57]); // 12345 BE
        assert_eq!(&packet[tcp + 2..tcp + 4], &[1, 187]); // 443 BE
        assert_eq!(packet[tcp + 13], TCP_SYN | TCP_ACK);
        assert_eq!(&packet[expect_len - 5..], b"hello");
    }

    #[test]
    fn synthesize_tcp_preserves_seq_ack_window() {
        let rec = record(6, TCP_SYN | TCP_ACK, 5, b"hello");
        let packet = synthesize(&rec);
        let tcp = L2_ETH + L3_IPV4;
        assert_eq!(
            u32::from_be_bytes([packet[tcp + 4], packet[tcp + 5], packet[tcp + 6], packet[tcp + 7]]),
            rec.tcp_seq
        );
        assert_eq!(
            u32::from_be_bytes([packet[tcp + 8], packet[tcp + 9], packet[tcp + 10], packet[tcp + 11]]),
            rec.tcp_ack
        );
        assert_eq!(
            u16::from_be_bytes([packet[tcp + 14], packet[tcp + 15]]),
            rec.window_size
        );
    }

    #[test]
    fn synthesize_udp_ipv4_layout() {
        let rec = record(17, 0, 3, b"abc");
        let packet = synthesize(&rec);
        let expect_len = L2_ETH + L3_IPV4 + (L4_UDP + rec.payload.len());
        assert_eq!(packet.len(), expect_len);
        assert_eq!(packet[14 + 9], 17);
        let udp = L2_ETH + L3_IPV4;
        let ulen = u16::from_be_bytes([packet[udp + 4], packet[udp + 5]]);
        assert_eq!(ulen, 8 + rec.payload.len() as u16);
    }

    #[test]
    fn bpf_summary_prefilter() {
        let s = RecordSummary {
            proto: 6,
            flags: 0,
            src_ip: 0xC0A8_0001,
            dst_ip: 0x0A00_0001,
            sport: 12345,
            dport: 443,
            len: 10,
        };
        let f = BpfFilter {
            dport: Some(443),
            proto: Some(6),
            ..Default::default()
        };
        assert!(f.matches_summary(&s));
        let f2 = BpfFilter {
            proto: Some(17),
            ..Default::default()
        };
        assert!(!f2.matches_summary(&s));
        let f3 = BpfFilter {
            src_ip: Some(0x0A00_0001),
            ..Default::default()
        };
        assert!(!f3.matches_summary(&s));
        assert!(BpfFilter::default().matches_summary(&s));
    }

    #[test]
    fn bpf_flags_record_level() {
        let rec = record(6, TCP_SYN | TCP_ACK, 0, b"");
        let f = BpfFilter {
            flags_any: Some(TCP_ACK),
            ..Default::default()
        };
        assert!(f.matches_record(&rec));
        let f = BpfFilter {
            flags_all: Some(TCP_SYN | TCP_ACK),
            ..Default::default()
        };
        assert!(f.matches_record(&rec));
        let f = BpfFilter {
            flags_all: Some(TCP_SYN | TCP_ACK | sov_probe::wal::header::TCP_FIN),
            ..Default::default()
        };
        assert!(!f.matches_record(&rec));
    }

    #[test]
    fn parse_flags_names() {
        assert_eq!(
            BpfFilter::parse_flags(&["syn", "ack"]),
            Some(TCP_SYN | TCP_ACK)
        );
        assert!(BpfFilter::parse_flags(&["bogus"]).is_none());
    }

    /// pcap-file 写读闭环：orig_len > incl_len（裁切）时校验通过且 orig 字段保真。
    #[test]
    fn pcap_write_read_truncated_fidelity() {
        let rec = record(6, TCP_SYN, 1000, b"GET /big HTTP/1.1"); // orig 1000，incl 仅 16
        let mut buf = Vec::new();
        let mut w = PcapWriter::new(BufWriter::new(&mut buf)).unwrap();
        let frame = synthesize(&rec);
        let orig = (L2_ETH + L3_IPV4 + L4_TCP + 1000) as u32;
        w.write_packet(&PcapPacket::new(Duration::from_nanos(rec.timestamp_ns), orig, &frame))
            .unwrap();
        drop(w);

        let mut r = PcapReader::new(BufReader::new(&buf[..])).unwrap();
        let pkt = r.next_packet().unwrap().unwrap();
        assert_eq!(pkt.orig_len, orig);
        assert_eq!(pkt.data.len() as u32, frame.len() as u32);
        assert!(pkt.orig_len > pkt.data.len() as u32, "裁切：orig > incl");
        // 握手 flag 位在帧内保真。
        assert_eq!(pkt.data[L2_ETH + L3_IPV4 + 13], TCP_SYN);
    }
}
