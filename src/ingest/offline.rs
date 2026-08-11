//! 离线输入：扫描 WAL 目录，逐文件四重校验解码为 WalRecord 流。

use crate::walscan::{scan_reader, ScanStats};
use anyhow::{Context, Result};
use sov_probe::wal::header::WalRecord;
use std::fs::File;
use std::path::{Path, PathBuf};

/// 单个 WAL 文件的扫描结果。
#[derive(Debug)]
pub struct WalFileScan {
    pub path: PathBuf,
    /// 文件字节数。
    pub file_size: u64,
    pub records: Vec<WalRecord>,
    pub stats: ScanStats,
}

/// 离线扫描器：枚举 `*.wal` 文件并解码。
pub struct OfflineScanner {
    dir: PathBuf,
}

impl OfflineScanner {
    pub fn new(dir: impl AsRef<Path>) -> OfflineScanner {
        OfflineScanner {
            dir: dir.as_ref().to_path_buf(),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// 扫描目录下全部 `*.wal` 文件（按文件名排序，保证确定性）。
    pub fn scan_all(&self) -> Result<Vec<WalFileScan>> {
        let mut files: Vec<PathBuf> = Vec::new();
        let rd = std::fs::read_dir(&self.dir)
            .with_context(|| format!("读取目录失败: {}", self.dir.display()))?;
        for e in rd {
            let e = e?;
            let p = e.path();
            if p.extension().map(|x| x == "wal").unwrap_or(false) && p.is_file() {
                files.push(p);
            }
        }
        files.sort();

        let mut out = Vec::with_capacity(files.len());
        for f in files {
            let mut file =
                File::open(&f).with_context(|| format!("打开 WAL 失败: {}", f.display()))?;
            let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
            let res = scan_reader(&mut file)
                .with_context(|| format!("扫描 WAL 失败: {}", f.display()))?;
            out.push(WalFileScan {
                path: f,
                file_size,
                records: res.records,
                stats: res.stats,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sov_probe::wal::header::WalRecord;

    fn rec(payload: &[u8]) -> WalRecord {
        WalRecord {
            timestamp_ns: 1,
            flags: 0,
            tcp_flags: 0x10,
            tcp_seq: 1,
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

    #[test]
    fn scan_dir_deterministic() {
        let dir = std::env::temp_dir().join(format!("sovvault-wal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, n) in [("seg_0002.wal", 2u32), ("seg_0001.wal", 1u32)] {
            let mut buf = Vec::new();
            for i in 0..n {
                rec(&format!("GET /{}", i).into_bytes()).encode(&mut buf);
            }
            std::fs::write(dir.join(name), &buf).unwrap();
        }
        // 非 .wal 文件应被忽略。
        std::fs::write(dir.join("notes.txt"), b"nope").unwrap();

        let s = OfflineScanner::new(&dir);
        let scans = s.scan_all().unwrap();
        assert_eq!(scans.len(), 2);
        // 排序保证确定性：seg_0001 在前。
        assert!(scans[0]
            .path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains("0001"));
        assert_eq!(scans[0].records.len(), 1);
        assert_eq!(scans[1].records.len(), 2);
        assert_eq!(scans[1].records[1].payload, b"GET /1");
        assert_eq!(scans[0].stats.dirty_tail_bytes, 0);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_dir_errors() {
        let s = OfflineScanner::new("/tmp/definitely-not-exist-xyz");
        assert!(s.scan_all().is_err());
    }
}
