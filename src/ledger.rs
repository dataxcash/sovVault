//! SQLite 管理平面：文件清单/水位线/审计/ext_meta/meta_binds。
//! DDL 对齐 09_sovVault_实施方案.md §4.4。

use anyhow::Result;
use rusqlite::{params, Connection};
use std::path::Path;

/// files.kind：0=WAL 1=PCAP。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum FileKind {
    Wal = 0,
    Pcap = 1,
}

/// OPEN 状态 hot 文件记录（重启恢复）。
#[derive(Debug, Clone)]
pub struct OpenFileRec {
    pub file_id: i64,
    pub path: String,
    pub watermark: u64,
    pub segment_seq: Option<i64>,
}

/// files.state：0=OPEN 1=SEALED 2=ARCHIVED。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum FileState {
    Open = 0,
    Sealed = 1,
    Archived = 2,
}

/// 审计异常事件（低频，逐条可查可回跳原文）。
#[derive(Debug, Clone, Default)]
pub struct AnomalyEvent {
    pub ts: i64,
    pub kind: i64,
    pub dev_id: Option<i64>,
    pub segment_seq: Option<i64>,
    pub conn_hash: Option<Vec<u8>>,
    pub qr_id: Option<i64>,
    pub detail: Option<String>,
}

pub struct Ledger {
    conn: Connection,
}

impl Ledger {
    /// 打开（不存在则创建）并建表。
    pub fn open(path: &Path) -> Result<Ledger> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        let ledger = Ledger { conn };
        ledger.init()?;
        Ok(ledger)
    }

    /// 建表（幂等：CREATE IF NOT EXISTS）。
    pub fn init(&self) -> Result<()> {
        self.conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS files(
               file_id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT NOT NULL UNIQUE,
               kind INTEGER NOT NULL,
               dev_id INTEGER NOT NULL DEFAULT 1, segment_seq INTEGER,
               size_bytes INTEGER NOT NULL DEFAULT 0, sha256 BLOB,
               first_ts INTEGER, last_ts INTEGER,
               state INTEGER NOT NULL DEFAULT 0,
               analysis_offset INTEGER NOT NULL DEFAULT 0,
               created_at INTEGER NOT NULL);
             CREATE INDEX IF NOT EXISTS idx_files_state ON files(state);
             CREATE TABLE IF NOT EXISTS anomalies(
               id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
               kind INTEGER NOT NULL, dev_id INTEGER, segment_seq INTEGER,
               conn_hash BLOB, qr_id INTEGER, detail TEXT);
             CREATE INDEX IF NOT EXISTS idx_anomalies_kind ON anomalies(kind,ts);
             CREATE TABLE IF NOT EXISTS ext_meta(
               meta_bind_id INTEGER PRIMARY KEY AUTOINCREMENT, protocol_hint INTEGER NOT NULL,
               magic_prefix BLOB, entropy REAL, has_fixed_header INTEGER NOT NULL DEFAULT 0,
               dst_port INTEGER, hit_count INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS meta_binds(id INTEGER PRIMARY KEY AUTOINCREMENT,
               name TEXT NOT NULL, proto INTEGER, dst_port INTEGER, dst_ip TEXT,
               fingerprint TEXT, extractor TEXT, enabled INTEGER DEFAULT 1);",
        )?;
        Ok(())
    }

    /// 登记新文件，返回 file_id（单调递增）。
    pub fn insert_file(
        &self,
        path: &str,
        kind: FileKind,
        dev_id: i64,
        segment_seq: Option<i64>,
        created_at: i64,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO files(path, kind, dev_id, segment_seq, created_at)
             VALUES(?1, ?2, ?3, ?4, ?5)",
            params![path, kind as i64, dev_id, segment_seq, created_at],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// 取文件水位线（已提交 LMDB 的字节边界）。
    pub fn watermark(&self, file_id: i64) -> Result<u64> {
        let v: i64 = self.conn.query_row(
            "SELECT analysis_offset FROM files WHERE file_id = ?1",
            params![file_id],
            |r| r.get(0),
        )?;
        Ok(v as u64)
    }

    /// 推进水位线（单调：只允许前进）。
    pub fn advance_watermark(&self, file_id: i64, new_offset: u64) -> Result<()> {
        let affected = self.conn.execute(
            "UPDATE files SET analysis_offset = ?2 WHERE file_id = ?1 AND analysis_offset <= ?2",
            params![file_id, new_offset as i64],
        )?;
        if affected == 0 {
            anyhow::bail!(
                "水位线回退被拒绝: file_id={} new_offset={}",
                file_id,
                new_offset
            );
        }
        Ok(())
    }

    pub fn set_file_state(&self, file_id: i64, state: FileState) -> Result<()> {
        self.conn.execute(
            "UPDATE files SET state = ?2 WHERE file_id = ?1",
            params![file_id, state as i64],
        )?;
        Ok(())
    }

    /// 查询某 dev 最新的 OPEN 状态 hot 文件（崩溃重启恢复依据）。
    pub fn open_file_for_dev(&self, dev_id: i64) -> Result<Option<OpenFileRec>> {
        let mut stmt = self.conn.prepare(
            "SELECT file_id, path, analysis_offset, segment_seq
             FROM files WHERE dev_id = ?1 AND state = 0 ORDER BY file_id DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(params![dev_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(OpenFileRec {
                file_id: row.get(0)?,
                path: row.get(1)?,
                watermark: row.get::<_, i64>(2)? as u64,
                segment_seq: row.get(3)?,
            }))
        } else {
            Ok(None)
        }
    }

    /// 归档/校验元数据更新（size/sha256/首末时间）。
    pub fn update_file_meta(
        &self,
        file_id: i64,
        size_bytes: i64,
        sha256: Option<&[u8]>,
        first_ts: Option<i64>,
        last_ts: Option<i64>,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE files SET size_bytes=?2, sha256=?3, first_ts=?4, last_ts=?5 WHERE file_id=?1",
            params![file_id, size_bytes, sha256, first_ts, last_ts],
        )?;
        Ok(())
    }

    /// 审计异常入库（低频，逐条可查可回跳）。
    pub fn insert_anomaly(&self, e: &AnomalyEvent) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO anomalies(ts, kind, dev_id, segment_seq, conn_hash, qr_id, detail)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                e.ts,
                e.kind,
                e.dev_id,
                e.segment_seq,
                e.conn_hash.as_deref(),
                e.qr_id,
                e.detail.as_deref()
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// ext_meta 注册（连接 ↔ 协议元数据指纹）。
    pub fn register_ext_meta(
        &self,
        protocol_hint: i64,
        magic_prefix: Option<&[u8]>,
        entropy: Option<f64>,
        has_fixed_header: bool,
        dst_port: Option<i64>,
        created_at: i64,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO ext_meta(protocol_hint, magic_prefix, entropy, has_fixed_header, dst_port, created_at)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                protocol_hint,
                magic_prefix,
                entropy,
                has_fixed_header as i64,
                dst_port,
                created_at
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// meta_binds 注册（协议绑定规则）。
    pub fn register_meta_bind(
        &self,
        name: &str,
        proto: Option<i64>,
        dst_port: Option<i64>,
        dst_ip: Option<&str>,
        fingerprint: Option<&str>,
        extractor: Option<&str>,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO meta_binds(name, proto, dst_port, dst_ip, fingerprint, extractor, enabled)
             VALUES(?1,?2,?3,?4,?5,?6,1)",
            params![name, proto, dst_port, dst_ip, fingerprint, extractor],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn meta_bind_count(&self) -> Result<i64> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM meta_binds", [], |r| r.get(0))?;
        Ok(n)
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmpdb(tag: &str) -> std::path::PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("sovvault-ledger-{}-{}.db", tag, ts));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn ddl_idempotent() {
        let p = tmpdb("ddl");
        let l = Ledger::open(&p).unwrap();
        // 第二次 init 必须幂等成功。
        l.init().unwrap();
        Ledger::open(&p).unwrap();
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn file_lifecycle_and_watermark() {
        let p = tmpdb("file");
        let l = Ledger::open(&p).unwrap();
        let id = l
            .insert_file("/data/hot/seg1.wal", FileKind::Wal, 1, Some(3), 123)
            .unwrap();
        assert_eq!(l.watermark(id).unwrap(), 0);

        l.advance_watermark(id, 4096).unwrap();
        assert_eq!(l.watermark(id).unwrap(), 4096);

        // 水位线只能前进：回退必须报错。
        assert!(l.advance_watermark(id, 1000).is_err());

        l.set_file_state(id, FileState::Sealed).unwrap();
        l.update_file_meta(id, 8192, Some(&[0xAA; 32]), Some(1), Some(2))
            .unwrap();
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn anomaly_and_metabinds() {
        let p = tmpdb("meta");
        let l = Ledger::open(&p).unwrap();
        let a = l
            .insert_anomaly(&AnomalyEvent {
                ts: 1,
                kind: 8,
                dev_id: Some(1),
                segment_seq: Some(2),
                conn_hash: Some(vec![0u8; 8]),
                qr_id: Some(77),
                detail: Some("SEQ_GAP".into()),
            })
            .unwrap();
        assert!(a > 0);
        let m = l
            .register_meta_bind(
                "web",
                Some(6),
                Some(80),
                None,
                Some("http"),
                Some("http_line"),
            )
            .unwrap();
        assert!(m > 0);
        assert_eq!(l.meta_bind_count().unwrap(), 1);
        let e = l
            .register_ext_meta(1, Some(b"GET "), Some(3.5), true, Some(80), 9)
            .unwrap();
        assert!(e > 0);
        let _ = std::fs::remove_file(&p);
    }
}
