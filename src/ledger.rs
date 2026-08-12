//! SQLite 管理平面：文件清单/水位线/审计/ext_meta/meta_binds。
//! DDL 对齐 09_sovVault_实施方案.md §4.4。

use anyhow::Result;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
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
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct AnomalyEvent {
    pub ts: i64,
    pub kind: i64,
    pub dev_id: Option<i64>,
    pub segment_seq: Option<i64>,
    pub conn_hash: Option<Vec<u8>>,
    pub qr_id: Option<i64>,
    pub detail: Option<String>,
}

/// meta_binds 表行（Meta 子命令 / 查询展示）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct MetaBindRow {
    pub id: i64,
    pub name: String,
    pub proto: Option<i64>,
    pub dst_port: Option<i64>,
    pub fingerprint: Option<String>,
    pub extractor: Option<String>,
    pub enabled: i64,
}

/// ext_meta 表行（Meta 子命令 / 查询展示）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExtMetaRow {
    pub meta_bind_id: i64,
    pub protocol_hint: i64,
    pub magic_prefix: Option<Vec<u8>>,
    pub entropy: Option<f64>,
    pub has_fixed_header: bool,
    pub dst_port: Option<i64>,
    pub hit_count: i64,
    pub created_at: i64,
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

    /// 数据平面文件路径（PCAP 导出回读 / 司法溯源用）。
    pub fn file_path(&self, file_id: i64) -> Result<Option<String>> {
        let v: Option<String> = self
            .conn
            .query_row(
                "SELECT path FROM files WHERE file_id = ?1",
                params![file_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(v)
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

    /// 批量审计入库（单事务；P4 终态事件族——TTL 扫描逐 Q 落库走此路径）。
    /// 使用 `unchecked_transaction`（&self）：Ledger 单连接、调用方串行，无嵌套事务风险。
    pub fn insert_anomalies(&self, events: &[AnomalyEvent]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO anomalies(ts, kind, dev_id, segment_seq, conn_hash, qr_id, detail)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)",
            )?;
            for e in events {
                stmt.execute(params![
                    e.ts,
                    e.kind,
                    e.dev_id,
                    e.segment_seq,
                    e.conn_hash.as_deref(),
                    e.qr_id,
                    e.detail.as_deref()
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// 异常聚合（只计数，按 kind 分组；时间窗可选）。
    /// 返回 (kind, count)，kind 升序。
    pub fn anomaly_summary(
        &self,
        start: Option<i64>,
        end: Option<i64>,
    ) -> Result<Vec<(i64, i64)>> {
        let mut conds: Vec<&str> = Vec::new();
        let mut pvals: Vec<i64> = Vec::new();
        if let Some(s) = start {
            conds.push("ts >= ?");
            pvals.push(s);
        }
        if let Some(e) = end {
            conds.push("ts <= ?");
            pvals.push(e);
        }
        let where_clause = if conds.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conds.join(" AND "))
        };
        let mut stmt = self.conn.prepare(&format!(
            "SELECT kind, COUNT(*) c FROM anomalies {} GROUP BY kind ORDER BY kind",
            where_clause
        ))?;
        let rows = stmt.query_map(params_from_iter(pvals), |r| Ok((r.get(0)?, r.get(1)?)))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// 异常回跳查询（终态事件逐 Q 可回跳原文；kind/时间窗/limit 过滤，按 id 倒序）。
    pub fn query_anomalies(
        &self,
        kind: Option<i64>,
        start: Option<i64>,
        end: Option<i64>,
        limit: usize,
    ) -> Result<Vec<AnomalyEvent>> {
        let mut sql = String::from(
            "SELECT ts, kind, dev_id, segment_seq, conn_hash, qr_id, detail FROM anomalies",
        );
        let mut conds: Vec<String> = Vec::new();
        let mut pvals: Vec<i64> = Vec::new();
        if let Some(k) = kind {
            conds.push("kind = ?".into());
            pvals.push(k);
        }
        if let Some(s) = start {
            conds.push("ts >= ?".into());
            pvals.push(s);
        }
        if let Some(e) = end {
            conds.push("ts <= ?".into());
            pvals.push(e);
        }
        if !conds.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conds.join(" AND "));
        }
        sql.push_str(" ORDER BY id DESC LIMIT ?");
        pvals.push(limit as i64);
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(pvals), |r| {
            Ok(AnomalyEvent {
                ts: r.get(0)?,
                kind: r.get(1)?,
                dev_id: r.get(2)?,
                segment_seq: r.get(3)?,
                conn_hash: r.get::<_, Option<Vec<u8>>>(4)?,
                qr_id: r.get(5)?,
                detail: r.get(6)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
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

    /// P5：meta_binds 幂等 upsert（按 name 查改插），返回主键 id。重启重跑不产生重复行。
    pub fn upsert_meta_bind(
        &self,
        name: &str,
        proto: i64,
        dst_port: i64,
        fingerprint: &str,
        extractor: &str,
    ) -> Result<i64> {
        let existing: Option<i64> = self
            .conn
            .query_row(
                "SELECT id FROM meta_binds WHERE name = ?1",
                params![name],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = existing {
            self.conn.execute(
                "UPDATE meta_binds SET proto=?2, dst_port=?3, fingerprint=?4, extractor=?5, enabled=1
                 WHERE id=?1",
                params![id, proto, dst_port, fingerprint, extractor],
            )?;
            return Ok(id);
        }
        self.conn.execute(
            "INSERT INTO meta_binds(name, proto, dst_port, fingerprint, extractor, enabled)
             VALUES(?1,?2,?3,?4,?5,1)",
            params![name, proto, dst_port, fingerprint, extractor],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// meta_binds 列表（Meta 子命令展示）。
    pub fn list_meta_binds(&self) -> Result<Vec<MetaBindRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, proto, dst_port, fingerprint, extractor, enabled FROM meta_binds
             ORDER BY id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(MetaBindRow {
                id: r.get(0)?,
                name: r.get(1)?,
                proto: r.get(2)?,
                dst_port: r.get(3)?,
                fingerprint: r.get(4)?,
                extractor: r.get(5)?,
                enabled: r.get(6)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// P5：ext_meta 幂等 upsert——同 (protocol_hint, magic_prefix, dst_port) 签名命中则 hit_count+1，
    /// 否则新登记（连接首载荷指纹台账，低频）。返回当前 hit_count。
    pub fn ext_meta_upsert(
        &self,
        protocol_hint: i64,
        magic_prefix: &[u8],
        entropy: f64,
        has_fixed_header: bool,
        dst_port: i64,
        created_at: i64,
    ) -> Result<i64> {
        let existing: Option<i64> = self
            .conn
            .query_row(
                "SELECT hit_count FROM ext_meta
                 WHERE protocol_hint=?1 AND magic_prefix=?2 AND dst_port=?3",
                params![protocol_hint, magic_prefix, dst_port],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(hits) = existing {
            let new_hits = hits + 1;
            self.conn.execute(
                "UPDATE ext_meta SET hit_count=?2, entropy=?3, has_fixed_header=?4
                 WHERE protocol_hint=?1 AND magic_prefix=?5 AND dst_port=?6",
                params![
                    protocol_hint,
                    new_hits,
                    entropy,
                    has_fixed_header as i64,
                    magic_prefix,
                    dst_port
                ],
            )?;
            return Ok(new_hits);
        }
        self.conn.execute(
            "INSERT INTO ext_meta(protocol_hint, magic_prefix, entropy, has_fixed_header, dst_port, hit_count, created_at)
             VALUES(?1,?2,?3,?4,?5,1,?6)",
            params![protocol_hint, magic_prefix, entropy, has_fixed_header as i64, dst_port, created_at],
        )?;
        Ok(1)
    }

    /// ext_meta 列表（Meta 子命令展示）。
    pub fn list_ext_meta(&self) -> Result<Vec<ExtMetaRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT meta_bind_id, protocol_hint, magic_prefix, entropy, has_fixed_header,
                    dst_port, hit_count, created_at FROM ext_meta ORDER BY hit_count DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ExtMetaRow {
                meta_bind_id: r.get(0)?,
                protocol_hint: r.get(1)?,
                magic_prefix: r.get::<_, Option<Vec<u8>>>(2)?,
                entropy: r.get(3)?,
                has_fixed_header: r.get(4)?,
                dst_port: r.get(5)?,
                hit_count: r.get(6)?,
                created_at: r.get(7)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
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

    #[test]
    fn file_path_and_p5_meta_upserts() {
        let p = tmpdb("p5meta");
        let l = Ledger::open(&p).unwrap();
        // file_path：登记后可回读。
        let id = l
            .insert_file("/data/hot/seg1.wal", FileKind::Wal, 1, Some(0), 1)
            .unwrap();
        assert_eq!(l.file_path(id).unwrap(), Some("/data/hot/seg1.wal".into()));
        assert_eq!(l.file_path(9999).unwrap(), None);

        // meta_binds upsert 幂等（按 name）。
        let m1 = l
            .upsert_meta_bind("web", 6, 80, "http", "http_line")
            .unwrap();
        let m2 = l
            .upsert_meta_bind("web", 6, 80, "http", "http_line")
            .unwrap();
        assert_eq!(m1, m2, "同名规则幂等返回同一 id");
        let binds = l.list_meta_binds().unwrap();
        assert_eq!(binds.len(), 1);
        assert_eq!(binds[0].name, "web");
        // 更新后仍同 id。
        let m3 = l
            .upsert_meta_bind("web", 6, 8080, "http", "http_line")
            .unwrap();
        assert_eq!(m1, m3);

        // ext_meta 幂等 upsert：同签名 hit_count 递增，不重复插行。
        let h1 = l.ext_meta_upsert(1, b"GET ", 3.2, false, 80, 9).unwrap();
        assert_eq!(h1, 1);
        let h2 = l.ext_meta_upsert(1, b"GET ", 3.2, false, 80, 9).unwrap();
        assert_eq!(h2, 2);
        let rows = l.list_ext_meta().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].hit_count, 2);
        assert_eq!(rows[0].magic_prefix.as_deref(), Some(&b"GET "[..]));
        let _ = std::fs::remove_file(&p);
    }
}
