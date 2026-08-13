//! 批量原子性：一个 Batch = 双 env 双事务（09 §13.4，epoch 先行）→ SQLite 殿后（2PC-Lite 收敛）。
//!
//! 提交协议（顺序不可颠倒，09 §5.2 + §13.4）：
//!   ① LMDB 双事务：QrMatcher 内部完成（RECORD_TS/终态 QR_PAIR/次级索引 → epoch_txn 先行；
//!      CONN_STATE/QR_PENDING/PENDING_TTL/在途 QR_PAIR → live_txn 殿后；逐条 NO_OVERWRITE 幂等）；
//!   ② SQLite 殿后：files.analysis_offset 水位线推进 + 文件状态；
//!   ③ 内存游标推进（本批 pending 清空，由调用方在 commit 成功后执行）。
//!
//! 文件边界屏障：扫描到达文件末尾（FILE_ID 变更）时，即使未满 BATCHSIZE 也强制截断提交，
//! 逻辑事务绝不跨物理文件（损坏隔离在单文件内）。
//!
//! 崩溃恢复（重启流程）：
//!   1) 把 OPEN 状态的 hot 文件截断到 SQLite 水位线（数据平面写入无事务性，未提交尾部丢弃）；
//!   2) 从旧水位线重新消费同一批记录；
//!   3) 确定性主键 + MDB_NOOVERWRITE + QR_PAIR 迁移幂等（§13.4.2）→ 重放收敛，零脏数据。
//!
//! > `BatchPipeline` 不再持有 `&DbRegistry`：`flush/push_record/finish` 以参数传入 `reg`，
//! > 使 ingest/zenoh.rs 能在批次间隙对 `Box<DbRegistry>` 执行 epoch 轮转（`rotate_epoch`），
//! > 关闭旧 epoch env（munmap）回收 RSS。

use crate::db::{DbRegistry, RecordSummary};
use crate::id;
use crate::ledger::{AnomalyEvent, FileKind, FileState, Ledger};
use crate::meta::{ExtMetaEvent, MetaRegistry};
use crate::qr::{ConnArchiveEvent, QrMatcher, QrParams};
use anyhow::{Context, Result};
use sov_probe::wal::header::WalRecord;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// 待提交的索引记录：携带数据平面锚点 (dev_id, file_id, offset)。
#[derive(Debug, Clone)]
pub struct IndexedRecord {
    pub dev_id: u32,
    pub file_id: u32,
    pub offset: u32,
    pub rec: WalRecord,
}

impl IndexedRecord {
    /// 数据平面物理定位符（司法溯源唯一基因）。
    pub fn idx(&self) -> u64 {
        id::encode(self.file_id, self.offset)
    }

    /// 记录在本文件内占用的字节长度（64B header + payload）。
    fn rec_len(&self) -> u64 {
        64 + self.rec.payload.len() as u64
    }
}

impl From<&WalRecord> for RecordSummary {
    fn from(rec: &WalRecord) -> RecordSummary {
        RecordSummary {
            proto: rec.proto as u8,
            flags: rec.tcp_flags | ((rec.flags & sov_probe::wal::header::FLAG_DEGRADED) as u8),
            src_ip: u32::from_be_bytes(rec.src_ip),
            dst_ip: u32::from_be_bytes(rec.dst_ip),
            sport: rec.src_port,
            dport: rec.dst_port,
            len: rec.payload.len() as u32,
        }
    }
}

/// ① LMDB 阶段：开启 RW_TXN，逐条处理（RECORD_TS 确定性索引 + P3 QR 匹配引擎），提交。
/// 一个 Batch = 一个 LMDB 事务（P2 2PC-Lite 第一步）；Q 打开走 NO_OVERWRITE（重放幂等）。
/// 返回审计事件（代际重代/RST 级联，低频），由调用方在 SQLite 阶段落库。
pub fn stage_lmdb(
    reg: &DbRegistry,
    records: &[IndexedRecord],
    params: &QrParams,
) -> Result<Vec<AnomalyEvent>> {
    stage_lmdb_with_meta(reg, records, params, None).map(|(a, _, _)| a)
}

/// P5：带 MetaRegistry 的 LMDB 阶段——连接绑定 + 协议键/伪键提取，返回 (审计, EXT META, 连接档案)。
pub fn stage_lmdb_with_meta(
    reg: &DbRegistry,
    records: &[IndexedRecord],
    params: &QrParams,
    meta: Option<&MetaRegistry>,
) -> Result<(Vec<AnomalyEvent>, Vec<ExtMetaEvent>, Vec<ConnArchiveEvent>)> {
    let mut m = QrMatcher::begin_with_meta(reg, params, meta)?;
    for r in records {
        m.ingest(r)?;
    }
    let ext_meta = m.ext_meta_events().to_vec();
    let out = m.commit()?;
    Ok((out.anomalies, ext_meta, out.conn_archives))
}

/// ② SQLite 阶段：按文件聚合推进水位线（每文件取本批最大已提交字节边界）。
pub fn stage_sqlite(ledger: &Ledger, records: &[IndexedRecord]) -> Result<()> {
    let mut end: HashMap<u32, u64> = HashMap::new();
    for r in records {
        let e = end.entry(r.file_id).or_insert(0);
        let rec_end = r.offset as u64 + r.rec_len();
        if rec_end > *e {
            *e = rec_end;
        }
    }
    for (file_id, off) in end {
        ledger.advance_watermark(file_id as i64, off)?;
    }
    Ok(())
}

/// 完整提交协议：① LMDB 先行 → ② SQLite 殿后 →（③ 游标推进由调用方执行）。
/// 审计事件（低频）best-effort 落库（单事务批量），不阻塞提交协议。
pub fn commit_batch(
    reg: &DbRegistry,
    ledger: &Ledger,
    records: &[IndexedRecord],
    params: &QrParams,
) -> Result<Vec<AnomalyEvent>> {
    commit_batch_with_meta(reg, ledger, records, params, None).map(|(a, _)| a)
}

/// P5：带 MetaRegistry 的完整提交协议。EXT META 指纹台账在 SQLite 阶段幂等 upsert（best-effort）。
/// L4：到终态连接的档案（conns 表）在 SQLite 阶段幂等 upsert（best-effort，不阻塞提交协议）。
pub fn commit_batch_with_meta(
    reg: &DbRegistry,
    ledger: &Ledger,
    records: &[IndexedRecord],
    params: &QrParams,
    meta: Option<&MetaRegistry>,
) -> Result<(Vec<AnomalyEvent>, Vec<ExtMetaEvent>)> {
    let (anomalies, ext_meta, conn_archives) =
        stage_lmdb_with_meta(reg, records, params, meta)?;
    stage_sqlite(ledger, records)?;
    if let Err(e) = ledger.insert_anomalies(&anomalies) {
        tracing::warn!("审计事件入库失败: {}", e);
    }
    for ev in &ext_meta {
        if let Err(e) = ledger.ext_meta_upsert(
            ev.protocol_hint as i64,
            &ev.magic_prefix,
            ev.entropy,
            ev.has_fixed_header,
            ev.dst_port as i64,
            now_secs(),
        ) {
            tracing::warn!("EXT META 指纹台账入库失败: {}", e);
        }
    }
    for a in &conn_archives {
        if let Err(e) = ledger.upsert_conn_archive(&crate::ledger::ConnArchive {
            conn_hash: a.conn_hash as i64,
            first_ts: Some(a.first_ts as i64),
            last_ts: Some(a.last_ts as i64),
            state: a.state as i64,
            updated_at: now_secs(),
        }) {
            tracing::warn!("连接档案入库失败: {}", e);
        }
    }
    Ok((anomalies, ext_meta))
}

/// hot 数据平面文件写器：append-only，文件边界按 segment_size 强制轮转。
pub struct HotFileWriter<'a> {
    dir: PathBuf,
    ledger: &'a Ledger,
    dev_id: i64,
    segment_seq: u32,
    segment_size: u64,
    file: Option<File>,
    path: PathBuf,
    file_id: u32,
    offset: u64,
}

impl<'a> HotFileWriter<'a> {
    pub fn open(
        dir: impl AsRef<Path>,
        ledger: &'a Ledger,
        dev_id: i64,
        segment_seq: u32,
        segment_size: u64,
    ) -> Result<HotFileWriter<'a>> {
        std::fs::create_dir_all(dir.as_ref())?;
        let mut w = HotFileWriter {
            dir: dir.as_ref().to_path_buf(),
            ledger,
            dev_id,
            segment_seq,
            segment_size,
            file: None,
            path: PathBuf::new(),
            file_id: 0,
            offset: 0,
        };
        w.ensure_open()?;
        Ok(w)
    }

    pub fn file_id(&self) -> u32 {
        self.file_id
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    fn ensure_open(&mut self) -> Result<()> {
        if self.file.is_some() {
            return Ok(());
        }
        let path = self
            .dir
            .join(format!("segment_{:04}.wal", self.segment_seq));
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("创建 hot 文件失败: {}", path.display()))?;
        let created_at = now_secs();
        let file_id = self.ledger.insert_file(
            path.to_str().unwrap(),
            FileKind::Wal,
            self.dev_id,
            Some(self.segment_seq as i64),
            created_at,
        )? as u32;
        self.file = Some(file);
        self.path = path;
        self.file_id = file_id;
        self.offset = 0;
        Ok(())
    }

    /// 追加一条记录，返回 (file_id, 起始偏移)。
    /// 文件边界屏障：超容量先强制封盘轮转（提交由调用方先行触发）。
    pub fn append(&mut self, rec: &WalRecord) -> Result<(u32, u32)> {
        let rec_len = (64 + rec.payload.len()) as u64;
        if self.offset + rec_len > self.segment_size {
            self.rotate()?;
        }
        let mut buf = Vec::with_capacity(rec_len as usize);
        rec.encode(&mut buf);
        let off = self.offset as u32;
        self.file.as_mut().unwrap().write_all(&buf)?;
        self.offset += rec_len;
        Ok((self.file_id, off))
    }

    /// 封盘当前文件（flush + 标 SEALED），开启下一个段文件。
    pub fn rotate(&mut self) -> Result<()> {
        if let Some(mut f) = self.file.take() {
            f.flush()?;
            f.sync_all()?;
        }
        if self.file_id != 0 {
            self.ledger
                .set_file_state(self.file_id as i64, FileState::Sealed)?;
        }
        self.segment_seq += 1;
        self.ensure_open()?;
        Ok(())
    }

    /// 崩溃恢复：把 OPEN 状态 hot 文件截断到 SQLite 水位线（丢弃未提交尾部）。
    pub fn recover(&mut self) -> Result<()> {
        // 当前文件：若 ledger 中已登记，则截断到水位线。
        if self.file_id != 0 {
            let wm = self.ledger.watermark(self.file_id as i64)?;
            if let Some(f) = self.file.as_mut() {
                f.set_len(wm)?;
                f.seek(SeekFrom::Start(wm))?;
            }
            self.offset = wm;
        }
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 崩溃重启构造器：若 dev 有 OPEN 状态文件则复用（截断到水位线），否则新建。
    /// 重启流程：文件截断到水位线 → 从旧水位线重放 → 2PC-Lite 收敛。
    pub fn open_or_recover(
        dir: impl AsRef<Path>,
        ledger: &'a Ledger,
        dev_id: i64,
        segment_seq: u32,
        segment_size: u64,
    ) -> Result<HotFileWriter<'a>> {
        let Some(of) = ledger.open_file_for_dev(dev_id)? else {
            return HotFileWriter::open(dir, ledger, dev_id, segment_seq, segment_size);
        };
        std::fs::create_dir_all(dir.as_ref())?;
        let path = PathBuf::from(&of.path);
        let mut file = OpenOptions::new()
            .write(true)
            .open(&path)
            .with_context(|| format!("重开 hot 文件失败: {}", path.display()))?;
        file.set_len(of.watermark)?;
        file.seek(SeekFrom::Start(of.watermark))?;
        Ok(HotFileWriter {
            dir: dir.as_ref().to_path_buf(),
            ledger,
            dev_id,
            segment_seq: of.segment_seq.unwrap_or(segment_seq as i64) as u32,
            segment_size,
            file: Some(file),
            path,
            file_id: of.file_id as u32,
            offset: of.watermark,
        })
    }
}

/// 批量流水线：推送记录 → 攒批 → 2PC-Lite 提交；文件边界强制屏障。
/// 不持有 `&DbRegistry`（以参数传入），使 ingest 能在批次间隙执行 epoch 轮转。
pub struct BatchPipeline<'a> {
    ledger: &'a Ledger,
    hot: HotFileWriter<'a>,
    pending: Vec<IndexedRecord>,
    batch_size: u32,
    analysis: QrParams,
    /// P5：MetaRegistry（在线 ingest 路径传入，离线/压测路径可空）。
    meta: Option<MetaRegistry>,
}

impl<'a> BatchPipeline<'a> {
    #[allow(clippy::too_many_arguments)] // 构造参数均为配置位，扁平可读优先。
    pub fn new(
        ledger: &'a Ledger,
        hot_dir: impl AsRef<Path>,
        dev_id: i64,
        segment_seq: u32,
        segment_size: u64,
        batch_size: u32,
        analysis: QrParams,
    ) -> Result<BatchPipeline<'a>> {
        let hot = HotFileWriter::open(hot_dir, ledger, dev_id, segment_seq, segment_size)?;
        Ok(BatchPipeline {
            ledger,
            hot,
            pending: Vec::with_capacity(batch_size as usize),
            batch_size,
            analysis,
            meta: None,
        })
    }

    /// 注入 P5 MetaRegistry（协议绑定 + EXT META 指纹提取）。
    pub fn set_meta(&mut self, meta: MetaRegistry) {
        self.meta = Some(meta);
    }

    /// 崩溃/重启恢复构造器：复用 dev 的 OPEN hot 文件（截断到 SQLite 水位线），
    /// 否则新建。live ingest 重启路径必须走此构造，否则 create_new 撞旧段文件崩溃
    /// （M7 实测：hot/dev1 遗留 segment_0000.wal → create_new AlreadyExists）。
    #[allow(clippy::too_many_arguments)] // 构造参数均为配置位，扁平可读优先。
    pub fn open_or_recover(
        ledger: &'a Ledger,
        hot_dir: impl AsRef<Path>,
        dev_id: i64,
        segment_seq: u32,
        segment_size: u64,
        batch_size: u32,
        analysis: QrParams,
    ) -> Result<BatchPipeline<'a>> {
        let hot =
            HotFileWriter::open_or_recover(hot_dir, ledger, dev_id, segment_seq, segment_size)?;
        Ok(BatchPipeline {
            ledger,
            hot,
            pending: Vec::with_capacity(batch_size as usize),
            batch_size,
            analysis,
            meta: None,
        })
    }

    pub fn push_record(&mut self, reg: &DbRegistry, rec: WalRecord) -> Result<()> {
        // 文件边界屏障：跨界 → 先强制提交当前批，再轮转封盘（逻辑事务绝不跨物理文件）。
        let rec_len = (64 + rec.payload.len()) as u64;
        if self.hot.offset() + rec_len > self.hot.segment_size && self.hot.offset() > 0 {
            self.flush(reg)?;
            self.hot.rotate()?;
        }
        let (file_id, offset) = self.hot.append(&rec)?;
        self.pending.push(IndexedRecord {
            dev_id: self.hot.dev_id as u32,
            file_id,
            offset,
            rec,
        });
        if self.pending.len() as u32 >= self.batch_size {
            self.flush(reg)?;
        }
        Ok(())
    }

    /// 强制提交当前批（2PC-Lite），成功后清空 pending（=内存游标推进）。
    pub fn flush(&mut self, reg: &DbRegistry) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let records = std::mem::take(&mut self.pending);
        if let Some(meta) = &self.meta {
            commit_batch_with_meta(reg, self.ledger, &records, &self.analysis, Some(meta))?;
        } else {
            commit_batch(reg, self.ledger, &records, &self.analysis)?;
        }
        Ok(())
    }

    /// 收尾：强制提交 + 封盘当前文件。
    pub fn finish(&mut self, reg: &DbRegistry) -> Result<()> {
        self.flush(reg)?;
        self.hot.rotate()?;
        Ok(())
    }

    pub fn recover_hot(&mut self) -> Result<()> {
        self.hot.recover()
    }

    pub fn hot_file_id(&self) -> u32 {
        self.hot.file_id()
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmpdir(tag: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("sovvault-batch-{}-{}", tag, ts));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn rec(ts: u64, payload: &[u8]) -> WalRecord {
        WalRecord {
            timestamp_ns: ts,
            flags: 0,
            tcp_flags: 0x10,
            tcp_seq: ts as u32,
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

    fn record_ts_count(reg: &DbRegistry) -> u64 {
        let txn = reg.epoch_read_txn().unwrap();
        reg.epoch_dbs()[crate::db::EPOCH_RECORD_TS].len(&txn).unwrap()
    }

    #[test]
    fn hot_writer_boundary_rotates() {
        let dir = tmpdir("hot");
        let ledger = Ledger::open(&dir.join("ledger.db")).unwrap();
        let mut w = HotFileWriter::open(dir.join("hot"), &ledger, 1, 0, 200).unwrap();
        // 每次 append 80B（64 header + 16 payload）：第 3 条（offset 160+80=240>200）触发轮转。
        for _ in 0..3 {
            w.append(&rec(1, &[7u8; 16])).unwrap();
        }
        assert_eq!(w.file_id(), 2); // 已轮转到第二个文件
        assert_eq!(w.offset(), 80);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pipeline_commit_and_watermark() {
        let dir = tmpdir("pipe");
        let ledger = Ledger::open(&dir.join("ledger.db")).unwrap();
        let reg = DbRegistry::open(&dir.join("qridx"), 10 * 1024 * 1024).unwrap();
        let mut pipe = BatchPipeline::new(
            &ledger,
            dir.join("hot"),
            1,
            0,
            64 * 1024,
            3,
            QrParams::default(),
        )
        .unwrap();
        let fid = pipe.hot_file_id(); // 数据实际落在文件 1
        for i in 0..7u64 {
            pipe.push_record(&reg, rec(i, &[i as u8; 10])).unwrap();
        }
        pipe.finish(&reg).unwrap();
        // batch_size=3：7 条 → 两次满批提交（3+3）+ 1 条收尾提交。
        assert_eq!(record_ts_count(&reg), 7);
        let wm = ledger.watermark(fid as i64).unwrap();
        assert_eq!(wm, 7 * (64 + 10)); // 文件 1 全部 7 条已提交
        let _ = std::fs::remove_dir_all(&dir);
    }
}
