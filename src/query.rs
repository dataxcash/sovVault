//! P3.5 查询维度矩阵：CONN_QR / QR_TIME / PACKET_QR / RECORD_TS 四维游标检索 + 导出接口。
//!
//! 设计依据：09 §4.2 DBI 矩阵、§9 P3.5（单 CONN 查询毫秒级；IDX 反查命中）、§13.5（跨 epoch 查询路由）。
//!
//! ## 双库查询路由（§13.5）★
//! - **live 库**（单库，无跨库）：连接热状态 `conn_state`；在途 QR_PAIR(PENDING)。
//! - **epoch 库**（枚举 `qridx/epoch_*/`，追加后只读）：终态 QR_PAIR、CONN_QR/QR_TIME/PACKET_QR/RECORD_TS。
//!
//! ## v0.4.1 查询裁剪与惰性打开（L1+L2）★
//! - **L1 epoch 时间边界索引**：历史 epoch 数据冻结，唯一裁剪依据是时间。Ledger `epochs` 表
//!   存 (epoch_id, dir, min_ts, max_ts, record_count, state)；轮转冻结时写入。
//!   `open_with_window` 按 `[start_ts, end_ts]` 只挑命中的 epoch，从「全量打开 N 个」降到「窗口内 k 个」。
//! - **L2 惰性打开 + 短事务**：`QuerySession` 不再持有全部 epoch 的静态只读事务。
//!   历史 epoch 用即开、用完即关（数据冻结，随时读到最终态，无需持久 txn）；
//!   仅 live + 当前 epoch 克隆 `DbRegistry` 已开 env 的短 txn（保证一致快照）。
//!   `page_rows_epochs` 扫到哪个 epoch 才 open，扫完 drop → reader slot / mmap 随用随放，
//!   峰值 = live + 当前 + 1 个历史。
//!
//! ## 次级索引 status 去重（§13.4.1）★
//! CONN_QR / QR_TIME 的 value 不再存 status（Q 打开写一次、永不更新）。因此：
//! - `scan_conn_qr` / `scan_time_qr` 仅用次级索引**定位候选 q_first_idx**（粗筛时间窗/连接）；
//! - 带 `--status` 过滤时**回查 QR_PAIR 主行**（`qr_by_idx` 现查，跨 live + 全部 epoch）判终态；
//! - `QrIndexRow.status` 以主行为准（`--detail` 本就回查主行），次级索引不再携带状态语义。
//!
//! 游标语义：键全大端有序，`cursor` 为上一页末键原文（排他），前向/后向双向翻页；
//! `has_more` 以"原始键级是否取满"判定（状态过滤不截断续页）。
//! 导出：`ExportSink` trait 可扩展 JSONL/CSV/Parquet，`stream_*` 自动翻页打满。

use crate::connection::ConnState;
use crate::db::{
    k_conn_state, k_packet_qr, k_qr_pair, v_packet_qr_decode, v_record_summary_decode,
    DbRegistry, QrPairValue, QrStatus, RecordSummary, EPOCH_CONN_QR,
    EPOCH_PACKET_QR, EPOCH_QR_PAIR, EPOCH_QR_TIME, EPOCH_RECORD_TS, LIVE_CONN_STATE, LIVE_QR_PAIR,
    NUM_EPOCH_DBIS,
};
use crate::ledger::{EpochBoundary, Ledger};
use anyhow::{bail, Result};
use heed::types::Bytes;
use heed::Database;
use serde::Serialize;
use std::collections::HashMap;
use std::io::Write;
use std::ops::Bound;
use std::path::Path;

/// 翻页控制：光标续读 + 页大小 + 方向。
#[derive(Debug, Clone)]
pub struct Page {
    /// 上一页末键原文（排他续读；空 = 首页）。
    pub cursor: Option<Vec<u8>>,
    pub limit: usize,
    /// true = 升序（时间正序）；false = 降序。
    pub forward: bool,
}

impl Default for Page {
    fn default() -> Self {
        Page {
            cursor: None,
            limit: 100,
            forward: true,
        }
    }
}

/// 分页结果：`has_more` 表示原始键级取满（可继续翻页），`next_cursor` 为续读键。
#[derive(Debug, Clone)]
pub struct PageRows<T> {
    pub rows: Vec<T>,
    pub has_more: bool,
    pub next_cursor: Option<Vec<u8>>,
}

/// QR 检索过滤（维度组合：conn 扫描 / 时间窗 / 状态）。
#[derive(Debug, Clone, Default)]
pub struct QrFilter {
    /// 指定后走 DBI_CONN_QR（连接维度）；None 走 DBI_QR_TIME（时间维度）。
    pub conn_hash: Option<u64>,
    pub start_ts: Option<u64>,
    pub end_ts: Option<u64>,
    pub status: Option<QrStatus>,
}

/// 报文时间窗过滤。
#[derive(Debug, Clone, Default)]
pub struct RecordFilter {
    pub start_ts: Option<u64>,
    pub end_ts: Option<u64>,
}

/// CONN_QR / QR_TIME 索引行（状态取数值 + 稳定名，导出友好）。
/// 注意：status 由 QR_PAIR 主行现查得出（§13.4.1 次级索引不再存 status）。
#[derive(Debug, Clone, Serialize)]
pub struct QrIndexRow {
    pub q_first_idx: u64,
    pub q_ts: u64,
    pub status: u8,
    pub status_name: &'static str,
    /// 仅连接维度扫描时携带（QR_TIME 索引不含连接键）。
    pub conn_hash: Option<u64>,
}

/// RECORD_TS 索引行（时间窗报文摘要）。
#[derive(Debug, Clone, Serialize)]
pub struct RecordRow {
    pub ts_ns: u64,
    pub packet_idx: u64,
    pub summary: RecordSummary,
}

/// 已打开的一个 epoch env（只读快照；L2 惰性——用即开、用完即关）。
struct OpenedEpoch {
    txn: heed::RoTxn<'static, heed::WithTls>,
    dbs: [Database<Bytes, Bytes>; NUM_EPOCH_DBIS],
}

/// epoch 候选目标（L1 裁剪后保留的子集）。
#[derive(Clone)]
struct EpochTarget {
    num: u32,
    dir: std::path::PathBuf,
    /// 当前 epoch（DbRegistry 已开 env，克隆快照即可；历史 epoch 惰性重开只读）。
    is_current: bool,
}

/// 只读查询会话：live + 当前 epoch 快照（常驻）+ 历史 epoch 惰性打开（用完即关）。
///
/// L2 之后不再持有全部 epoch 的静态事务：reader slot / mmap 峰值 = live + 当前 + 1 个历史；
/// L1 之后候选集按时间窗裁剪（`open_with_window`）。
///
/// > 注意（heed/LMDB TLS reader）：`static_read_txn` 同线程对同一 env 并发开第二个会话
/// > 会触发 `MDB_BAD_RSLOT`。使用约束：**同一线程同一时刻至多一个 QuerySession 存活**；
/// > 实际消费路径（CLI 查询 / export / stream_*）均单会话短生命周期，天然满足。
pub struct QuerySession {
    /// live 库（连接热状态 / 在途 QR_PAIR，量有界，会话内快照）。
    live_txn: heed::RoTxn<'static, heed::WithTls>,
    live_dbs: [Database<Bytes, Bytes>; crate::db::NUM_LIVE_DBIS],
    /// 当前 epoch 快照（写 env 克隆，保证一致快照）。
    cur_txn: heed::RoTxn<'static, heed::WithTls>,
    cur_dbs: [Database<Bytes, Bytes>; NUM_EPOCH_DBIS],
    /// 候选 epoch（含当前；升序；已按时间窗/连接档案裁剪）——**范围扫描**使用。
    targets: Vec<EpochTarget>,
    /// 全部 epoch（升序）——**点查**使用（QR_PAIR 终态可能因 TTL 迁移到裁剪集外的晚 epoch，
    /// 点查必须全量枚举才正确；O(logN) 惰性重开，成本可控）。
    all_targets: Vec<EpochTarget>,
    map_size: usize,
}

impl QuerySession {
    /// 打开只读查询会话：live + 当前 epoch 快照 + 全部历史 epoch（惰性打开，L2）。
    pub fn open(reg: &DbRegistry) -> Result<QuerySession> {
        QuerySession::build(reg, None, None, None)
    }

    /// L1：打开只读查询会话并按 `[start_ts, end_ts]` 裁剪历史 epoch。
    /// 依据 Ledger `epochs` 表（轮转冻结时写入）只挑时间窗内命中的 epoch；
    /// 无边界行（旧库/未轮转）不裁剪、当前 epoch 不裁剪——保证正确性优先。
    pub fn open_with_window(
        reg: &DbRegistry,
        ledger: &Ledger,
        start_ts: Option<u64>,
        end_ts: Option<u64>,
    ) -> Result<QuerySession> {
        QuerySession::build(reg, Some(ledger), start_ts, end_ts)
    }

    /// L4：连接维度路由（DIAG/ROOT CAUSE）——按连接档案定位 epoch 子集再扫，避免全 epoch 枚举。
    /// 窗口 = live CONN_STATE 的 first_ts..last_ts（真源，连接热状态常驻 live）；
    /// 不在 live → 回退 Ledger `conns` 档案（连接关闭后的持久记录）。
    pub fn open_for_conn(reg: &DbRegistry, ledger: &Ledger, conn_hash: u64) -> Result<QuerySession> {
        match QuerySession::conn_window(reg, ledger, conn_hash)? {
            Some((first_ts, last_ts)) => {
                QuerySession::build(reg, Some(ledger), Some(first_ts), Some(last_ts))
            }
            None => QuerySession::build(reg, None, None, None),
        }
    }

    /// 连接时间窗：live CONN_STATE 优先，Ledger 档案兜底。
    fn conn_window(
        reg: &DbRegistry,
        ledger: &Ledger,
        conn_hash: u64,
    ) -> Result<Option<(u64, u64)>> {
        let lt = reg.live_read_txn()?;
        let st = reg.live_dbs()[LIVE_CONN_STATE]
            .get(&lt, &k_conn_state(conn_hash))?
            .and_then(ConnState::from_bytes);
        drop(lt);
        if let Some(st) = st {
            if st.first_ts > 0 && st.last_ts > 0 {
                return Ok(Some((st.first_ts, st.last_ts)));
            }
        }
        if let Some(a) = ledger.conn_archive(conn_hash)? {
            if let (Some(f), Some(l)) = (a.first_ts, a.last_ts) {
                if f > 0 && l > 0 {
                    return Ok(Some((f as u64, l as u64)));
                }
            }
        }
        Ok(None)
    }

    fn build(
        reg: &DbRegistry,
        ledger: Option<&Ledger>,
        start_ts: Option<u64>,
        end_ts: Option<u64>,
    ) -> Result<QuerySession> {
        let live_txn = reg.live_env().clone().static_read_txn()?;
        let live_dbs = *reg.live_dbs();
        let cur_txn = reg.epoch_env().clone().static_read_txn()?;
        let cur_dbs = *reg.epoch_dbs();

        let all_targets: Vec<EpochTarget> = reg
            .epoch_targets()
            .into_iter()
            .map(|(num, dir)| EpochTarget {
                num,
                dir,
                is_current: num == reg.epoch_num(),
            })
            .collect();
        let mut targets = all_targets.clone();
        if let Some(ledger) = ledger {
            targets = prune_targets_by_window(targets, ledger, start_ts, end_ts)?;
        }

        Ok(QuerySession {
            live_txn,
            live_dbs,
            cur_txn,
            cur_dbs,
            targets,
            all_targets,
            map_size: reg.map_size(),
        })
    }

    /// L2：惰性打开历史 epoch（数据冻结，用即开、用完即关；`static_read_txn` 持 env 引用计数，
    /// env 句柄随函数返回即 drop → reader slot 随用随放）。
    fn open_epoch(&self, _num: u32, dir: &Path) -> Result<OpenedEpoch> {
        let env = crate::db::open_epoch_env_read_only(dir, self.map_size)?;
        let txn = env.clone().static_read_txn()?;
        let dbs = crate::db::open_epoch_dbs_in_txn(&env, &txn)?;
        Ok(OpenedEpoch { txn, dbs })
    }

    /// 跨全部 epoch 的 O(logN) 点查（当前 epoch 快照 + 历史惰性重开），先命中即返回。
    /// L4：点查用 `all_targets`（全量）——QR_PAIR 终态可能因 TTL 扫描迁移到裁剪集外的晚 epoch，
    /// 点查必须全量枚举才正确（范围扫描用裁剪后的 `targets`）。
    fn epoch_get<T>(
        &self,
        db_idx: usize,
        key: &[u8],
        decode: impl Fn(&[u8]) -> Option<T>,
    ) -> Result<Option<T>> {
        for t in &self.all_targets {
            let hit: Option<T> = if t.is_current {
                self.cur_dbs[db_idx]
                    .get(&self.cur_txn, key)?
                    .and_then(&decode)
            } else {
                let o = self.open_epoch(t.num, &t.dir)?;
                let r = o.dbs[db_idx].get(&o.txn, key)?.and_then(&decode);
                drop(o);
                r
            };
            if hit.is_some() {
                return Ok(hit);
            }
        }
        Ok(None)
    }

    /// QRPAIR 主键直查：live（在途 PENDING）→ 候选 epoch（终态）→ 按 q_first_idx 定位。
    /// O(logN) 点查，回跳基因锚。
    pub fn qr_by_idx(&self, q_first_idx: u64) -> Result<Option<QrPairValue>> {
        let kp = k_qr_pair(q_first_idx);
        if let Some(v) = self.live_dbs()[LIVE_QR_PAIR].get(&self.live_txn, &kp)? {
            if let Some(p) = QrPairValue::decode(v) {
                return Ok(Some(p));
            }
        }
        self.epoch_get(EPOCH_QR_PAIR, &kp, QrPairValue::decode)
    }

    /// PACKET_QR 反查：报文 IDX → 所属 Q 首包 IDX（跨候选 epoch，O(logN) 点查）。
    pub fn qr_by_packet(&self, packet_idx: u64) -> Result<Option<u64>> {
        let kp = k_packet_qr(packet_idx);
        self.epoch_get(EPOCH_PACKET_QR, &kp, v_packet_qr_decode)
    }

    /// CONN_STATE 点查（连接热状态，live 库）。
    pub fn conn_state(&self, conn_hash: u64) -> Result<Option<ConnState>> {
        let Some(v) = self.live_dbs()[LIVE_CONN_STATE].get(&self.live_txn, &k_conn_state(conn_hash))? else {
            return Ok(None);
        };
        Ok(ConnState::from_bytes(v))
    }

    /// DBI_CONN_QR：单连接按时间序的 Q 检索（跨 epoch 聚合，前缀 + 时间窗）。
    pub fn scan_conn_qr(&self, f: &QrFilter, page: &Page) -> Result<PageRows<QrIndexRow>> {
        let Some(ch) = f.conn_hash else {
            bail!("CONN_QR 扫描必须指定 conn_hash");
        };
        let (lo, hi) = conn_qr_bounds(ch, f.start_ts, f.end_ts);
        let raw = self.page_rows_epochs(EPOCH_CONN_QR, lo, hi, page)?;
        let mut rows = Vec::with_capacity(raw.len());
        for (_num, k, _v) in &raw {
            let q_ts = be64(&k[8..16]);
            let q_first_idx = be64(&k[16..24]);
            // §13.4.1：次级索引 value 不存 status；状态以 QR_PAIR 主行为准（现查）。
            let Some(status) = self.status_by_main(q_first_idx)? else {
                continue;
            };
            if let Some(sf) = f.status {
                if sf != status {
                    continue;
                }
            }
            rows.push(QrIndexRow {
                q_first_idx,
                q_ts,
                status: status as u8,
                status_name: status.name(),
                conn_hash: Some(ch),
            });
        }
        Ok(paged(&raw, rows, page.limit))
    }

    /// DBI_QR_TIME：全量时间窗 Q 检索（跨 epoch 聚合）。
    pub fn scan_time_qr(&self, f: &QrFilter, page: &Page) -> Result<PageRows<QrIndexRow>> {
        let (lo, hi) = ts_bounds(f.start_ts, f.end_ts);
        let raw = self.page_rows_epochs(EPOCH_QR_TIME, lo, hi, page)?;
        let mut rows = Vec::with_capacity(raw.len());
        for (_num, k, _v) in &raw {
            let q_ts = be64(&k[0..8]);
            let q_first_idx = be64(&k[8..16]);
            let Some(status) = self.status_by_main(q_first_idx)? else {
                continue;
            };
            if let Some(sf) = f.status {
                if sf != status {
                    continue;
                }
            }
            rows.push(QrIndexRow {
                q_first_idx,
                q_ts,
                status: status as u8,
                status_name: status.name(),
                conn_hash: None,
            });
        }
        Ok(paged(&raw, rows, page.limit))
    }

    /// DBI_RECORD_TS：报文时间窗检索（跨 epoch 聚合，含紧凑摘要）。
    pub fn scan_records(&self, f: &RecordFilter, page: &Page) -> Result<PageRows<RecordRow>> {
        let (lo, hi) = ts_bounds(f.start_ts, f.end_ts);
        let raw = self.page_rows_epochs(EPOCH_RECORD_TS, lo, hi, page)?;
        let mut rows = Vec::with_capacity(raw.len());
        for (_num, k, v) in &raw {
            let Some(summary) = v_record_summary_decode(v) else {
                continue;
            };
            rows.push(RecordRow {
                ts_ns: be64(&k[0..8]),
                packet_idx: be64(&k[8..16]),
                summary,
            });
        }
        Ok(paged(&raw, rows, page.limit))
    }

    /// L3：单次流式扫描 RECORD_TS（时间窗）连续喂给 sink——不经分页框架。
    /// 每个 epoch 内单次 range 迭代，键值就地解码（不重建迭代器、无游标往返）；
    /// 返回喂给 sink 的行数。`sink.finish()` 由调用方负责。
    pub fn replay_into_sink<S: ExportSink>(
        &self,
        start_ts: Option<u64>,
        end_ts: Option<u64>,
        sink: &mut S,
    ) -> Result<u64> {
        let (lo, hi) = ts_bounds(start_ts, end_ts);
        let mut total = 0u64;
        for t in &self.targets {
            if t.is_current {
                replay_epoch_range(&self.cur_txn, &self.cur_dbs, &lo, &hi, sink, &mut total)?;
            } else {
                let o = self.open_epoch(t.num, &t.dir)?;
                replay_epoch_range(&o.txn, &o.dbs, &lo, &hi, sink, &mut total)?;
                drop(o);
            }
        }
        Ok(total)
    }

    fn live_dbs(&self) -> &[Database<Bytes, Bytes>; crate::db::NUM_LIVE_DBIS] {
        &self.live_dbs
    }

    /// 状态以 QR_PAIR 主行为准（§13.4.1）：live 在途 → 全部 epoch 终态，先命中即返回。
    fn status_by_main(&self, q_first_idx: u64) -> Result<Option<QrStatus>> {
        match self.qr_by_idx(q_first_idx)? {
            Some(p) => Ok(QrStatus::from_u8(p.status)),
            None => Ok(None),
        }
    }

    /// 跨 epoch 原始键级扫描：epoch 序号升序 + 库内主键序（§13.9.4 确定性排序）。
    /// 游标格式 = `[epoch_num:u32 BE][key]`（跨 epoch 排他续读；None = 首页）。
    /// 返回 `(epoch_num, key, value)` 三元组（上限 limit 条）。
    /// L2：扫到哪个 epoch 才 open（当前 epoch 用快照，历史惰性重开），扫完即 drop。
    fn page_rows_epochs(
        &self,
        db_idx: usize,
        lo: Vec<u8>,
        hi: Vec<u8>,
        page: &Page,
    ) -> Result<Vec<RawEpochRow>> {
        let limit = page.limit.max(1);
        let mut out: Vec<RawEpochRow> = Vec::with_capacity(limit.min(4096));
        let (cur_epoch, cur_key) = parse_cursor(&page.cursor);

        // 前向：从 cursor.epoch（排他 key）开始升序。
        let forward_epochs: Vec<&EpochTarget> = if page.forward {
            self.targets.iter().filter(|t| t.num >= cur_epoch).collect()
        } else {
            self.targets
                .iter()
                .rev()
                .filter(|t| t.num <= cur_epoch)
                .collect()
        };

        for t in forward_epochs {
            // 当前页起点：cursor 落在本 epoch → 从 cursor.key 之后；否则从区间头/尾。
            let cursor_key: Option<&[u8]> =
                if t.num == cur_epoch && page.cursor.is_some() {
                    cur_key.as_deref()
                } else {
                    None
                };
            let done = if t.is_current {
                scan_epoch_range(
                    &self.cur_txn,
                    &self.cur_dbs,
                    db_idx,
                    &lo,
                    &hi,
                    t.num,
                    cursor_key,
                    page.forward,
                    limit,
                    &mut out,
                )?
            } else {
                let o = self.open_epoch(t.num, &t.dir)?;
                let done = scan_epoch_range(
                    &o.txn,
                    &o.dbs,
                    db_idx,
                    &lo,
                    &hi,
                    t.num,
                    cursor_key,
                    page.forward,
                    limit,
                    &mut out,
                )?;
                drop(o);
                done
            };
            if done {
                return Ok(out);
            }
        }
        Ok(out)
    }
}

/// 组装分页结果：has_more = 原始键取满一整页（=limit）；next_cursor = (epoch, 末键) 编码游标。
fn paged<T>(raw: &[RawEpochRow], rows: Vec<T>, limit: usize) -> PageRows<T> {
    let next_cursor = raw.last().map(|(num, k, _)| encode_cursor(*num, k));
    PageRows {
        rows,
        has_more: raw.len() >= limit && next_cursor.is_some(),
        next_cursor,
    }
}

/// 编码跨 epoch 游标：`[epoch_num:u32 BE][key]`。
fn encode_cursor(epoch: u32, key: &[u8]) -> Vec<u8> {
    let mut c = Vec::with_capacity(4 + key.len());
    c.extend_from_slice(&epoch.to_be_bytes());
    c.extend_from_slice(key);
    c
}

/// 解析游标为 (epoch_num, key)。None 游标 → (0, None)。
fn parse_cursor(cursor: &Option<Vec<u8>>) -> (u32, Option<Vec<u8>>) {
    match cursor {
        Some(c) if c.len() >= 4 => {
            let epoch = u32::from_be_bytes(c[0..4].try_into().unwrap());
            (epoch, Some(c[4..].to_vec()))
        }
        _ => (0, None),
    }
}

/// 原始键级扫描行：(epoch_num, key, value)。
type RawEpochRow = (u32, Vec<u8>, Vec<u8>);

/// 单 epoch 范围扫描迭代器（range/rev_range 统一盒化后的流；借用 txn，非 'static）。
type RawEpochStream<'a> = Box<dyn Iterator<Item = Result<(Vec<u8>, Vec<u8>)>> + 'a>;

/// 导出接口：逐行喂给 sink，由实现决定输出格式（JSONL/CSV/Parquet）。
pub trait ExportSink {
    fn qr(&mut self, row: &QrIndexRow) -> Result<()>;
    fn record(&mut self, row: &RecordRow) -> Result<()>;
    fn finish(&mut self) -> Result<()> {
        Ok(())
    }
}

/// JSONL 导出（每行一个 JSON 对象，流式不驻内存）。
pub struct JsonlSink<W: Write> {
    w: W,
}

impl<W: Write> JsonlSink<W> {
    pub fn new(w: W) -> JsonlSink<W> {
        JsonlSink { w }
    }
}

impl<W: Write> ExportSink for JsonlSink<W> {
    fn qr(&mut self, row: &QrIndexRow) -> Result<()> {
        writeln!(self.w, "{}", serde_json::to_string(row)?)?;
        Ok(())
    }
    fn record(&mut self, row: &RecordRow) -> Result<()> {
        writeln!(self.w, "{}", serde_json::to_string(row)?)?;
        Ok(())
    }
}

/// 流式导出 Q 行：conn 维度走 CONN_QR，否则走 QR_TIME；自动翻页，返回导出条数。
pub fn stream_qrs<S: ExportSink>(reg: &DbRegistry, f: &QrFilter, sink: &mut S) -> Result<u64> {
    let s = QuerySession::open(reg)?;
    let mut page = Page::default();
    let mut total = 0u64;
    loop {
        let r = match f.conn_hash {
            Some(_) => s.scan_conn_qr(f, &page)?,
            None => s.scan_time_qr(f, &page)?,
        };
        for row in &r.rows {
            sink.qr(row)?;
            total += 1;
        }
        if !r.has_more {
            break;
        }
        page.cursor = r.next_cursor;
    }
    sink.finish()?;
    Ok(total)
}

/// 流式导出报文行（RECORD_TS 时间窗），返回导出条数。
pub fn stream_records<S: ExportSink>(
    reg: &DbRegistry,
    f: &RecordFilter,
    sink: &mut S,
) -> Result<u64> {
    let s = QuerySession::open(reg)?;
    let n = s.replay_into_sink(f.start_ts, f.end_ts, sink)?;
    sink.finish()?;
    Ok(n)
}

/// L3：REPLAY 专用流式路径——直接按 epoch 边界裁剪 + 单次 range 迭代连续喂给 sink。
///
/// 与 `stream_records`（分页框架）的区别：**不做分页、不重建迭代器、无游标往返**。
/// - L1 裁剪：`open_with_window` 只挑时间窗内命中的 epoch（无窗/无边界/当前恒全扫）；
/// - 每个 epoch 内**单次 range** 遍历 `RECORD_TS`，键值就地解码（零额外分配喂行）连续喂 `sink.record`；
/// - 输出即「时间序连续原始流量」（epoch 升序 + 库内键序），供 REPLAY 加速回放直连；
/// - `sink.finish()` 由调用方负责（PcapSink 需在 finish 时 flush 并返回统计）。
///
/// 返回喂给 sink 的行数。
pub fn replay_scan<S: ExportSink>(
    reg: &DbRegistry,
    ledger: &Ledger,
    start_ts: Option<u64>,
    end_ts: Option<u64>,
    sink: &mut S,
) -> Result<u64> {
    let s = QuerySession::open_with_window(reg, ledger, start_ts, end_ts)?;
    s.replay_into_sink(start_ts, end_ts, sink)
}

// --- 内部：键区间构造 + 原始分页扫描 ---

/// L3：单 epoch 内 RECORD_TS 单次 range 流式喂行（键值就地解码，零额外分配）。
fn replay_epoch_range<S: ExportSink>(
    txn: &heed::RoTxn<'static, heed::WithTls>,
    dbs: &[Database<Bytes, Bytes>; NUM_EPOCH_DBIS],
    lo: &[u8],
    hi: &[u8],
    sink: &mut S,
    total: &mut u64,
) -> Result<()> {
    for item in dbs[EPOCH_RECORD_TS]
        .range(txn, &(Bound::Included(lo), Bound::Included(hi)))?
    {
        let (k, v) = item?;
        let Some(summary) = v_record_summary_decode(v) else {
            continue; // 摘要损坏（不应出现）→ 跳过该行。
        };
        let row = RecordRow {
            ts_ns: be64(&k[0..8]),
            packet_idx: be64(&k[8..16]),
            summary,
        };
        sink.record(&row)?;
        *total += 1;
    }
    Ok(())
}

/// 单 epoch 内 range/rev_range 扫描（当前 epoch 快照 txn 或惰性重开 txn 通用）。
/// 游标落在本 epoch 时排他续读；返回「是否已达 limit」。
#[allow(clippy::too_many_arguments)] // 原始扫描参数位，扁平直白。
fn scan_epoch_range(
    txn: &heed::RoTxn<'static, heed::WithTls>,
    dbs: &[Database<Bytes, Bytes>; NUM_EPOCH_DBIS],
    db_idx: usize,
    lo: &[u8],
    hi: &[u8],
    epoch_num: u32,
    cursor_key: Option<&[u8]>,
    forward: bool,
    limit: usize,
    out: &mut Vec<RawEpochRow>,
) -> Result<bool> {
    let (start, end) = if forward {
        let start: Bound<&[u8]> = match cursor_key {
            Some(k) => Bound::Excluded(k),
            None => Bound::Included(lo),
        };
        (start, Bound::Included(hi))
    } else {
        let end: Bound<&[u8]> = match cursor_key {
            Some(k) => Bound::Excluded(k),
            None => Bound::Included(hi),
        };
        (Bound::Included(lo), end)
    };
    // range / rev_range 迭代器类型不同，统一盒化为 `Result<(Vec<u8>, Vec<u8>)>` 流。
    let items: RawEpochStream<'_> = if forward {
        Box::new(
            dbs[db_idx]
                .range(txn, &(start, end))?
                .map(|x| x.map(|(k, v)| (k.to_vec(), v.to_vec())).map_err(Into::into)),
        )
    } else {
        Box::new(
            dbs[db_idx]
                .rev_range(txn, &(start, end))?
                .map(|x| x.map(|(k, v)| (k.to_vec(), v.to_vec())).map_err(Into::into)),
        )
    };
    for item in items {
        let (k, v) = item?;
        out.push((epoch_num, k, v));
        if out.len() >= limit {
            return Ok(true);
        }
    }
    Ok(false)
}

/// L1：按 `[start_ts, end_ts]` 裁剪 epoch 候选集。
/// - 无时间窗 → 全保留；
/// - 当前 epoch（max_ts 未知）→ 恒保留；
/// - 无边界行（旧库/未轮转冻结）→ 保留（正确性优先，宁可多扫）；
/// - 否则按 [min_ts, max_ts] 与窗口是否重叠判定。
fn prune_targets_by_window(
    targets: Vec<EpochTarget>,
    ledger: &Ledger,
    start_ts: Option<u64>,
    end_ts: Option<u64>,
) -> Result<Vec<EpochTarget>> {
    if start_ts.is_none() && end_ts.is_none() {
        return Ok(targets);
    }
    let boundaries: HashMap<i64, EpochBoundary> = ledger
        .epoch_boundaries()?
        .into_iter()
        .map(|b| (b.epoch_id, b))
        .collect();
    let s = start_ts.unwrap_or(0);
    let e = end_ts.unwrap_or(u64::MAX);
    Ok(targets
        .into_iter()
        .filter(|t| {
            if t.is_current {
                return true;
            }
            let Some(b) = boundaries.get(&(t.num as i64)) else {
                return true;
            };
            let bmin = b.min_ts.map(|v| v as u64).unwrap_or(0);
            let bmax = b.max_ts.map(|v| v as u64).unwrap_or(u64::MAX);
            !(bmax < s || bmin > e)
        })
        .collect())
}

/// CONN_QR 区间：[conn][start_ts][0] .. [conn][end_ts][0xFF]，24B。
fn conn_qr_bounds(conn_hash: u64, start_ts: Option<u64>, end_ts: Option<u64>) -> (Vec<u8>, Vec<u8>) {
    let mut lo = Vec::with_capacity(24);
    lo.extend_from_slice(&conn_hash.to_be_bytes());
    lo.extend_from_slice(&start_ts.unwrap_or(0).to_be_bytes());
    lo.extend_from_slice(&[0u8; 8]);
    let mut hi = Vec::with_capacity(24);
    hi.extend_from_slice(&conn_hash.to_be_bytes());
    hi.extend_from_slice(&end_ts.unwrap_or(u64::MAX).to_be_bytes());
    hi.extend_from_slice(&[0xFFu8; 8]);
    (lo, hi)
}

/// 时间主索引（QR_TIME / RECORD_TS）区间：[ts][0] .. [ts][0xFF]，16B。
fn ts_bounds(start_ts: Option<u64>, end_ts: Option<u64>) -> (Vec<u8>, Vec<u8>) {
    let mut lo = Vec::with_capacity(16);
    lo.extend_from_slice(&start_ts.unwrap_or(0).to_be_bytes());
    lo.extend_from_slice(&[0u8; 8]);
    let mut hi = Vec::with_capacity(16);
    hi.extend_from_slice(&end_ts.unwrap_or(u64::MAX).to_be_bytes());
    hi.extend_from_slice(&[0xFFu8; 8]);
    (lo, hi)
}

#[inline]
fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b[..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::IndexedRecord;
    use crate::connection::conn_hash;
    use crate::qr::{QrMatcher, QrParams};
    use sov_probe::wal::header::{TCP_ACK, TCP_SYN, WalRecord};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    const CIP: [u8; 4] = [192, 168, 1, 10];
    const SIP: [u8; 4] = [10, 0, 0, 1];
    const CPORT: u16 = 12345;
    const SPORT: u16 = 443;

    fn tmpdir(tag: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("sovvault-query-{}-{}", tag, ts));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[allow(clippy::too_many_arguments)] // 测试报文构造器，参数扁平直白。
    fn pkt(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, proto: u16, flags: u8, ts_ns: u64, seq: u32, ack: u32, payload: &[u8]) -> WalRecord {
        WalRecord {
            timestamp_ns: ts_ns,
            flags: 0,
            tcp_flags: flags,
            tcp_seq: seq,
            tcp_ack: ack,
            window_size: 65535,
            src_ip: src,
            dst_ip: dst,
            src_port: sport,
            dst_port: dport,
            proto,
            orig_payload_len: payload.len() as u32,
            payload: payload.to_vec(),
        }
    }
    fn c2s(ts_ns: u64, seq: u32, ack: u32, payload: &[u8]) -> WalRecord {
        pkt(CIP, SIP, CPORT, SPORT, 6, TCP_ACK, ts_ns, seq, ack, payload)
    }
    fn s2c(ts_ns: u64, seq: u32, ack: u32, payload: &[u8]) -> WalRecord {
        pkt(SIP, CIP, SPORT, CPORT, 6, TCP_ACK, ts_ns, seq, ack, payload)
    }

    /// 跑一批记录并提交（构建查询样本）。
    fn run(reg: &DbRegistry, recs: &[(WalRecord, u32)]) {
        let mut m = QrMatcher::begin(reg, &QrParams::default()).unwrap();
        for (rec, off) in recs {
            m.ingest(&IndexedRecord {
                dev_id: 1,
                file_id: 1,
                offset: *off,
                rec: rec.clone(),
            })
            .unwrap();
        }
        m.commit().unwrap();
    }

    fn ch() -> u64 {
        conn_hash(1, u32::from_be_bytes(CIP), CPORT, u32::from_be_bytes(SIP), SPORT, 6)
    }

    /// 样本：1 连接握手 + 3 个 Q（不同 ts）→ 2 个被累积 ACK 消费（聚合），1 个残留 PENDING。
    /// 另注入 2 条 UDP 报文进 RECORD_TS。返回时间升序的 qidx。
    /// 注：引擎语义——S2C 报文的 ack 属 c→s 数空间，≤ 流头时映射到流头 → 消费全部 ≤ 头的挂起 Q；
    /// 故 Q3 必须排在响应之后发送才能保持 PENDING。
    fn seed(reg: &DbRegistry) -> Vec<u64> {
        let base = 1_700_000_000_000_000_000u64;
        let syn = pkt(CIP, SIP, CPORT, SPORT, 6, TCP_SYN, base, 1000, 0, b"");
        let synack = pkt(SIP, CIP, SPORT, CPORT, 6, TCP_SYN | TCP_ACK, base + 1, 5000, 1001, b"");
        let ack = c2s(base + 2, 1001, 5001, b"");
        let q1 = c2s(base + 10, 1001, 5001, b"GET /a");
        let q2 = c2s(base + 20, 1011, 5001, b"GET /b");
        let r2 = s2c(base + 30, 5001, 1017, b"200-ab"); // 累积 ACK=1017 消费 q1+q2
        let q3 = c2s(base + 40, 1021, 5001, b"GET /c"); // 响应后发出 → PENDING
        let udp1 = pkt(CIP, SIP, CPORT, 53, 17, 0, base + 50, 0, 0, b"DNSQUERY");
        let udp2 = pkt(SIP, CIP, 53, CPORT, 17, 0, base + 60, 0, 0, b"DNSRESP");

        // 先定 offsets（记录进 IndexedRecord 的锚点 = q_first_idx 低 32 位）。
        let mut o: u32 = 0;
        let mut offs: Vec<u32> = Vec::with_capacity(9);
        for r in [&syn, &synack, &ack, &q1, &q2, &r2, &q3, &udp1, &udp2] {
            offs.push(o);
            o += 64 + r.payload.len() as u32;
        }
        let qidx: Vec<u64> = offs[3..5]
            .iter()
            .chain(&offs[6..7])
            .map(|x| (1u64 << 32) | *x as u64)
            .collect(); // q1, q2, q3
        let recs: Vec<(WalRecord, u32)> = vec![syn, synack, ack, q1, q2, r2, q3, udp1, udp2]
            .into_iter()
            .zip(offs)
            .collect();
        run(reg, &recs);
        qidx
    }

    #[test]
    fn conn_scan_ordered_and_filtered() {
        let dir = tmpdir("conn");
        let reg = DbRegistry::open(&dir.join("qridx"), 16 * 1024 * 1024).unwrap();
        let qidx = seed(&reg);
        let s = QuerySession::open(&reg).unwrap();
        let h = ch();

        // 全量：3 行，按 q_ts 升序。
        let f = QrFilter { conn_hash: Some(h), ..Default::default() };
        let r = s.scan_conn_qr(&f, &Page::default()).unwrap();
        assert_eq!(r.rows.len(), 3);
        assert_eq!(r.rows[0].q_first_idx, qidx[0]);
        assert_eq!(r.rows[1].q_first_idx, qidx[1]);
        assert_eq!(r.rows[2].q_first_idx, qidx[2]);
        assert_eq!(r.rows[0].status, QrStatus::Matched as u8);
        assert_eq!(r.rows[2].status, QrStatus::Pending as u8);
        assert_eq!(r.rows[0].conn_hash, Some(h));

        // 状态过滤：仅 matched。
        let f = QrFilter { conn_hash: Some(h), status: Some(QrStatus::Matched), ..Default::default() };
        let r = s.scan_conn_qr(&f, &Page::default()).unwrap();
        assert_eq!(r.rows.len(), 2);

        // 时间窗：[q2_ts, q3_ts]。
        let t2 = s.qr_by_idx(qidx[1]).unwrap().unwrap().q_ts;
        let t3 = s.qr_by_idx(qidx[2]).unwrap().unwrap().q_ts;
        let f = QrFilter {
            conn_hash: Some(h),
            start_ts: Some(t2),
            end_ts: Some(t3),
            ..Default::default()
        };
        let r = s.scan_conn_qr(&f, &Page::default()).unwrap();
        assert_eq!(r.rows.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn time_scan_window() {
        let dir = tmpdir("time");
        let reg = DbRegistry::open(&dir.join("qridx"), 16 * 1024 * 1024).unwrap();
        seed(&reg);
        let s = QuerySession::open(&reg).unwrap();
        let base = 1_700_000_000_000_000_000u64;
        // [base+15, base+45]：q2(base+20) + q3(base+40)。
        let f = QrFilter { start_ts: Some(base + 15), end_ts: Some(base + 45), ..Default::default() };
        let r = s.scan_time_qr(&f, &Page::default()).unwrap();
        assert_eq!(r.rows.len(), 2);
        assert!(r.rows.iter().all(|x| x.conn_hash.is_none()));
        // 降序。
        let page = Page { forward: false, ..Default::default() };
        let r = s.scan_time_qr(&f, &page).unwrap();
        assert_eq!(r.rows.len(), 2);
        assert!(r.rows[0].q_ts >= r.rows[1].q_ts);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn packet_reverse_lookup_and_idx() {
        let dir = tmpdir("packet");
        let reg = DbRegistry::open(&dir.join("qridx"), 16 * 1024 * 1024).unwrap();
        let qidx = seed(&reg);
        let s = QuerySession::open(&reg).unwrap();
        // 报文 IDX（q 首包）反查所属 Q。
        assert_eq!(s.qr_by_packet(qidx[0]).unwrap(), Some(qidx[0]));
        assert_eq!(s.qr_by_packet(qidx[2]).unwrap(), Some(qidx[2]));
        // 直查 QRPAIR（取无聚合的 PENDING Q3：q_idx 精确单元素）。
        let p = s.qr_by_idx(qidx[2]).unwrap().unwrap();
        assert_eq!(p.q_idx, vec![qidx[2]]);
        assert_eq!(p.status, QrStatus::Pending as u8);
        // CONN_STATE 点查。
        let cs = s.conn_state(ch()).unwrap().unwrap();
        assert_eq!(cs.req_cnt, 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_scan_window() {
        let dir = tmpdir("rec");
        let reg = DbRegistry::open(&dir.join("qridx"), 16 * 1024 * 1024).unwrap();
        seed(&reg);
        let s = QuerySession::open(&reg).unwrap();
        let base = 1_700_000_000_000_000_000u64;
        // 时间窗 [base+40, +∞]：r2 + 两条 UDP。
        let f = RecordFilter { start_ts: Some(base + 40), end_ts: None };
        let r = s.scan_records(&f, &Page::default()).unwrap();
        assert_eq!(r.rows.len(), 3);
        // 报文内容窗内 + 摘要字段。
        assert!(r.rows.iter().all(|x| x.ts_ns >= base + 40));
        let udp = r.rows.iter().find(|x| x.summary.proto == 17).unwrap();
        assert_eq!(udp.summary.dport, 53);
        assert_eq!(udp.summary.len, 8); // "DNSRESP"
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cursor_pagination_no_dup_no_skip() {
        let dir = tmpdir("page");
        let reg = DbRegistry::open(&dir.join("qridx"), 16 * 1024 * 1024).unwrap();
        let qidx = seed(&reg);
        let s = QuerySession::open(&reg).unwrap();
        let h = ch();
        let f = QrFilter { conn_hash: Some(h), ..Default::default() };

        // 前向 limit=1 翻页：3 行无重无漏（qidx 即时间升序）。
        let mut page = Page { limit: 1, ..Default::default() };
        let mut got = Vec::new();
        loop {
            let r = s.scan_conn_qr(&f, &page).unwrap();
            for row in &r.rows {
                got.push(row.q_first_idx);
            }
            if !r.has_more {
                break;
            }
            page.cursor = r.next_cursor;
        }
        assert_eq!(got, qidx);

        // 后向 limit=2 → 翻一页。
        let mut page = Page { limit: 2, forward: false, ..Default::default() };
        let r1 = s.scan_conn_qr(&f, &page).unwrap();
        assert!(r1.has_more);
        assert_eq!(r1.rows.len(), 2);
        page.cursor = r1.next_cursor;
        let r2 = s.scan_conn_qr(&f, &page).unwrap();
        assert!(!r2.has_more);
        assert_eq!(r2.rows.len(), 1);
        assert!(r1.rows[0].q_ts >= r1.rows[1].q_ts);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn jsonl_export_stream() {
        let dir = tmpdir("export");
        let reg = DbRegistry::open(&dir.join("qridx"), 16 * 1024 * 1024).unwrap();
        seed(&reg);
        let h = ch();
        let mut buf = Vec::new();
        let mut sink = JsonlSink::new(&mut buf);
        let f = QrFilter { conn_hash: Some(h), ..Default::default() };
        let n = stream_qrs(&reg, &f, &mut sink).unwrap();
        assert_eq!(n, 3);
        let lines: Vec<&str> = std::str::from_utf8(&buf).unwrap().lines().collect();
        assert_eq!(lines.len(), 3);
        let row: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(row["status_name"], "matched");

        // 报文导出。
        let mut buf = Vec::new();
        let mut sink = JsonlSink::new(&mut buf);
        let base = 1_700_000_000_000_000_000u64;
        let f = RecordFilter { start_ts: Some(base + 50), end_ts: None };
        let n = stream_records(&reg, &f, &mut sink).unwrap();
        assert_eq!(n, 2); // udp1 + udp2
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// L1：时间窗裁剪只命中 epoch 子集——历史边界索引 + 惰性打开正确性。
    #[test]
    fn window_pruning_skips_non_overlapping_epochs() {
        use crate::ledger::{EpochBoundary, EpochState, Ledger};
        let dir = tmpdir("prune");
        let root = dir.join("qridx");
        let mut reg = DbRegistry::open(&root, 16 * 1024 * 1024).unwrap();
        let ledger = Ledger::open(&dir.join("ledger.db")).unwrap();
        let base = 1_700_000_000_000_000_000u64;

        // epoch_0000：写种子（ts ∈ [base, base+60]）→ 冻结边界 → 轮转。
        seed(&reg);
        let (min0, max0, cnt0) = reg.current_epoch_bounds().unwrap();
        assert_eq!(min0, Some(base));
        ledger
            .upsert_epoch_boundary(&EpochBoundary {
                epoch_id: 0,
                dir: "epoch_0000".into(),
                min_ts: min0.map(|v| v as i64),
                max_ts: max0.map(|v| v as i64),
                record_count: cnt0 as i64,
                state: EpochState::Frozen,
            })
            .unwrap();
        reg.rotate_epoch().unwrap();

        // epoch_0001（当前）：再写一批（同一批 ts，仅验证当前 epoch 恒不裁剪）。
        seed(&reg);

        // 窗口落在 epoch_0001 → epoch_0000 裁剪，只剩当前。
        let s =
            QuerySession::open_with_window(&reg, &ledger, Some(base + 70), Some(base + 90))
                .unwrap();
        assert_eq!(s.targets.len(), 1, "非命中历史 epoch 应被裁剪");
        assert_eq!(s.targets[0].num, 1);
        assert!(s.targets[0].is_current);
        drop(s); // 会话持有 static 只读事务，同线程并发开第二个会 MDB_BAD_RSLOT，先释放。

        // 窗口命中 epoch_0000 → 历史保留（全量 2）。
        let s = QuerySession::open_with_window(&reg, &ledger, Some(base), Some(base + 10)).unwrap();
        assert_eq!(s.targets.len(), 2, "命中 epoch_0000 → 历史保留");
        assert_eq!(s.targets[0].num, 0);
        assert_eq!(s.targets[1].num, 1);
        drop(s);

        // 无窗口 → 全保留。
        let s = QuerySession::open(&reg).unwrap();
        assert_eq!(s.targets.len(), 2);
        drop(s);

        // 裁剪后的会话仍能正确翻页/点查（epoch_0000 不在候选内，读不到其数据 → 结果只含 epoch_0001）。
        let s = QuerySession::open_with_window(&reg, &ledger, Some(base + 70), Some(base + 90)).unwrap();
        let f = RecordFilter { start_ts: Some(base + 70), end_ts: None };
        let r = s.scan_records(&f, &Page::default()).unwrap();
        assert!(r.rows.is_empty(), "窗口外无数据");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 收集流式行的测试 sink。
    struct CountingSink {
        rows: Vec<RecordRow>,
    }
    impl ExportSink for CountingSink {
        fn qr(&mut self, _row: &QrIndexRow) -> Result<()> {
            Ok(())
        }
        fn record(&mut self, row: &RecordRow) -> Result<()> {
            self.rows.push(row.clone());
            Ok(())
        }
    }

    /// L3：replay_scan 单次流式——时间升序连续喂行 + 时间窗过滤 + 与分页路径结果一致。
    #[test]
    fn replay_scan_single_pass_ordered_and_filtered() {
        use crate::ledger::Ledger;
        let dir = tmpdir("replay");
        let reg = DbRegistry::open(&dir.join("qridx"), 16 * 1024 * 1024).unwrap();
        let ledger = Ledger::open(&dir.join("ledger.db")).unwrap();
        let base = 1_700_000_000_000_000_000u64;
        seed(&reg);

        // 全量：9 条 RECORD_TS，时间升序连续喂行。
        let mut sink = CountingSink { rows: Vec::new() };
        let n = replay_scan(&reg, &ledger, None, None, &mut sink).unwrap();
        assert_eq!(n, 9);
        assert_eq!(n as usize, sink.rows.len());
        assert!(
            sink.rows.windows(2).all(|w| w[0].ts_ns <= w[1].ts_ns),
            "replay 输出时间升序"
        );

        // 时间窗 [base+50, base+60]：仅 UDP 两条。
        let mut sink = CountingSink { rows: Vec::new() };
        let n = replay_scan(&reg, &ledger, Some(base + 50), Some(base + 60), &mut sink).unwrap();
        assert_eq!(n, 2);
        assert!(sink.rows.iter().all(|r| r.summary.proto == 17));
        assert!(sink.rows.iter().all(|r| r.ts_ns >= base + 50 && r.ts_ns <= base + 60));

        // 与分页路径（stream_records）结果一致性：同一窗口 JSONL 行数相同。
        let mut sink = CountingSink { rows: Vec::new() };
        let f = RecordFilter { start_ts: Some(base + 50), end_ts: None };
        let n2 = stream_records(&reg, &f, &mut sink).unwrap();
        assert_eq!(n2, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// L4：连接维度路由——按连接时间窗裁剪 epoch 子集，避免全 epoch 枚举。
    /// 点查（QR_PAIR 回查）仍走全量 epoch，TTL 迁移到裁剪集外的终态仍可回跳。
    #[test]
    fn conn_routing_prunes_epochs_by_conn_window() {
        use crate::connection::conn_hash as chash;
        use crate::ledger::{EpochBoundary, EpochState, Ledger};
        let dir = tmpdir("connroute");
        let root = dir.join("qridx");
        let mut reg = DbRegistry::open(&root, 16 * 1024 * 1024).unwrap();
        let ledger = Ledger::open(&dir.join("ledger.db")).unwrap();
        let base = 1_700_000_000_000_000_000u64;

        // epoch_0000：conn X（ch）的握手 + 3 Q，ts ∈ [base, base+60]。
        seed(&reg);
        let (min0, max0, cnt0) = reg.current_epoch_bounds().unwrap();
        ledger
            .upsert_epoch_boundary(&EpochBoundary {
                epoch_id: 0,
                dir: "epoch_0000".into(),
                min_ts: min0.map(|v| v as i64),
                max_ts: max0.map(|v| v as i64),
                record_count: cnt0 as i64,
                state: EpochState::Frozen,
            })
            .unwrap();
        reg.rotate_epoch().unwrap();

        // epoch_0001（当前）：conn Y（8443 端口），ts ∈ [base+1000, base+1002]。
        let sy = pkt(CIP, SIP, CPORT, 8443, 6, TCP_SYN, base + 1000, 1, 0, b"");
        let sya = pkt(SIP, CIP, 8443, CPORT, 6, TCP_SYN | TCP_ACK, base + 1001, 5000, 2, b"");
        let ay = pkt(CIP, SIP, CPORT, 8443, 6, TCP_ACK, base + 1002, 2, 5001, b"");
        let recs: Vec<(WalRecord, u32)> = vec![sy, sya, ay]
            .into_iter()
            .enumerate()
            .map(|(i, r)| (r, (i as u32) * 100))
            .collect();
        run(&reg, &recs);

        // conn X 窗口 [base, base+60] → epoch_0000 命中 + 当前 epoch_0001 → 2。
        let h_x = ch();
        let s = QuerySession::open_for_conn(&reg, &ledger, h_x).unwrap();
        assert_eq!(s.targets.len(), 2, "conn X 命中 epoch_0000");
        assert_eq!(s.targets[0].num, 0);
        drop(s);

        // conn Y 窗口 [base+1000, base+1002] → epoch_0000 不命中被裁剪 → 仅当前 epoch_0001。
        let h_y = chash(1, u32::from_be_bytes(CIP), CPORT, u32::from_be_bytes(SIP), 8443, 6);
        let s = QuerySession::open_for_conn(&reg, &ledger, h_y).unwrap();
        assert_eq!(s.targets.len(), 1, "conn Y 应裁剪掉 epoch_0000");
        assert_eq!(s.targets[0].num, 1);
        assert!(s.targets[0].is_current);

        // 裁剪会话内范围扫描可跑（conn Y 无 Q → 0 行）；点查走全量 epoch 不受裁剪影响。
        let f = QrFilter { conn_hash: Some(h_y), ..Default::default() };
        let r = s.scan_conn_qr(&f, &Page::default()).unwrap();
        assert!(r.rows.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
