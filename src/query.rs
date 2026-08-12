//! P3.5 查询维度矩阵：CONN_QR / QR_TIME / PACKET_QR / RECORD_TS 四维游标检索 + 导出接口。
//!
//! 设计依据：09 §四.2 DBI 矩阵与 §九 P3.5（单 CONN 查询毫秒级；IDX 反查命中）。
//!
//! - `DBI_CONN_QR`（键 `[conn][q_ts][q_first_idx]`）→ 单连接内按时间序的 Q 检索；
//! - `DBI_QR_TIME`（键 `[q_ts][q_first_idx]`）→ 全量时间窗 Q 检索；
//! - `DBI_PACKET_QR`（键 `[packet_idx]`）→ 报文 IDX 反查所属 Q（O(logN) 点查）；
//! - `DBI_RECORD_TS`（键 `[ts_ns][packet_idx]`）→ 报文时间窗检索（含紧凑摘要）。
//!
//! 游标语义：键全大端有序，`cursor` 为上一页末键原文（排他），前向/后向双向翻页；
//! `has_more` 以"原始键级是否取满"判定（状态过滤不截断续页）。
//! 导出：`ExportSink` trait 可扩展 JSONL/CSV/Parquet，`stream_*` 自动翻页打满。

use crate::connection::ConnState;
use crate::db::{
    k_conn_state, k_packet_qr, k_qr_pair, v_packet_qr_decode, v_record_summary_decode,
    v_status_decode, DbRegistry, QrPairValue, QrStatus, RecordSummary, IDX_CONN_QR, IDX_CONN_STATE,
    IDX_PACKET_QR, IDX_QR_PAIR, IDX_QR_TIME, IDX_RECORD_TS,
};
use anyhow::{bail, Result};
use heed::types::Bytes;
use heed::Database;
use serde::Serialize;
use std::io::Write;
use std::ops::Bound;

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

/// 只读查询会话：一个只读事务内完成多维检索（读一致性快照）。
pub struct QuerySession<'e> {
    txn: heed::RoTxn<'e, heed::WithTls>,
    dbs: [Database<Bytes, Bytes>; crate::db::NUM_DBIS],
}

impl<'e> QuerySession<'e> {
    pub fn open(reg: &'e DbRegistry) -> Result<QuerySession<'e>> {
        let txn = reg.read_txn()?;
        Ok(QuerySession {
            txn,
            dbs: reg.dbs,
        })
    }

    /// QRPAIR 主键直查（O(logN) 点查，回跳基因锚）。
    pub fn qr_by_idx(&self, q_first_idx: u64) -> Result<Option<QrPairValue>> {
        let Some(v) = self.dbs[IDX_QR_PAIR].get(&self.txn, &k_qr_pair(q_first_idx))? else {
            return Ok(None);
        };
        Ok(QrPairValue::decode(v))
    }

    /// PACKET_QR 反查：报文 IDX → 所属 Q 首包 IDX（O(logN) 点查）。
    pub fn qr_by_packet(&self, packet_idx: u64) -> Result<Option<u64>> {
        let Some(v) = self.dbs[IDX_PACKET_QR].get(&self.txn, &k_packet_qr(packet_idx))? else {
            return Ok(None);
        };
        Ok(v_packet_qr_decode(v))
    }

    /// CONN_STATE 点查（连接热状态审计）。
    pub fn conn_state(&self, conn_hash: u64) -> Result<Option<ConnState>> {
        let Some(v) = self.dbs[IDX_CONN_STATE].get(&self.txn, &k_conn_state(conn_hash))? else {
            return Ok(None);
        };
        Ok(ConnState::from_bytes(v))
    }

    /// DBI_CONN_QR：单连接按时间序的 Q 检索（前缀 + 时间窗）。
    pub fn scan_conn_qr(&self, f: &QrFilter, page: &Page) -> Result<PageRows<QrIndexRow>> {
        let Some(ch) = f.conn_hash else {
            bail!("CONN_QR 扫描必须指定 conn_hash");
        };
        let (lo, hi) = conn_qr_bounds(ch, f.start_ts, f.end_ts);
        let raw = page_rows(
            &self.dbs[IDX_CONN_QR],
            &self.txn,
            lo,
            hi,
            page.cursor.clone(),
            page.limit,
            page.forward,
        )?;
        let mut rows = Vec::with_capacity(raw.len());
        for (k, v) in &raw {
            let q_ts = be64(&k[8..16]);
            let q_first_idx = be64(&k[16..24]);
            let Some(status) = v_status_decode(v) else {
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
        Ok(paged(raw, rows, page.limit))
    }

    /// DBI_QR_TIME：全量时间窗 Q 检索。
    pub fn scan_time_qr(&self, f: &QrFilter, page: &Page) -> Result<PageRows<QrIndexRow>> {
        let (lo, hi) = ts_bounds(f.start_ts, f.end_ts);
        let raw = page_rows(
            &self.dbs[IDX_QR_TIME],
            &self.txn,
            lo,
            hi,
            page.cursor.clone(),
            page.limit,
            page.forward,
        )?;
        let mut rows = Vec::with_capacity(raw.len());
        for (k, v) in &raw {
            let q_ts = be64(&k[0..8]);
            let q_first_idx = be64(&k[8..16]);
            let Some(status) = v_status_decode(v) else {
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
        Ok(paged(raw, rows, page.limit))
    }

    /// DBI_RECORD_TS：报文时间窗检索（含紧凑摘要）。
    pub fn scan_records(&self, f: &RecordFilter, page: &Page) -> Result<PageRows<RecordRow>> {
        let (lo, hi) = ts_bounds(f.start_ts, f.end_ts);
        let raw = page_rows(
            &self.dbs[IDX_RECORD_TS],
            &self.txn,
            lo,
            hi,
            page.cursor.clone(),
            page.limit,
            page.forward,
        )?;
        let mut rows = Vec::with_capacity(raw.len());
        for (k, v) in &raw {
            let Some(summary) = v_record_summary_decode(v) else {
                continue;
            };
            rows.push(RecordRow {
                ts_ns: be64(&k[0..8]),
                packet_idx: be64(&k[8..16]),
                summary,
            });
        }
        Ok(paged(raw, rows, page.limit))
    }
}

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
    let mut page = Page::default();
    let mut total = 0u64;
    loop {
        let r = s.scan_records(f, &page)?;
        for row in &r.rows {
            sink.record(row)?;
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

// --- 内部：键区间构造 + 分页原始扫描 ---

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

/// 原始键级分页扫描：升序走 `range`、降序走 `rev_range`，cursor 排他续读。
/// 返回 (key, value) 原文对（上限 limit 条）。
fn page_rows(
    db: &Database<Bytes, Bytes>,
    txn: &heed::RoTxn<heed::WithTls>,
    lo: Vec<u8>,
    hi: Vec<u8>,
    cursor: Option<Vec<u8>>,
    limit: usize,
    forward: bool,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let limit = limit.max(1);
    let mut out = Vec::with_capacity(limit.min(4096));
    if forward {
        let start: Bound<&[u8]> = match &cursor {
            Some(c) => Bound::Excluded(c.as_slice()),
            None => Bound::Included(lo.as_slice()),
        };
        let rng = db.range(txn, &(start, Bound::Included(hi.as_slice())))?;
        for item in rng {
            let (k, v) = item?;
            out.push((k.to_vec(), v.to_vec()));
            if out.len() >= limit {
                break;
            }
        }
    } else {
        let end: Bound<&[u8]> = match &cursor {
            Some(c) => Bound::Excluded(c.as_slice()),
            None => Bound::Included(hi.as_slice()),
        };
        let rng = db.rev_range(txn, &(Bound::Included(lo.as_slice()), end))?;
        for item in rng {
            let (k, v) = item?;
            out.push((k.to_vec(), v.to_vec()));
            if out.len() >= limit {
                break;
            }
        }
    }
    Ok(out)
}

    /// 组装分页结果：has_more = 原始键取满一整页（=limit）；next_cursor = 末键。
    fn paged<T>(raw: Vec<(Vec<u8>, Vec<u8>)>, rows: Vec<T>, limit: usize) -> PageRows<T> {
        let next_cursor = raw.last().map(|(k, _)| k.clone());
        PageRows {
            rows,
            has_more: raw.len() >= limit && next_cursor.is_some(),
            next_cursor,
        }
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
}
