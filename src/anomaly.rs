//! P4 异常与慢路径：PENDING_TTL 定时超时扫描协程 + 终态事件审计。
//!
//! 设计依据：09 §九 P4（异常与慢路径）与 §七（异常台账可统计可回跳）。
//!
//! - **TTL 扫描**：`DBI_PENDING_TTL` 键序 `[q_ts][conn_hash]` 天然按打开时间升序，
//!   扫描上界 = `now - min(qr_timeout, fin_short_timeout)`（FIN 缩短后最紧的超时），
//!   窗口内逐条评估 → 过期 PENDING Q 原子翻转 `TIMEOUT`（QRPAIR + 次级索引同 txn 软缓存一致），
//!   清 QR_PENDING / PENDING_TTL，连接 qr_open 计数同步递减。
//! - **FIN 缩短超时**：`q_ts <= fin_seen`（FIN 发生在 Q 生命周期内）的挂起 Q，
//!   按 `fin_seen + fin_short_timeout` 提前到期；代际翻转已物理清退旧 PENDING，
//!   故 `q_ts > fin_seen` 的新代际 Q 绝不会被旧代际 FIN 误伤。
//! - **终态审计**：TIMEOUT / UNMATCHED / RST_ABORT 全部逐 Q 落 `anomalies` 台账
//!   （qr.rs 翻转路径 + 本模块 TTL 路径），`qr_id` 即数据平面 IDX 可回跳原文。
//! - **幂等**：QRPAIR 已终态 / 主键缺失 → 仅清残留 TTL（stale），绝不重复翻转。

use crate::connection::ConnState;
use crate::db::{
    k_conn_state, k_qr_pair, v_pending_ttl_decode, v_qr_pending_decode, DbRegistry, QrPairValue,
    QrStatus, IDX_CONN_STATE, IDX_PENDING_TTL, IDX_QR_PAIR, IDX_QR_PENDING,
};
use crate::ledger::{AnomalyEvent, Ledger};
use crate::qr::write_secondary_status;
use anyhow::Result;
use std::collections::HashMap;
use std::ops::Bound;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 审计异常种类（P3 起逐步引入；P4 补齐终态家族）。
pub const ANOM_EPOCH_REBIRTH: i64 = 10;
pub const ANOM_CONN_RST: i64 = 11;
pub const ANOM_QR_TIMEOUT: i64 = 12;
pub const ANOM_QR_UNMATCHED: i64 = 13;
pub const ANOM_QR_RST_ABORT: i64 = 14;

/// 单次 TTL 扫描统计（供运行循环/观测）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TtlScanStats {
    /// 本次评估的 PENDING_TTL 条目数。
    pub scanned: u64,
    /// 翻转为 TIMEOUT 的 Q 数。
    pub timed_out: u64,
    /// 残留清理（QRPAIR 已终态/缺失）条目数。
    pub stale: u64,
    /// 被改写连接状态的连接数。
    pub conns_touched: u64,
}

/// PENDING_TTL 扫描：过期 PENDING Q → TIMEOUT（同 txn 原子），返回逐 Q 审计事件。
///
/// - `now_ns`：当前单调时钟 ns（调用方传入，测试可注入）。
/// - `qr_timeout_secs` / `fin_short_timeout_secs`：见 09 §11 `[analysis]`。
pub fn scan_pending_ttl(
    reg: &DbRegistry,
    now_ns: u64,
    qr_timeout_secs: u64,
    fin_short_timeout_secs: u64,
) -> Result<(Vec<AnomalyEvent>, TtlScanStats)> {
    let mut stats = TtlScanStats::default();
    if qr_timeout_secs == 0 {
        return Ok((Vec::new(), stats)); // TTL 关闭
    }
    let qr_timeout_ns = qr_timeout_secs.saturating_mul(1_000_000_000);
    // 扫描上界：最紧超时（FIN 缩短 < 基础超时才有意义）。
    let short_ns = if fin_short_timeout_secs > 0 && fin_short_timeout_secs < qr_timeout_secs {
        fin_short_timeout_secs.saturating_mul(1_000_000_000)
    } else {
        qr_timeout_ns
    };
    let scan_hi_qts = now_ns.saturating_sub(short_ns);

    let mut txn = reg.write_txn()?;
    let db = reg.dbs[IDX_PENDING_TTL];

    // ① 收集窗口内候选（q_ts ≤ now - min_timeout）。键序升序 = 打开时间升序。
    let lo = [0u8; 16];
    let mut hi = [0u8; 16];
    hi[0..8].copy_from_slice(&scan_hi_qts.to_be_bytes());
    hi[8..].fill(0xFF);
    let mut hits: Vec<(Vec<u8>, u64, u64, u64, u64)> = Vec::new(); // (ttl_key,q_ts,conn,q_first_idx,abs_q_end)
    for item in db.range(&txn, &(Bound::Included(lo.as_slice()), Bound::Included(hi.as_slice())))? {
        let (k, v) = item?;
        stats.scanned += 1;
        let Some((q_first_idx, abs_q_end)) = v_pending_ttl_decode(v) else {
            continue;
        };
        let q_ts = be64(&k[0..8]);
        let conn_hash = be64(&k[8..16]);
        hits.push((k.to_vec(), q_ts, conn_hash, q_first_idx, abs_q_end));
    }

    let mut conn_cache: HashMap<u64, ConnState> = HashMap::new();
    let mut events: Vec<AnomalyEvent> = Vec::new();

    // ② 逐条评估到期。
    for (ttl_key, q_ts, h, q_first_idx, _abs_q_end) in hits {
        let st = conn_cache
            .entry(h)
            .or_insert_with(|| load_conn(&txn, reg, h).ok().flatten().unwrap_or_default());

        // 到期判定：基础 TTL vs FIN 缩短超时（二者取较早）。
        let base_deadline = q_ts.saturating_add(qr_timeout_ns);
        let fin_deadline = if st.fin_seen > 0 && q_ts <= st.fin_seen {
            st.fin_seen.saturating_add(short_ns)
        } else {
            u64::MAX
        };
        if base_deadline.min(fin_deadline) > now_ns {
            continue; // 未到期（基础 TTL 窗口内、无 FIN 缩短）。
        }

        // ③ QRPAIR 主行读改写（幂等：已终态仅清理残留）。
        let dbp = reg.dbs[IDX_QR_PAIR];
        let Some(vp) = dbp.get(&txn, &k_qr_pair(q_first_idx))? else {
            cleanup_residual(reg, &mut txn, h, q_first_idx, &ttl_key)?;
            stats.stale += 1;
            continue;
        };
        let Some(mut pair) = QrPairValue::decode(vp) else {
            cleanup_residual(reg, &mut txn, h, q_first_idx, &ttl_key)?;
            stats.stale += 1;
            continue;
        };
        if pair.status != QrStatus::Pending as u8 {
            cleanup_residual(reg, &mut txn, h, q_first_idx, &ttl_key)?;
            stats.stale += 1;
            continue;
        }

        pair.status = QrStatus::Timeout as u8;
        dbp.put(&mut txn, &k_qr_pair(q_first_idx), &pair.encode())?;
        write_secondary_status(&reg.dbs, &mut txn, &pair, q_first_idx, QrStatus::Timeout)?;
        // 清 QR_PENDING（按连接前缀扫描，q_first_idx 匹配）+ 清 PENDING_TTL。
        cleanup_pending(reg, &mut txn, h, q_first_idx)?;
        reg.dbs[IDX_PENDING_TTL].delete(&mut txn, &ttl_key)?;

        // 连接侧：qr_open 递减 + 未匹配标记（L1 预算/审计口径同步）。
        st.qr_open = st.qr_open.saturating_sub(1);
        st.anomaly_flags |= crate::connection::anomaly::QR_UNMATCHED;

        events.push(AnomalyEvent {
            ts: now_ns as i64,
            kind: ANOM_QR_TIMEOUT,
            dev_id: None,
            segment_seq: None,
            conn_hash: Some(h.to_be_bytes().to_vec()),
            qr_id: Some(q_first_idx as i64),
            detail: Some(format!("qr_timeout_ms={}", now_ns.saturating_sub(q_ts) / 1_000_000)),
        });
        stats.timed_out += 1;
    }

    // ④ 连接状态写回。
    for (h, st) in &conn_cache {
        reg.dbs[IDX_CONN_STATE].put(&mut txn, &k_conn_state(*h), &st.to_bytes())?;
        stats.conns_touched += 1;
    }
    txn.commit()?;
    Ok((events, stats))
}

/// 后台 TTL 扫描协程：常驻循环，每 `interval_secs` 扫描一次并把终态事件落 SQLite 台账。
/// 当前运行时为同步 std 线程（与 serve 骨架一致）；`shutdown` 置位即优雅退出。
pub fn run_ttl_loop(
    reg: DbRegistry,
    ledger: Ledger,
    interval_secs: u64,
    qr_timeout_secs: u64,
    fin_short_timeout_secs: u64,
    shutdown: Arc<AtomicBool>,
) {
    let interval = Duration::from_secs(interval_secs.max(1));
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        match scan_pending_ttl(&reg, now_ns, qr_timeout_secs, fin_short_timeout_secs) {
            Ok((events, stats)) => {
                if let Err(e) = ledger.insert_anomalies(&events) {
                    tracing::error!("TTL 审计落库失败: {}", e);
                }
                if stats.scanned > 0 {
                    tracing::info!(
                        "TTL 扫描: scanned={} timed_out={} stale={} conns={}",
                        stats.scanned,
                        stats.timed_out,
                        stats.stale,
                        stats.conns_touched
                    );
                }
            }
            Err(e) => tracing::error!("TTL 扫描失败: {}", e),
        }
        std::thread::sleep(interval);
    }
}

/// QRPAIR 已终态/缺失 → 仅清理 TTL 残留 + 尝试清理 pending 残留（幂等）。
fn cleanup_residual(
    reg: &DbRegistry,
    txn: &mut heed::RwTxn<'_>,
    h: u64,
    q_first_idx: u64,
    ttl_key: &[u8],
) -> Result<()> {
    cleanup_pending(reg, txn, h, q_first_idx)?;
    reg.dbs[IDX_PENDING_TTL].delete(txn, ttl_key)?;
    Ok(())
}

/// 按连接前缀扫描 QR_PENDING，删除 q_first_idx 匹配的条目（TTL 键不含 incarnation）。
fn cleanup_pending(
    reg: &DbRegistry,
    txn: &mut heed::RwTxn<'_>,
    h: u64,
    q_first_idx: u64,
) -> Result<()> {
    let db = reg.dbs[IDX_QR_PENDING];
    let mut lo = [0u8; 16];
    lo[0..8].copy_from_slice(&h.to_be_bytes());
    let mut hi = [0u8; 16];
    hi[0..8].copy_from_slice(&h.to_be_bytes());
    hi[8..].fill(0xFF);
    let range = (Bound::Included(lo.as_slice()), Bound::Included(hi.as_slice()));
    // 先定位（迭代器占用 txn 借用，释放后再删除）。
    let mut to_delete: Option<Vec<u8>> = None;
    for item in db.range(txn, &range)? {
        let (k, v) = item?;
        if let Some((fid, _, _)) = v_qr_pending_decode(v) {
            if fid == q_first_idx {
                to_delete = Some(k.to_vec());
                break;
            }
        }
    }
    if let Some(k) = to_delete {
        db.delete(txn, &k)?;
    }
    Ok(())
}

fn load_conn(txn: &heed::RwTxn<'_>, reg: &DbRegistry, h: u64) -> Result<Option<ConnState>> {
    let Some(v) = reg.dbs[IDX_CONN_STATE].get(txn, &k_conn_state(h))? else {
        return Ok(None);
    };
    Ok(ConnState::from_bytes(v))
}

#[inline]
fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b[..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::IndexedRecord;
    use crate::connection::anomaly as conn_anomaly;
    use crate::connection::conn_hash;
    use crate::db::{
        IDX_PENDING_TTL, IDX_QR_PAIR, IDX_QR_PENDING, k_conn_state, k_pending_ttl, k_qr_pair,
        k_qr_pending, k_qr_pending_prefix, v_pending_ttl_encode,
    };
    use crate::qr::{QrMatcher, QrParams};
    use sov_probe::wal::header::{TCP_ACK, TCP_FIN, TCP_SYN, WalRecord};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    const CIP: [u8; 4] = [192, 168, 1, 10];
    const SIP: [u8; 4] = [10, 0, 0, 1];
    const CPORT: u16 = 12345;
    const SPORT: u16 = 443;
    const SEC: u64 = 1_000_000_000;

    fn tmpdir(tag: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("sovvault-ttl-{}-{}", tag, ts));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[allow(clippy::too_many_arguments)] // 测试报文构造器，参数扁平直白。
    fn pkt(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8, ts_ns: u64, seq: u32, ack: u32, payload: &[u8]) -> WalRecord {
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
            proto: 6,
            orig_payload_len: payload.len() as u32,
            payload: payload.to_vec(),
        }
    }

    fn c2s(ts_ns: u64, seq: u32, ack: u32, payload: &[u8]) -> WalRecord {
        pkt(CIP, SIP, CPORT, SPORT, TCP_ACK, ts_ns, seq, ack, payload)
    }

    struct Offset(u32);
    impl Offset {
        fn next(&mut self, r: &WalRecord) -> u32 {
            let o = self.0;
            self.0 += 64 + r.payload.len() as u32;
            o
        }
    }

    /// 注入一条 PENDING Q（独立连接 + 独立 file_id，避免 QRPAIR 主键碰撞），返回 (conn_hash, q_first_idx)。
    fn open_pending(reg: &DbRegistry, ts_ns: u64, cport: u16, file_id: u32) -> (u64, u64) {
        let mut o = Offset(0);
        let syn = pkt(CIP, SIP, cport, SPORT, TCP_SYN, ts_ns - 1000, 1000, 0, b"");
        let synack = pkt(SIP, CIP, SPORT, cport, TCP_SYN | TCP_ACK, ts_ns - 900, 5000, 1001, b"");
        let ack = pkt(CIP, SIP, cport, SPORT, TCP_ACK, ts_ns - 800, 1001, 5001, b"");
        let q = pkt(CIP, SIP, cport, SPORT, TCP_ACK, ts_ns, 1001, 5001, b"GET /ttl");
        let mut indexed: Vec<IndexedRecord> = Vec::with_capacity(4);
        for r in [syn, synack, ack] {
            let off = o.next(&r);
            indexed.push(IndexedRecord {
                dev_id: 1,
                file_id,
                offset: off,
                rec: r,
            });
        }
        let q_off = o.next(&q);
        let q_idx = (u64::from(file_id) << 32) | q_off as u64;
        indexed.push(IndexedRecord {
            dev_id: 1,
            file_id,
            offset: q_off,
            rec: q,
        });
        let mut m = QrMatcher::begin(reg, &QrParams::default()).unwrap();
        for r in indexed {
            m.ingest(&r).unwrap();
        }
        m.commit().unwrap();
        let h = conn_hash(1, u32::from_be_bytes(CIP), cport, u32::from_be_bytes(SIP), SPORT, 6);
        (h, q_idx)
    }

    fn pair_status(reg: &DbRegistry, q_first_idx: u64) -> u8 {
        let txn = reg.read_txn().unwrap();
        let v = reg.dbs[IDX_QR_PAIR].get(&txn, &k_qr_pair(q_first_idx)).unwrap().unwrap();
        QrPairValue::decode(v).unwrap().status
    }

    fn pending_len(reg: &DbRegistry, h: u64, inc: u16) -> u64 {
        let txn = reg.read_txn().unwrap();
        let lo = k_qr_pending_prefix(h, inc);
        let hi = k_qr_pending(h, inc, 0x0000_FFFF_FFFF_FFFF);
        let range = (Bound::Included(lo.as_slice()), Bound::Included(hi.as_slice()));
        reg.dbs[IDX_QR_PENDING].range(&txn, &range).unwrap().count() as u64
    }

    fn ttl_len(reg: &DbRegistry) -> u64 {
        let txn = reg.read_txn().unwrap();
        reg.dbs[IDX_PENDING_TTL].len(&txn).unwrap()
    }

    fn conn_state_at(reg: &DbRegistry, h: u64) -> ConnState {
        let txn = reg.read_txn().unwrap();
        let v = reg.dbs[IDX_CONN_STATE].get(&txn, &k_conn_state(h)).unwrap().unwrap();
        ConnState::from_bytes(v).unwrap()
    }

    #[test]
    fn ttl_expires_stale_and_keeps_fresh() {
        let dir = tmpdir("expire");
        let reg = DbRegistry::open(&dir.join("qridx"), 16 * 1024 * 1024).unwrap();
        let now = 1_700_000_000_000_000_000u64;
        let (h_old, q_old) = open_pending(&reg, now - 40 * SEC, 11111, 1);
        let (h_new, q_new) = open_pending(&reg, now - SEC, 22222, 2);
        assert_ne!(h_old, h_new);
        assert_eq!(pending_len(&reg, h_old, 0), 1);
        assert_eq!(pending_len(&reg, h_new, 0), 1);
        assert_eq!(ttl_len(&reg), 2);

        let (events, stats) =
            scan_pending_ttl(&reg, now, 30, 5).unwrap();

        assert_eq!(stats.timed_out, 1);
        assert_eq!(stats.scanned, 1);
        // 旧 Q → TIMEOUT + 清 pending/TTL + qr_open 归零。
        assert_eq!(pair_status(&reg, q_old), QrStatus::Timeout as u8);
        assert_eq!(pending_len(&reg, h_old, 0), 0);
        assert_eq!(conn_state_at(&reg, h_old).qr_open, 0);
        assert_ne!(conn_state_at(&reg, h_old).anomaly_flags & conn_anomaly::QR_UNMATCHED, 0);
        // 新 Q 原样 PENDING。
        assert_eq!(pair_status(&reg, q_new), QrStatus::Pending as u8);
        assert_eq!(pending_len(&reg, h_new, 0), 1);
        assert_eq!(conn_state_at(&reg, h_new).qr_open, 1);
        // 审计事件逐 Q。
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, ANOM_QR_TIMEOUT);
        assert_eq!(events[0].qr_id, Some(q_old as i64));
        // TTL 索引残留清理。
        assert_eq!(ttl_len(&reg), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fin_short_timeout_shortens_in_life_q() {
        let dir = tmpdir("fin");
        let reg = DbRegistry::open(&dir.join("qridx"), 16 * 1024 * 1024).unwrap();
        let fin_ts = 1_700_000_000_000_000_000u64;
        let now = fin_ts + 6 * SEC; // FIN 后 6s > fin_short(5s)，仍 < 基础 TTL(30s)
        let q1 = c2s(fin_ts - 2 * SEC, 1001, 5001, b"GET /pre-fin");
        // 客户端 FIN（C2S）：服务端从不响应，Q1 无消费保持 PENDING；fin_seen 触发缩短超时。
        let fin = pkt(CIP, SIP, CPORT, SPORT, TCP_FIN, fin_ts, 1007, 5001, b"");
        let q2 = c2s(fin_ts + SEC, 1011, 5001, b"GET /post-fin");
        let mut recs: Vec<WalRecord> = vec![
            pkt(CIP, SIP, CPORT, SPORT, TCP_SYN, fin_ts - 1000, 1000, 0, b""),
            pkt(SIP, CIP, SPORT, CPORT, TCP_SYN | TCP_ACK, fin_ts - 900, 5000, 1001, b""),
            c2s(fin_ts - 800, 1001, 5001, b""),
            q1,
            fin,
            q2,
        ];
        let mut o = Offset(0);
        let mut offsets = Vec::with_capacity(recs.len());
        for r in &recs {
            offsets.push(o.next(r));
        }
        let q1_idx = (1u64 << 32) | offsets[3] as u64;
        let q2_idx = (1u64 << 32) | offsets[5] as u64;
        let mut m = QrMatcher::begin(&reg, &QrParams::default()).unwrap();
        for (r, off) in recs.drain(..).zip(offsets) {
            m.ingest(&IndexedRecord {
                dev_id: 1,
                file_id: 1,
                offset: off,
                rec: r,
            })
            .unwrap();
        }
        m.commit().unwrap();

        let h = conn_hash(1, u32::from_be_bytes(CIP), CPORT, u32::from_be_bytes(SIP), SPORT, 6);
        assert_eq!(pending_len(&reg, h, 0), 2);

        let (events, stats) = scan_pending_ttl(&reg, now, 30, 5).unwrap();
        assert_eq!(stats.timed_out, 1, "仅 Q1（FIN 生命周期内）被缩短到期");
        // Q1 超时；Q2（基础 TTL 未到）保留。
        assert_eq!(pair_status(&reg, q1_idx), QrStatus::Timeout as u8);
        assert_eq!(pair_status(&reg, q2_idx), QrStatus::Pending as u8);
        assert_eq!(pending_len(&reg, h, 0), 1);
        assert_eq!(events[0].qr_id, Some(q1_idx as i64));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ttl_scan_idempotent_no_double_flip() {
        let dir = tmpdir("idem");
        let reg = DbRegistry::open(&dir.join("qridx"), 16 * 1024 * 1024).unwrap();
        let now = 1_700_000_000_000_000_000u64;
        let (h, q) = open_pending(&reg, now - 40 * SEC, 33333, 1);
        let (ev1, s1) = scan_pending_ttl(&reg, now, 30, 5).unwrap();
        assert_eq!(s1.timed_out, 1);
        assert_eq!(ev1.len(), 1);
        // 同条件再扫：无新翻转，无残留。
        let (ev2, s2) = scan_pending_ttl(&reg, now, 30, 5).unwrap();
        assert_eq!(s2.timed_out, 0);
        assert_eq!(s2.stale, 0);
        assert!(ev2.is_empty());
        assert_eq!(pair_status(&reg, q), QrStatus::Timeout as u8);
        assert_eq!(pending_len(&reg, h, 0), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ttl_audit_persists_to_ledger() {
        let dir = tmpdir("audit");
        let reg = DbRegistry::open(&dir.join("qridx"), 16 * 1024 * 1024).unwrap();
        let ledger = Ledger::open(&dir.join("ledger.db")).unwrap();
        let now = 1_700_000_000_000_000_000u64;
        let (h, _) = open_pending(&reg, now - 40 * SEC, 44444, 1);
        let (events, _) = scan_pending_ttl(&reg, now, 30, 5).unwrap();
        ledger.insert_anomalies(&events).unwrap();
        let sum = ledger.anomaly_summary(None, None).unwrap();
        assert_eq!(sum, vec![(ANOM_QR_TIMEOUT, 1)]);
        let rows = ledger
            .query_anomalies(Some(ANOM_QR_TIMEOUT), None, None, 10)
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].conn_hash, Some(h.to_be_bytes().to_vec()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 直接注入 PENDING_TTL 残留（QRPAIR 已终态）→ stale 清理不翻转。
    #[test]
    fn ttl_stale_residual_cleaned() {
        let dir = tmpdir("stale");
        let reg = DbRegistry::open(&dir.join("qridx"), 16 * 1024 * 1024).unwrap();
        let now = 1_700_000_000_000_000_000u64;
        let q_ts = now - 40 * SEC;
        let conn = 0xDEADBEEF;
        let key = k_pending_ttl(q_ts, conn);
        let val = v_pending_ttl_encode(777, 1000);
        let mut txn = reg.write_txn().unwrap();
        reg.dbs[IDX_PENDING_TTL].put(&mut txn, &key, &val).unwrap();
        // 无对应 QRPAIR → 残留清理。
        txn.commit().unwrap();
        let (_, stats) = scan_pending_ttl(&reg, now, 30, 5).unwrap();
        assert_eq!(stats.stale, 1);
        assert_eq!(stats.timed_out, 0);
        assert_eq!(ttl_len(&reg), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ttl_disabled_no_op() {
        let dir = tmpdir("disabled");
        let reg = DbRegistry::open(&dir.join("qridx"), 16 * 1024 * 1024).unwrap();
        let (_, _) = open_pending(&reg, 1_000_000_000, 55555, 1);
        let (events, stats) = scan_pending_ttl(&reg, 1_000_000_000_000, 0, 5).unwrap();
        assert!(events.is_empty());
        assert_eq!(stats.timed_out, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
