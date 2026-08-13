//! P3 QR 匹配引擎 e2e 验收（v0.5 评审指令补齐）：
//!
//! 核心原则：数据流回绕（自然 rewrap）与控制面重代（SYN）物理解耦。
//!
//! 1. `e2e_db_long_conn_rewrap` —— 单条长连接连续传输 ≥10GB 载荷（≥2 次 u32 完整回绕）：
//!    - 断言 incarnation 全程为 0（回绕绝不清 PENDING、绝不递增代际）；
//!    - 断言跨回绕边界的 DB 请求/响应 100% 匹配为 MATCHED（abs 单调无缝，无模运算跳变）。
//!
//! 2. `e2e_5tuple_reuse_ghost_prevent` —— 五元组复用 + 幽灵包隔离：
//!    - 老连接残留 PENDING Q（inc=0）→ 注入新 SYN（强制重代 → inc=1）；
//!    - 断言老 PENDING Q 被原子翻转 UNMATCHED（保留基因锚）、pending/TTL 清理；
//!    - 断言新 ACK 的 [ConnHash][current_inc] 前缀扫描绝不误扫老 PENDING 项（B+ 树物理隔离）。

use sov_probe::wal::header::{TCP_ACK, TCP_SYN, WalRecord};
use sov_vault::batch::IndexedRecord;
use sov_vault::connection::{ConnState, conn_hash};
use sov_vault::db::{
    DbRegistry, QrPairValue, QrStatus, LIVE_CONN_STATE, LIVE_QR_PENDING, EPOCH_QR_PAIR,
    k_conn_state, k_qr_pair, k_qr_pending, k_qr_pending_prefix,
};
use sov_vault::qr::{QrMatcher, QrParams, U48_MAX, ANOM_EPOCH_REBIRTH};
use std::ops::Bound;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const CIP: [u8; 4] = [192, 168, 1, 10];
const SIP: [u8; 4] = [10, 0, 0, 1];
const CPORT: u16 = 12345;
const SPORT: u16 = 443;
/// 模拟载荷线长（1GB，seq 空间推进用；payload 本体保持小 Vec，测试内存无关紧要）。
const GB: u32 = 0x4000_0000;

fn tmpdir(tag: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("sovvault-qre2e-{}-{}", tag, ts));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn pkt(
    flags: u8,
    seq: u32,
    ack: u32,
    orig_len: u32,
    payload: &[u8],
) -> WalRecord {
    WalRecord {
        timestamp_ns: seq as u64,
        flags: 0,
        tcp_flags: flags,
        tcp_seq: seq,
        tcp_ack: ack,
        window_size: 65535,
        src_ip: CIP,
        dst_ip: SIP,
        src_port: CPORT,
        dst_port: SPORT,
        proto: 6,
        orig_payload_len: orig_len,
        payload: payload.to_vec(),
    }
}

fn s2c(flags: u8, seq: u32, ack: u32, orig_len: u32, payload: &[u8]) -> WalRecord {
    let mut r = pkt(flags, seq, ack, orig_len, payload);
    r.src_ip = SIP;
    r.dst_ip = CIP;
    r.src_port = SPORT;
    r.dst_port = CPORT;
    r
}

struct Offset(u32);
impl Offset {
    fn next(&mut self, len: u32) -> u32 {
        let o = self.0;
        self.0 += 64 + len;
        o
    }
}

fn run(reg: &DbRegistry, recs: &[(WalRecord, u32)]) -> Vec<sov_vault::ledger::AnomalyEvent> {
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
    m.commit().unwrap().anomalies
}

fn ch() -> u64 {
    conn_hash(1, u32::from_be_bytes(CIP), CPORT, u32::from_be_bytes(SIP), SPORT, 6)
}

fn pair_at(reg: &DbRegistry, q_first_idx: u64) -> Option<QrPairValue> {
    let txn = reg.epoch_read_txn().unwrap();
    let v = reg.epoch_dbs()[EPOCH_QR_PAIR]
        .get(&txn, &k_qr_pair(q_first_idx))
        .unwrap()?;
    QrPairValue::decode(v)
}

fn pending_len(reg: &DbRegistry, h: u64, inc: u16) -> u64 {
    let txn = reg.live_read_txn().unwrap();
    let lo = k_qr_pending_prefix(h, inc);
    let hi = k_qr_pending(h, inc, U48_MAX);
    let range = (Bound::Included(lo.as_slice()), Bound::Included(hi.as_slice()));
    reg.live_dbs()[LIVE_QR_PENDING]
        .range(&txn, &range)
        .unwrap()
        .count() as u64
}

fn conn_state_at(reg: &DbRegistry, h: u64) -> ConnState {
    let txn = reg.live_read_txn().unwrap();
    let v = reg.live_dbs()[LIVE_CONN_STATE]
        .get(&txn, &k_conn_state(h))
        .unwrap()
        .unwrap();
    ConnState::from_bytes(v).unwrap()
}

/// ① 长连接回绕：单连接 ≥10GB、≥2 次 u32 完整溢出回绕。
///    回绕是数据流正常热路径：incarnation 全程 0，跨回绕边界的 DB 请求/响应 100% MATCHED。
#[test]
fn e2e_db_long_conn_rewrap() {
    let dir = tmpdir("rewrap");
    let reg = DbRegistry::open(&dir.join("qridx"), 64 * 1024 * 1024).unwrap();
    let mut o = Offset(0);

    // 客户端 ISN = 0x8000_0000（距回绕边界约 2GB，首个 1GB 包即跨边界）。
    let syn = pkt(TCP_SYN, 0x8000_0000, 0, 0, b"");
    let syn_off = o.next(0);
    let synack = s2c(TCP_SYN | TCP_ACK, 0x9000_0000, 0x8000_0001, 0, b"");
    let synack_off = o.next(0);

    // 10 × 1GB 请求/响应对 = 10GB 载荷，raw seq 跨越 2 次以上完整回绕。
    let mut recs = vec![(syn, syn_off), (synack, synack_off)];
    let mut q_seq: u32 = 0x8000_0001;
    let mut s_seq: u32 = 0x9000_0001;
    let mut q_idx_by_i: Vec<u64> = Vec::with_capacity(10);
    for _ in 0..10 {
        let q = pkt(TCP_ACK, q_seq, 0, GB, b"DBREQ");
        let q_off = o.next(q.payload.len() as u32);
        let r_ack = q_seq.wrapping_add(GB);
        let r = s2c(TCP_ACK, s_seq, r_ack, 0, b"DBRESP");
        let r_off = o.next(r.payload.len() as u32);
        recs.push((q, q_off));
        recs.push((r, r_off));
        q_idx_by_i.push((1u64 << 32) | q_off as u64);
        q_seq = r_ack;
        s_seq = s_seq.wrapping_add(1);
    }

    run(&reg, &recs);

    let h = ch();
    // incarnation 全程为 0：回绕绝不清 PENDING、绝不递增代际。
    assert_eq!(conn_state_at(&reg, h).incarnation, 0);
    assert_eq!(conn_state_at(&reg, h).qr_open, 0);

    // 跨回绕边界的 DB 请求/响应 100% MATCHED。
    let mut wrap_spanning = 0u32;
    for (i, q_idx) in q_idx_by_i.iter().enumerate() {
        let p = pair_at(&reg, *q_idx).unwrap();
        assert_eq!(p.status, QrStatus::Matched as u8, "Q{} 未匹配", i);
        assert_eq!(p.q_len, GB, "Q{} 线长失真", i);
        // 单调无缝 abs：跨边界包 abs_q_seq < k·2^32 ≤ abs_q_end
        if (p.abs_q_seq >> 32) < (p.abs_q_end >> 32) {
            wrap_spanning += 1;
        }
    }
    assert_eq!(wrap_spanning, 3, "应有 3 个包跨过回绕边界");
    // 末 Q abs_q_end = 0x8000_0001 + 10GB = 0x3_0000_0001（u48 域内，无模运算跳变）。
    let last = pair_at(&reg, *q_idx_by_i.last().unwrap()).unwrap();
    assert_eq!(last.abs_q_end, 0x3_0000_0001);
    assert_eq!(last.abs_q_seq, 0x2_C000_0001);
    assert_eq!(pending_len(&reg, h, 0), 0);

    let _ = std::fs::remove_dir_all(&dir);
}

/// ② 五元组复用幽灵包隔离：老 PENDING（inc=0）→ 新 SYN（重代 → inc=1）。
///    老 Q 被原子翻转为 UNMATCHED（保留基因锚）；新 ACK 前缀扫描绝不误扫老 PENDING 项。
#[test]
fn e2e_5tuple_reuse_ghost_prevent() {
    let dir = tmpdir("ghost");
    let reg = DbRegistry::open(&dir.join("qridx"), 32 * 1024 * 1024).unwrap();
    let mut o = Offset(0);

    // —— 老连接（inc=0）：握手 + 残留 PENDING Q ——
    let syn_old = pkt(TCP_SYN, 1000, 0, 0, b"");
    let q_old = pkt(TCP_ACK, 1001, 5001, b"GET /old".len() as u32, b"GET /old");
    let q_old_idx = (1u64 << 32) | o.next(q_old.payload.len() as u32) as u64;
    run(
        &reg,
        &[
            (syn_old, o.next(0)),
            (s2c(TCP_SYN | TCP_ACK, 5000, 1001, 0, b""), o.next(0)),
            (q_old, q_old_idx as u32),
        ],
    );
    let h = ch();
    assert_eq!(pending_len(&reg, h, 0), 1);
    assert_eq!(conn_state_at(&reg, h).incarnation, 0);

    // —— 新 SYN：同一五元组复用，异窗 ISN → 强制重代（inc=0 → 1） ——
    let new_isn = 0xABCD_1234u32;
    let anomalies = run(
        &reg,
        &[(pkt(TCP_SYN, new_isn, 0, 0, b""), o.next(0))],
    );
    // 老 PENDING Q 被准确翻转为 UNMATCHED + pending 物理清理。
    assert_eq!(pair_at(&reg, q_old_idx).unwrap().status, QrStatus::Unmatched as u8);
    assert_eq!(pending_len(&reg, h, 0), 0); // 老代际 PENDING 已清退
    assert_eq!(conn_state_at(&reg, h).incarnation, 1);
    assert!(anomalies.iter().any(|e| e.kind == ANOM_EPOCH_REBIRTH));

    // —— 新连接流量：新 Q + 新 ACK ——
    let q_new = pkt(TCP_ACK, new_isn.wrapping_add(1), 0, b"GET /new".len() as u32, b"GET /new");
    let q_new_idx = (1u64 << 32) | o.next(q_new.payload.len() as u32) as u64;
    let r_new_ack = new_isn.wrapping_add(1).wrapping_add(8);
    let r_new = s2c(TCP_ACK, 6000, r_new_ack, 0, b"200-new");
    run(
        &reg,
        &[
            (q_new, q_new_idx as u32),
            (r_new, o.next(7)),
        ],
    );
    // 新 ACK 消费新 Q 成功，且绝不误扫老 PENDING（物理前缀隔离 + 老项已清退）。
    assert_eq!(pair_at(&reg, q_new_idx).unwrap().status, QrStatus::Matched as u8);
    assert_eq!(pair_at(&reg, q_old_idx).unwrap().status, QrStatus::Unmatched as u8); // 老 Q 不被幽灵标记
    assert_eq!(pending_len(&reg, h, 1), 0);
    assert_eq!(pending_len(&reg, h, 0), 0);

    let _ = std::fs::remove_dir_all(&dir);
}
