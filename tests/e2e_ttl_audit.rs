//! P3.5 + P4 端到端验收：灌库 → TTL 超时扫描 → SQLite 审计台账 → 四维查询回跳。
//!
//! 覆盖链条（用户验收点）：
//!   1. P2 灌库：BatchPipeline 推送握手 + Q → 2PC-Lite 提交（LMDB 先行 / SQLite 水位线殿后）；
//!   2. P4 TTL：后台协程同款扫描逻辑翻转过期 PENDING → TIMEOUT，逐 Q 落审计台账；
//!   3. P3.5 查询：CONN_QR / QR_TIME / PACKET_QR / RECORD_TS 四维检索 + JSONL 导出接口；
//!   4. 审计回跳：`anomalies.qr_id`（数据平面 IDX）可定位原文 QRPAIR。

use sov_probe::wal::header::{TCP_ACK, TCP_SYN, WalRecord};
use sov_vault::anomaly::scan_pending_ttl;
use sov_vault::batch::BatchPipeline;
use sov_vault::connection::conn_hash;
use sov_vault::db::{DbRegistry, QrStatus};
use sov_vault::ledger::Ledger;
use sov_vault::qr::QrParams;
use sov_vault::query::{JsonlSink, Page, QrFilter, QuerySession, RecordFilter, stream_qrs};
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
    let p = std::env::temp_dir().join(format!("sovvault-e2ettl-{}-{}", tag, ts));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[allow(clippy::too_many_arguments)] // 测试报文构造器，参数扁平直白。
fn pkt(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    flags: u8,
    ts_ns: u64,
    seq: u32,
    ack: u32,
    payload: &[u8],
) -> WalRecord {
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

#[test]
fn e2e_ingest_ttl_audit_query_loop() {
    let dir = tmpdir("loop");
    let ledger = Ledger::open(&dir.join("ledger.db")).unwrap();
    let reg = DbRegistry::open(&dir.join("qridx"), 16 * 1024 * 1024).unwrap();

    let now = now_ns();
    // 灌库：握手 + 一条过期未响应 Q（q_ts = now - 40s > qr_timeout 30s）。
    let mut pipe = BatchPipeline::new(
        &ledger,
        dir.join("hot"),
        1,
        0,
        64 * 1024,
        100,
        QrParams::default(),
    )
    .unwrap();
    let recs: Vec<WalRecord> = vec![
        pkt(CIP, SIP, CPORT, SPORT, TCP_SYN, now - 41 * SEC, 1000, 0, b""),
        pkt(SIP, CIP, SPORT, CPORT, TCP_SYN | TCP_ACK, now - 40 * SEC, 5000, 1001, b""),
        pkt(CIP, SIP, CPORT, SPORT, TCP_ACK, now - 39 * SEC, 1001, 5001, b""),
        pkt(CIP, SIP, CPORT, SPORT, TCP_ACK, now - 40 * SEC, 1001, 5001, b"GET /stale"),
    ];
    for r in recs {
        pipe.push_record(&reg, r).unwrap();
    }
    pipe.finish(&reg).unwrap();

    // P4：TTL 扫描（后台协程同款逻辑）+ 终态事件落 SQLite 台账。
    let (events, stats) = scan_pending_ttl(&reg, now, 30, 5).unwrap();
    assert_eq!(stats.timed_out, 1, "过期 Q 应翻转 TIMEOUT");
    ledger.insert_anomalies(&events).unwrap();
    let h = conn_hash(
        1,
        u32::from_be_bytes(CIP),
        CPORT,
        u32::from_be_bytes(SIP),
        SPORT,
        6,
    );
    let q_first_idx = events[0].qr_id.unwrap() as u64;

    // ① QRPAIR 主键直查：终态 TIMEOUT、基因锚保留。
    let s = QuerySession::open(&reg).unwrap();
    let pair = s.qr_by_idx(q_first_idx).unwrap().unwrap();
    assert_eq!(pair.status, QrStatus::Timeout as u8);
    assert_eq!(pair.conn_hash, h);
    assert_eq!(pair.q_idx, vec![q_first_idx]);
    assert_eq!(pair.req_key, b"GET /stale".to_vec());

    // ② DBI_CONN_QR 连接维度检索。
    let r = s
        .scan_conn_qr(
            &QrFilter { conn_hash: Some(h), ..Default::default() },
            &Page::default(),
        )
        .unwrap();
    assert_eq!(r.rows.len(), 1);
    assert_eq!(r.rows[0].q_first_idx, q_first_idx);
    assert_eq!(r.rows[0].status_name, "timeout");

    // ③ DBI_QR_TIME 时间维度检索。
    let r = s
        .scan_time_qr(
            &QrFilter { start_ts: Some(now - 45 * SEC), end_ts: Some(now - 35 * SEC), ..Default::default() },
            &Page::default(),
        )
        .unwrap();
    assert!(r.rows.iter().any(|x| x.q_first_idx == q_first_idx));

    // ④ DBI_PACKET_QR 报文反查。
    assert_eq!(s.qr_by_packet(q_first_idx).unwrap(), Some(q_first_idx));

    // ⑤ DBI_RECORD_TS 报文时间窗。
    let r = s
        .scan_records(
            &RecordFilter { start_ts: Some(now - 45 * SEC), end_ts: Some(now - 35 * SEC) },
            &Page::default(),
        )
        .unwrap();
    assert!(r.rows.iter().any(|x| x.packet_idx == q_first_idx));
    assert!(r.rows.iter().any(|x| x.summary.len == 10)); // "GET /stale"
    drop(s); // 释放只读事务的 reader slot，避免与后续写事务冲突（LMDB 单线程单槽）

    // ⑥ SQLite 审计台账：终态事件聚合可查、qr_id 可回跳。
    let sum = ledger.anomaly_summary(None, None).unwrap();
    assert!(sum.contains(&(sov_vault::anomaly::ANOM_QR_TIMEOUT, 1)));
    let audits = ledger
        .query_anomalies(Some(sov_vault::anomaly::ANOM_QR_TIMEOUT), None, None, 10)
        .unwrap();
    assert_eq!(audits[0].qr_id, Some(q_first_idx as i64));

    // ⑦ 导出接口：JSONL 流式导出 Q 行。
    let mut buf = Vec::new();
    let mut sink = JsonlSink::new(&mut buf);
    let n = stream_qrs(
        &reg,
        &QrFilter { conn_hash: Some(h), ..Default::default() },
        &mut sink,
    )
    .unwrap();
    assert_eq!(n, 1);
    let line = std::str::from_utf8(&buf).unwrap().lines().next().unwrap();
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(v["status_name"], "timeout");

    // ⑧ 重放自愈：同条件再扫零新增（P2 幂等收敛 + P4 幂等不重复审计）。
    let (ev2, s2) = scan_pending_ttl(&reg, now, 30, 5).unwrap();
    assert!(ev2.is_empty());
    assert_eq!(s2.timed_out, 0);

    let _ = std::fs::remove_dir_all(&dir);
}
