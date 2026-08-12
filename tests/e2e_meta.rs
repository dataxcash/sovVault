//! P5 MetaBind / EXT META E2E 验收：经 `commit_batch_with_meta` 全链路
//! （LMDB 索引 + SQLite 水位线 + 审计 + EXT META 指纹台账）。
//!
//! 覆盖用户验收点：
//!   1. HTTP 连接 → 绑定 web 规则（ConnState.meta_bind_id=规则真实 id），req_key=请求行，pseudo=0；
//!   2. TLS 连接 → SNI 提取（req_key=主机名），magic_prefix + 定长头指纹；
//!   3. 无规则二进制连接 → 伪键稳定（同签名同 KEY），pseudo=1；
//!   4. ext_meta 幂等 upsert：同签名 hit_count 递增；meta_binds 按 name 幂等重注册同 id。

use sov_probe::wal::header::{TCP_ACK, TCP_SYN, WalRecord};
use sov_vault::batch::{IndexedRecord, commit_batch_with_meta};
use sov_vault::config::MetaBind;
use sov_vault::connection::{ConnState, conn_hash};
use sov_vault::db::{
    DbRegistry, QrPairValue, QrStatus, IDX_CONN_STATE, IDX_QR_PAIR, k_conn_state, k_qr_pair,
};
use sov_vault::ledger::{FileKind, Ledger};
use sov_vault::meta::MetaRegistry;
use sov_vault::qr::QrParams;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const CIP: [u8; 4] = [192, 168, 1, 10];
const SIP: [u8; 4] = [10, 0, 0, 1];
const CPORT: u16 = 12345;

fn tmpdir(tag: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("sovvault-p5meta-{}-{}", tag, ts));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
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

struct Offset(u32);
impl Offset {
    fn next(&mut self, r: &WalRecord) -> u32 {
        let o = self.0;
        self.0 += 64 + r.payload.len() as u32;
        o
    }
}

/// TLS ClientHello 构造（与 meta.rs 单测一致）。
fn tls_client_hello(sni: &str) -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&(0..32u32).map(|i| (i.wrapping_mul(7)) as u8).collect::<Vec<_>>());
    body.push(0);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.push(1);
    body.push(0x00);
    let mut sn = vec![0x00, 0x00];
    sn.push(0);
    sn.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    sn.extend_from_slice(sni.as_bytes());
    let sn_len = (sn.len() as u16).to_be_bytes();
    sn[0..2].copy_from_slice(&sn_len);
    body.extend_from_slice(&(2 + 2 + sn.len() as u16).to_be_bytes());
    body.extend_from_slice(&[0x00, 0x00]);
    body.extend_from_slice(&(sn.len() as u16).to_be_bytes());
    body.extend_from_slice(&sn);
    let body_len = body.len();
    let mut hs = vec![0x01];
    hs.extend_from_slice(&(body_len as u32).to_be_bytes()[1..4]);
    hs.extend_from_slice(&body);
    let hs_len = hs.len();
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs_len as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

struct BatchCtx {
    reg: DbRegistry,
    ledger: Ledger,
    file_id: u32,
}

/// 建库 + 登记文件 + 灌一批（commit_batch_with_meta 全链路）。
fn commit_meta(
    dir: &Path,
    records: Vec<(WalRecord, u32)>,
    mr: Option<&MetaRegistry>,
) -> BatchCtx {
    let ledger = Ledger::open(&dir.join("ledger.db")).unwrap();
    let reg = DbRegistry::open(&dir.join("qridx"), 16 * 1024 * 1024).unwrap();
    let file_id = ledger
        .insert_file(
            dir.join("hot").join("seg_0000.wal").to_str().unwrap(),
            FileKind::Wal,
            1,
            Some(0),
            now_secs(),
        )
        .unwrap() as u32;
    let indexed: Vec<IndexedRecord> = records
        .into_iter()
        .map(|(rec, offset)| IndexedRecord {
            dev_id: 1,
            file_id,
            offset,
            rec,
        })
        .collect();
    commit_batch_with_meta(&reg, &ledger, &indexed, &QrParams::default(), mr).unwrap();
    BatchCtx {
        reg,
        ledger,
        file_id,
    }
}

fn conn_state(ctx: &BatchCtx, h: u64) -> ConnState {
    let txn = ctx.reg.read_txn().unwrap();
    let v = ctx.reg.dbs[IDX_CONN_STATE]
        .get(&txn, &k_conn_state(h))
        .unwrap()
        .unwrap();
    ConnState::from_bytes(v).unwrap()
}

fn pair_at(ctx: &BatchCtx, q_first_idx: u64) -> QrPairValue {
    let txn = ctx.reg.read_txn().unwrap();
    let v = ctx.reg.dbs[IDX_QR_PAIR]
        .get(&txn, &k_qr_pair(q_first_idx))
        .unwrap()
        .unwrap();
    QrPairValue::decode(v).unwrap()
}

/// 握手 + 单请求 + 响应；返回 (记录流, 请求报文 offset)。
fn build_handshake(
    cport: u16,
    dport: u16,
    ts: u64,
    q_payload: &[u8],
    o: &mut Offset,
) -> (Vec<(WalRecord, u32)>, u32) {
    let syn = pkt(CIP, SIP, cport, dport, TCP_SYN, ts, 1000, 0, b"");
    let synack = pkt(SIP, CIP, dport, cport, TCP_SYN | TCP_ACK, ts + 1, 5000, 1001, b"");
    let ack = pkt(CIP, SIP, cport, dport, TCP_ACK, ts + 2, 1001, 5001, b"");
    let q = pkt(CIP, SIP, cport, dport, TCP_ACK, ts + 10, 1001, 5001, q_payload);
    let q_off = o.next(&q);
    let r = pkt(
        SIP,
        CIP,
        dport,
        cport,
        TCP_ACK,
        ts + 20,
        5001,
        1001 + q_payload.len() as u32,
        b"200",
    );
    let out = vec![
        (syn.clone(), o.next(&syn)),
        (synack.clone(), o.next(&synack)),
        (ack.clone(), o.next(&ack)),
        (q.clone(), q_off),
        (r.clone(), o.next(&r)),
    ];
    (out, q_off)
}

fn conn_of(cport: u16, dport: u16) -> u64 {
    conn_hash(1, u32::from_be_bytes(CIP), cport, u32::from_be_bytes(SIP), dport, 6)
}

#[test]
fn e2e_meta_http_binds_and_extracts_request_line() {
    let dir = tmpdir("http");
    let binds = vec![MetaBind {
        name: "web".into(),
        proto: 6,
        dst_port: 80,
        fingerprint: "http".into(),
        extractor: "http_line".into(),
    }];
    // 先经 ledger 注册规则取真实主键，再校正 MetaRegistry。
    let ledger = Ledger::open(&dir.join("ledger.db")).unwrap();
    let ids: Vec<i64> = binds
        .iter()
        .map(|b| {
            ledger
                .upsert_meta_bind(
                    &b.name,
                    b.proto as i64,
                    b.dst_port as i64,
                    &b.fingerprint,
                    &b.extractor,
                )
                .unwrap()
        })
        .collect();
    let mut mr = MetaRegistry::from_binds(&binds);
    for (i, id) in ids.iter().enumerate() {
        mr.set_rule_id(i, *id);
    }
    drop(ledger);

    let mut o = Offset(0);
    let (recs, q_off) = build_handshake(
        CPORT,
        80,
        1_700_000_000_000_000_000,
        b"GET /orders/42 HTTP/1.1\r\nHost: shop\r\n",
        &mut o,
    );
    let ctx = commit_meta(&dir, recs, Some(&mr));
    let h = conn_of(CPORT, 80);

    // 连接绑定：真实 meta_binds 主键 + protocol_hint=http。
    let cs = conn_state(&ctx, h);
    assert_eq!(cs.meta_bind_id, ids[0], "应绑定到 ledger 真实主键");
    assert_eq!(cs.protocol_hint, 1);

    // QRPAIR：req_key=请求行（截掉 CRLF 后续），pseudo=0，状态 MATCHED。
    let q_idx = (u64::from(ctx.file_id) << 32) | q_off as u64;
    let p = pair_at(&ctx, q_idx);
    assert_eq!(p.pseudo, 0);
    assert_eq!(p.req_key, b"GET /orders/42 HTTP/1.1");
    assert_eq!(p.status, QrStatus::Matched as u8);

    // EXT META 台账：HTTP 指纹（magic "GET " + 低熵）。
    let rows = ctx.ledger.list_ext_meta().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].protocol_hint, 1);
    assert_eq!(rows[0].magic_prefix.as_deref(), Some(&b"GET "[..]));
    assert!(rows[0].entropy.unwrap_or(9.0) < 4.8, "HTTP 文本熵应低");

    // meta_binds 幂等重注册 → 同 id。
    let ledger2 = Ledger::open(&dir.join("ledger.db")).unwrap();
    let id2 = ledger2
        .upsert_meta_bind("web", 6, 80, "http", "http_line")
        .unwrap();
    assert_eq!(id2, ids[0], "同名规则重注册必须幂等");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_meta_tls_sni_extraction() {
    let dir = tmpdir("tls");
    let binds = vec![MetaBind {
        name: "https".into(),
        proto: 6,
        dst_port: 443,
        fingerprint: "tls".into(),
        extractor: "sni".into(),
    }];
    let mr = MetaRegistry::from_binds(&binds);

    let mut o = Offset(0);
    let ch = tls_client_hello("pay.gateway.com");
    let (recs, q_off) = build_handshake(CPORT, 443, 1_700_000_000_000_000_000, &ch, &mut o);
    let ctx = commit_meta(&dir, recs, Some(&mr));
    let h = conn_of(CPORT, 443);

    let cs = conn_state(&ctx, h);
    assert_eq!(cs.meta_bind_id, 1);
    assert_eq!(cs.protocol_hint, 2, "protocol_hint=tls");

    let q_idx = (u64::from(ctx.file_id) << 32) | q_off as u64;
    let p = pair_at(&ctx, q_idx);
    assert_eq!(p.pseudo, 0);
    assert_eq!(p.req_key, b"pay.gateway.com", "TLS 应提取 SNI 作为请求键");
    assert_eq!(p.status, QrStatus::Matched as u8);

    // EXT META：magic = TLS record 头，定长头判定 true，熵较高（含随机数）。
    let rows = ctx.ledger.list_ext_meta().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].protocol_hint, 2);
    assert!(rows[0].has_fixed_header, "TLS 应判定定长头");
    assert!(rows[0].entropy.unwrap_or(0.0) > 4.0, "TLS 含随机数熵较高");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_meta_binary_pseudo_key_stable_and_ext_meta_bumps() {
    let dir = tmpdir("binary");
    let mr = MetaRegistry::from_binds(&[]); // 无规则 → 自动检测二进制伪键

    let sig: Vec<u8> = (0..64u32).map(|i| (i.wrapping_mul(0x9E3779B9) >> 16) as u8).collect();
    let base = 1_700_000_000_000_000_000u64;
    let mut o = Offset(0);
    // 两连接（不同客户端口 30001/30002，同 dport=9999）同签名请求 →
    // 伪键跨连接一致，ext_meta 同签名同 dport 合并为单行 hit_count=2。
    let (a, q_off_a) = build_handshake(30001, 9999, base, &sig, &mut o);
    let (b, q_off_b) = build_handshake(30002, 9999, base + 100, &sig, &mut o);
    let mut all = a;
    all.extend(b);
    let ctx = commit_meta(&dir, all, Some(&mr));

    let h_a = conn_of(30001, 9999);
    let cs_a = conn_state(&ctx, h_a);
    assert_eq!(cs_a.meta_bind_id, -1, "无规则 → 仅自动检测");
    assert_eq!(cs_a.protocol_hint, 5, "高熵二进制 → BINARY");

    let q_idx_a = (u64::from(ctx.file_id) << 32) | q_off_a as u64;
    let q_idx_b = (u64::from(ctx.file_id) << 32) | q_off_b as u64;
    let p1 = pair_at(&ctx, q_idx_a);
    let p2 = pair_at(&ctx, q_idx_b);
    assert_eq!(p1.pseudo, 1);
    assert_eq!(p2.pseudo, 1);
    assert_eq!(p1.req_key, p2.req_key, "同签名二进制必须同伪键（跨连接）");

    // EXT META：同签名两连接 → hit_count=2（幂等 bump 单行）。
    let rows = ctx.ledger.list_ext_meta().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].hit_count, 2);

    let _ = std::fs::remove_dir_all(&dir);
}
