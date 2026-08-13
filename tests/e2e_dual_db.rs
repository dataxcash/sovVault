//! v0.4 双库分库轮转 E2E 验收（09 §13.3 / §13.4 / §13.5 / §13.9 回归面）：
//!
//! 1. **QR_PAIR 迁移（§13.3/§13.4.2）**：Q 打开 PENDING 留 live；R 消费/TTL 超时/RST 级联进入终态时
//!    迁移到当前 epoch，live 行删除；跨批慢路径同样迁移正确。
//! 2. **迁移幂等（§13.4.2 设计点②）**：重放「已写 epoch、未删 live」窗口 → 先查 epoch 命中则跳过迁移、
//!    仅清 live 残留 → 收敛零脏数据（不重复写、不翻倍）。
//! 3. **epoch 轮转（§13.5）**：epoch_max_bytes 小值强制轮转 → 新 epoch 写入、旧 epoch 只读历史、
//!    重启恢复复用最高 epoch。
//! 4. **跨 epoch 查询（§13.5/§13.9.4）**：QuerySession 枚举全部 epoch，历史终态可查、确定性排序
//!    （epoch 升序 + 库内主键序）；QR 详情 live 查在途 + epoch 查终态。
//! 5. **次级索引 status 去重（§13.4.1）**：终态翻转后 CONN_QR/QR_TIME value 仍为 q_first_idx 定位值，
//!    无 status 更新；--status 过滤走「索引定位 + QR_PAIR 主行现查」。

use sov_probe::wal::header::{TCP_ACK, TCP_SYN, WalRecord};
use sov_vault::batch::IndexedRecord;
use sov_vault::connection::conn_hash;
use sov_vault::db::{
    DbRegistry, QrPairValue, QrStatus, EPOCH_QR_PAIR, LIVE_QR_PAIR, LIVE_QR_PENDING,
    k_qr_pending, k_qr_pending_prefix,
};
use sov_vault::query::{Page, QrFilter, QuerySession};
use sov_vault::qr::{QrMatcher, QrParams, U48_MAX};
use std::ops::Bound;
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
    let p = std::env::temp_dir().join(format!("sovvault-dualdb-{}-{}", tag, ts));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn pkt(flags: u8, seq: u32, ack: u32, payload: &[u8]) -> WalRecord {
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
        orig_payload_len: payload.len() as u32,
        payload: payload.to_vec(),
    }
}

fn s2c(flags: u8, seq: u32, ack: u32, payload: &[u8]) -> WalRecord {
    let mut r = pkt(flags, seq, ack, payload);
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

/// 跨库读取 QR_PAIR（live 在途 + 全部 epoch 终态）。
fn pair_at(reg: &DbRegistry, q_first_idx: u64) -> Option<QrPairValue> {
    reg.qr_pair_at(q_first_idx).unwrap()
}

fn pending_len(reg: &DbRegistry, h: u64, inc: u16) -> u64 {
    let txn = reg.live_read_txn().unwrap();
    let lo = k_qr_pending_prefix(h, inc);
    let hi = k_qr_pending(h, inc, U48_MAX);
    let range = (Bound::Included(lo.as_slice()), Bound::Included(hi.as_slice()));
    reg.live_dbs()[LIVE_QR_PENDING].range(&txn, &range).unwrap().count() as u64
}

/// live QR_PAIR 行是否存在（在途）。
fn live_pair_exists(reg: &DbRegistry, q_first_idx: u64) -> bool {
    let txn = reg.live_read_txn().unwrap();
    reg.live_dbs()[LIVE_QR_PAIR]
        .get(&txn, &sov_vault::db::k_qr_pair(q_first_idx))
        .unwrap()
        .is_some()
}

/// epoch QR_PAIR 行是否存在（终态）。
fn epoch_pair_exists(reg: &DbRegistry, q_first_idx: u64) -> bool {
    let txn = reg.epoch_read_txn().unwrap();
    reg.epoch_dbs()[EPOCH_QR_PAIR]
        .get(&txn, &sov_vault::db::k_qr_pair(q_first_idx))
        .unwrap()
        .is_some()
}

/// ① 迁移 + 幂等重放（§13.4.2）：消费终态迁移到 epoch 后，重放同批
///    → 先查 epoch 命中 → 跳过迁移（不重复写）、仅清 live 残留 → 收敛零脏数据。
#[test]
fn e2e_migration_idempotent_after_replay() {
    let dir = tmpdir("migidem");
    let reg = DbRegistry::open(&dir.join("qridx"), 16 * 1024 * 1024).unwrap();
    let mut o = Offset(0);

    let q = pkt(TCP_ACK, 1001, 5001, b"GET /a");
    let q_idx = (1u64 << 32) | o.next(6) as u64;
    let r = s2c(TCP_ACK, 5001, 1007, b"200");
    let r_idx = (1u64 << 32) | o.next(3) as u64;
    let recs = vec![
        (pkt(TCP_SYN, 1000, 0, b""), o.next(0)),
        (s2c(TCP_SYN | TCP_ACK, 5000, 1001, b""), o.next(0)),
        (q.clone(), q_idx as u32),
        (r.clone(), r_idx as u32),
    ];

    // 第一次：消费 → 终态 MATCHED 迁移到 epoch，live 行删除。
    run(&reg, &recs);
    assert!(epoch_pair_exists(&reg, q_idx));
    assert!(!live_pair_exists(&reg, q_idx));
    assert_eq!(pending_len(&reg, ch(), 0), 0);
    assert_eq!(reg.qr_pair_count().unwrap(), 1);

    // 重放同批（模拟崩溃窗口：epoch 已写、live 未删残留）→ 幂等收敛：不翻倍、不重复迁移。
    run(&reg, &recs);
    assert_eq!(reg.qr_pair_count().unwrap(), 1, "重放零翻倍");
    let p = pair_at(&reg, q_idx).unwrap();
    assert_eq!(p.status, QrStatus::Matched as u8);
    assert_eq!(pending_len(&reg, ch(), 0), 0);

    let _ = std::fs::remove_dir_all(&dir);
}

/// ② epoch 轮转（§13.5）：epoch_max_bytes 小值 → 轮转后新 epoch 承接终态，旧 epoch 只读历史；
///    重启复用最高 epoch；跨 epoch 查询可聚合历史 + 当前。
#[test]
fn e2e_epoch_rotation_and_cross_epoch_query() {
    let dir = tmpdir("rotate");
    let root = dir.join("qridx");
    // epoch_max_bytes 极小 → 写几条即触发轮转。
    let mut reg = DbRegistry::open_with(&root, 16 * 1024 * 1024, 16 * 1024).unwrap();
    let mut o = Offset(0);

    // epoch_0000：握手 + Q1 消费（终态落 epoch_0000）。
    let q1 = pkt(TCP_ACK, 1001, 5001, b"GET /e0");
    let q1_idx = (1u64 << 32) | o.next(7) as u64;
    let r1 = s2c(TCP_ACK, 5001, 1008, b"200");
    let r1_idx = (1u64 << 32) | o.next(3) as u64;
    run(
        &reg,
        &[
            (pkt(TCP_SYN, 1000, 0, b""), o.next(0)),
            (s2c(TCP_SYN | TCP_ACK, 5000, 1001, b""), o.next(0)),
            (q1.clone(), q1_idx as u32),
            (r1.clone(), r1_idx as u32),
        ],
    );
    assert_eq!(reg.epoch_num(), 0);

    // 轮转 → epoch_0001。
    let new = reg.rotate_epoch().unwrap();
    assert_eq!(new, 1);
    assert_eq!(reg.epoch_num(), 1);
    // 旧 epoch 目录保持只读历史。
    let dirs = reg.epoch_dirs();
    assert!(dirs.iter().any(|d| d.file_name().unwrap() == "epoch_0000"));
    assert!(dirs.iter().any(|d| d.file_name().unwrap() == "epoch_0001"));

    // epoch_0001：握手 + Q2 消费（终态落 epoch_0001）；Q2 的 RECORD_TS 也落 epoch_0001。
    // 用不同起始 offset 保证 q_first_idx 与 epoch_0000 的 Q1 不冲突（不同报文）。
    let mut o2 = Offset(4096);
    let q2 = pkt(TCP_ACK, 1001, 5001, b"GET /e1");
    let q2_idx = (1u64 << 32) | o2.next(7) as u64;
    let r2 = s2c(TCP_ACK, 5001, 1008, b"200");
    let r2_idx = (1u64 << 32) | o2.next(3) as u64;
    run(
        &reg,
        &[
            (pkt(TCP_SYN, 1000, 0, b""), o2.next(0)),
            (s2c(TCP_SYN | TCP_ACK, 5000, 1001, b""), o2.next(0)),
            (q2.clone(), q2_idx as u32),
            (r2.clone(), r2_idx as u32),
        ],
    );

    // 跨 epoch 查询：QuerySession 枚举 epoch_0000 + epoch_0001，历史 + 当前终态都可查。
    eprintln!("DEBUG: dirs = {:?}", reg.epoch_dirs());
    eprintln!("DEBUG: epoch_num = {}", reg.epoch_num());
    let s = QuerySession::open(&reg).unwrap();
    let f = QrFilter { conn_hash: Some(ch()), ..Default::default() };
    let r = s.scan_conn_qr(&f, &Page::default()).unwrap();
    let mut idxs: Vec<u64> = r.rows.iter().map(|x| x.q_first_idx).collect();
    idxs.sort_unstable();
    assert_eq!(idxs, vec![q1_idx, q2_idx], "跨 epoch 聚合两代终态");
    // 状态主行现查（§13.4.1）：终态 MATCHED。
    assert!(r.rows.iter().all(|x| x.status == QrStatus::Matched as u8));
    // QR 详情：q_first_idx 定位跨库命中。
    assert!(s.qr_by_idx(q1_idx).unwrap().is_some());
    assert!(s.qr_by_idx(q2_idx).unwrap().is_some());
    // 报文反查（PACKET_QR 分布在两个 epoch）。
    assert_eq!(s.qr_by_packet(q1_idx).unwrap(), Some(q1_idx));
    assert_eq!(s.qr_by_packet(q2_idx).unwrap(), Some(q2_idx));
    drop(s);

    // 重启恢复：复用最高 epoch（epoch_0001）。
    drop(reg);
    let reg2 = DbRegistry::open(&root, 16 * 1024 * 1024).unwrap();
    assert_eq!(reg2.epoch_num(), 1);
    // 跨全部 epoch 可查两代终态（历史 epoch_0000 + 当前 epoch_0001）。
    let s2 = QuerySession::open(&reg2).unwrap();
    assert_eq!(s2.qr_by_idx(q1_idx).unwrap().unwrap().status, QrStatus::Matched as u8);
    assert_eq!(s2.qr_by_idx(q2_idx).unwrap().unwrap().status, QrStatus::Matched as u8);

    let _ = std::fs::remove_dir_all(&dir);
}

/// ③ 跨 epoch 连接延续（§13.3 核心）：Q 在 epoch_0000 打开（PENDING 留 live），
///    轮转后 R 在 epoch_0001 到达 → 在途 QR_PAIR 天然延续于 live，终态迁入 epoch_0001。
#[test]
fn e2e_cross_epoch_connection_inflight_continues() {
    let dir = tmpdir("crossconn");
    let root = dir.join("qridx");
    let mut reg = DbRegistry::open_with(&root, 16 * 1024 * 1024, 16 * 1024).unwrap();
    let mut o = Offset(0);

    // epoch_0000：握手 + Q 打开（PENDING 在 live）。
    let q = pkt(TCP_ACK, 1001, 5001, b"GET /slow");
    let q_idx = (1u64 << 32) | o.next(9) as u64;
    run(
        &reg,
        &[
            (pkt(TCP_SYN, 1000, 0, b""), o.next(0)),
            (s2c(TCP_SYN | TCP_ACK, 5000, 1001, b""), o.next(0)),
            (q.clone(), q_idx as u32),
        ],
    );
    assert!(live_pair_exists(&reg, q_idx));
    assert!(!epoch_pair_exists(&reg, q_idx));

    // 轮转 → epoch_0001（live 在途不随轮转迁移，天然延续）。
    reg.rotate_epoch().unwrap();

    // R 在 epoch_0001 到达 → 读 live 消费 → 终态迁入 epoch_0001（当时当前 epoch）。
    let r = s2c(TCP_ACK, 5001, 1010, b"200");
    let r_idx = (1u64 << 32) | o.next(3) as u64;
    run(&reg, &[(r, r_idx as u32)]);
    assert!(!live_pair_exists(&reg, q_idx));
    assert!(epoch_pair_exists(&reg, q_idx));
    let p = pair_at(&reg, q_idx).unwrap();
    assert_eq!(p.status, QrStatus::Matched as u8);
    assert_eq!(p.r_idx, vec![r_idx]);
    // 终态应落在 epoch_0001（迁移写入"当时的当前 epoch"）。
    let txn = reg.epoch_read_txn().unwrap();
    assert!(reg.epoch_dbs()[EPOCH_QR_PAIR]
        .get(&txn, &sov_vault::db::k_qr_pair(q_idx))
        .unwrap()
        .is_some());
    drop(txn);

    let _ = std::fs::remove_dir_all(&dir);
}
