//! LMDB 索引平面：双库分库轮转（v0.4，09 §13）。
//! live 库（常驻，量有界）+ 当前 epoch 库（历史，按 `epoch_max_bytes` 轮转）。
//!
//! DBI 归属（09 §13.2）：
//! - **live**：CONN_STATE / QR_PAIR(PENDING) / QR_PENDING / PENDING_TTL —— 活状态永居 live；
//! - **epoch**：QR_PAIR(终态) / CONN_QR / QR_KEY / QR_TIME / PACKET_QR / RECORD_TS —— 追加后只读，
//!   轮转关闭旧 env（munmap）即完整回收其 RSS（M7 资源红线 RSS ≤ 256MB 治本）。
//!
//! 提交协议（09 §13.4）：epoch 先行（历史索引 NO_OVERWRITE 幂等）→ live 殿后（活状态/残留删除），
//! 然后 SQLite 水位线 advance。QR_PAIR 迁移幂等规则见 qr.rs / anomaly.rs（§13.4.2）：
//! 「先查 epoch → 已有则跳过迁移（不重复写）、仅清理 live 残留」。
//!
//! > 与 09 §13.4 字面顺序（①live ②epoch）的偏差说明：§13.4.2 幂等规则（正确性核心 ★）要求
//! > 「写 epoch 后、删 live 前」窗口内重放能收敛——即 epoch 必须先在磁盘上持久、live 残留删除在
//! > 其后。epoch 先行 + live 残留删除原子（同 live txn）正好满足该表全部三行；若 live 先行则在
//! > ①成功②失败窗口丢失 QR_PENDING 导致 Q 永久丢失。故取 epoch 先行。

use anyhow::Result;
use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions, EnvFlags, MdbError, PutFlags};
use std::path::{Path, PathBuf};

// --- 双库 DBI 归属 ---

/// live 库 DBI（4）：活状态，永居 live，量有界。
pub const LIVE_DBI_NAMES: [&str; NUM_LIVE_DBIS] = ["conn_state", "qr_pair", "qr_pending", "pending_ttl"];
/// epoch 库 DBI（6）：历史索引，追加后只读。
pub const EPOCH_DBI_NAMES: [&str; NUM_EPOCH_DBIS] = [
    "qr_pair", "conn_qr", "qr_key", "qr_time", "packet_qr", "record_ts",
];

pub const NUM_LIVE_DBIS: usize = 4;
pub const NUM_EPOCH_DBIS: usize = 6;

// live DBI 下标
pub const LIVE_CONN_STATE: usize = 0;
pub const LIVE_QR_PAIR: usize = 1;
pub const LIVE_QR_PENDING: usize = 2;
pub const LIVE_PENDING_TTL: usize = 3;

// epoch DBI 下标
pub const EPOCH_QR_PAIR: usize = 0;
pub const EPOCH_CONN_QR: usize = 1;
pub const EPOCH_QR_KEY: usize = 2;
pub const EPOCH_QR_TIME: usize = 3;
pub const EPOCH_PACKET_QR: usize = 4;
pub const EPOCH_RECORD_TS: usize = 5;

/// 默认单 epoch 数据量上限（M7 资源红线推导：RSS ≤ 128MB 数据 + ~120MB 固定开销 ≤ 256MB）。
pub const DEFAULT_EPOCH_MAX_BYTES: u64 = 128 * 1024 * 1024;

/// QrStatus 枚举（09 §4.2，跨 DBI 一致）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[repr(u8)]
pub enum QrStatus {
    Pending = 0,
    Matched = 1,
    Timeout = 2,
    Unmatched = 3,
    RstAbort = 4,
    AbortedResource = 5,
}

impl QrStatus {
    pub fn from_u8(v: u8) -> Option<QrStatus> {
        match v {
            0 => Some(QrStatus::Pending),
            1 => Some(QrStatus::Matched),
            2 => Some(QrStatus::Timeout),
            3 => Some(QrStatus::Unmatched),
            4 => Some(QrStatus::RstAbort),
            5 => Some(QrStatus::AbortedResource),
            _ => None,
        }
    }

    /// 稳定字面名（P3.5 查询/导出使用）。
    pub fn name(self) -> &'static str {
        match self {
            QrStatus::Pending => "pending",
            QrStatus::Matched => "matched",
            QrStatus::Timeout => "timeout",
            QrStatus::Unmatched => "unmatched",
            QrStatus::RstAbort => "rst_abort",
            QrStatus::AbortedResource => "aborted_resource",
        }
    }

    /// CLI 过滤解析。
    pub fn parse(s: &str) -> Option<QrStatus> {
        match s {
            "pending" => Some(QrStatus::Pending),
            "matched" => Some(QrStatus::Matched),
            "timeout" => Some(QrStatus::Timeout),
            "unmatched" => Some(QrStatus::Unmatched),
            "rst_abort" | "rst" => Some(QrStatus::RstAbort),
            "aborted_resource" | "aborted" => Some(QrStatus::AbortedResource),
            _ => None,
        }
    }
}

// --- 大端原语读写（键值编解码唯一途径） ---

pub fn put_u8(v: &mut Vec<u8>, x: u8) {
    v.push(x);
}
pub fn put_u16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_be_bytes());
}
pub fn put_u32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_be_bytes());
}
pub fn put_u48(v: &mut Vec<u8>, x: u64) {
    debug_assert!(x <= 0x0000_FFFF_FFFF_FFFF, "u48 溢出: {}", x);
    v.extend_from_slice(&x.to_be_bytes()[2..8]);
}
pub fn put_u64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_be_bytes());
}

pub fn take_u8(b: &[u8], o: &mut usize) -> Option<u8> {
    let v = *b.get(*o)?;
    *o += 1;
    Some(v)
}
pub fn take_u16(b: &[u8], o: &mut usize) -> Option<u16> {
    let s = b.get(*o..*o + 2)?;
    *o += 2;
    Some(u16::from_be_bytes(s.try_into().ok()?))
}
pub fn take_u32(b: &[u8], o: &mut usize) -> Option<u32> {
    let s = b.get(*o..*o + 4)?;
    *o += 4;
    Some(u32::from_be_bytes(s.try_into().ok()?))
}
pub fn take_u48(b: &[u8], o: &mut usize) -> Option<u64> {
    let s = b.get(*o..*o + 6)?;
    *o += 6;
    let mut buf = [0u8; 8];
    buf[2..8].copy_from_slice(s);
    Some(u64::from_be_bytes(buf))
}
pub fn take_u64(b: &[u8], o: &mut usize) -> Option<u64> {
    let s = b.get(*o..*o + 8)?;
    *o += 8;
    Some(u64::from_be_bytes(s.try_into().ok()?))
}

// --- 各 DBI 键构造（BE 拼接） ---

/// CONN_STATE: [conn_hash:u64]
pub fn k_conn_state(conn_hash: u64) -> [u8; 8] {
    conn_hash.to_be_bytes()
}

/// QR_PAIR: [q_first_idx:u64]
pub fn k_qr_pair(q_first_idx: u64) -> [u8; 8] {
    q_first_idx.to_be_bytes()
}

/// QR_PENDING: [conn_hash:u64][incarnation:u16][abs_q_end:u48]（v0.5 代际物理前缀，16B）。
/// 旧代际挂起 Q 在 B+ 树存储层被物理隔离——幽灵包（旧连接迟到 ACK/RST）游标读不到。
pub fn k_qr_pending(conn_hash: u64, incarnation: u16, abs_q_end: u64) -> [u8; 16] {
    let mut k = [0u8; 16];
    k[0..8].copy_from_slice(&conn_hash.to_be_bytes());
    k[8..10].copy_from_slice(&incarnation.to_be_bytes());
    k[10..16].copy_from_slice(&put_u48_bytes(abs_q_end));
    k
}

/// QR_PENDING 前缀：[conn_hash:u64][incarnation:u16]（10B），范围扫描起点。
pub fn k_qr_pending_prefix(conn_hash: u64, incarnation: u16) -> [u8; 10] {
    let mut k = [0u8; 10];
    k[0..8].copy_from_slice(&conn_hash.to_be_bytes());
    k[8..10].copy_from_slice(&incarnation.to_be_bytes());
    k
}

/// u48 大端编码（供键构造，避免中途分配）。
fn put_u48_bytes(x: u64) -> [u8; 6] {
    debug_assert!(x <= 0x0000_FFFF_FFFF_FFFF, "u48 溢出: {}", x);
    let b = x.to_be_bytes();
    let mut out = [0u8; 6];
    out.copy_from_slice(&b[2..8]);
    out
}

/// CONN_QR / QR_KEY 复合键：[prefix:u64][q_ts:u64][q_first_idx:u64]
pub fn k_conn_qr(conn_hash: u64, q_ts: u64, q_first_idx: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(24);
    put_u64(&mut v, conn_hash);
    put_u64(&mut v, q_ts);
    put_u64(&mut v, q_first_idx);
    v
}

/// QR_KEY：[reqkey_hash:u64][q_ts:u64][q_first_idx:u64]
pub fn k_qr_key(reqkey_hash: u64, q_ts: u64, q_first_idx: u64) -> Vec<u8> {
    k_conn_qr(reqkey_hash, q_ts, q_first_idx)
}

/// QR_TIME：[q_ts:u64][q_first_idx:u64]
pub fn k_qr_time(q_ts: u64, q_first_idx: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(16);
    put_u64(&mut v, q_ts);
    put_u64(&mut v, q_first_idx);
    v
}

/// PACKET_QR：[packet_idx:u64]
pub fn k_packet_qr(packet_idx: u64) -> [u8; 8] {
    packet_idx.to_be_bytes()
}

/// PENDING_TTL：[q_ts:u64][conn_hash:u64]
pub fn k_pending_ttl(q_ts: u64, conn_hash: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(16);
    put_u64(&mut v, q_ts);
    put_u64(&mut v, conn_hash);
    v
}

/// RECORD_TS：[ts_ns:u64][packet_idx:u64]（定长 16B）。
pub fn k_record_ts(ts_ns: u64, packet_idx: u64) -> [u8; 16] {
    let mut k = [0u8; 16];
    k[0..8].copy_from_slice(&ts_ns.to_be_bytes());
    k[8..16].copy_from_slice(&packet_idx.to_be_bytes());
    k
}

/// RECORD_TS Value：紧凑摘要（09 §4.9）proto|flags|src_ip|dst_ip|sport|dport|len（18B）。
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct RecordSummary {
    pub proto: u8,
    pub flags: u8,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub sport: u16,
    pub dport: u16,
    pub len: u32,
}

pub fn v_record_summary_encode(s: &RecordSummary) -> [u8; 18] {
    let mut v = [0u8; 18];
    v[0] = s.proto;
    v[1] = s.flags;
    v[2..6].copy_from_slice(&s.src_ip.to_be_bytes());
    v[6..10].copy_from_slice(&s.dst_ip.to_be_bytes());
    v[10..12].copy_from_slice(&s.sport.to_be_bytes());
    v[12..14].copy_from_slice(&s.dport.to_be_bytes());
    v[14..18].copy_from_slice(&s.len.to_be_bytes());
    v
}

pub fn v_record_summary_decode(b: &[u8]) -> Option<RecordSummary> {
    if b.len() != 18 {
        return None;
    }
    Some(RecordSummary {
        proto: b[0],
        flags: b[1],
        src_ip: u32::from_be_bytes(b[2..6].try_into().ok()?),
        dst_ip: u32::from_be_bytes(b[6..10].try_into().ok()?),
        sport: u16::from_be_bytes(b[10..12].try_into().ok()?),
        dport: u16::from_be_bytes(b[12..14].try_into().ok()?),
        len: u32::from_be_bytes(b[14..18].try_into().ok()?),
    })
}

// --- QR_PENDING Value：q_first_idx:u64 | q_ts:u64 | q_len:u32 ---

pub fn v_qr_pending_encode(q_first_idx: u64, q_ts: u64, q_len: u32) -> [u8; 20] {
    let mut v = [0u8; 20];
    v[0..8].copy_from_slice(&q_first_idx.to_be_bytes());
    v[8..16].copy_from_slice(&q_ts.to_be_bytes());
    v[16..20].copy_from_slice(&q_len.to_be_bytes());
    v
}

pub fn v_qr_pending_decode(b: &[u8]) -> Option<(u64, u64, u32)> {
    if b.len() != 20 {
        return None;
    }
    Some((
        u64::from_be_bytes(b[0..8].try_into().ok()?),
        u64::from_be_bytes(b[8..16].try_into().ok()?),
        u32::from_be_bytes(b[16..20].try_into().ok()?),
    ))
}

// --- CONN_QR/QR_KEY/QR_TIME Value（§13.4.1：不存 status，仅存在性+定位，写 q_first_idx 8B） ---

/// §13.4.1 次级索引 value：写 q_first_idx（8B BE）作「存在性 + 定位」，Q 打开时写一次、永不更新。
pub fn v_secondary_encode(q_first_idx: u64) -> [u8; 8] {
    q_first_idx.to_be_bytes()
}

pub fn v_secondary_decode(b: &[u8]) -> Option<u64> {
    if b.len() != 8 {
        return None;
    }
    Some(u64::from_be_bytes(b.try_into().ok()?))
}

// --- PACKET_QR Value：q_first_idx:u64 ---

pub fn v_packet_qr_encode(q_first_idx: u64) -> [u8; 8] {
    q_first_idx.to_be_bytes()
}

pub fn v_packet_qr_decode(b: &[u8]) -> Option<u64> {
    if b.len() != 8 {
        return None;
    }
    Some(u64::from_be_bytes(b.try_into().ok()?))
}

// --- PENDING_TTL Value：q_first_idx:u64 | abs_q_end:u48 ---

pub fn v_pending_ttl_encode(q_first_idx: u64, abs_q_end: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(14);
    put_u64(&mut v, q_first_idx);
    put_u48(&mut v, abs_q_end);
    v
}

pub fn v_pending_ttl_decode(b: &[u8]) -> Option<(u64, u64)> {
    let mut o = 0usize;
    let q_first_idx = take_u64(b, &mut o)?;
    let abs_q_end = take_u48(b, &mut o)?;
    if o != b.len() {
        return None;
    }
    Some((q_first_idx, abs_q_end))
}

// --- QR_PAIR Value（变长，09 §4.2） ---

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct QrPairValue {
    pub status: u8,
    pub conn_hash: u64,
    pub q_ts: u64,
    pub r_ts: u64,
    pub latency_ms: u64,
    pub q_len: u32,
    pub r_len: u32,
    pub abs_q_seq: u64,
    pub abs_q_end: u64,
    pub pseudo: u8,
    pub q_idx: Vec<u64>,
    pub r_idx: Vec<u64>,
    pub req_key: Vec<u8>,
    pub resp_key: Vec<u8>,
}

impl QrPairValue {
    /// 序列化：status:u8 | conn_hash:u64 | q_ts:u64 | r_ts:u64 | latency_ms:u64 |
    /// q_len:u32 | r_len:u32 | abs_q_seq:u64 | abs_q_end:u64 | pseudo:u8 |
    /// q_cnt:u16 | r_cnt:u16 | [q_idx:u64;q_cnt] | [r_idx:u64;r_cnt] |
    /// req_key:u32len+bytes | resp_key:u32len+bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut v =
            Vec::with_capacity(9 * 8 + 2 * 4 + 2 + 2 + 8 * (self.q_idx.len() + self.r_idx.len()));
        put_u8(&mut v, self.status);
        put_u64(&mut v, self.conn_hash);
        put_u64(&mut v, self.q_ts);
        put_u64(&mut v, self.r_ts);
        put_u64(&mut v, self.latency_ms);
        put_u32(&mut v, self.q_len);
        put_u32(&mut v, self.r_len);
        put_u64(&mut v, self.abs_q_seq);
        put_u64(&mut v, self.abs_q_end);
        put_u8(&mut v, self.pseudo);
        put_u16(&mut v, self.q_idx.len() as u16);
        put_u16(&mut v, self.r_idx.len() as u16);
        for &x in &self.q_idx {
            put_u64(&mut v, x);
        }
        for &x in &self.r_idx {
            put_u64(&mut v, x);
        }
        put_u32(&mut v, self.req_key.len() as u32);
        v.extend_from_slice(&self.req_key);
        put_u32(&mut v, self.resp_key.len() as u32);
        v.extend_from_slice(&self.resp_key);
        v
    }

    pub fn decode(b: &[u8]) -> Option<QrPairValue> {
        let mut o = 0usize;
        let status = take_u8(b, &mut o)?;
        let conn_hash = take_u64(b, &mut o)?;
        let q_ts = take_u64(b, &mut o)?;
        let r_ts = take_u64(b, &mut o)?;
        let latency_ms = take_u64(b, &mut o)?;
        let q_len = take_u32(b, &mut o)?;
        let r_len = take_u32(b, &mut o)?;
        let abs_q_seq = take_u64(b, &mut o)?;
        let abs_q_end = take_u64(b, &mut o)?;
        let pseudo = take_u8(b, &mut o)?;
        let q_cnt = take_u16(b, &mut o)? as usize;
        let r_cnt = take_u16(b, &mut o)? as usize;
        let mut q_idx = Vec::with_capacity(q_cnt);
        for _ in 0..q_cnt {
            q_idx.push(take_u64(b, &mut o)?);
        }
        let mut r_idx = Vec::with_capacity(r_cnt);
        for _ in 0..r_cnt {
            r_idx.push(take_u64(b, &mut o)?);
        }
        let req_len = take_u32(b, &mut o)? as usize;
        let req_key = b.get(o..o + req_len)?.to_vec();
        o += req_len;
        let resp_len = take_u32(b, &mut o)? as usize;
        let resp_key = b.get(o..o + resp_len)?.to_vec();
        o += resp_len;
        if o != b.len() {
            return None;
        }
        Some(QrPairValue {
            status,
            conn_hash,
            q_ts,
            r_ts,
            latency_ms,
            q_len,
            r_len,
            abs_q_seq,
            abs_q_end,
            pseudo,
            q_idx,
            r_idx,
            req_key,
            resp_key,
        })
    }
}

// --- 双库环境注册表 ---

/// 双库 DbRegistry：live env + 当前 epoch env。
///
/// 目录布局（09 §13.1）：
/// ```text
/// qridx/
/// ├── live/        ← 常驻，永不轮转（活状态，量有界）
/// ├── epoch_0000/  ← 历史分库，追加后只读
/// └── epoch_0001/
/// ```
pub struct DbRegistry {
    root: PathBuf,
    map_size: usize,
    epoch_max_bytes: u64,
    live: Env,
    live_dbs: [Database<Bytes, Bytes>; NUM_LIVE_DBIS],
    epoch: Env,
    epoch_dbs: [Database<Bytes, Bytes>; NUM_EPOCH_DBIS],
    epoch_num: u32,
}

fn open_env(dir: &Path, map_size: usize) -> Result<Env> {
    std::fs::create_dir_all(dir)?;
    let env = unsafe {
        EnvOpenOptions::new()
            .map_size(map_size)
            .max_dbs(16)
            .open(dir)?
    };
    Ok(env)
}

/// 打开 env 内全部具名 DBI（CREATE）。
fn open_dbis(
    env: &Env<heed::WithTls>,
    names: &[&str],
) -> Result<Vec<Database<Bytes, Bytes>>> {
    let mut txn = env.write_txn()?;
    let mut dbs = Vec::with_capacity(names.len());
    for name in names {
        dbs.push(env.create_database::<Bytes, Bytes>(&mut txn, Some(name))?);
    }
    txn.commit()?;
    Ok(dbs)
}

/// 打开历史 epoch env（追加后只读，query/export 用）。
pub fn open_epoch_env_read_only(dir: &Path, map_size: usize) -> Result<Env> {
    let env = unsafe {
        EnvOpenOptions::new()
            .map_size(map_size)
            .max_dbs(16)
            .flags(EnvFlags::READ_ONLY)
            .open(dir)?
    };
    Ok(env)
}

/// 打开历史 epoch env + 同一事务内打开的 DBI 数组（便捷路径；QuerySession 需自行开 txn 时用上面的拆法）。
pub fn open_epoch_read_only(
    dir: &Path,
    map_size: usize,
) -> Result<(Env, [Database<Bytes, Bytes>; NUM_EPOCH_DBIS])> {
    let env = open_epoch_env_read_only(dir, map_size)?;
    let txn = env.read_txn()?;
    let dbs = open_epoch_dbs_in_txn(&env, &txn)?;
    drop(txn);
    Ok((env, dbs))
}

/// 在指定只读事务内打开全部 epoch DBI（与后续查询同一事务，保证 DBI 有效）。
pub fn open_epoch_dbs_in_txn(
    env: &Env,
    txn: &heed::RoTxn<'_>,
) -> Result<[Database<Bytes, Bytes>; NUM_EPOCH_DBIS]> {
    let mut dbs = Vec::with_capacity(NUM_EPOCH_DBIS);
    for name in EPOCH_DBI_NAMES.iter() {
        let db = env
            .open_database::<Bytes, Bytes>(txn, Some(name))?
            .ok_or_else(|| anyhow::anyhow!("epoch DBI 缺失: {}", name))?;
        dbs.push(db);
    }
    dbs.try_into()
        .map_err(|_| anyhow::anyhow!("epoch DBI 数量不匹配"))
}

impl DbRegistry {
    /// 打开双库：`dir` = qridx 根目录（live/ + epoch_XXXX/ 在其下）。
    /// 默认 epoch_max_bytes = 128MB。等价于 `open_with(dir, map_size, DEFAULT_EPOCH_MAX_BYTES)`。
    pub fn open(dir: &Path, map_size: usize) -> Result<DbRegistry> {
        DbRegistry::open_with(dir, map_size, DEFAULT_EPOCH_MAX_BYTES)
    }

    /// 打开双库并指定单 epoch 数据量上限（轮转触发阈值）。
    pub fn open_with(root: &Path, map_size: usize, epoch_max_bytes: u64) -> Result<DbRegistry> {
        std::fs::create_dir_all(root)?;
        let live = open_env(&root.join("live"), map_size)?;
        let live_dbs = open_dbis(&live, &LIVE_DBI_NAMES)?;
        let live_dbs: [Database<Bytes, Bytes>; NUM_LIVE_DBIS] = live_dbs
            .try_into()
            .map_err(|_| anyhow::anyhow!("live DBI 数量不匹配"))?;

        // 恢复语义：优先复用已存在的最高 epoch（追加后只读历史 + 当前可写），否则建 epoch_0000。
        let epoch_num = DbRegistry::highest_epoch(root);
        let epoch_dir = root.join(format!("epoch_{:04}", epoch_num));
        let epoch = open_env(&epoch_dir, map_size)?;
        let epoch_dbs = open_dbis(&epoch, &EPOCH_DBI_NAMES)?;
        let epoch_dbs: [Database<Bytes, Bytes>; NUM_EPOCH_DBIS] = epoch_dbs
            .try_into()
            .map_err(|_| anyhow::anyhow!("epoch DBI 数量不匹配"))?;

        Ok(DbRegistry {
            root: root.to_path_buf(),
            map_size,
            epoch_max_bytes,
            live,
            live_dbs,
            epoch,
            epoch_dbs,
            epoch_num,
        })
    }

    /// 枚举已存在 epoch 目录（升序，epoch_XXXX）。
    pub fn epoch_dirs(&self) -> Vec<PathBuf> {
        epoch_dirs(&self.root)
    }

    /// 根目录（qridx/）。
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn map_size(&self) -> usize {
        self.map_size
    }

    pub fn epoch_max_bytes(&self) -> u64 {
        self.epoch_max_bytes
    }

    pub fn live_env(&self) -> &Env {
        &self.live
    }

    pub fn epoch_env(&self) -> &Env {
        &self.epoch
    }

    pub fn live_dbs(&self) -> &[Database<Bytes, Bytes>; NUM_LIVE_DBIS] {
        &self.live_dbs
    }

    pub fn epoch_dbs(&self) -> &[Database<Bytes, Bytes>; NUM_EPOCH_DBIS] {
        &self.epoch_dbs
    }

    pub fn epoch_num(&self) -> u32 {
        self.epoch_num
    }

    pub fn epoch_dir(&self) -> PathBuf {
        self.root.join(format!("epoch_{:04}", self.epoch_num))
    }

    pub fn live_write_txn(&self) -> Result<heed::RwTxn<'_>> {
        Ok(self.live.write_txn()?)
    }

    pub fn epoch_write_txn(&self) -> Result<heed::RwTxn<'_>> {
        Ok(self.epoch.write_txn()?)
    }

    pub fn live_read_txn(&self) -> Result<heed::RoTxn<'_, heed::WithTls>> {
        Ok(self.live.read_txn()?)
    }

    pub fn epoch_read_txn(&self) -> Result<heed::RoTxn<'_, heed::WithTls>> {
        Ok(self.epoch.read_txn()?)
    }

    /// 当前 epoch 库实际磁盘占用（data.mdb 大小）。轮转触发阈值（§13.5）。
    pub fn real_disk_size(&self) -> Result<u64> {
        Ok(self.epoch.real_disk_size()?)
    }

    /// epoch 轮转：冻结当前 epoch（保持只读历史），开启下一个 epoch env。
    /// 旧 env 随字段赋值被 drop → munmap → 完整回收其 RSS（M7 实测 drop env 后 RSS 25.9MB→2.2MB）。
    /// 调用方必须在无活事务（commit 后）时调用。
    pub fn rotate_epoch(&mut self) -> Result<u32> {
        let next = self.epoch_num + 1;
        let dir = self.root.join(format!("epoch_{:04}", next));
        let env = open_env(&dir, self.map_size)?;
        let dbs = open_dbis(&env, &EPOCH_DBI_NAMES)?;
        let dbs: [Database<Bytes, Bytes>; NUM_EPOCH_DBIS] = dbs
            .try_into()
            .map_err(|_| anyhow::anyhow!("epoch DBI 数量不匹配"))?;
        self.epoch = env;
        self.epoch_dbs = dbs;
        self.epoch_num = next;
        Ok(next)
    }

    /// 当前 epoch 已满（real_disk_size ≥ epoch_max_bytes）？
    pub fn epoch_should_rotate(&self) -> Result<bool> {
        Ok(self.real_disk_size()? >= self.epoch_max_bytes)
    }

    /// 找出已存在的最高 epoch 序号（无则 0）。
    fn highest_epoch(root: &Path) -> u32 {
        let mut max = 0u32;
        if let Ok(rd) = std::fs::read_dir(root) {
            for e in rd.flatten() {
                let name = e.file_name();
                let Some(s) = name.to_str() else { continue };
                if let Some(rest) = s.strip_prefix("epoch_") {
                    if let Ok(n) = rest.parse::<u32>() {
                        if n >= max {
                            max = n;
                        }
                    }
                }
            }
        }
        max
    }

    // --- 跨库只读辅助（测试/查询便捷） ---

    /// QR_PAIR 主行检索：先 live（在途 PENDING）再当前 epoch（终态）。返回 None 表示两库均无。
    pub fn qr_pair_at(&self, q_first_idx: u64) -> Result<Option<QrPairValue>> {
        let k = k_qr_pair(q_first_idx);
        let lt = self.live_read_txn()?;
        if let Some(v) = self.live_dbs[LIVE_QR_PAIR].get(&lt, &k)? {
            if let Some(p) = QrPairValue::decode(v) {
                return Ok(Some(p));
            }
        }
        drop(lt);
        let et = self.epoch_read_txn()?;
        if let Some(v) = self.epoch_dbs[EPOCH_QR_PAIR].get(&et, &k)? {
            return Ok(QrPairValue::decode(v));
        }
        Ok(None)
    }

    /// QR_PAIR 总数（live 在途 + 当前 epoch 终态；历史 epoch 需另行枚举）。
    pub fn qr_pair_count(&self) -> Result<u64> {
        let lt = self.live_read_txn()?;
        let a = self.live_dbs[LIVE_QR_PAIR].len(&lt)?;
        drop(lt);
        let et = self.epoch_read_txn()?;
        let b = self.epoch_dbs[EPOCH_QR_PAIR].len(&et)?;
        Ok(a + b)
    }
}

/// 枚举 qridx 下全部 epoch_XXXX 目录（升序）。
fn epoch_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(root) {
        for e in rd.flatten() {
            let path = e.path();
            let name = e.file_name();
            if let Some(s) = name.to_str() {
                if s.starts_with("epoch_") {
                    dirs.push(path);
                }
            }
        }
    }
    dirs.sort();
    dirs
}

/// NO_OVERWRITE 幂等写入：键已存在（KeyExist）返回 Ok(false)，否则写入返回 Ok(true)。
/// 回放自愈的核心机制——确定性主键下重放同批记录收敛、零脏数据。
pub fn put_no_overwrite(
    db: &Database<Bytes, Bytes>,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8],
    value: &[u8],
) -> Result<bool> {
    match db.put_with_flags(txn, PutFlags::NO_OVERWRITE, key, value) {
        Ok(()) => Ok(true),
        Err(heed::Error::Mdb(MdbError::KeyExist)) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("sovvault-db-{}-{}", tag, ts));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn key_builders_roundtrip() {
        // QR_PENDING 键（v0.5 含代际）：解码回字段。
        let k = k_qr_pending(0x1122_3344_5566_7788, 0xAB, 0x1234_5678_9ABC);
        assert_eq!(k.len(), 16);
        assert_eq!(&k[0..8], &0x1122_3344_5566_7788u64.to_be_bytes());
        assert_eq!(&k[8..10], &0x00ABu16.to_be_bytes());
        assert_eq!(&k[10..16], &0x1234_5678_9ABCu64.to_be_bytes()[2..8]);
        // 前缀：前 10B 与全键一致。
        let p = k_qr_pending_prefix(0x1122_3344_5566_7788, 0xAB);
        assert_eq!(p.len(), 10);
        assert_eq!(&k[..10], &p[..]);

        let k = k_conn_qr(1, 2, 3);
        assert_eq!(k.len(), 24);
        let k = k_qr_time(1, 2);
        assert_eq!(k.len(), 16);
        let k = k_pending_ttl(1, 2);
        assert_eq!(k.len(), 16);
        assert_eq!(k_conn_state(7), 7u64.to_be_bytes());
        assert_eq!(k_qr_pair(9), 9u64.to_be_bytes());
        assert_eq!(k_packet_qr(5), 5u64.to_be_bytes());
    }

    #[test]
    fn u48_bounds() {
        let mut v = Vec::new();
        put_u48(&mut v, 0xFFFF_FFFF_FFFF);
        assert_eq!(v.len(), 6);
        let mut o = 0;
        assert_eq!(take_u48(&v, &mut o).unwrap(), 0xFFFF_FFFF_FFFF);
        assert_eq!(o, 6);
    }

    #[test]
    fn qr_pending_value_roundtrip() {
        let v = v_qr_pending_encode(100, 200, 300);
        assert_eq!(v_qr_pending_decode(&v).unwrap(), (100, 200, 300));
        assert!(v_qr_pending_decode(&v[..19]).is_none());
    }

    #[test]
    fn secondary_value_roundtrip() {
        assert_eq!(v_secondary_decode(&v_secondary_encode(42)).unwrap(), 42);
        assert!(v_secondary_decode(&[0u8; 7]).is_none());
    }

    #[test]
    fn packet_ttl_value_roundtrip() {
        assert_eq!(v_packet_qr_decode(&v_packet_qr_encode(42)).unwrap(), 42);
        let t = v_pending_ttl_encode(7, 0xABCDEF123456);
        assert_eq!(v_pending_ttl_decode(&t).unwrap(), (7, 0xABCDEF123456));
    }

    #[test]
    fn qr_pair_value_roundtrip() {
        let v = QrPairValue {
            status: QrStatus::Matched as u8,
            conn_hash: 0xDEAD_BEEF,
            q_idx: vec![1, 2, 3],
            r_idx: vec![9, 10, 11, 12],
            req_key: b"GET /foo HTTP/1.1".to_vec(),
            resp_key: b"200 OK".to_vec(),
            abs_q_seq: 0xFFFF_FFFF_FFF0,
            ..Default::default()
        };
        let enc = v.encode();
        let back = QrPairValue::decode(&enc).unwrap();
        assert_eq!(back, v);

        // 截断必须拒绝（防越界读取）。
        assert!(QrPairValue::decode(&enc[..enc.len() - 1]).is_none());
    }

    #[test]
    fn record_ts_codec() {
        let k = k_record_ts(123456789, 0x1122_3344_5566_7788);
        assert_eq!(k.len(), 16);
        assert_eq!(&k[0..8], &123456789u64.to_be_bytes());
        assert_eq!(&k[8..16], &0x1122_3344_5566_7788u64.to_be_bytes());

        let s = RecordSummary {
            proto: 6,
            flags: 0x12,
            src_ip: 0xC0A8_0001,
            dst_ip: 0x0A00_0002,
            sport: 12345,
            dport: 443,
            len: 1024,
        };
        let enc = v_record_summary_encode(&s);
        assert_eq!(enc.len(), 18);
        assert_eq!(v_record_summary_decode(&enc).unwrap(), s);
        assert!(v_record_summary_decode(&enc[..17]).is_none());
    }

    #[test]
    fn put_no_overwrite_idempotent() {
        let dir = tmpdir("nooverwrite");
        let reg = DbRegistry::open(&dir, 10 * 1024 * 1024).unwrap();
        let mut txn = reg.epoch_write_txn().unwrap();
        let k = k_record_ts(1, 2);
        let v = v_record_summary_encode(&RecordSummary::default());
        // 首次写入 → true；同键重复写入 → false（幂等收敛依据）。
        assert!(put_no_overwrite(
            &reg.epoch_dbs()[EPOCH_RECORD_TS],
            &mut txn,
            &k,
            &v
        )
        .unwrap());
        assert!(!put_no_overwrite(
            &reg.epoch_dbs()[EPOCH_RECORD_TS],
            &mut txn,
            &k,
            &v
        )
        .unwrap());
        txn.commit().unwrap();
        let txn = reg.epoch_read_txn().unwrap();
        assert_eq!(
            reg.epoch_dbs()[EPOCH_RECORD_TS].len(&txn).unwrap(),
            1
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn registry_open_dual_env_layout() {
        let dir = tmpdir("dual");
        let root = dir.join("qridx");
        let reg = DbRegistry::open(&root, 10 * 1024 * 1024).unwrap();
        // 目录布局：live/ + epoch_0000/。
        assert!(root.join("live/data.mdb").exists());
        assert!(root.join("epoch_0000/data.mdb").exists());
        assert_eq!(reg.epoch_num(), 0);

        // live 库写 CONN_STATE + QR_PENDING（活状态 DBI）。
        let mut lt = reg.live_write_txn().unwrap();
        let conn = k_conn_state(123);
        reg.live_dbs()[LIVE_CONN_STATE]
            .put(&mut lt, &conn, &[0xAB; 169])
            .unwrap();
        let pending = k_qr_pending(123, 0, 456);
        reg.live_dbs()[LIVE_QR_PENDING]
            .put(&mut lt, &pending, &v_qr_pending_encode(9, 10, 11))
            .unwrap();
        lt.commit().unwrap();

        // epoch 库写 RECORD_TS（历史索引 DBI）。
        let mut et = reg.epoch_write_txn().unwrap();
        reg.epoch_dbs()[EPOCH_RECORD_TS]
            .put(&mut et, &k_record_ts(1, 2), &v_record_summary_encode(&RecordSummary::default()))
            .unwrap();
        et.commit().unwrap();

        let lt = reg.live_read_txn().unwrap();
        let got = reg.live_dbs()[LIVE_CONN_STATE].get(&lt, &conn).unwrap().unwrap();
        assert_eq!(got, &[0xAB; 169][..]);
        let got = reg.live_dbs()[LIVE_QR_PENDING].get(&lt, &pending).unwrap().unwrap();
        assert_eq!(v_qr_pending_decode(got).unwrap(), (9, 10, 11));
        drop(lt);

        let et = reg.epoch_read_txn().unwrap();
        let got = reg.epoch_dbs()[EPOCH_RECORD_TS]
            .get(&et, &k_record_ts(1, 2))
            .unwrap()
            .unwrap();
        assert!(v_record_summary_decode(got).is_some());
        drop(et);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn epoch_rotation_opens_next_and_reclaims() {
        let dir = tmpdir("rotate");
        let root = dir.join("qridx");
        let mut reg = DbRegistry::open_with(&root, 10 * 1024 * 1024, 4 * 1024 * 1024).unwrap();
        assert_eq!(reg.epoch_num(), 0);

        let n = reg.rotate_epoch().unwrap();
        assert_eq!(n, 1);
        assert_eq!(reg.epoch_num(), 1);
        assert!(root.join("epoch_0001/data.mdb").exists());
        // 旧 epoch_0000 保持只读历史（可枚举）。
        let dirs = reg.epoch_dirs();
        assert_eq!(dirs.len(), 2);
        assert_eq!(dirs[0].file_name().unwrap(), "epoch_0000");
        assert_eq!(dirs[1].file_name().unwrap(), "epoch_0001");

        // 历史 epoch 只读打开可枚举全部 DBI。
        let (env, dbs) = open_epoch_read_only(&dirs[0], 10 * 1024 * 1024).unwrap();
        assert_eq!(dbs.len(), NUM_EPOCH_DBIS);
        drop(env);

        // 重启恢复：open 复用最高 epoch。
        drop(reg);
        let reg2 = DbRegistry::open(&root, 10 * 1024 * 1024).unwrap();
        assert_eq!(reg2.epoch_num(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn real_disk_size_tracks_epoch() {
        let dir = tmpdir("rds");
        let reg = DbRegistry::open(&dir, 10 * 1024 * 1024).unwrap();
        // 空 epoch：real_disk_size 应 > 0（LMDB 元数据页）且 < map_size。
        let sz = reg.real_disk_size().unwrap();
        assert!(sz > 0 && sz < 10 * 1024 * 1024);
        assert!(!reg.epoch_should_rotate().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 轮转后旧 epoch 只读重开（QuerySession 同款路径）：先 RW 打开写入 → 轮转丢弃 →
    /// 再重开历史 epoch 必须成功。
    #[test]
    fn historical_epoch_readonly_reopen_after_rotation() {
        let dir = tmpdir("histro");
        let root = dir.join("qridx");
        let reg = DbRegistry::open(&root, 10 * 1024 * 1024).unwrap();

        // 往 epoch_0000 写点数据（模拟已归档历史）。
        {
            let mut et = reg.epoch_write_txn().unwrap();
            reg.epoch_dbs()[EPOCH_RECORD_TS]
                .put(&mut et, &k_record_ts(1, 2), &v_record_summary_encode(&RecordSummary::default()))
                .unwrap();
            et.commit().unwrap();
        }
        let e0 = root.join("epoch_0000");
        drop(reg);

        // 完全关闭后重开历史 epoch_0000（不轮转、纯关闭重开）。QuerySession 同款：
        // env → static txn → 同 txn 内打开 DBI → get。
        let env = open_epoch_env_read_only(&e0, 10 * 1024 * 1024)
            .map_err(|e| anyhow::anyhow!("open fail: {e}"))
            .unwrap();
        let txn = env
            .clone()
            .static_read_txn()
            .map_err(|e| anyhow::anyhow!("rtxn fail: {e}"))
            .unwrap();
        let dbs = open_epoch_dbs_in_txn(&env, &txn)
            .map_err(|e| anyhow::anyhow!("dbi fail: {e}"))
            .unwrap();
        let got = dbs[EPOCH_RECORD_TS]
            .get(&txn, &k_record_ts(1, 2))
            .map_err(|e| anyhow::anyhow!("get fail: {e}"))
            .unwrap()
            .unwrap();
        assert!(v_record_summary_decode(got).is_some());
        drop(txn);
        drop(env);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
