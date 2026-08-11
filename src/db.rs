//! LMDB 索引平面：8 DBI 注册表 + 键值大端编解码。
//! 键值规格对齐 09_sovVault_实施方案.md §4.2（键一律大端）。

use anyhow::Result;
use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions};
use std::path::Path;

/// 8 DBI 名称（09 §4.2 表格顺序）。
pub const DBI_CONN_STATE: &str = "conn_state";
pub const DBI_QR_PAIR: &str = "qr_pair";
pub const DBI_QR_PENDING: &str = "qr_pending";
pub const DBI_CONN_QR: &str = "conn_qr";
pub const DBI_QR_KEY: &str = "qr_key";
pub const DBI_QR_TIME: &str = "qr_time";
pub const DBI_PACKET_QR: &str = "packet_qr";
pub const DBI_PENDING_TTL: &str = "pending_ttl";

pub const NUM_DBIS: usize = 8;
const DBI_NAMES: [&str; NUM_DBIS] = [
    DBI_CONN_STATE,
    DBI_QR_PAIR,
    DBI_QR_PENDING,
    DBI_CONN_QR,
    DBI_QR_KEY,
    DBI_QR_TIME,
    DBI_PACKET_QR,
    DBI_PENDING_TTL,
];

/// QrStatus 枚举（09 §4.2，跨 DBI 一致）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// QR_PENDING: [conn_hash:u64][abs_q_end:u48]
pub fn k_qr_pending(conn_hash: u64, abs_q_end: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(14);
    put_u64(&mut v, conn_hash);
    put_u48(&mut v, abs_q_end);
    v
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

// --- CONN_QR/QR_KEY/QR_TIME Value：status:u8（单字节） ---

pub fn v_status_encode(status: QrStatus) -> [u8; 1] {
    [status as u8]
}

pub fn v_status_decode(b: &[u8]) -> Option<QrStatus> {
    if b.len() != 1 {
        return None;
    }
    QrStatus::from_u8(b[0])
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
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

// --- LMDB 环境与 8 DBI 注册表 ---

pub struct DbRegistry {
    env: Env,
    pub dbs: [Database<Bytes, Bytes>; NUM_DBIS],
}

impl DbRegistry {
    pub fn open(dir: &Path, map_size: usize) -> Result<DbRegistry> {
        std::fs::create_dir_all(dir)?;
        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(map_size)
                .max_dbs(16)
                .open(dir)?
        };
        let mut txn = env.write_txn()?;
        let mut dbs: Vec<Database<Bytes, Bytes>> = Vec::with_capacity(NUM_DBIS);
        for name in DBI_NAMES.iter() {
            dbs.push(env.create_database::<Bytes, Bytes>(&mut txn, Some(name))?);
        }
        txn.commit()?;
        let dbs: [Database<Bytes, Bytes>; NUM_DBIS] = dbs
            .try_into()
            .map_err(|_| anyhow::anyhow!("DBI 数量不匹配"))?;
        Ok(DbRegistry { env, dbs })
    }

    pub fn env(&self) -> &Env {
        &self.env
    }

    pub fn write_txn(&self) -> Result<heed::RwTxn<'_>> {
        Ok(self.env.write_txn()?)
    }

    pub fn read_txn(&self) -> Result<heed::RoTxn<'_, heed::WithTls>> {
        Ok(self.env.read_txn()?)
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
        // QR_PENDING 键：解码回字段。
        let k = k_qr_pending(0x1122_3344_5566_7788, 0x1234_5678_9ABC);
        assert_eq!(k.len(), 14);
        assert_eq!(&k[0..8], &0x1122_3344_5566_7788u64.to_be_bytes());
        assert_eq!(&k[8..14], &0x1234_5678_9ABCu64.to_be_bytes()[2..8]);

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
    fn status_value_roundtrip() {
        for s in [
            QrStatus::Pending,
            QrStatus::Matched,
            QrStatus::Timeout,
            QrStatus::Unmatched,
            QrStatus::RstAbort,
            QrStatus::AbortedResource,
        ] {
            assert_eq!(v_status_decode(&v_status_encode(s)).unwrap(), s);
        }
        assert!(v_status_decode(&[9]).is_none());
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
    fn registry_open_all_dbis_and_roundtrip() {
        let dir = tmpdir("registry");
        let reg = DbRegistry::open(&dir, 10 * 1024 * 1024).unwrap();

        let mut txn = reg.write_txn().unwrap();
        let conn = k_conn_state(123);
        reg.dbs[0].put(&mut txn, &conn, &[0xAB; 169]).unwrap();
        let pending = k_qr_pending(123, 456);
        reg.dbs[2]
            .put(&mut txn, &pending, &v_qr_pending_encode(9, 10, 11))
            .unwrap();
        txn.commit().unwrap();

        let txn = reg.read_txn().unwrap();
        let got = reg.dbs[0].get(&txn, &conn).unwrap().unwrap();
        assert_eq!(got, &[0xAB; 169][..]);
        let got = reg.dbs[2].get(&txn, &pending).unwrap().unwrap();
        assert_eq!(v_qr_pending_decode(got).unwrap(), (9, 10, 11));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
