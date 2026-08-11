//! 连接热状态：conn_hash 派生（fnv-1a-64 零依赖）+ ConnState 定长布局。
//! 键值规格对齐 09_sovVault_实施方案.md §4.3/§4.5。

/// FNV-1a 64 位偏移基。
const FNV1A64_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a 64 位素因子。
const FNV1A64_PRIME: u64 = 0x0000_0100_0000_01b3;

/// fnv1a64（同一哈希在 8 个 DBI 间一致）。
pub fn fnv1a64(data: &[u8]) -> u64 {
    let mut h = FNV1A64_OFFSET;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(FNV1A64_PRIME);
    }
    h
}

/// conn_key 字节序（17B，BE）：
/// dev_id:u32 | client_ip:u32 | client_port:u16 | server_ip:u32 | server_port:u16 | proto:u8
pub fn conn_key_bytes(
    dev_id: u32,
    client_ip: u32,
    client_port: u16,
    server_ip: u32,
    server_port: u16,
    proto: u8,
) -> [u8; 17] {
    let mut b = [0u8; 17];
    b[0..4].copy_from_slice(&dev_id.to_be_bytes());
    b[4..8].copy_from_slice(&client_ip.to_be_bytes());
    b[8..10].copy_from_slice(&client_port.to_be_bytes());
    b[10..14].copy_from_slice(&server_ip.to_be_bytes());
    b[14..16].copy_from_slice(&server_port.to_be_bytes());
    b[16] = proto;
    b
}

/// 连接键哈希（五元组 + dev_id + proto）。
pub fn conn_hash(
    dev_id: u32,
    client_ip: u32,
    client_port: u16,
    server_ip: u32,
    server_port: u16,
    proto: u8,
) -> u64 {
    let key = conn_key_bytes(
        dev_id,
        client_ip,
        client_port,
        server_ip,
        server_port,
        proto,
    );
    fnv1a64(&key)
}

/// ConnState 状态值枚举（09 §六）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnStateKind {
    SynSent = 0,
    SynRcvd = 1,
    Established = 2,
    Closed = 3,
    Reset = 4,
    Timeout = 5,
    HalfOpen = 6,
    Quarantined = 7,
}

/// anomaly_flags 统一位掩码（08 §4.1 + 09/08 v0.5 检疫扩展）。
pub mod anomaly {
    pub const INCOMPLETE: u32 = 1 << 0;
    pub const RESET: u32 = 1 << 1;
    pub const HALF_OPEN: u32 = 1 << 2;
    pub const QR_UNMATCHED: u32 = 1 << 3;
    pub const SYN_SEEN: u32 = 1 << 4;
    pub const FIN_SEEN: u32 = 1 << 5;
    pub const ZERO_WIN: u32 = 1 << 6;
    pub const RETRANS: u32 = 1 << 7;
    pub const SEQ_GAP: u32 = 1 << 8;
    pub const DEGRADED: u32 = 1 << 9;
    /// L1 超限：未决 Q 数 ≥ qr_pending_budget。
    pub const CONN_QR_FLOOD: u32 = 1 << 10;
    /// L2.5 超限：单连接 OOO 字节持续病态。
    pub const CONN_OOO_FLOOD: u32 = 1 << 11;
}

/// ConnState 定长 Value（09 §4.3 布局，字段自大至小防 padding 浪费）。
/// 序列化总长：8 + 14 + 16 + 32 + 48 + 32 + 21 = 171 字节
/// （ip/port 块 14B = client_ip:4+client_port:2+server_ip:4+server_port:2+proto:1+reserved:1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct ConnState {
    pub state: u8,
    pub reserved0: [u8; 7],
    pub client_ip: u32,
    pub client_port: u16,
    pub server_ip: u32,
    pub server_port: u16,
    pub proto: u8,
    pub reserved1: [u8; 1],
    pub first_ts: u64,
    pub last_ts: u64,
    pub syn_seen: u64,
    pub synack_seen: u64,
    pub fin_seen: u64,
    pub rst_seen: u64,
    pub req_cnt: u64,
    pub resp_cnt: u64,
    pub bytes_c: u64,
    pub bytes_s: u64,
    pub pkts_c: u64,
    pub pkts_s: u64,
    pub abs_seq_c: u64,
    pub abs_seq_s: u64,
    pub consumed_ack_c: u64,
    pub consumed_ack_s: u64,
    pub meta_bind_id: i64,
    pub protocol_hint: u8,
    pub anomaly_flags: u32,
    pub qr_open: u64,
}

/// ConnState 定长序列化长度。
pub const CONN_STATE_SIZE: usize = 171;

impl ConnState {
    /// 全 BE 定长序列化。
    pub fn to_bytes(&self) -> [u8; CONN_STATE_SIZE] {
        let mut b = [0u8; CONN_STATE_SIZE];
        let mut o = 0usize;
        b[o] = self.state;
        o += 8; // state + reserved0[7]
        for v in [self.client_ip, self.server_ip] {
            b[o..o + 4].copy_from_slice(&v.to_be_bytes());
            o += 4;
        }
        for v in [self.client_port, self.server_port] {
            b[o..o + 2].copy_from_slice(&v.to_be_bytes());
            o += 2;
        }
        b[o] = self.proto;
        o += 2; // proto + reserved1[1]
        for v in [
            self.first_ts,
            self.last_ts,
            self.syn_seen,
            self.synack_seen,
            self.fin_seen,
            self.rst_seen,
            self.req_cnt,
            self.resp_cnt,
            self.bytes_c,
            self.bytes_s,
            self.pkts_c,
            self.pkts_s,
            self.abs_seq_c,
            self.abs_seq_s,
            self.consumed_ack_c,
            self.consumed_ack_s,
        ] {
            b[o..o + 8].copy_from_slice(&v.to_be_bytes());
            o += 8;
        }
        b[o..o + 8].copy_from_slice(&self.meta_bind_id.to_be_bytes());
        o += 8;
        b[o] = self.protocol_hint;
        o += 1;
        b[o..o + 4].copy_from_slice(&self.anomaly_flags.to_be_bytes());
        o += 4;
        b[o..o + 8].copy_from_slice(&self.qr_open.to_be_bytes());
        o += 8;
        debug_assert_eq!(o, CONN_STATE_SIZE);
        b
    }

    /// 从定长字节反序列化（长度不符返回 None）。
    pub fn from_bytes(b: &[u8]) -> Option<ConnState> {
        if b.len() != CONN_STATE_SIZE {
            return None;
        }
        let mut o = 0usize;
        let state = b[o];
        o += 8;
        let client_ip = u32::from_be_bytes(b[o..o + 4].try_into().ok()?);
        o += 4;
        let server_ip = u32::from_be_bytes(b[o..o + 4].try_into().ok()?);
        o += 4;
        let client_port = u16::from_be_bytes(b[o..o + 2].try_into().ok()?);
        o += 2;
        let server_port = u16::from_be_bytes(b[o..o + 2].try_into().ok()?);
        o += 2;
        let proto = b[o];
        o += 2;
        let rd = |b_: &[u8], o: &mut usize| -> Option<u64> {
            let v = u64::from_be_bytes(b_[*o..*o + 8].try_into().ok()?);
            *o += 8;
            Some(v)
        };
        let first_ts = rd(b, &mut o)?;
        let last_ts = rd(b, &mut o)?;
        let syn_seen = rd(b, &mut o)?;
        let synack_seen = rd(b, &mut o)?;
        let fin_seen = rd(b, &mut o)?;
        let rst_seen = rd(b, &mut o)?;
        let req_cnt = rd(b, &mut o)?;
        let resp_cnt = rd(b, &mut o)?;
        let bytes_c = rd(b, &mut o)?;
        let bytes_s = rd(b, &mut o)?;
        let pkts_c = rd(b, &mut o)?;
        let pkts_s = rd(b, &mut o)?;
        let abs_seq_c = rd(b, &mut o)?;
        let abs_seq_s = rd(b, &mut o)?;
        let consumed_ack_c = rd(b, &mut o)?;
        let consumed_ack_s = rd(b, &mut o)?;
        let meta_bind_id = i64::from_be_bytes(b[o..o + 8].try_into().ok()?);
        o += 8;
        let protocol_hint = b[o];
        o += 1;
        let anomaly_flags = u32::from_be_bytes(b[o..o + 4].try_into().ok()?);
        o += 4;
        let qr_open = u64::from_be_bytes(b[o..o + 8].try_into().ok()?);
        o += 8;
        debug_assert_eq!(o, CONN_STATE_SIZE);
        Some(ConnState {
            state,
            reserved0: [0u8; 7],
            client_ip,
            client_port,
            server_ip,
            server_port,
            proto,
            reserved1: [0u8; 1],
            first_ts,
            last_ts,
            syn_seen,
            synack_seen,
            fin_seen,
            rst_seen,
            req_cnt,
            resp_cnt,
            bytes_c,
            bytes_s,
            pkts_c,
            pkts_s,
            abs_seq_c,
            abs_seq_s,
            consumed_ack_c,
            consumed_ack_s,
            meta_bind_id,
            protocol_hint,
            anomaly_flags,
            qr_open,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a64_known_vector() {
        // 空串 FNV-1a64 标准结果。
        assert_eq!(fnv1a64(b""), 0xcbf29ce484222325);
        // "a" 的 FNV-1a64。
        assert_eq!(fnv1a64(b"a"), 0xaf63dc4c8601ec8c);
    }

    #[test]
    fn conn_hash_stable() {
        let h1 = conn_hash(1, 0xC0A8_0001, 12345, 0xC0A8_0002, 443, 6);
        let h2 = conn_hash(1, 0xC0A8_0001, 12345, 0xC0A8_0002, 443, 6);
        assert_eq!(h1, h2);
        let h3 = conn_hash(1, 0xC0A8_0001, 12346, 0xC0A8_0002, 443, 6);
        assert_ne!(h1, h3);
        let h4 = conn_hash(2, 0xC0A8_0001, 12345, 0xC0A8_0002, 443, 6);
        assert_ne!(h1, h4);
    }

    #[test]
    fn conn_key_17b_layout() {
        let b = conn_key_bytes(1, 0xC0A8_0001, 12345, 0xC0A8_0002, 443, 6);
        assert_eq!(b.len(), 17);
        assert_eq!(b[0..4], 1u32.to_be_bytes());
        assert_eq!(b[4..8], 0xC0A8_0001u32.to_be_bytes());
        assert_eq!(b[8..10], 12345u16.to_be_bytes());
        assert_eq!(b[10..14], 0xC0A8_0002u32.to_be_bytes());
        assert_eq!(b[14..16], 443u16.to_be_bytes());
        assert_eq!(b[16], 6);
    }

    #[test]
    fn conn_state_roundtrip() {
        let cs = ConnState {
            state: ConnStateKind::Established as u8,
            client_ip: 0xC0A8_0001,
            server_port: 443,
            bytes_c: 123456,
            anomaly_flags: anomaly::SEQ_GAP | anomaly::CONN_OOO_FLOOD,
            qr_open: 7,
            meta_bind_id: -1,
            ..Default::default()
        };
        let b = cs.to_bytes();
        assert_eq!(b.len(), CONN_STATE_SIZE);
        let back = ConnState::from_bytes(&b).unwrap();
        assert_eq!(back, cs);
    }

    #[test]
    fn conn_state_wrong_len_rejected() {
        assert!(ConnState::from_bytes(&[0u8; 168]).is_none());
        assert!(ConnState::from_bytes(&[0u8; 170]).is_none());
    }
}
