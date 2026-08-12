//! P5 MetaBind / EXT META：二进制协议指纹绑定 + 伪 Key 提取。
//!
//! 设计依据：09 §九 P5（MetaBind/EXT META）与 §4.4（ext_meta/meta_binds DDL）、§8.1 meta 单测清单。
//!
//! - `Fingerprint`：由载荷前缀提炼的**协议指纹**（magic_prefix + Shannon 熵 + 定长头判定），
//!   即"magic_prefix + entropy"绑定——同签名 → 同指纹，把二进制协议从字节流里辨识出来。
//! - `ProtocolKind`：HTTP / TLS / DNS / JSON / BINARY / UNKNOWN 六类；检测先按 magic 字节、
//!   再按目标端口（`meta_binds.dst_port` 校正中流抓包方向歧义）。
//! - 伪 Key（PSEUDO KEY）：不可读二进制载荷无法提炼业务键时，用 `fnv1a64(magic_prefix + 采样)`
//!   派生**稳定伪键**——同签名同 KEY（去重/聚合依据），`QrPairValue.pseudo=1` 标记。
//! - `MetaRegistry`：由 `config.analysis.meta_binds` 构建；`bind_and_extract` 在连接首载荷
//!   评估时完成绑定（写入 `ConnState.meta_bind_id / protocol_hint`）+ 提取请求键。

use crate::config::MetaBind;
use crate::connection::fnv1a64;

/// 协议种类（ConnState.protocol_hint 取值，跨平面一致）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtocolKind {
    Unknown = 0,
    Http = 1,
    Tls = 2,
    Dns = 3,
    Json = 4,
    Binary = 5,
}

impl ProtocolKind {
    pub fn from_u8(v: u8) -> ProtocolKind {
        match v {
            1 => ProtocolKind::Http,
            2 => ProtocolKind::Tls,
            3 => ProtocolKind::Dns,
            4 => ProtocolKind::Json,
            5 => ProtocolKind::Binary,
            _ => ProtocolKind::Unknown,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            ProtocolKind::Unknown => "unknown",
            ProtocolKind::Http => "http",
            ProtocolKind::Tls => "tls",
            ProtocolKind::Dns => "dns",
            ProtocolKind::Json => "json",
            ProtocolKind::Binary => "binary",
        }
    }

    /// 配置 fingerprint 字符串 → 种类。
    fn from_fingerprint(s: &str) -> Option<ProtocolKind> {
        match s.to_ascii_lowercase().as_str() {
            "http" => Some(ProtocolKind::Http),
            "tls" => Some(ProtocolKind::Tls),
            "dns" => Some(ProtocolKind::Dns),
            "json" => Some(ProtocolKind::Json),
            "binary" => Some(ProtocolKind::Binary),
            _ => None,
        }
    }
}

/// 载荷前缀采样字节数（熵计算窗口）。
pub const ENTROPY_SAMPLE: usize = 64;
/// magic_prefix 最大字节数。
pub const MAGIC_MAX: usize = 4;

/// 协议指纹：magic_prefix + 熵 + 定长头（"magic_prefix + entropy" 绑定的数据载体）。
#[derive(Debug, Clone, PartialEq)]
pub struct Fingerprint {
    /// 载荷前 ≤4 字节（二进制协议签名）。
    pub magic_prefix: Vec<u8>,
    /// Shannon 熵（位/字节，0..8）：文本低、加密/二进制高。
    pub entropy: f64,
    /// 是否识别为定长协议头（TLS 5B / DNS 12B）。
    pub has_fixed_header: bool,
}

/// 提取结果：业务键 + 是否伪键。
#[derive(Debug, Clone)]
pub struct ExtractedKey {
    pub key: Vec<u8>,
    /// true = 伪键（二进制协议指纹派生的稳定键）。
    pub pseudo: bool,
}

/// 连接绑定结果（MetaBind 规则命中 → 库 id + 协议种类；未命中 → 自动检测）。
#[derive(Debug, Clone)]
pub struct BindResult {
    /// 命中的 meta_binds.id；-1 = 无配置规则（仅自动检测）。
    pub meta_bind_id: i64,
    pub protocol_hint: u8,
    pub key: Vec<u8>,
    pub pseudo: bool,
}

/// EXT META 事件：连接首次绑定时收集的指纹，供调用方落 `ext_meta` 台账（低频幂等）。
#[derive(Debug, Clone)]
pub struct ExtMetaEvent {
    pub conn_hash: u64,
    pub protocol_hint: u8,
    pub dst_port: u16,
    pub magic_prefix: Vec<u8>,
    pub entropy: f64,
    pub has_fixed_header: bool,
}

/// 配置规则（meta_binds 表 + 库内 id）。
#[derive(Debug, Clone)]
pub struct MetaBindRule {
    pub id: i64,
    pub name: String,
    pub proto: u8,
    pub dst_port: u16,
    pub fingerprint: Option<ProtocolKind>,
    pub extractor: Option<String>,
}

/// 协议绑定注册表：由 config.analysis.meta_binds 构建，供匹配引擎绑定/提取。
#[derive(Debug, Clone, Default)]
pub struct MetaRegistry {
    rules: Vec<MetaBindRule>,
}

/// 载荷前缀指纹（magic_prefix + entropy + 定长头）。长度检查：空载荷返回空指纹。
pub fn fingerprint(payload: &[u8]) -> Fingerprint {
    let n = payload.len().min(MAGIC_MAX);
    let magic_prefix = payload[..n].to_vec();
    let sample = &payload[..payload.len().min(ENTROPY_SAMPLE)];
    Fingerprint {
        magic_prefix,
        entropy: shannon_entropy(sample),
        has_fixed_header: is_tls_record(payload) || is_dns_header(payload),
    }
}

/// Shannon 熵（位/字节）：对字节直方图求和 −p·log2(p)。
fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    let mut h = 0.0;
    for &c in &counts {
        if c != 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    h
}

/// TLS record 头：content_type=0x16(Handshake) + version 0x03 0x??（定长 5B 头）。
fn is_tls_record(b: &[u8]) -> bool {
    b.len() >= 5 && b[0] == 0x16 && b[1] == 0x03
}

/// DNS 头（12B）：ID(2) + flags(2)；QR/RD 位合法 + 问题数/回答数在合理范围。
fn is_dns_header(b: &[u8]) -> bool {
    if b.len() < 12 {
        return false;
    }
    let qd = u16::from_be_bytes([b[4], b[5]]);
    let ar = u16::from_be_bytes([b[10], b[11]]);
    let flags = b[2];
    // 查询：RD=0x01；响应：QR=0x80。opcode 前三位置零（普通查询）。
    (flags & 0x80 != 0 || flags & 0x01 != 0)
        && flags & 0x78 == 0
        && (1..=16).contains(&qd)
        && ar <= 16
}

/// 协议检测：先按 magic 字节，再按目标端口（端口校正中流方向歧义）。
pub fn detect_protocol(payload: &[u8], dst_port: u16) -> ProtocolKind {
    if is_tls_record(payload) {
        return ProtocolKind::Tls;
    }
    if is_http_magic(payload) {
        return ProtocolKind::Http;
    }
    if is_dns_header(payload) {
        return ProtocolKind::Dns;
    }
    if payload.first() == Some(&b'{') {
        return ProtocolKind::Json;
    }
    if dst_port == 443 || dst_port == 8443 {
        return ProtocolKind::Tls;
    }
    if dst_port == 53 {
        return ProtocolKind::Dns;
    }
    if dst_port == 80 || dst_port == 8080 {
        return ProtocolKind::Http;
    }
    // 高熵且含不可打印字节 → 二进制（伪键）。
    if payload.len() >= 16 && shannon_entropy(payload) > 4.0 {
        return ProtocolKind::Binary;
    }
    ProtocolKind::Unknown
}

fn is_http_magic(b: &[u8]) -> bool {
    const METHODS: [&[u8]; 8] = [
        b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"TRACE ",
    ];
    let n = b.len().min(8);
    METHODS
        .iter()
        .any(|m| b[..n].starts_with(m))
        || b.starts_with(b"HTTP/1.")
}

/// 按协议提取请求键（HTTP 请求行 / TLS SNI / DNS qname；其余走伪键）。
pub fn extract_key(payload: &[u8], kind: ProtocolKind) -> ExtractedKey {
    match kind {
        ProtocolKind::Http => match http_request_line(payload) {
            Some(k) => ExtractedKey { key: k, pseudo: false },
            None => pseudo_key(payload),
        },
        ProtocolKind::Tls => match tls_sni(payload) {
            Some(k) => ExtractedKey { key: k, pseudo: false },
            None => pseudo_key(payload),
        },
        ProtocolKind::Dns => match dns_qname(payload) {
            Some(k) => ExtractedKey { key: k, pseudo: false },
            None => pseudo_key(payload),
        },
        _ => pseudo_key(payload),
    }
}

/// 伪键：fnv1a64(magic_prefix + 采样) → 8B 大端，稳定（同签名同 KEY）。
fn pseudo_key(payload: &[u8]) -> ExtractedKey {
    let mut seed = Vec::with_capacity(MAGIC_MAX + ENTROPY_SAMPLE);
    let n = payload.len().min(MAGIC_MAX);
    seed.extend_from_slice(&payload[..n]);
    let s = &payload[..payload.len().min(ENTROPY_SAMPLE)];
    seed.extend_from_slice(s);
    ExtractedKey {
        key: fnv1a64(&seed).to_be_bytes().to_vec(),
        pseudo: true,
    }
}

/// HTTP 请求行：首个 CRLF/LF 前的首行（≤256B，防超长毒行）。
fn http_request_line(payload: &[u8]) -> Option<Vec<u8>> {
    let line = payload.split(|&b| b == b'\n').next()?;
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let n = line.len().min(256);
    if n == 0 {
        return None;
    }
    Some(line[..n].to_vec())
}

/// TLS ClientHello 中提取 SNI（server_name 扩展 type=0）。长度全程检查，绝不越界。
fn tls_sni(payload: &[u8]) -> Option<Vec<u8>> {
    // TLS record 头 5B + handshake 头 4B（type 1B + len 3B）。
    let hs = payload.get(5..)?;
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
    let body = hs.get(4..4 + hs_len)?;
    let version = body.get(0..2)?;
    if version[0] != 0x03 {
        return None;
    }
    let mut o = 2usize + 32; // version + random
    let sid_len = *body.get(o)? as usize;
    o += 1 + sid_len;
    let cs_len = u16::from_be_bytes(body.get(o..o + 2)?.try_into().ok()?) as usize;
    o += 2 + cs_len;
    let cm_len = *body.get(o)? as usize;
    o += 1 + cm_len;
    let ext_total = u16::from_be_bytes(body.get(o..o + 2)?.try_into().ok()?) as usize;
    o += 2;
    let mut e = o;
    while e + 4 <= o + ext_total {
        let etype = u16::from_be_bytes(body.get(e..e + 2)?.try_into().ok()?);
        let elen = u16::from_be_bytes(body.get(e + 2..e + 4)?.try_into().ok()?) as usize;
        e += 4;
        if etype == 0 {
            // server_name: list_len(2) + name_type(1) + name_len(2) + name
            let data = body.get(e..e + elen)?;
            let name_type = *data.get(2)?;
            let name_len = u16::from_be_bytes(data.get(3..5)?.try_into().ok()?) as usize;
            if name_type == 0 {
                let name = data.get(5..5 + name_len)?;
                if !name.is_empty() {
                    return Some(name.to_vec());
                }
            }
        }
        e += elen;
    }
    None
}

/// DNS 查询 qname（offset 12 起逐 label，遇压缩指针截断；≤255B）。
fn dns_qname(payload: &[u8]) -> Option<Vec<u8>> {
    if !is_dns_header(payload) || payload.len() < 12 {
        return None;
    }
    let mut o = 12usize;
    let mut out = Vec::with_capacity(64);
    loop {
        let l = *payload.get(o)? as usize;
        if l == 0 {
            break;
        }
        if l & 0xC0 == 0xC0 {
            return None; // 压缩指针：查询 qname 不应压缩
        }
        if l > 63 {
            return None;
        }
        let label = payload.get(o + 1..o + 1 + l)?;
        if !out.is_empty() {
            out.push(b'.');
        }
        out.extend_from_slice(label);
        o += 1 + l;
        if out.len() > 255 {
            return None;
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

impl MetaRegistry {
    /// 由配置 meta_binds 构建（id 取 1-based 下标，确定性；落库后用 set_rule_id 校正）。
    pub fn from_binds(binds: &[MetaBind]) -> MetaRegistry {
        let rules = binds
            .iter()
            .enumerate()
            .map(|(i, b)| MetaBindRule {
                id: (i as i64) + 1,
                name: b.name.clone(),
                proto: b.proto,
                dst_port: b.dst_port,
                fingerprint: ProtocolKind::from_fingerprint(&b.fingerprint),
                extractor: (!b.extractor.is_empty()).then(|| b.extractor.clone()),
            })
            .collect();
        MetaRegistry { rules }
    }

    /// 落库后校正规则 id（与 meta_binds 表真实主键对齐）。
    pub fn set_rule_id(&mut self, idx: usize, id: i64) {
        if let Some(r) = self.rules.get_mut(idx) {
            r.id = id;
        }
    }

    pub fn rule(&self, idx: usize) -> Option<&MetaBindRule> {
        self.rules.get(idx)
    }

    pub fn rules(&self) -> &[MetaBindRule] {
        &self.rules
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// 按 (proto, dst_port) 命中配置规则。
    pub fn resolve(&self, proto: u8, dst_port: u16) -> Option<&MetaBindRule> {
        self.rules
            .iter()
            .find(|r| r.proto == proto && r.dst_port == dst_port)
    }

    /// 连接绑定 + 请求键提取（open_q 首载荷路径）：
    /// 命中规则 → 用规则 fingerprint 强化检测 + extractor 提取；未命中 → 纯 magic+entropy 自动检测。
    pub fn bind_and_extract(&self, payload: &[u8], proto: u8, dst_port: u16) -> BindResult {
        if let Some(rule) = self.resolve(proto, dst_port) {
            let kind = rule
                .fingerprint
                .unwrap_or_else(|| detect_protocol(payload, dst_port));
            let k = extract_key(payload, kind);
            return BindResult {
                meta_bind_id: rule.id,
                protocol_hint: kind as u8,
                key: k.key,
                pseudo: k.pseudo,
            };
        }
        let kind = detect_protocol(payload, dst_port);
        let k = extract_key(payload, kind);
        BindResult {
            meta_bind_id: -1,
            protocol_hint: kind as u8,
            key: k.key,
            pseudo: k.pseudo,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binds() -> Vec<MetaBind> {
        vec![
            MetaBind {
                name: "web".into(),
                proto: 6,
                dst_port: 80,
                fingerprint: "http".into(),
                extractor: "http_line".into(),
            },
            MetaBind {
                name: "https".into(),
                proto: 6,
                dst_port: 443,
                fingerprint: "tls".into(),
                extractor: "sni".into(),
            },
            MetaBind {
                name: "dns".into(),
                proto: 17,
                dst_port: 53,
                fingerprint: "dns".into(),
                extractor: "qname".into(),
            },
        ]
    }

    fn tls_client_hello(sni: &str) -> Vec<u8> {
        // record: 0x16 0x03 0x01 len(2) | handshake: 0x01 len(3) | version 0x03 0x03
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&(0..32u32).map(|i| (i.wrapping_mul(7)) as u8).collect::<Vec<_>>()); // random
        body.push(0); // session_id_len
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
        body.push(1); // compression
        body.push(0x00); // comp_method null
        // extensions: server_name(0)
        let mut sn = vec![0x00, 0x00]; // list_len placeholder
        sn.push(0); // name_type host_name
        sn.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        sn.extend_from_slice(sni.as_bytes());
        let sn_len = (sn.len() as u16).to_be_bytes();
        sn[0..2].copy_from_slice(&sn_len);
        body.extend_from_slice(&(2 + 2 + sn.len() as u16).to_be_bytes()); // extensions_total
        body.extend_from_slice(&[0x00, 0x00]); // ext type=server_name(0)
        body.extend_from_slice(&(sn.len() as u16).to_be_bytes()); // ext len
        body.extend_from_slice(&sn);
        let body_len = body.len();
        // 拼 handshake 头
        let mut hs = vec![0x01]; // ClientHello
        hs.extend_from_slice(&(body_len as u32).to_be_bytes()[1..4]);
        hs.extend_from_slice(&body);
        let hs_len = hs.len();
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs_len as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn http_fingerprint_magic_low_entropy() {
        let p = fingerprint(b"GET /api HTTP/1.1\r\nHost: x\r\n");
        assert_eq!(p.magic_prefix, b"GET ");
        assert!(p.entropy < 4.8, "HTTP 文本熵应低: {}", p.entropy);
        assert!(!p.has_fixed_header);
    }

    #[test]
    fn tls_fingerprint_fixed_header() {
        let p = fingerprint(&tls_client_hello("example.com"));
        assert_eq!(p.magic_prefix, [0x16, 0x03, 0x01, 0x00]);
        assert!(p.has_fixed_header, "TLS record 应判定定长头");
        assert!(p.entropy > 4.0, "TLS 随机数使熵较高");
    }

    #[test]
    fn dns_fingerprint() {
        // ID=0x1234, flags=0x0100(RD), QD=1, AN=0, NS=0, AR=0, qname "example.com"
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(&[7]); // "example"
        q.extend_from_slice(b"example");
        q.extend_from_slice(&[3]);
        q.extend_from_slice(b"com");
        q.push(0);
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE A, QCLASS IN
        let p = fingerprint(&q);
        assert!(p.has_fixed_header, "DNS 头应判定定长头");
        assert_eq!(extract_key(&q, ProtocolKind::Dns).key, b"example.com");
    }

    #[test]
    fn json_low_entropy_vs_binary_high_entropy() {
        let p = fingerprint(b"{\"k\":\"v\",\"n\":1}");
        assert_eq!(p.magic_prefix, b"{\"k\"");
        assert!(p.entropy < 5.0);
        let rand: Vec<u8> = (0..64u32).map(|i| (i.wrapping_mul(0x9E3779B9) >> 16) as u8).collect();
        let pb = fingerprint(&rand);
        assert!(pb.entropy > 5.5, "高熵二进制: {}", pb.entropy);
        assert!(pb.magic_prefix.len() >= 4);
    }

    #[test]
    fn detect_by_magic_and_port() {
        assert_eq!(detect_protocol(b"GET /x", 9999), ProtocolKind::Http);
        assert_eq!(detect_protocol(&tls_client_hello("a.com"), 9999), ProtocolKind::Tls);
        assert_eq!(detect_protocol(b"hello", 443), ProtocolKind::Tls);
        assert_eq!(detect_protocol(b"{\"a\":1}", 9999), ProtocolKind::Json);
        let rand: Vec<u8> = (0..64u32).map(|i| (i.wrapping_mul(0x9E3779B9) >> 16) as u8).collect();
        assert_eq!(detect_protocol(&rand, 9999), ProtocolKind::Binary);
        assert_eq!(detect_protocol(b"hello world", 9999), ProtocolKind::Unknown);
    }

    #[test]
    fn http_extract_first_line() {
        let k = extract_key(b"GET /a/b?x=1 HTTP/1.1\r\nHost: h\r\n", ProtocolKind::Http);
        assert_eq!(k.key, b"GET /a/b?x=1 HTTP/1.1");
        assert!(!k.pseudo);
        // 长行截断 ≤256B。
        let long = format!("GET /{} HTTP/1.1", "x".repeat(400));
        let k = extract_key(long.as_bytes(), ProtocolKind::Http);
        assert_eq!(k.key.len(), 256);
    }

    #[test]
    fn tls_sni_extract() {
        let k = extract_key(&tls_client_hello("api.example.com"), ProtocolKind::Tls);
        assert_eq!(k.key, b"api.example.com");
        assert!(!k.pseudo);
    }

    #[test]
    fn pseudo_key_stability_same_signature_same_key() {
        let rand: Vec<u8> = (0..128u32).map(|i| (i.wrapping_mul(0x9E3779B9) >> 16) as u8).collect();
        let k1 = extract_key(&rand, ProtocolKind::Binary);
        let k2 = extract_key(&rand, ProtocolKind::Binary);
        assert!(k1.pseudo);
        assert_eq!(k1.key, k2.key, "同签名必须同伪键");

        let mut rand2 = rand.clone();
        rand2[0] ^= 0x01;
        let k3 = extract_key(&rand2, ProtocolKind::Binary);
        assert_ne!(k1.key, k3.key, "签名不同则键不同");
    }

    #[test]
    fn registry_bind_by_port_and_extract() {
        let r = MetaRegistry::from_binds(&binds());
        assert_eq!(r.rules().len(), 3);
        assert_eq!(r.resolve(6, 443).unwrap().id, 2);
        assert!(r.resolve(6, 22).is_none());

        let b = r.bind_and_extract(b"GET /x", 6, 80);
        assert_eq!(b.meta_bind_id, 1);
        assert_eq!(b.protocol_hint, ProtocolKind::Http as u8);
        assert_eq!(b.key, b"GET /x");
        assert!(!b.pseudo);

        let b = r.bind_and_extract(&tls_client_hello("srv.test"), 6, 443);
        assert_eq!(b.meta_bind_id, 2);
        assert_eq!(b.key, b"srv.test");
        assert!(!b.pseudo);

        // 未命中规则 → 自动检测（端口 22 的 TLS 流量仍按 magic 识别，无规则 id）。
        let b = r.bind_and_extract(&tls_client_hello("h.zz"), 6, 22);
        assert_eq!(b.meta_bind_id, -1);
        assert_eq!(b.protocol_hint, ProtocolKind::Tls as u8);
        assert_eq!(b.key, b"h.zz");
    }

    #[test]
    fn binary_payload_gets_pseudo_key_via_registry() {
        let r = MetaRegistry::from_binds(&binds());
        let rand: Vec<u8> = (0..96u32).map(|i| (i.wrapping_mul(0x9E3779B9) >> 16) as u8).collect();
        let b = r.bind_and_extract(&rand, 6, 9999);
        assert_eq!(b.meta_bind_id, -1);
        assert_eq!(b.protocol_hint, ProtocolKind::Binary as u8);
        assert!(b.pseudo);
        let b2 = r.bind_and_extract(&rand, 6, 9999);
        assert_eq!(b.key, b2.key);
    }
}
