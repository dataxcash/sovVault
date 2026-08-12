//! P5 PCAP 司法级导出 E2E 验收（09 §8.2）：
//! 灌库（BatchPipeline 写 WAL + LMDB）→ `export_pcap`（DBI_RECORD_TS 游标 + 内存 BPF）→
//! `pcap-file` 读回断言：
//!   1. 握手还原：SYN/SYN+ACK 的 tcp_flags、真实 seq/ack/window 逐位保真；
//!   2. 裁切标志：orig_len（线上原始）> incl_len（落盘帧长）→ Wireshark `[Packet size limited]`；
//!   3. BPF 过滤：按 dport/proto/flags 预过滤，命中率精确。

use pcap_file::pcap::PcapReader;
use sov_probe::wal::header::{TCP_ACK, TCP_SYN, WalRecord};
use sov_vault::batch::BatchPipeline;
use sov_vault::db::DbRegistry;
use sov_vault::export::{BpfFilter, L2_ETH, L3_IPV4, L4_TCP, L4_UDP, export_pcap};
use sov_vault::ledger::Ledger;
use sov_vault::qr::QrParams;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
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
    let p = std::env::temp_dir().join(format!("sovvault-p5export-{}-{}", tag, ts));
    let _ = std::fs::remove_dir_all(&p);
    p
}

#[allow(clippy::too_many_arguments)]
fn pkt(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    proto: u16,
    flags: u8,
    ts_ns: u64,
    seq: u32,
    ack: u32,
    window: u16,
    orig_len: u32,
    payload: &[u8],
) -> WalRecord {
    WalRecord {
        timestamp_ns: ts_ns,
        flags: 0,
        tcp_flags: flags,
        tcp_seq: seq,
        tcp_ack: ack,
        window_size: window,
        src_ip: src,
        dst_ip: dst,
        src_port: sport,
        dst_port: dport,
        proto,
        orig_payload_len: orig_len,
        payload: payload.to_vec(),
    }
}

/// 构造握手 + 裁切大请求 + 响应 + 两条 UDP（DNS），灌库后导出。
fn seed(dir: &Path) {
    let ledger = Ledger::open(&dir.join("ledger.db")).unwrap();
    let reg = DbRegistry::open(&dir.join("qridx"), 16 * 1024 * 1024).unwrap();
    let mut pipe = BatchPipeline::new(
        &reg,
        &ledger,
        dir.join("hot"),
        1,
        0,
        64 * 1024,
        100,
        QrParams::default(),
    )
    .unwrap();

    let base = 1_700_000_000_000_000_000u64;
    // 握手（seq/ack/window 真实值）。
    pipe.push_record(pkt(CIP, SIP, CPORT, SPORT, 6, TCP_SYN, base, 1000, 0, 65535, 0, b""))
        .unwrap();
    pipe.push_record(pkt(
        SIP,
        CIP,
        SPORT,
        CPORT,
        6,
        TCP_SYN | TCP_ACK,
        base + 1,
        5000,
        1001,
        8192,
        0,
        b"",
    ))
    .unwrap();
    pipe.push_record(pkt(CIP, SIP, CPORT, SPORT, 6, TCP_ACK, base + 2, 1001, 5001, 65535, 0, b""))
        .unwrap();
    // 裁切请求：orig 线上 2000B，落盘仅 21B（截断）→ [Packet size limited] 场景。
    pipe.push_record(pkt(
        CIP,
        SIP,
        CPORT,
        SPORT,
        6,
        TCP_ACK,
        base + 10,
        1001,
        5001,
        65535,
        2000,
        b"GET /big/file HTTP/1.1",
    ))
    .unwrap();
    // 正常响应。
    pipe.push_record(pkt(
        SIP,
        CIP,
        SPORT,
        CPORT,
        6,
        TCP_ACK,
        base + 20,
        5001,
        1007,
        65535,
        3,
        b"200",
    ))
    .unwrap();
    // 两条 UDP DNS（16B 载荷，orig=incl）。
    pipe.push_record(pkt(CIP, SIP, CPORT, 53, 17, 0, base + 30, 0, 0, 0, 16, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x03\x00\x01"))
        .unwrap();
    pipe.push_record(pkt(SIP, CIP, 53, CPORT, 17, 0, base + 40, 0, 0, 0, 16, b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03\x03\x00\x01"))
        .unwrap();
    pipe.finish().unwrap();
}

struct PcapPacketView {
    orig_len: u32,
    incl_len: usize,
    timestamp_secs: u64,
    tcp_flags: u8,
    seq: u32,
    ack: u32,
    window: u16,
    proto: u8,
    sport: u16,
    dport: u16,
}

/// 读回 pcap 并解析帧头（Ethernet+IPv4+TCP/UDP）。
fn read_back(path: &Path) -> Vec<PcapPacketView> {
    let f = File::open(path).unwrap();
    let mut r = PcapReader::new(BufReader::new(f)).unwrap();
    let mut out = Vec::new();
    while let Some(pkt) = r.next_packet() {
        let pkt = pkt.unwrap();
        let d = &pkt.data;
        let proto = d[L2_ETH + 9];
        let sport = u16::from_be_bytes([d[L2_ETH + L3_IPV4], d[L2_ETH + L3_IPV4 + 1]]);
        let dport = u16::from_be_bytes([
            d[L2_ETH + L3_IPV4 + 2],
            d[L2_ETH + L3_IPV4 + 3],
        ]);
        let (tcp_flags, seq, ack, window) = if proto == 6 {
            let t = L2_ETH + L3_IPV4;
            (
                d[t + 13],
                u32::from_be_bytes([d[t + 4], d[t + 5], d[t + 6], d[t + 7]]),
                u32::from_be_bytes([d[t + 8], d[t + 9], d[t + 10], d[t + 11]]),
                u16::from_be_bytes([d[t + 14], d[t + 15]]),
            )
        } else {
            (0, 0, 0, 0)
        };
        out.push(PcapPacketView {
            orig_len: pkt.orig_len,
            incl_len: d.len(),
            timestamp_secs: pkt.timestamp.as_secs(),
            tcp_flags,
            seq,
            ack,
            window,
            proto,
            sport,
            dport,
        });
    }
    out
}

#[test]
fn e2e_export_handshake_and_truncation_fidelity() {
    let dir = tmpdir("handshake");
    seed(&dir);
    let reg = DbRegistry::open(&dir.join("qridx"), 16 * 1024 * 1024).unwrap();
    let ledger = Ledger::open(&dir.join("ledger.db")).unwrap();
    let out_path = dir.join("export.pcap");

    // 全量导出（7 条：3 握手 + 1 裁切请求 + 1 响应 + 2 UDP）。
    let stats = export_pcap(
        &reg,
        &ledger,
        &BpfFilter::default(),
        None,
        None,
        File::create(&out_path).unwrap(),
    )
    .unwrap();
    assert_eq!(stats.packets, 7);
    assert_eq!(stats.unresolved, 0);

    let pkts = read_back(&out_path);
    assert_eq!(pkts.len(), 7);

    // ① 握手还原：SYN（seq=1000 ack=0）与 SYN+ACK（seq=5000 ack=1001 window=8192）。
    let syn = pkts.iter().find(|p| p.tcp_flags == TCP_SYN).unwrap();
    assert_eq!(syn.seq, 1000);
    assert_eq!(syn.ack, 0);
    assert_eq!(syn.window, 65535);
    assert_eq!(syn.orig_len as usize, L2_ETH + L3_IPV4 + L4_TCP); // 无载荷
    assert_eq!(syn.incl_len, L2_ETH + L3_IPV4 + L4_TCP);
    let synack = pkts
        .iter()
        .find(|p| p.tcp_flags == TCP_SYN | TCP_ACK)
        .unwrap();
    assert_eq!(synack.seq, 5000);
    assert_eq!(synack.ack, 1001);
    assert_eq!(synack.window, 8192);

    // ② 裁切标志：orig_len > incl_len → Wireshark [Packet size limited] 精准出现。
    let truncated = pkts
        .iter()
        .find(|p| p.orig_len as usize == L2_ETH + L3_IPV4 + L4_TCP + 2000)
        .unwrap();
    assert_eq!(
        truncated.incl_len,
        L2_ETH + L3_IPV4 + L4_TCP + b"GET /big/file HTTP/1.1".len()
    );
    assert!(truncated.orig_len > truncated.incl_len as u32, "裁切必须 orig > incl");
    assert_eq!(truncated.seq, 1001);

    // ③ UDP DNS：proto=17、dport/sport=53，orig = 14+20+8+16。
    let dns = pkts.iter().filter(|p| p.proto == 17).collect::<Vec<_>>();
    assert_eq!(dns.len(), 2);
    assert_eq!(dns[0].orig_len as usize, L2_ETH + L3_IPV4 + L4_UDP + 16);
    assert!(dns.iter().all(|p| p.dport == 53 || p.sport == 53));

    // ④ 时间戳秒级保真（ts_ns/1e9）。
    assert!(pkts.iter().all(|p| p.timestamp_secs == 1_700_000_000));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_export_bpf_filter_filters_in_memory() {
    let dir = tmpdir("bpf");
    seed(&dir);
    let reg = DbRegistry::open(&dir.join("qridx"), 16 * 1024 * 1024).unwrap();
    let ledger = Ledger::open(&dir.join("ledger.db")).unwrap();

    // ① 按 proto=6：命中全部 5 条 TCP（握手 + 裁切请求 + 响应），剔除 2 条 UDP。
    let filter = BpfFilter {
        proto: Some(6),
        ..Default::default()
    };
    let mut buf = Vec::new();
    let stats = export_pcap(&reg, &ledger, &filter, None, None, &mut buf).unwrap();
    assert_eq!(stats.packets, 5);
    assert_eq!(stats.filtered, 2);
    // pcap 全局头 magic（LE µs）= D4 C3 B2 A1。
    assert_eq!(&buf[0..4], &[0xD4, 0xC3, 0xB2, 0xA1]);

    // ② 按 dport=443 + proto=6：仅 c2s 请求方 3 条（SYN/ACK/裁切请求）。
    let filter = BpfFilter {
        dport: Some(443),
        proto: Some(6),
        ..Default::default()
    };
    let mut buf = Vec::new();
    let stats = export_pcap(&reg, &ledger, &filter, None, None, &mut buf).unwrap();
    assert_eq!(stats.packets, 3);

    // ③ 按 flags_all=SYN：只保留握手 SYN 与 SYN+ACK 两条。
    let filter = BpfFilter {
        flags_all: Some(TCP_SYN),
        ..Default::default()
    };
    let mut buf = Vec::new();
    let stats = export_pcap(&reg, &ledger, &filter, None, None, &mut buf).unwrap();
    assert_eq!(stats.packets, 2, "仅握手 SYN 与 SYN+ACK");
    assert!(stats.filtered >= 5);

    // ④ 时间窗过滤：起始在响应之后 → 仅 2 条 UDP（base+30/40）。
    let base = 1_700_000_000_000_000_000u64;
    let mut buf = Vec::new();
    let stats = export_pcap(&reg, &ledger, &BpfFilter::default(), Some(base + 25), None, &mut buf)
        .unwrap();
    assert_eq!(stats.packets, 2, "时间窗 [base+25,∞) 仅两条 UDP");

    let _ = std::fs::remove_dir_all(&dir);
}
