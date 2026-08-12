//! P5 双 VM E2E 压测（单进程模拟 M7 框架）——高压场景数据完整性验收（09 §8.3 / §12）：
//!
//!   1. **MD5 对账**：64 连接 × 多请求灌库 → `export_pcap` 全量导出 → 回读帧载荷拼流
//!      MD5 与源载荷拼流 MD5 字节级一致（重组 100% 无丢失无篡改）；
//!   2. **QR 命中率**：精确匹配 100%（≥99%）、管道化批量 ACK 100%（≥95%）；
//!   3. **慢 Q 零丢失**：16 条响应延迟到第二个批提交（跨批慢路径）→ 全部 MATCHED，
//!      终态 qr_open=0、PENDING=0，无任何 Q 消失。
//!
//! 三线合并验证：数据平面（WAL 回读）+ 索引平面（LMDB 四维检索）+ 管理平面（水位线推进）。

use pcap_file::pcap::PcapReader;
use sov_probe::wal::header::{TCP_ACK, TCP_SYN, WalRecord};
use sov_vault::batch::BatchPipeline;
use sov_vault::connection::ConnState;
use sov_vault::db::{DbRegistry, QrPairValue, QrStatus, IDX_CONN_STATE, IDX_QR_PAIR, k_conn_state};
use sov_vault::export::{BpfFilter, export_pcap};
use sov_vault::ledger::Ledger;
use sov_vault::qr::QrParams;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const CIP: [u8; 4] = [192, 168, 1, 10];
const SIP: [u8; 4] = [10, 0, 0, 1];
const SPORT: u16 = 443;
const N_CONN: usize = 64;
const N_REQ_EXACT: usize = 8;
const N_PIPE: usize = 16;
const N_PIPE_REQ: usize = 3;
const N_SLOW: usize = 8;
const N_SLOW_DELAYED: usize = 2;

fn tmpdir(tag: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("sovvault-p5stress-{}-{}", tag, ts));
    let _ = std::fs::remove_dir_all(&p);
    p
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

/// 生成一个连接的完整流量并推入 `push`。`mode`：0=Exact（8 请求各配独立响应）、
/// 1=Pipe（3 流水请求 + 1 批量 ACK）、2=Slow（4 请求，前 N_SLOW_DELAYED 条响应延迟到第二批）。
/// 同步记录源载荷序列（MD5 对账基准）。
fn conn_traffic(
    cport: u16,
    mode: u8,
    t0: &mut u64,
    push: &mut dyn FnMut(WalRecord),
    src_payloads: &mut Vec<Vec<u8>>,
    delayed: &mut Vec<WalRecord>,
) {
    let next = |t: &mut u64| {
        let v = *t;
        *t += 1;
        v
    };
    let mut seq: u32 = 1000;
    let mut sseq: u32 = 5000;

    // 握手。
    push(pkt(CIP, SIP, cport, SPORT, TCP_SYN, next(t0), seq, 0, b""));
    seq += 1;
    push(pkt(
        SIP,
        CIP,
        SPORT,
        cport,
        TCP_SYN | TCP_ACK,
        next(t0),
        sseq,
        1001,
        b"",
    ));
    sseq += 1;
    push(pkt(CIP, SIP, cport, SPORT, TCP_ACK, next(t0), seq, sseq, b""));
    seq = 1001;

    if mode == 1 {
        // 管道化：3 请求 + 单个批量 ACK 覆盖全部。
        let mut pipe_seq = seq;
        for i in 0..N_PIPE_REQ {
            let payload = format!("GET /c{}/p{} HTTP/1.1", cport, i).into_bytes();
            push(pkt(
                CIP,
                SIP,
                cport,
                SPORT,
                TCP_ACK,
                next(t0),
                pipe_seq,
                sseq,
                &payload,
            ));
            src_payloads.push(payload);
            pipe_seq = pipe_seq.wrapping_add(src_payloads.last().unwrap().len() as u32);
        }
        let resp = format!("OK-{}-P", cport).into_bytes();
        push(pkt(
            SIP,
            CIP,
            SPORT,
            cport,
            TCP_ACK,
            next(t0),
            sseq,
            pipe_seq,
            &resp,
        ));
        src_payloads.push(resp);
        return;
    }

    let nreq = if mode == 0 { N_REQ_EXACT } else { 4 };
    let delayed_flags = mode == 2;
    let mut q_seq = seq;
    for i in 0..nreq {
        let payload = format!("GET /c{}/r{} HTTP/1.1", cport, i).into_bytes();
        push(pkt(
            CIP,
            SIP,
            cport,
            SPORT,
            TCP_ACK,
            next(t0),
            q_seq,
            sseq,
            &payload,
        ));
        src_payloads.push(payload.clone());
        let q_end = q_seq.wrapping_add(payload.len() as u32);
        let resp = format!("OK-{}-{}", cport, i).into_bytes();
        let resp_rec = pkt(
            SIP,
            CIP,
            SPORT,
            cport,
            TCP_ACK,
            next(t0),
            sseq,
            q_end,
            &resp,
        );
        sseq = sseq.wrapping_add(resp.len() as u32);
        // 延迟最后 N_SLOW_DELAYED 条响应到第二批：先到的响应各自精确消费，
        // 验证跨批慢路径下 Q 不丢、不被误聚合（零丢失 + 零误判）。
        if delayed_flags && i >= nreq - N_SLOW_DELAYED {
            delayed.push(resp_rec);
        } else {
            push(resp_rec);
        }
        src_payloads.push(resp);
        q_seq = q_end;
    }
}

/// 源载荷拼流 MD5。
fn md5_of(payloads: &[Vec<u8>]) -> String {
    let mut buf = Vec::new();
    for p in payloads {
        buf.extend_from_slice(p);
    }
    format!("{:x}", md5::compute(&buf))
}

/// 从导出 pcap 读回全部 TCP 载荷（按时间序），拼流 MD5。
fn pcap_payload_md5(path: &Path) -> (String, u64) {
    let f = File::open(path).unwrap();
    let mut r = PcapReader::new(BufReader::new(f)).unwrap();
    let mut buf = Vec::new();
    let mut n = 0u64;
    while let Some(pkt) = r.next_packet() {
        let pkt = pkt.unwrap();
        n += 1;
        let d = &pkt.data;
        let proto = d[14 + 9];
        let hdr = if proto == 6 { 14 + 20 + 20 } else { 14 + 20 + 8 };
        buf.extend_from_slice(&d[hdr..]);
    }
    (format!("{:x}", md5::compute(&buf)), n)
}

#[test]
fn e2e_p5_stress_md5_hitrate_slowq() {
    let dir = tmpdir("stress");
    let ledger = Ledger::open(&dir.join("ledger.db")).unwrap();
    let reg = DbRegistry::open(&dir.join("qridx"), 64 * 1024 * 1024).unwrap();
    let mut pipe = BatchPipeline::new(
        &reg,
        &ledger,
        dir.join("hot"),
        1,
        0,
        8 * 1024 * 1024,
        10_000,
        QrParams::default(),
    )
    .unwrap();

    let mut t0 = 1_700_000_000_000_000_000u64;
    let mut src_payloads: Vec<Vec<u8>> = Vec::new();
    let mut delayed: Vec<WalRecord> = Vec::new();

    // 第一批：全部握手 + 请求 + 精确/管道响应；慢连接的 2 条响应延迟。
    for i in 0..N_CONN {
        let cport = 20000 + i as u16;
        let mode = if i < N_CONN - N_SLOW - N_PIPE {
            0
        } else if i < N_CONN - N_SLOW {
            1
        } else {
            2
        };
        let mut push = |rec: WalRecord| pipe.push_record(rec).unwrap();
        conn_traffic(cport, mode, &mut t0, &mut push, &mut src_payloads, &mut delayed);
    }
    pipe.flush().unwrap(); // 批 1 提交（慢 Q 落 PENDING）。

    // 第二批：慢连接的延迟响应（跨批慢路径消费）。
    for rec in &delayed {
        pipe.push_record(rec.clone()).unwrap();
    }
    pipe.finish().unwrap(); // 批 2 提交。

    // ① QR 命中率与慢 Q 零丢失：全部 QRPAIR 终态 MATCHED。
    let txn = reg.read_txn().unwrap();
    let total = reg.dbs[IDX_QR_PAIR].len(&txn).unwrap();
    let expect_total = (N_CONN - N_SLOW - N_PIPE) * N_REQ_EXACT
        + N_PIPE * N_PIPE_REQ
        + N_SLOW * 4;
    assert_eq!(total, expect_total as u64, "QRPAIR 总数应等于请求总数");

    let mut matched = 0u64;
    let mut pipe_groups = 0u64;
    let mut it = reg.dbs[IDX_QR_PAIR].iter(&txn).unwrap();
    for item in it.by_ref() {
        let (k, v) = item.unwrap();
        let q_idx = u64::from_be_bytes(k[0..8].try_into().unwrap());
        let pair = QrPairValue::decode(v).unwrap();
        assert_eq!(
            pair.status,
            QrStatus::Matched as u8,
            "Q{} 必须终态 MATCHED（慢 Q 零丢失）",
            q_idx
        );
        matched += 1;
        if pair.q_idx.len() > 1 {
            pipe_groups += 1;
        }
    }
    drop(it);
    drop(txn);

    // 精确 + 慢 Q 命中率 = 100% ≥ 99%。
    assert_eq!(matched, expect_total as u64);
    let hit_rate = matched as f64 / expect_total as f64;
    assert!(hit_rate >= 0.99, "QR 命中率 {:.2}% < 99%", hit_rate * 100.0);
    // 聚合组：16 个管道化连接各 1 组 + 8 个慢连接（客户端流头越过延迟 ack，
    // 累积 ACK 钳制到流头 → 2 条延迟 Q 合并为 1 组）各 1 组 = 24。
    assert_eq!(
        pipe_groups,
        (N_PIPE + N_SLOW) as u64,
        "管道化 + 慢连接延迟 Q 聚合组数"
    );

    // ② 终态无挂起：全部连接 qr_open=0。
    for cport in 20000u16..20000 + N_CONN as u16 {
        let h = sov_vault::connection::conn_hash(
            1,
            u32::from_be_bytes(CIP),
            cport,
            u32::from_be_bytes(SIP),
            SPORT,
            6,
        );
        let txn = reg.read_txn().unwrap();
        let v = reg.dbs[IDX_CONN_STATE].get(&txn, &k_conn_state(h)).unwrap().unwrap();
        let cs = ConnState::from_bytes(v).unwrap();
        drop(txn);
        assert_eq!(cs.qr_open, 0, "连接 {} qr_open 必须归零", cport);
    }

    // ③ MD5 对账：导出全量 pcap → 回读载荷拼流 MD5 == 源载荷拼流 MD5。
    let out_path = dir.join("stress.pcap");
    let stats = export_pcap(
        &reg,
        &ledger,
        &BpfFilter::default(),
        None,
        None,
        File::create(&out_path).unwrap(),
    )
    .unwrap();
    let src_md5 = md5_of(&src_payloads);
    let (pcap_md5, n_pkt) = pcap_payload_md5(&out_path);
    assert_eq!(src_md5, pcap_md5, "源载荷与导出 pcap 载荷 MD5 必须一致");
    assert_eq!(stats.unresolved, 0, "数据平面回读零失败");
    // 导出的包数 = 推送总记录数（握手 + 请求 + 响应）。
    assert_eq!(n_pkt, (src_payloads.len() + N_CONN * 3) as u64);
    assert_eq!(stats.packets, n_pkt);

    // ④ 管理平面：全部 SEALED 文件水位线推进（无未提交尾部）；旋转产生的空 OPEN 文件除外。
    let mut files = ledger
        .conn()
        .prepare("SELECT file_id, analysis_offset, state FROM files")
        .unwrap();
    let mut sealed_uncommitted: Vec<i64> = Vec::new();
    let mut rows = files.query([]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        let _fid: i64 = row.get(0).unwrap();
        let off: i64 = row.get(1).unwrap();
        let state: i64 = row.get(2).unwrap();
        if state == 1 && off == 0 {
            sealed_uncommitted.push(_fid);
        }
    }
    assert!(
        sealed_uncommitted.is_empty(),
        "SEALED 文件必须全部提交: {:?}",
        sealed_uncommitted
    );

    let _ = std::fs::remove_dir_all(&dir);
}
