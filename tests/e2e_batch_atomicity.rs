//! P2 批量原子性 E2E（09 §8.2）：
//! 1. 注入提交失败 → 水位线不推进；
//! 2. 崩溃窗口模拟：LMDB 提交成功、SQLite 水位线未推进 → 重启重放 → 幂等收敛、零脏数据；
//! 3. 文件边界屏障：跨界强制截断提交（逻辑事务不跨物理文件）。

use sov_probe::wal::header::WalRecord;
use sov_vault::batch::{commit_batch, stage_lmdb, BatchPipeline, HotFileWriter, IndexedRecord};
use sov_vault::db::DbRegistry;
use sov_vault::ledger::Ledger;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn tmpdir(tag: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("sovvault-e2e-{}-{}", tag, ts));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn rec(ts: u64, payload: &[u8]) -> WalRecord {
    WalRecord {
        timestamp_ns: ts,
        flags: 0,
        tcp_flags: 0x10,
        tcp_seq: ts as u32,
        tcp_ack: 0,
        window_size: 65535,
        src_ip: [192, 168, 1, 10],
        dst_ip: [10, 0, 0, 1],
        src_port: 12345,
        dst_port: 443,
        proto: 6,
        orig_payload_len: payload.len() as u32,
        payload: payload.to_vec(),
    }
}

fn indexed(file_id: u32, offset: u32, rec: WalRecord) -> IndexedRecord {
    IndexedRecord {
        file_id,
        offset,
        rec,
    }
}

fn rec_ts_count(reg: &DbRegistry) -> u64 {
    let txn = reg.read_txn().unwrap();
    reg.dbs[sov_vault::db::IDX_RECORD_TS].len(&txn).unwrap()
}

/// ① 注入提交失败（SQLite 殿后失败）→ 水位线不推进；注册文件后重放 → 收敛。
#[test]
fn injected_commit_failure_keeps_watermark() {
    let dir = tmpdir("fail");
    let ledger = Ledger::open(&dir.join("ledger.db")).unwrap();
    let reg = DbRegistry::open(&dir.join("qridx"), 10 * 1024 * 1024).unwrap();

    // 批次引用未注册的 file_id=1：stage_lmdb（先行）成功，stage_sqlite 失败 → 协议报错。
    let r1 = indexed(1, 0, rec(1, b"GET /a"));
    assert!(commit_batch(&reg, &ledger, std::slice::from_ref(&r1)).is_err());
    // LMDB 已先行提交（1 条），水位线无从推进。
    assert_eq!(rec_ts_count(&reg), 1);

    // 注册文件后从旧水位线重放同批 → 幂等收敛。
    let _ = ledger.insert_file(
        "/hot/segment_0000.wal",
        sov_vault::ledger::FileKind::Wal,
        1,
        Some(0),
        1,
    );
    commit_batch(&reg, &ledger, &[r1]).unwrap();
    assert_eq!(rec_ts_count(&reg), 1); // 不翻倍
    assert_eq!(ledger.watermark(1).unwrap(), 64 + 6); // "GET /a"=6B → 70
    let _ = std::fs::remove_dir_all(&dir);
}

/// ② 崩溃窗口：LMDB 提交成功、SQLite 水位线未推进 → 重启重放 → 幂等收敛、零脏数据。
#[test]
fn crash_window_replay_converges() {
    let dir = tmpdir("crash");
    let ledger = Ledger::open(&dir.join("ledger.db")).unwrap();
    let reg = DbRegistry::open(&dir.join("qridx"), 10 * 1024 * 1024).unwrap();
    let hot = dir.join("hot");

    let recs: Vec<WalRecord> = (0..5u64).map(|i| rec(i, &[i as u8; 10])).collect();

    // —— 第一次运行：写入 5 条到 hot 文件 + LMDB 提交，但 SQLite 水位线未推进（崩溃现场） ——
    {
        let mut w = HotFileWriter::open(&hot, &ledger, 1, 0, 64 * 1024).unwrap();
        let mut indexed = Vec::new();
        for r in &recs {
            let (file_id, offset) = w.append(r).unwrap();
            indexed.push(IndexedRecord {
                file_id,
                offset,
                rec: r.clone(),
            });
        }
        // ① LMDB 先行（提交成功）。
        stage_lmdb(&reg, &indexed).unwrap();
        // 模拟崩溃：SQLite 水位线未推进，进程即退。
        assert_eq!(ledger.watermark(1).unwrap(), 0);
        assert_eq!(rec_ts_count(&reg), 5);
        drop(w);
    }

    // —— 第二次运行（重启）：复用 OPEN 文件并截断到水位线 → 从旧水位线重放同批 → 收敛 ——
    {
        // ① open_or_recover：发现 OPEN 文件 → 截断到水位线 0（丢弃未提交尾部）。
        let mut w = HotFileWriter::open_or_recover(&hot, &ledger, 1, 0, 64 * 1024).unwrap();
        assert_eq!(w.offset(), 0);
        assert_eq!(w.file_id(), 1); // 复用原 file_id，不重复登记
        assert_eq!(
            std::fs::metadata(hot.join("segment_0000.wal"))
                .unwrap()
                .len(),
            0
        );

        // ② 从旧水位线（0）重新消费同一批记录，走完整 2PC-Lite。
        let mut indexed = Vec::new();
        for r in &recs {
            let (file_id, offset) = w.append(r).unwrap();
            indexed.push(IndexedRecord {
                file_id,
                offset,
                rec: r.clone(),
            });
        }
        commit_batch(&reg, &ledger, &indexed).unwrap();
        drop(w);

        // ③ 收敛断言：RECORD_TS 仍为 5 条（NO_OVERWRITE 幂等，不翻倍）、水位线 = 文件尾。
        assert_eq!(rec_ts_count(&reg), 5);
        assert_eq!(ledger.watermark(1).unwrap(), 5 * (64 + 10));
        assert_eq!(
            std::fs::metadata(hot.join("segment_0000.wal"))
                .unwrap()
                .len(),
            5 * (64 + 10)
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// ③ 文件边界屏障：segment_size 极小 → 跨界强制截断提交，逻辑事务不跨物理文件。
#[test]
fn file_boundary_forces_commit() {
    let dir = tmpdir("boundary");
    let ledger = Ledger::open(&dir.join("ledger.db")).unwrap();
    let reg = DbRegistry::open(&dir.join("qridx"), 10 * 1024 * 1024).unwrap();
    // segment_size=80：每条 74B，文件 1 放 1 条，文件 2 放 1 条，文件 3 放 1 条。
    let mut pipe = BatchPipeline::new(&reg, &ledger, dir.join("hot"), 1, 0, 80, 100).unwrap();
    let fid1 = pipe.hot_file_id();
    pipe.push_record(rec(1, &[1u8; 10])).unwrap(); // 文件1
    pipe.push_record(rec(2, &[2u8; 10])).unwrap(); // 跨界 → 强制提交文件1 + 轮转
    let fid2 = pipe.hot_file_id();
    assert_ne!(fid1, fid2);
    pipe.push_record(rec(3, &[3u8; 10])).unwrap(); // 文件2
    pipe.push_record(rec(4, &[4u8; 10])).unwrap(); // 跨界 → 强制提交文件2 + 轮转
    let fid3 = pipe.hot_file_id();
    assert_ne!(fid2, fid3);
    pipe.finish().unwrap();

    // 未满 batch_size(100) 但跨界即提交：文件1 水位线 = 74（1 条已入库）。
    assert_eq!(ledger.watermark(fid1 as i64).unwrap(), 74);
    assert_eq!(ledger.watermark(fid2 as i64).unwrap(), 74);
    // 收尾提交文件3 的 1 条。
    assert_eq!(ledger.watermark(fid3 as i64).unwrap(), 74);
    assert_eq!(rec_ts_count(&reg), 4);
    let _ = std::fs::remove_dir_all(&dir);
}
