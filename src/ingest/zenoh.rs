//! 在线 ingest：Zenoh 订阅（batch/chunk/seal + gaps 回源自愈）→ Reassembler → BatchPipeline。
//!
//! 设计依据：09_sovVault_实施方案.md §3 `ingest/zenoh.rs`——在线订阅（batch+seal+gap自愈）
//! → Reassembler；§7 错误分类（传输帧坏/解密失败/重组缺口/段校验失败/提交失败）；§8.3 双 VM E2E。
//!
//! 数据流（与 slimSync 发送端契约对齐，唯一真源 slim-common/src/framing.rs）：
//!   slim/sync/batches/**  ChunkBatch 帧（批量化，主路径）→ 解密 → Reassembler.place_chunk
//!   slim/sync/chunks/**   单 Chunk 帧（兼容，config 默认关）→ 同上
//!   slim/sync/segments/** Seal 帧 → Reassembler.seal（对账 → Sealed / SealGap）
//!   slim/sync/gaps/**     GapQuery 回源自愈：封盘缺洞 → 向发送端查询重发（幂等落位回填）
//!   slim/status/exists/** 盲去重查询（REF_ONLY 已弃用 → 恒答 false，发送端回退全量数据帧）
//!
//! 内存安全（M7 资源红线 RSS ≤ 256MB）：
//!   - Reassembler L2/L2.5/L3 四层乱序预算在写入前强制检查，恶意流量烧不掉主进程内存；
//!   - Zenoh 订阅通道有界（FifoChannel 65536），消费端滞后时背压传导到发送端；
//!   - 单段流式 WAL 解码器只保留未对齐残段（≤ 一条记录大小），不整段缓存。
//!
//! 线程模型：单线程串行消费（无锁）——订阅任务只做通道转发，Reassembler/BatchPipeline
//! 全部在主循环内串行访问，与 reassembly.rs "单线程 ingest 串行消费" 的设计一致。

use crate::batch::BatchPipeline;
use crate::config::Config;
use crate::db::DbRegistry;
use crate::decrypt::Decryptor;
use crate::ledger::{AnomalyEvent, Ledger};
use crate::meta::MetaRegistry;
use crate::qr::QrParams;
use crate::reassembly::{Budgets, Event, Reassembler};
use anyhow::{Context, Result};
use slim_common::framing::{
    decode_chunk_batch, decode_chunk_frame, decode_seal_frame, encode_gap_query, GapQuery,
};
use slim_common::topics;
use sov_probe::wal::header::WalRecord;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use zenoh::handlers::FifoChannel;

/// 数据平面单文件上限：OFFSET 为 u32，单文件 < 4GB 硬不变量；取 2GB 留安全余量。
/// 文件边界屏障由源段封盘事件驱动（Event::Sealed → flush + rotate），本值是兜底轮转。
const HOT_SEGMENT_SIZE: u64 = 2 * 1024 * 1024 * 1024;
/// Gap 回源自愈最大尝试轮数（每轮发送一次查询 + 1s 等待）。
const GAP_MAX_ROUNDS: u32 = 20;
/// Zenoh 订阅通道容量（batch/chunk）：消费端瞬时滞后不立刻堵死 zenoh 读线程。
const SUB_CHANNEL_CAP: usize = 65536;
/// 单段流式解码器残段缓冲上限（一条 WAL 记录 header + 最大 payload 的兜底）。
const WAL_RESIDUAL_CAP: usize = 1024 * 1024;

/// 订阅任务转发的消息（统一进主循环串行消费）。
enum Msg {
    Batch(Vec<u8>),
    Chunk(Vec<u8>),
    Seal(Vec<u8>),
}

/// Gap 回源自愈在途状态（封盘缺洞，等待回填重发）。
struct RefillState {
    sealed_size: u64,
    last_expected: u64,
    rounds: u32,
}

/// 运行统计（仅计数字段，供周期日志）。
#[derive(Debug, Default)]
struct Stats {
    batches: u64,
    chunks: u64,
    seals: u64,
    unframed_dropped: u64,
    decrypt_failed: u64,
    dups: u64,
    gaps: u64,
    seq_skips: u64,
    seg_errors: u64,
    evict_bytes: u64,
    quarantines: u64,
    q_drop_bytes: u64,
    dirty_tail_bytes: u64,
    resolved_gaps: u64,
}

/// 在线 ingest 主体：串行持有 Reassembler / 数据平面写器 / 流式解码器。
struct LiveIngest<'a> {
    reg: &'a DbRegistry,
    ledger: &'a Ledger,
    decryptor: Decryptor,
    reassembler: Reassembler,
    pipelines: HashMap<i64, BatchPipeline<'a>>,
    decoders: HashMap<(u32, u32), WalStreamDecoder>,
    meta: Option<MetaRegistry>,
    batch_size: u32,
    qr_params: QrParams,
    hot_root: PathBuf,
    refills: HashMap<(u32, u32), RefillState>,
    stats: Stats,
    /// 已完成解码的记录数（累计，供周期日志吞吐估算）。
    total_records: u64,
    /// TTL 扫描参数（构造期提取，避免持有 Config 引用）。
    ttl_secs: u64,
    qr_timeout_secs: u64,
    fin_short_timeout_secs: u64,
    /// TTL 节流计数（每 1s tick 递增，达 ttl_scan_secs 后执行一次扫描）。
    ttl_ticks: u64,
}

impl<'a> LiveIngest<'a> {
    fn new(
        reg: &'a DbRegistry,
        ledger: &'a Ledger,
        decryptor: Decryptor,
        reassembler: Reassembler,
        meta: Option<MetaRegistry>,
        cfg: &Config,
    ) -> LiveIngest<'a> {
        LiveIngest {
            reg,
            ledger,
            decryptor,
            reassembler,
            pipelines: HashMap::new(),
            decoders: HashMap::new(),
            meta,
            batch_size: cfg.ingest.batch_size,
            qr_params: QrParams {
                ack_tolerance: cfg.analysis.ack_tolerance,
            },
            hot_root: cfg.hot_dir(),
            refills: HashMap::new(),
            stats: Stats::default(),
            total_records: 0,
            ttl_secs: cfg.analysis.ttl_scan_secs,
            qr_timeout_secs: cfg.analysis.qr_timeout_secs,
            fin_short_timeout_secs: cfg.analysis.fin_short_timeout_secs,
            ttl_ticks: 0,
        }
    }

    /// 取（或创建）dev 对应的批量流水线。dev_id 隔离落盘目录，避免多探针串段。
    /// 重启恢复：复用 dev 的 OPEN hot 文件（截断到 SQLite 水位线），杜绝 create_new 撞旧段文件。
    fn pipeline_for(&mut self, dev_id: u32) -> Result<&mut BatchPipeline<'a>> {
        let key = dev_id as i64;
        if !self.pipelines.contains_key(&key) {
            let dev_hot = self.hot_root.join(format!("dev{}", dev_id));
            let pipe = BatchPipeline::open_or_recover(
                self.reg,
                self.ledger,
                &dev_hot,
                key,
                0,
                HOT_SEGMENT_SIZE,
                self.batch_size,
                self.qr_params,
            )
            .with_context(|| format!("创建 dev{} 批量流水线失败", dev_id))?;
            if let Some(m) = &self.meta {
                let mut p = pipe;
                p.set_meta(m.clone());
                self.pipelines.insert(key, p);
            } else {
                self.pipelines.insert(key, pipe);
            }
        }
        Ok(self.pipelines.get_mut(&key).unwrap())
    }

    /// 处理一个 Chunk 批量帧：解帧 → 逐条解密 → 落位 → 处理事件。
    fn on_batch(&mut self, payload: &[u8]) {
        let Some(batch) = decode_chunk_batch(payload) else {
            self.stats.unframed_dropped += 1;
            tracing::warn!("unframed batch dropped (len={})", payload.len());
            return;
        };
        self.stats.batches += 1;
        let mut events = Vec::new();
        for entry in &batch.entries {
            self.stats.chunks += 1;
            match self
                .decryptor
                .decrypt_chunk_payload(entry.payload, entry.chunk_len)
            {
                Ok(plain) => events.extend(
                    self.reassembler
                        .place_chunk(batch.dev_id, batch.segment_seq, entry.start_offset, &plain),
                ),
                Err(e) => {
                    self.stats.decrypt_failed += 1;
                    tracing::warn!(
                        "decrypt failed (dev={} seg={} off={}): {}",
                        batch.dev_id,
                        batch.segment_seq,
                        entry.start_offset,
                        e
                    );
                }
            }
        }
        self.drain_events(events);
    }

    /// 处理一个单 Chunk 帧（兼容路径，默认关）。
    fn on_chunk(&mut self, payload: &[u8]) {
        let Some(frame) = decode_chunk_frame(payload) else {
            self.stats.unframed_dropped += 1;
            tracing::warn!("unframed chunk dropped (len={})", payload.len());
            return;
        };
        self.stats.chunks += 1;
        if frame.ref_only {
            // REF_ONLY 去重引用帧已在传输层弃用（slimRAG e752838）；恒答 EXISTS=false 后不会收到。
            return;
        }
        let body = &payload[slim_common::framing::CHUNK_FRAME_HEADER_LEN..];
        match self.decryptor.decrypt_chunk_payload(body, frame.chunk_len) {
            Ok(plain) => {
                let events =
                    self.reassembler
                        .place_chunk(frame.dev_id, frame.segment_seq, frame.start_offset, &plain);
                self.drain_events(events);
            }
            Err(e) => {
                self.stats.decrypt_failed += 1;
                tracing::warn!(
                    "decrypt failed (dev={} seg={} off={}): {}",
                    frame.dev_id,
                    frame.segment_seq,
                    frame.start_offset,
                    e
                );
            }
        }
    }

    /// 处理一个 Seal 帧：对账 → 可能产生缺口（进 refill 在途）。
    fn on_seal(&mut self, payload: &[u8]) {
        let Some(seal) = decode_seal_frame(payload) else {
            self.stats.unframed_dropped += 1;
            tracing::warn!("unframed seal dropped (len={})", payload.len());
            return;
        };
        self.stats.seals += 1;
        let events = self.reassembler.seal(seal.dev_id, seal.segment_seq, seal.sealed_size);
        self.drain_events(events);
    }

    /// 周期处理：重试在途 refill 的重封盘，按 ttl_scan_secs 节流推进 TTL 扫描。
    fn on_tick(&mut self, session: &Option<zenoh::Session>) {
        self.ttl_ticks += 1;
        if self.ttl_ticks >= self.ttl_secs.max(1) {
            self.ttl_ticks = 0;
            self.ttl_scan();
        }
        if !self.refills.is_empty() {
            let keys: Vec<(u32, u32)> = self.refills.keys().copied().collect();
            for (dev, seg) in keys {
                // 重发封盘信号：若缺口已补齐则产出 Sealed（段释放 + 提交屏障），refill 完成。
                let sealed_size = self.refills.get(&(dev, seg)).unwrap().sealed_size;
                let events = self.reassembler.seal(dev, seg, sealed_size);
                // 同步最新水位：缺口在回填推进时，下次查询应从新边界重发。
                if let Some(Event::SealGap { next_expected, .. }) =
                    events.iter().find(|e| matches!(e, Event::SealGap { .. }))
                {
                    if let Some(st) = self.refills.get_mut(&(dev, seg)) {
                        st.last_expected = *next_expected;
                    }
                }
                let released = events
                    .iter()
                    .any(|e| matches!(e, Event::Sealed { .. }));
                if released {
                    self.stats.resolved_gaps += 1;
                    tracing::info!("GAP refill complete: dev={} seg={}", dev, seg);
                } else {
                    // 仍未补齐：达到轮数上限则放弃，否则发起下一轮回源查询。
                    let round = {
                        let st = self.refills.get_mut(&(dev, seg)).unwrap();
                        st.rounds += 1;
                        if st.rounds >= GAP_MAX_ROUNDS {
                            tracing::warn!("GAP refill give up: dev={} seg={}", dev, seg);
                            None
                        } else {
                            Some(GapQuery {
                                dev_id: dev,
                                segment_seq: seg,
                                start_offset: st.last_expected,
                            })
                        }
                    };
                    if let Some(q) = round {
                        if let Some(s) = session {
                            let sess = s.clone();
                            tokio::spawn(async move {
                                let req = encode_gap_query(&q);
                                let _ = sess
                                    .get(topics::GAPS_PREFIX)
                                    .payload(req)
                                    .timeout(Duration::from_secs(5))
                                    .await;
                            });
                        }
                    }
                }
                if released || self.refills.get(&(dev, seg)).unwrap().rounds >= GAP_MAX_ROUNDS {
                    self.refills.remove(&(dev, seg));
                }
                // 处理 Sealed（提交屏障）等事件，但 SealGap 已在途，勿重复入列。
                for e in events {
                    if !matches!(e, Event::SealGap { .. }) {
                        self.drain_events(vec![e]);
                    }
                }
            }
        }
    }

    /// 消费事件流：Append → 流式解码 → 批量落库；Sealed → 提交屏障轮转；其余计数。
    fn drain_events(&mut self, events: Vec<Event>) {
        for ev in events {
            match ev {
                Event::Append {
                    dev_id,
                    segment_seq,
                    data,
                    ..
                } => {
                    let recs = self.feed_decoder(dev_id, segment_seq, &data);
                    self.total_records += recs.len() as u64;
                    let pipe = match self.pipeline_for(dev_id) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::error!("pipeline_for dev={} failed: {}", dev_id, e);
                            continue;
                        }
                    };
                    for r in recs {
                        if let Err(e) = pipe.push_record(r) {
                            tracing::error!("push_record failed: {}", e);
                        }
                    }
                }
                Event::Sealed {
                    dev_id,
                    segment_seq,
                    ..
                } => {
                    // 文件边界屏障：源段封盘 = 数据平面文件切换，先提交再轮转。
                    if let Some(pipe) = self.pipelines.get_mut(&(dev_id as i64)) {
                        if let Err(e) = pipe.finish() {
                            tracing::error!("seal flush/rotate failed: {}", e);
                        }
                    }
                    if let Some(dec) = self.decoders.remove(&(dev_id, segment_seq)) {
                        let dirty = dec.residual_len();
                        if dirty > 0 {
                            self.stats.dirty_tail_bytes += dirty as u64;
                        }
                    }
                    tracing::info!("SEAL dev={} seg={} done", dev_id, segment_seq);
                }
                Event::Dup { .. } => self.stats.dups += 1,
                Event::Gap { .. } => self.stats.gaps += 1,
                Event::SeqSkipped { dev_id, segment_seq } => {
                    self.stats.seq_skips += 1;
                    self.audit(
                        crate::anomaly::ANOM_CONN_RST,
                        dev_id,
                        segment_seq,
                        "segment skipped (Unlink-Oldest)",
                    );
                }
                Event::SegmentError {
                    dev_id,
                    segment_seq,
                    reason,
                } => {
                    self.stats.seg_errors += 1;
                    self.audit(
                        crate::anomaly::ANOM_QR_UNMATCHED,
                        dev_id,
                        segment_seq,
                        &format!("segment error: {}", reason),
                    );
                }
                Event::Evict { bytes, .. } => self.stats.evict_bytes += bytes,
                Event::Quarantine { dev_id } => {
                    self.stats.quarantines += 1;
                    self.audit(
                        crate::anomaly::ANOM_QR_TIMEOUT,
                        dev_id,
                        0,
                        "connection quarantined (OOO flood)",
                    );
                }
                Event::QuarantinedDrop { bytes, .. } => self.stats.q_drop_bytes += bytes,
                Event::SealGap {
                    dev_id,
                    segment_seq,
                    next_expected,
                    sealed_size,
                } => {
                    self.stats.gaps += 1;
                    let st = RefillState {
                        sealed_size,
                        last_expected: next_expected,
                        rounds: 0,
                    };
                    self.refills.insert((dev_id, segment_seq), st);
                    tracing::warn!(
                        "SEAL gap dev={} seg={} next={} size={} — 进入回源自愈",
                        dev_id,
                        segment_seq,
                        next_expected,
                        sealed_size
                    );
                }
            }
        }
    }

    /// 流式 WAL 解码：把连续明文字节喂入段解码器，产出完整记录。
    fn feed_decoder(&mut self, dev_id: u32, segment_seq: u32, data: &[u8]) -> Vec<WalRecord> {
        let dec = self
            .decoders
            .entry((dev_id, segment_seq))
            .or_insert_with(WalStreamDecoder::new);
        dec.feed(data)
    }

    /// 低频审计事件落 SQLite（best-effort，不阻塞 ingest）。
    fn audit(&self, kind: i64, dev_id: u32, segment_seq: u32, detail: &str) {
        let ev = AnomalyEvent {
            ts: now_secs(),
            kind,
            dev_id: Some(dev_id as i64),
            segment_seq: Some(segment_seq as i64),
            conn_hash: None,
            qr_id: None,
            detail: Some(detail.to_string()),
        };
        if let Err(e) = self.ledger.insert_anomalies(std::slice::from_ref(&ev)) {
            tracing::warn!("audit insert failed: {}", e);
        }
    }

    /// TTL 扫描（serve 常驻路径复用）：PENDING_TTL 过期 Q → TIMEOUT + 终态审计。
    fn ttl_scan(&self) {
        if self.ttl_secs == 0 {
            return;
        }
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        // serve 骨架下由外部协程负责；在线 ingest 主循环内联执行，避免跨线程共享 SQLite。
        match crate::anomaly::scan_pending_ttl(
            self.reg,
            now_ns,
            self.qr_timeout_secs,
            self.fin_short_timeout_secs,
        ) {
            Ok((events, stats)) => {
                if !events.is_empty() {
                    if let Err(e) = self.ledger.insert_anomalies(&events) {
                        tracing::error!("TTL 审计落库失败: {}", e);
                    }
                }
                if stats.scanned > 0 {
                    tracing::info!(
                        "TTL 扫描: scanned={} timed_out={} stale={} conns={}",
                        stats.scanned,
                        stats.timed_out,
                        stats.stale,
                        stats.conns_touched
                    );
                }
            }
            Err(e) => tracing::error!("TTL 扫描失败: {}", e),
        }
    }

    /// 周期统计日志。
    fn log_stats(&self) {
        tracing::info!(
            "ingest: batches={} chunks={} seals={} records={} dup={} gap={} skip={} seg_err={} evict={}B q_drop={}B dirty={}B unframed={} dec_err={} refill_inflight={}",
            self.stats.batches,
            self.stats.chunks,
            self.stats.seals,
            self.total_records,
            self.stats.dups,
            self.stats.gaps,
            self.stats.seq_skips,
            self.stats.seg_errors,
            self.stats.evict_bytes,
            self.stats.q_drop_bytes,
            self.stats.dirty_tail_bytes,
            self.stats.unframed_dropped,
            self.stats.decrypt_failed,
            self.refills.len()
        );
    }

    /// 收尾：flush 全部在途批量 + 摘要。
    fn finalize(&mut self) {
        for (dev, pipe) in self.pipelines.iter_mut() {
            if let Err(e) = pipe.finish() {
                tracing::error!("finalize dev={} failed: {}", dev, e);
            }
        }
        self.log_stats();
    }
}

/// 单段流式 WAL 解码器：保留未对齐残段，跨 chunk 拼接记录。
struct WalStreamDecoder {
    residual: Vec<u8>,
}

impl WalStreamDecoder {
    fn new() -> WalStreamDecoder {
        WalStreamDecoder {
            residual: Vec::with_capacity(4096),
        }
    }

    /// 喂入连续明文 WAL 字节，返回本次解码出的完整记录。
    fn feed(&mut self, data: &[u8]) -> Vec<WalRecord> {
        self.residual.extend_from_slice(data);
        if self.residual.len() > WAL_RESIDUAL_CAP {
            // 极端防御：残段异常膨胀（非记录流），整体清空防无界增长。
            self.residual.clear();
            return Vec::new();
        }
        let (recs, res) = WalRecord::decode_stream(&self.residual);
        let keep = self.residual.len() - res;
        self.residual.drain(..keep);
        recs
    }

    fn residual_len(&self) -> usize {
        self.residual.len()
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 从配置构建在线 ingest 全部依赖并运行至退出（Ctrl-C / 订阅断开）。
pub async fn run(cfg: &Config) -> Result<()> {
    for d in [cfg.hot_dir(), cfg.warm_dir(), cfg.lmdb_dir()] {
        std::fs::create_dir_all(&d)?;
    }
    let ledger = Ledger::open(&cfg.ledger_path())?;
    let map_size = cfg.lmdb_map_size_bytes()? as usize;
    let reg = DbRegistry::open(&cfg.lmdb_dir(), map_size)?;

    // MetaBind：幂等登记配置规则，构建带真实 id 的 MetaRegistry。
    let mut meta = MetaRegistry::from_binds(&cfg.analysis.meta_binds);
    for (i, b) in cfg.analysis.meta_binds.iter().enumerate() {
        let id = ledger.upsert_meta_bind(
            &b.name,
            b.proto as i64,
            b.dst_port as i64,
            &b.fingerprint,
            &b.extractor,
        )?;
        meta.set_rule_id(i, id);
    }

    // 解密器：key_hex 优先，否则 key_file。
    let decryptor = match &cfg.crypto.key_hex {
        Some(h) => Decryptor::from_key_hex(h)?,
        None => Decryptor::from_key_file(&cfg.crypto.key_file)?,
    };

    // 四层乱序预算（L2 单段 / L2.5 单连接 / L3 全局）。
    let budgets = Budgets::from_config(
        cfg.ingest.segment_pending_cap,
        cfg.conn_pending_cap_bytes()?,
        cfg.pending_budget_bytes()?,
        cfg.ingest.conn_evict_window_secs,
        cfg.ingest.conn_evict_threshold,
    );
    let reassembler = Reassembler::new(budgets);
    let mut ingest = LiveIngest::new(&reg, &ledger, decryptor, reassembler, Some(meta), cfg);

    // Zenoh 会话：显式 connect 端点（跨 VM 直连），无则回退默认。
    let mut zcfg = zenoh::Config::default();
    if !cfg.zenoh.connect.is_empty() {
        let _ = zcfg.insert_json5(
            "connect/endpoints",
            &serde_json::to_string(&cfg.zenoh.connect).unwrap_or_default(),
        );
    }
    if !cfg.zenoh.listen.is_empty() {
        let _ = zcfg.insert_json5(
            "listen/endpoints",
            &serde_json::to_string(&cfg.zenoh.listen).unwrap_or_default(),
        );
    }
    let session = zenoh::open(zcfg)
        .await
        .map_err(|e| anyhow::anyhow!("zenoh open: {e}"))?;
    tracing::info!(
        "sovVault live ingest up (connect={:?} listen={:?})",
        cfg.zenoh.connect,
        cfg.zenoh.listen
    );

    // ── 订阅通道（转发任务只做搬运，主循环串行消费） ──
    let (tx, mut rx) = mpsc::channel::<Msg>(SUB_CHANNEL_CAP);

    // batch 主路径。
    let batch_topic = format!("{}/**", topics::BATCH_PREFIX);
    let batch_sub = session
        .declare_subscriber(&batch_topic)
        .with(FifoChannel::new(SUB_CHANNEL_CAP))
        .await
        .map_err(|e| anyhow::anyhow!("declare_subscriber {}: {e}", batch_topic))?;
    tracing::info!("subscribed: {}", batch_topic);
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            while let Ok(sample) = batch_sub.recv_async().await {
                let payload: Vec<u8> = sample.payload().to_bytes().into();
                if tx.send(Msg::Batch(payload)).await.is_err() {
                    break;
                }
            }
        });
    }

    // chunk 兼容路径（默认关）。
    if cfg.ingest.subscribe_chunks {
        let chunk_topic = format!("{}/**", topics::CHUNK_PREFIX);
        let chunk_sub = session
            .declare_subscriber(&chunk_topic)
            .with(FifoChannel::new(SUB_CHANNEL_CAP))
            .await
            .map_err(|e| anyhow::anyhow!("declare_subscriber {}: {e}", chunk_topic))?;
        tracing::info!("subscribed: {}", chunk_topic);
        {
            let tx = tx.clone();
            tokio::spawn(async move {
                while let Ok(sample) = chunk_sub.recv_async().await {
                    let payload: Vec<u8> = sample.payload().to_bytes().into();
                    if tx.send(Msg::Chunk(payload)).await.is_err() {
                        break;
                    }
                }
            });
        }
    }

    // seal 封盘信号。
    let seal_topic = format!("{}/**", topics::SEAL_PREFIX);
    let seal_sub = session
        .declare_subscriber(&seal_topic)
        .await
        .map_err(|e| anyhow::anyhow!("declare_subscriber {}: {e}", seal_topic))?;
    tracing::info!("subscribed: {}", seal_topic);
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            while let Ok(sample) = seal_sub.recv_async().await {
                let payload: Vec<u8> = sample.payload().to_bytes().into();
                if tx.send(Msg::Seal(payload)).await.is_err() {
                    break;
                }
            }
        });
    }

    // 盲去重 EXISTS 查询：REF_ONLY 已弃用 → 恒答 false，发送端回退全量数据帧。
    let exists_topic = format!("{}/**", topics::EXISTS);
    let exists_q = session
        .declare_queryable(&exists_topic)
        .await
        .map_err(|e| anyhow::anyhow!("declare_queryable {}: {e}", exists_topic))?;
    tracing::info!("queryable: {}", exists_topic);
    tokio::spawn(async move {
        while let Ok(query) = exists_q.recv_async().await {
            let _ = query
                .reply(query.key_expr().clone(), b"false".as_slice())
                .await;
        }
    });

    // ── 主循环：串行消费 + 周期 refill/TTL + 周期统计 ──
    let session_opt: Option<zenoh::Session> = Some(session);
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let mut stat_ticker = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Some(Msg::Batch(p)) => ingest.on_batch(&p),
                Some(Msg::Chunk(p)) => ingest.on_chunk(&p),
                Some(Msg::Seal(p)) => ingest.on_seal(&p),
                None => { tracing::warn!("all subscribers closed — exiting"); break; }
            },
            _ = ticker.tick() => ingest.on_tick(&session_opt),
            _ = stat_ticker.tick() => ingest.log_stats(),
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("ctrl-c received, finalizing ingest...");
                break;
            }
        }
    }
    ingest.finalize();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decrypt::Decryptor;
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    use slim_common::framing::{encode_chunk_batch, encode_seal_frame};

    fn key() -> [u8; 32] {
        [0x22; 32]
    }

    fn enc(data: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key()));
        let mut nonce = [0u8; 12];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut ct = data.to_vec();
        cipher
            .encrypt_in_place(Nonce::from_slice(&nonce), &[], &mut ct)
            .unwrap();
        [nonce.as_slice(), ct.as_slice()].concat()
    }

    fn wal_segment(n: u32) -> (Vec<u8>, Vec<WalRecord>) {
        let mut buf = Vec::new();
        let mut recs = Vec::new();
        for i in 0..n {
            let rec = WalRecord {
                timestamp_ns: 1_700_000_000_000 + i as u64,
                flags: 0,
                tcp_flags: 0x10,
                tcp_seq: 1000 + i,
                tcp_ack: 0,
                window_size: 65535,
                src_ip: [192, 168, 1, 10],
                dst_ip: [10, 0, 0, 1],
                src_port: 12345,
                dst_port: 8080,
                proto: 6,
                orig_payload_len: 4,
                payload: format!("r{}!", i).into_bytes(),
            };
            rec.encode(&mut buf);
            recs.push(rec);
        }
        (buf, recs)
    }

    /// 乱序批量帧 → 解密落位 → 连续推流 → 解码出完整记录。
    #[test]
    fn batch_reassembly_stream_decode() {
        let (seg, src) = wal_segment(50);
        let n = 4;
        // 边界数组 [0, len/4, 2len/4, 3len/4, len]，保证 4 片完整覆盖段字节。
        let bounds: Vec<usize> = (0..=n).map(|i| seg.len() * i / n).collect();
        // 乱序投递：先中段后前段。
        let order: Vec<usize> = vec![2, 0, 3, 1];
        let mut r = Reassembler::new(Budgets {
            l2_segment_cap: 8 * 1024 * 1024,
            l25_conn_cap: 16 * 1024 * 1024,
            l3_global_cap: 256 * 1024 * 1024,
            evict_window_secs: 30,
            evict_threshold: 3,
        });
        let mut dec = WalStreamDecoder::new();
        let mut out = Vec::new();
        for i in order {
            let off = bounds[i] as u64;
            let bytes = &seg[bounds[i]..bounds[i + 1]];
            let entries = vec![(off, bytes.len() as u32, enc(bytes))];
            let frame = encode_chunk_batch(1, 3, &entries);
            let batch = decode_chunk_batch(&frame).unwrap();
            for e in &batch.entries {
                let plain = Decryptor::new(key())
                    .decrypt_chunk_payload(e.payload, e.chunk_len)
                    .unwrap();
                let events = r.place_chunk(1, 3, e.start_offset, &plain);
                for ev in events {
                    if let Event::Append { data, .. } = ev {
                        out.extend(dec.feed(&data));
                    }
                }
            }
        }
        assert_eq!(out.len(), 50, "全部 50 条记录跨 chunk 重组解码");
        for (a, b) in out.iter().zip(src.iter()) {
            assert_eq!(a.timestamp_ns, b.timestamp_ns);
            assert_eq!(a.payload, b.payload);
            assert_eq!(a.src_port, b.src_port);
            assert_eq!(a.dst_port, b.dst_port);
        }
        assert_eq!(r.global_pending(), 0);
    }

    /// Seal 完整 → Sealed；Seal 缺洞 → SealGap + refill 入在途。
    #[test]
    fn seal_gap_enters_refill() {
        let mut r = Reassembler::new(Budgets {
            l2_segment_cap: 8 * 1024 * 1024,
            l25_conn_cap: 16 * 1024 * 1024,
            l3_global_cap: 256 * 1024 * 1024,
            evict_window_secs: 30,
            evict_threshold: 3,
        });
        r.place_chunk(1, 0, 0, &[1u8; 100]);
        let e = r.seal(1, 0, 200);
        assert!(
            e.iter().any(|x| matches!(x, Event::SealGap { .. })),
            "缺洞封盘必须报 SealGap"
        );
        let e = r.seal(1, 0, 100);
        assert!(
            e.iter().any(|x| matches!(x, Event::Sealed { .. })),
            "补齐后封盘必须报 Sealed"
        );
    }

    /// 流式解码器：记录跨多次 feed 拼接；残段不丢字节。
    #[test]
    fn stream_decoder_spans_feeds() {
        let (seg, _) = wal_segment(3);
        let mut dec = WalStreamDecoder::new();
        let mut out = Vec::new();
        // 每次只喂 3 字节，强制跨 feed 拼接。
        for i in (0..seg.len()).step_by(3) {
            out.extend(dec.feed(&seg[i..(i + 3).min(seg.len())]));
        }
        assert_eq!(out.len(), 3);
        assert_eq!(dec.residual_len(), 0);
    }

    /// 封盘帧编解码 roundtrip。
    #[test]
    fn seal_frame_roundtrip() {
        let f = encode_seal_frame(1, 7, 65536);
        let seal = decode_seal_frame(&f).unwrap();
        assert_eq!(seal.dev_id, 1);
        assert_eq!(seal.segment_seq, 7);
        assert_eq!(seal.sealed_size, 65536);
    }
}
