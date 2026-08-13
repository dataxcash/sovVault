//! P3 QR 匹配引擎：绝对序列流翻译器 + 累积 ACK 消费 + 快/慢路径缝合 + 代际（incarnation）隔离。
//!
//! 设计依据：08 §4.0/§5.1/§5.2/§5.4 + 09 §13（双库分库轮转）+ v0.5 代际规格。
//!
//! 关键决策：
//! - `SeqStream`：raw(u32)→abs(u64) 非回退翻译器；前向推进、重叠/重传不倒退（DUP 检测）。
//!   每方向 `last_raw`/`abs_seq`/激活位持久化进 DBI_CONN_STATE（08 §4.1）——跨批/跨文件慢路径
//!   重载翻译器时 wrap 仍正确。
//! - incarnation:u16 升格为 DBI_QR_PENDING 的 Key 物理前缀 `[conn][incarnation][abs_q_end]`：
//!   旧代际挂起 Q 在 B+ 树存储层被物理隔离，幽灵包（旧连接迟到 ACK/RST）游标根本读不到。
//!
//! ## 双库事务模型（09 §13.3/13.4）★
//!
//! QrMatcher 持有 **两个写事务**（live_txn + epoch_txn），DBI 归属见 db.rs 模块注释：
//! - **live_txn**：CONN_STATE / QR_PENDING / PENDING_TTL / 在途 QR_PAIR(PENDING)；
//! - **epoch_txn**：终态 QR_PAIR / CONN_QR / QR_KEY / QR_TIME / PACKET_QR / RECORD_TS。
//!
//! **QR_PAIR 在途→终态迁移**：Q 打开写 live(PENDING)；R 消费 / TTL 超时 / RST 级联 / 代际翻转 /
//! 检疫进入终态时，`migrate_terminal` 执行「读 live → 翻转终态 → 写 epoch（NO_OVERWRITE）→ 删 live」。
//! **迁移幂等（§13.4.2）**：先查 epoch → 已有终态则跳过迁移（不重复写）、仅清理 live 残留；不存在才迁移。
//!
//! **提交顺序（epoch 先行）**：epoch_txn.commit() → live_txn.commit()。理由见 db.rs 模块注释——
//! §13.4.2 幂等表要求「写 epoch 后、删 live 前」窗口内重放收敛，live 残留删除与 CONN_STATE 在同一
//! live txn 原子提交，故 epoch 必须先持久。
//!
//! **次级索引 status 去重（§13.4.1）**：CONN_QR / QR_KEY / QR_TIME 不再存 status，Q 打开时写一次
//! （value = q_first_idx，纯定位索引）、永不更新——消除跨 epoch 更新矛盾，历史库回归「追加后只读」。
//! status 过滤查询改为「索引定位候选 → QR_PAIR 主行现查」（见 query.rs）。

use crate::batch::IndexedRecord;
use crate::connection::{anomaly, conn_hash, ConnState, ConnStateKind};
use crate::db::{
    put_no_overwrite, v_pending_ttl_encode, v_qr_pending_decode, v_qr_pending_encode,
    v_record_summary_encode, v_secondary_encode, DbRegistry, QrPairValue, QrStatus, RecordSummary,
    EPOCH_CONN_QR, EPOCH_PACKET_QR, EPOCH_QR_KEY, EPOCH_QR_PAIR, EPOCH_QR_TIME, EPOCH_RECORD_TS,
    LIVE_CONN_STATE, LIVE_PENDING_TTL, LIVE_QR_PAIR, LIVE_QR_PENDING, k_conn_qr, k_conn_state,
    k_packet_qr, k_pending_ttl, k_qr_key, k_qr_pair, k_qr_pending, k_qr_pending_prefix, k_qr_time,
    k_record_ts,
};
use crate::ledger::AnomalyEvent;
use crate::anomaly::{ANOM_QR_RST_ABORT, ANOM_QR_UNMATCHED};
use crate::meta::{ExtMetaEvent, MetaRegistry, ProtocolKind};
use anyhow::Result;
use heed::types::Bytes;
use heed::Database;
use sov_probe::wal::header::{TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, WalRecord};
use std::collections::HashMap;
use std::ops::Bound;

/// 不可解释大跳变阈值（非 SYN 报文 |signed diff| 超过即标 SEQ_GAP，绝不触发重代）。
/// 远超合法乱序距离（TCP 窗口有界）；数据流自然回绕经 wrapping_sub 是小数差，不受影响。
pub const EPOCH_JUMP_THRESHOLD: u32 = 1 << 30;
/// u48 键域上限（DBI_QR_PENDING 的 abs_q_end 域）。
pub const U48_MAX: u64 = 0x0000_FFFF_FFFF_FFFF;
/// 单次 ACK 可超前于 c→s 流头的合理上限（64MB）。
/// 超过视为越窗 ACK（旧代际幽灵包污染等），仅计数不推进 consumed——
/// 防止幽灵 ack 把新代际的 consumed 抬高后误压真实新 Q。
pub const ACK_LEAD_CAP: u64 = 1 << 26;

/// 审计异常种类（定义在 anomaly.rs，此处 re-export 保持旧引用兼容）。
pub use crate::anomaly::{ANOM_CONN_RST, ANOM_EPOCH_REBIRTH};

/// QR 匹配参数（来自 config.analysis）。
#[derive(Debug, Clone, Copy)]
pub struct QrParams {
    /// ACK 容差（累积 ACK 消费的边界补偿）。
    pub ack_tolerance: u32,
}

impl Default for QrParams {
    fn default() -> Self {
        QrParams { ack_tolerance: 4 }
    }
}

/// 绝对序列流翻译器（wrap-proof，非回退）。08 §4.0。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeqStream {
    pub last_raw: u32,
    pub last_abs: u64,
    /// 基线已建立（区分 ISN=0 的合法首包）。
    pub active: bool,
}

impl SeqStream {
    /// 从持久化 ConnState 重建（跨批/慢路径/崩溃恢复后 wrap 仍正确）。
    pub fn from_state(st: &ConnState, client: bool) -> SeqStream {
        if client {
            SeqStream {
                last_raw: st.last_raw_c,
                last_abs: st.abs_seq_c,
                active: st.active_c(),
            }
        } else {
            SeqStream {
                last_raw: st.last_raw_s,
                last_abs: st.abs_seq_s,
                active: st.active_s(),
            }
        }
    }

    /// 代际重代：重置为新 ISN 基线。
    pub fn reset_baseline(&mut self, isin: u32) {
        self.last_raw = isin;
        self.last_abs = isin as u64;
        self.active = true;
    }

    /// 带符号 modular diff（前向 +，回退 −）。
    #[inline]
    pub fn diff(&self, raw: u32) -> i32 {
        raw.wrapping_sub(self.last_raw) as i32
    }

    /// 只读翻译（R.ack 属对向流数空间，不得推进本流基线）。
    #[inline]
    pub fn abs_of(&self, raw: u32) -> u64 {
        if !self.active {
            return raw as u64;
        }
        let d = raw.wrapping_sub(self.last_raw) as i32;
        if d > 0 {
            self.last_abs.wrapping_add(d as u64)
        } else {
            self.last_abs
        }
    }

    /// 数据包推进：返回 (abs_start, wire_new)。
    /// - 首包：建立基线，整段为新数据；
    /// - 前向（d>0）：整段新数据（含缺口，abs 连续无跳点）；
    /// - 重叠/重传（d≤0）：仅 [head_raw, end_raw) 尾部为新数据；
    /// - 完全重复：wire_new=0（DUP/RETRANS 仅计数，不产 Q）。
    pub fn feed_packet(&mut self, seq: u32, wire_len: u32) -> (u64, u32) {
        if !self.active {
            self.reset_baseline(seq);
            return (self.last_abs, wire_len);
        }
        let d = seq.wrapping_sub(self.last_raw) as i32;
        let end = seq.wrapping_add(wire_len);
        if d > 0 {
            self.last_abs = self.last_abs.wrapping_add(d as u64);
            let abs_start = self.last_abs;
            self.last_abs = abs_start.wrapping_add(wire_len as u64);
            self.last_raw = end;
            (abs_start, wire_len)
        } else {
            let new_len = end.wrapping_sub(self.last_raw);
            if new_len == 0 || (new_len as i32) < 0 {
                // 完全重复（或环绕歧义）：无新数据
                (self.last_abs, 0)
            } else {
                let abs_start = self.last_abs;
                self.last_abs = abs_start.wrapping_add(new_len as u64);
                self.last_raw = end;
                (abs_start, new_len)
            }
        }
    }
}

/// 方向：src == 存储的 client 元组 = C2S（请求），否则 S2C（响应）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    C2S,
    S2C,
}

/// 单连接批内热状态（连接热状态 + 双向翻译器均持久化进 ConnState）。
#[derive(Debug, Clone)]
struct ConnRt {
    state: ConnState,
}

impl ConnRt {
    fn fresh(_h: u64, rec: &WalRecord) -> ConnRt {
        let src_ip = u32::from_be_bytes(rec.src_ip);
        let dst_ip = u32::from_be_bytes(rec.dst_ip);
        let is_syn = rec.tcp_flags & TCP_SYN != 0;
        let mut anomaly_flags = 0;
        if !is_syn {
            // 无 SYN 即入中流：HALF_OPEN（方向标签可能交换，但 5-tuple 集合一致）。
            anomaly_flags |= anomaly::HALF_OPEN;
        }
        ConnRt {
            state: ConnState {
                state: ConnStateKind::HalfOpen as u8,
                client_ip: src_ip,
                client_port: rec.src_port,
                server_ip: dst_ip,
                server_port: rec.dst_port,
                proto: rec.proto as u8,
                first_ts: rec.timestamp_ns,
                last_ts: rec.timestamp_ns,
                anomaly_flags,
                meta_bind_id: -1,
                ..Default::default()
            },
        }
    }
}

/// PENDING 命中项（消费/级联/重代共用）。
#[derive(Debug, Clone)]
struct PendingHit {
    key: Vec<u8>,
    q_first_idx: u64,
    q_ts: u64,
}

/// P3 匹配引擎：一个 Batch = 双 env 双写事务（09 §13.4，epoch 先行提交）。
pub struct QrMatcher<'e> {
    live_dbs: [Database<Bytes, Bytes>; crate::db::NUM_LIVE_DBIS],
    epoch_dbs: [Database<Bytes, Bytes>; crate::db::NUM_EPOCH_DBIS],
    live_txn: heed::RwTxn<'e>,
    epoch_txn: heed::RwTxn<'e>,
    ack_tol: u32,
    /// 批内连接热状态缓存（load-modify-write，同 txn，杜绝内存/LMDB 双态漂移）。
    conns: HashMap<u64, ConnRt>,
    anomalies: Vec<AnomalyEvent>,
    /// P5：MetaBind 注册表（可选）。命中规则 → 连接绑定 + 提取请求键；None = P3 旧行为（32B 前缀键）。
    meta: Option<&'e MetaRegistry>,
    /// P5：连接首次绑定收集的协议指纹（低频），供调用方落 ext_meta 台账。
    ext_meta: Vec<ExtMetaEvent>,
}

impl<'e> QrMatcher<'e> {
    pub fn begin(reg: &'e DbRegistry, params: &QrParams) -> Result<QrMatcher<'e>> {
        QrMatcher::begin_with_meta(reg, params, None)
    }

    /// P5：带 MetaRegistry 的匹配引擎（首载荷绑定连接 + 协议键/伪键提取）。
    pub fn begin_with_meta<'a>(
        reg: &'a DbRegistry,
        params: &QrParams,
        meta: Option<&'a MetaRegistry>,
    ) -> Result<QrMatcher<'a>> {
        let live_txn = reg.live_write_txn()?;
        let epoch_txn = reg.epoch_write_txn()?;
        Ok(QrMatcher {
            live_dbs: *reg.live_dbs(),
            epoch_dbs: *reg.epoch_dbs(),
            live_txn,
            epoch_txn,
            ack_tol: params.ack_tolerance,
            conns: HashMap::new(),
            anomalies: Vec::new(),
            meta,
            ext_meta: Vec::new(),
        })
    }

    /// 提交：写回全部连接热状态（live）→ epoch 先行 → live 殿后 → 返回审计事件（调用方落 SQLite）。
    pub fn commit(mut self) -> Result<Vec<AnomalyEvent>> {
        self.writeback_conns()?;
        self.epoch_txn.commit()?;
        self.live_txn.commit()?;
        Ok(self.anomalies)
    }

    /// P5：本批收集的连接级 EXT META 指纹事件（commit 前读取）。
    pub fn ext_meta_events(&self) -> &[ExtMetaEvent] {
        &self.ext_meta
    }

    /// 处理一条报文：RECORD_TS 确定性索引（epoch，P2）+ 连接状态机 + QR 匹配（P3），双 txn。
    pub fn ingest(&mut self, r: &IndexedRecord) -> Result<()> {
        // P2 兼容：RECORD_TS 逐条确定性索引（epoch，NO_OVERWRITE 幂等，重放收敛依据）。
        {
            let db = self.epoch_dbs[EPOCH_RECORD_TS];
            let key = k_record_ts(r.rec.timestamp_ns, r.idx());
            let val = v_record_summary_encode(&RecordSummary::from(&r.rec));
            put_no_overwrite(&db, &mut self.epoch_txn, &key, &val)?;
        }

        let rec = &r.rec;
        if rec.proto != 6 {
            return Ok(()); // 仅 TCP 参与 QR 匹配（UDP 只进 RECORD_TS）。
        }

        let (h, dir) = self.locate(rec, r.dev_id)?;
        let mut st = self.conns.get_mut(&h).unwrap().state;

        let is_syn = rec.tcp_flags & TCP_SYN != 0;
        let is_ack = rec.tcp_flags & TCP_ACK != 0;
        let is_rst = rec.tcp_flags & TCP_RST != 0;
        let is_fin = rec.tcp_flags & TCP_FIN != 0;
        let wire_len = rec.orig_payload_len;

        // ① 代际边界检测（v0.5 定论：数据流回绕与控制面重代物理解耦）：
        //    - 自然回绕（非 SYN）：无论 Raw SEQ 跳变幅度多大，绝对不触发重代/不清 PENDING——
        //      `SeqStream::feed_packet` 的 wrapping_sub 统一映射为单调 u48 abs；
        //      不可解释的大跳变仅标记 `anomaly_flags |= SEQ_GAP`。
        //    - 控制面重写（SYN==1）：仅当捕获到新 SYN 且 `syn_pkt_idx` 校验为新报文
        //      （非本代际 SYN 重传、非崩溃重放）时触发——同 RW_TXN 原子完成
        //      代际 +1、翻译器重置（last_raw=ISN,last_abs=ISN）、旧代际 PENDING 批量
        //      翻转 UNMATCHED + pending/TTL 清除（B+ 树 Key 前缀物理隔离幽灵包）。
        let (sc0, ss0) = (
            SeqStream::from_state(&st, true),
            SeqStream::from_state(&st, false),
        );
        let cur = if dir == Dir::C2S { &sc0 } else { &ss0 };
        let d = cur.diff(rec.tcp_seq);
        let in_handshake = matches!(st.state, 0 | 1); // SynSent=0 SynRcvd=1
        let dead_state = matches!(st.state, 3..=5); // Closed=3 Reset=4 Timeout=5
        let epoch_triggered = cur.active
            && is_syn
            && !in_handshake
            && (d != 0 || dead_state)
            && r.idx() != st.syn_pkt_idx;
        if !is_syn && i64::from(d).abs() > i64::from(EPOCH_JUMP_THRESHOLD) {
            // 数据流不可解释大跳变：仅标记，绝不重代。
            st.anomaly_flags |= anomaly::SEQ_GAP;
        }

        if epoch_triggered {
            self.flip_epoch(h, rec, dir, r.idx())?;
            st = self.conns.get_mut(&h).unwrap().state;
        }

        // ② RST 级联：当前代际 PENDING → RST_ABORT（同 txn，不留超时）。
        if is_rst {
            self.rst_cascade(h, &mut st, rec)?;
            st.state = ConnStateKind::Reset as u8;
            st.rst_seen = rec.timestamp_ns;
            st.anomaly_flags |= anomaly::RESET;
            self.persist_state(h, &st);
            return Ok(());
        }

        let mut stream_c = SeqStream::from_state(&st, true);
        let mut stream_s = SeqStream::from_state(&st, false);

        // ③ 序列推进（abs 翻译，wrap-proof）。
        let (abs_start, wire_new) = if dir == Dir::C2S {
            stream_c.feed_packet(rec.tcp_seq, wire_len)
        } else {
            stream_s.feed_packet(rec.tcp_seq, wire_len)
        };

        // ④ 连接状态机推进。
        if is_syn && dir == Dir::C2S {
            st.state = ConnStateKind::SynSent as u8;
            st.syn_seen = rec.timestamp_ns;
            st.anomaly_flags |= anomaly::SYN_SEEN;
            st.syn_pkt_idx = r.idx(); // 当前代际 SYN 标识（重放/重代判定锚点）。
        } else if is_syn && dir == Dir::S2C {
            if st.state == ConnStateKind::SynSent as u8 {
                st.state = ConnStateKind::SynRcvd as u8;
            }
            st.synack_seen = rec.timestamp_ns;
        } else if is_ack && dir == Dir::C2S && st.state == ConnStateKind::SynRcvd as u8 {
            st.state = ConnStateKind::Established as u8;
        }
        if is_fin {
            st.fin_seen = rec.timestamp_ns;
            st.anomaly_flags |= anomaly::FIN_SEEN;
        }

        // ⑤ 连接计数。
        st.last_ts = rec.timestamp_ns;
        if dir == Dir::C2S {
            st.pkts_c += 1;
            st.bytes_c = st.bytes_c.saturating_add(wire_len as u64);
        } else {
            st.pkts_s += 1;
            st.bytes_s = st.bytes_s.saturating_add(wire_len as u64);
        }

        // ⑥ Q / R：Q=客户端载荷（开 PENDING），R=服务端 ack（累积消费）。
        if dir == Dir::C2S {
            if wire_len > 0 {
                if wire_new > 0 {
                    let abs_end = abs_start.saturating_add(wire_new as u64);
                    if abs_end > st.consumed_ack_s {
                        self.open_q(h, &mut st, r, abs_start, abs_end)?;
                    } else {
                        // 已确认区重传：仅计数（网络天气，不逐包入库）。
                        st.anomaly_flags |= anomaly::RETRANS;
                    }
                } else {
                    st.anomaly_flags |= anomaly::RETRANS;
                }
            }
        } else {
            // R.ack 属 c→s 数空间：只读翻译，不推进 c→s 流基线。
            let abs_ack = stream_c.abs_of(rec.tcp_ack);
            if wire_new > 0 {
                st.resp_cnt += 1;
            }
            // 越窗 ACK（超出流头合理领先）→ 旧代际幽灵包/异常，仅计数，不推进 consumed。
            if abs_ack > st.consumed_ack_s
                && abs_ack <= stream_c.last_abs.saturating_add(ACK_LEAD_CAP)
            {
                self.consume_r(h, &mut st, r, abs_ack)?;
            }
        }

        // ⑦ 翻译器状态持久化回 st（跨批/跨文件慢路径 wrap 正确）。
        st.last_raw_c = stream_c.last_raw;
        st.abs_seq_c = stream_c.last_abs;
        st.set_active_c(stream_c.active);
        st.last_raw_s = stream_s.last_raw;
        st.abs_seq_s = stream_s.last_abs;
        st.set_active_s(stream_s.active);

        self.persist_state(h, &st);
        Ok(())
    }

    /// 定位连接：先查缓存/LMDB 的 h_f（src=client），再查 h_b；全无则新建（src 为 client）。
    fn locate(&mut self, rec: &WalRecord, dev_id: u32) -> Result<(u64, Dir)> {
        let src_ip = u32::from_be_bytes(rec.src_ip);
        let dst_ip = u32::from_be_bytes(rec.dst_ip);
        let proto = rec.proto as u8;
        let h_f = conn_hash(dev_id, src_ip, rec.src_port, dst_ip, rec.dst_port, proto);
        let h_b = conn_hash(dev_id, dst_ip, rec.dst_port, src_ip, rec.src_port, proto);
        if self.load_conn(h_f)? {
            return Ok((h_f, Dir::C2S));
        }
        if self.load_conn(h_b)? {
            return Ok((h_b, Dir::S2C));
        }
        self.conns.insert(h_f, ConnRt::fresh(h_f, rec));
        Ok((h_f, Dir::C2S))
    }

    /// 缓存/LMDB 加载连接热状态（live 库，存在返回 true）。
    fn load_conn(&mut self, h: u64) -> Result<bool> {
        if self.conns.contains_key(&h) {
            return Ok(true);
        }
        let db = self.live_dbs[LIVE_CONN_STATE];
        let got = db.get(&self.live_txn, &k_conn_state(h))?;
        if let Some(v) = got {
            if let Some(st) = ConnState::from_bytes(v) {
                self.conns.insert(h, ConnRt { state: st });
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Q 打开：PENDING QRPAIR → live；次级索引（CONN_QR/QR_KEY/QR_TIME/PACKET_QR）→ epoch 纯追加。
    /// 次级索引 value 不存 status（§13.4.1），Q 打开写一次、永不更新。
    fn open_q(
        &mut self,
        h: u64,
        st: &mut ConnState,
        r: &IndexedRecord,
        abs_start: u64,
        abs_end: u64,
    ) -> Result<()> {
        let q_first_idx = r.idx();
        // P5：请求键提取（MetaBind 绑定连接 + 协议键/伪键）。首载荷评估绑定连接；
        // 已绑定 → 按 protocol_hint 复用提取器；无 MetaRegistry → P3 兼容（32B 前缀键）。
        let (req_key, pseudo) = if let Some(mr) = self.meta {
            if st.meta_bind_id < 0 {
                let b = mr.bind_and_extract(&r.rec.payload, r.rec.proto as u8, r.rec.dst_port);
                st.meta_bind_id = b.meta_bind_id;
                st.protocol_hint = b.protocol_hint;
                if st.protocol_hint != ProtocolKind::Unknown as u8 {
                    let fp = crate::meta::fingerprint(&r.rec.payload);
                    self.ext_meta.push(ExtMetaEvent {
                        conn_hash: h,
                        protocol_hint: st.protocol_hint,
                        dst_port: r.rec.dst_port,
                        magic_prefix: fp.magic_prefix,
                        entropy: fp.entropy,
                        has_fixed_header: fp.has_fixed_header,
                    });
                }
                (b.key, if b.pseudo { 1 } else { 0 })
            } else {
                let kind = ProtocolKind::from_u8(st.protocol_hint);
                let k = crate::meta::extract_key(&r.rec.payload, kind);
                (k.key, if k.pseudo { 1 } else { 0 })
            }
        } else {
            (req_key_of(&r.rec), 0)
        };
        let pair = QrPairValue {
            status: QrStatus::Pending as u8,
            conn_hash: h,
            q_ts: r.rec.timestamp_ns,
            r_ts: 0,
            latency_ms: 0,
            q_len: r.rec.orig_payload_len,
            r_len: 0,
            abs_q_seq: abs_start,
            abs_q_end: abs_end,
            pseudo,
            q_idx: vec![q_first_idx],
            r_idx: Vec::new(),
            req_key,
            resp_key: Vec::new(),
        };
        let inc = st.incarnation;

        // live：在途 QR_PAIR(PENDING) + QR_PENDING + PENDING_TTL。
        let dbp = self.live_dbs[LIVE_QR_PAIR];
        put_no_overwrite(
            &dbp,
            &mut self.live_txn,
            &k_qr_pair(q_first_idx),
            &pair.encode(),
        )?;

        let dpp = self.live_dbs[LIVE_QR_PENDING];
        put_no_overwrite(
            &dpp,
            &mut self.live_txn,
            &k_qr_pending(h, inc, abs_end),
            &v_qr_pending_encode(q_first_idx, pair.q_ts, pair.q_len),
        )?;

        let dtt = self.live_dbs[LIVE_PENDING_TTL];
        put_no_overwrite(
            &dtt,
            &mut self.live_txn,
            &k_pending_ttl(pair.q_ts, h),
            &v_pending_ttl_encode(q_first_idx, abs_end),
        )?;

        // epoch：次级索引纯追加（§13.4.1，value=q_first_idx 定位，无 status）。
        let dpq = self.epoch_dbs[EPOCH_PACKET_QR];
        put_no_overwrite(
            &dpq,
            &mut self.epoch_txn,
            &k_packet_qr(q_first_idx),
            &v_packet_qr_enc(q_first_idx),
        )?;

        let kh = crate::connection::fnv1a64(&pair.req_key);
        let sec = v_secondary_encode(q_first_idx);
        let dcq = self.epoch_dbs[EPOCH_CONN_QR];
        put_no_overwrite(
            &dcq,
            &mut self.epoch_txn,
            &k_conn_qr(h, pair.q_ts, q_first_idx),
            &sec,
        )?;
        let dqk = self.epoch_dbs[EPOCH_QR_KEY];
        put_no_overwrite(
            &dqk,
            &mut self.epoch_txn,
            &k_qr_key(kh, pair.q_ts, q_first_idx),
            &sec,
        )?;
        let dqt = self.epoch_dbs[EPOCH_QR_TIME];
        put_no_overwrite(
            &dqt,
            &mut self.epoch_txn,
            &k_qr_time(pair.q_ts, q_first_idx),
            &sec,
        )?;

        st.req_cnt += 1;
        st.qr_open += 1;
        Ok(())
    }

    /// R 累积 ACK 消费：范围扫描 [conn][inc][0..=abs_ack+tol]，命中翻转 MATCHED 并迁移到 epoch；
    /// 批量 ACK 命中多个 Q → 聚合进首个 QRPAIR 的 q_idx_list（重放不重复注入同一响应）。
    fn consume_r(
        &mut self,
        h: u64,
        st: &mut ConnState,
        r: &IndexedRecord,
        abs_ack: u64,
    ) -> Result<()> {
        let inc = st.incarnation;
        let limit = abs_ack.saturating_add(self.ack_tol as u64);
        let hits = self.scan_pending_upto(h, inc, limit)?;
        if hits.is_empty() {
            st.consumed_ack_s = abs_ack.max(st.consumed_ack_s);
            return Ok(());
        }

        for (i, hit) in hits.iter().enumerate() {
            let primary = i == 0;
            let migrated = self.migrate_terminal(hit.q_first_idx, |pair| {
                pair.status = QrStatus::Matched as u8;
                pair.r_ts = r.rec.timestamp_ns;
                pair.latency_ms = pair.r_ts.saturating_sub(pair.q_ts) / 1_000_000;
                pair.r_len = pair.r_len.saturating_add(r.rec.orig_payload_len);
                pair.r_idx.push(r.idx());
                if primary {
                    // 批量 ACK 聚合：后续挂起 Q 并入 primary 的 q_idx_list。
                    pair.resp_key = req_key_of(&r.rec);
                    for other in hits.iter().skip(1) {
                        if !pair.q_idx.contains(&other.q_first_idx) {
                            pair.q_idx.push(other.q_first_idx);
                        }
                    }
                }
            })?;

            // live 残留清理（幂等）：QR_PENDING + PENDING_TTL。
            let dpp = self.live_dbs[LIVE_QR_PENDING];
            dpp.delete(&mut self.live_txn, &hit.key)?;
            let dtt = self.live_dbs[LIVE_PENDING_TTL];
            dtt.delete(&mut self.live_txn, &k_pending_ttl(hit.q_ts, h))?;
            // 实际迁移（非重放跳过）才递减 qr_open；writeback 时按 live QR_PENDING 计数兜底校准。
            if migrated {
                st.qr_open = st.qr_open.saturating_sub(1);
            }
        }
        st.consumed_ack_s = abs_ack.max(st.consumed_ack_s);
        Ok(())
    }

    /// 代际边界原子切换：旧代际 PENDING → UNMATCHED（迁移到 epoch）+ 清理；代际 +1；双向翻译器重置。
    fn flip_epoch(&mut self, h: u64, rec: &WalRecord, dir: Dir, syn_idx: u64) -> Result<()> {
        let old_inc = self.conns.get(&h).unwrap().state.incarnation;
        let hits = self.scan_pending_upto(h, old_inc, U48_MAX)?;
        for hit in &hits {
            self.migrate_terminal(hit.q_first_idx, |pair| {
                pair.status = QrStatus::Unmatched as u8;
            })?;
            // P4：终态事件逐 Q 串接审计台账（可回跳原文，不丢失基因锚）。
            self.anomalies.push(AnomalyEvent {
                ts: rec.timestamp_ns as i64,
                kind: ANOM_QR_UNMATCHED,
                dev_id: None,
                segment_seq: None,
                conn_hash: Some(h.to_be_bytes().to_vec()),
                qr_id: Some(hit.q_first_idx as i64),
                detail: Some(format!("epoch={} gen_flip", old_inc)),
            });
            let dpp = self.live_dbs[LIVE_QR_PENDING];
            dpp.delete(&mut self.live_txn, &hit.key)?;
            let dtt = self.live_dbs[LIVE_PENDING_TTL];
            dtt.delete(&mut self.live_txn, &k_pending_ttl(hit.q_ts, h))?;
        }

        let st = &mut self.conns.get_mut(&h).unwrap().state;
        st.incarnation = st.incarnation.wrapping_add(1);
        // P4 修复：旧代际 PENDING 已全量清退，qr_open（L1 预算/审计口径）必须归零，
        // 否则跨代际累积虚高 → 新代际无辜触发 CONN_QR_FLOOD 内部检疫。
        st.qr_open = 0;
        // 新代际 SYN 标识：SYN 触发 → 本报文；裸跳变触发 → 0（无 SYN 建立）。
        st.syn_pkt_idx = if rec.tcp_flags & TCP_SYN != 0 {
            syn_idx
        } else {
            0
        };
        if dir == Dir::C2S {
            // c→s 基线 = 本包（SYN）seq；s→c 待首个包激活。
            st.last_raw_c = rec.tcp_seq;
            st.abs_seq_c = rec.tcp_seq as u64;
            st.set_active_c(true);
            st.last_raw_s = 0;
            st.abs_seq_s = 0;
            st.set_active_s(false);
        } else {
            st.last_raw_s = rec.tcp_seq;
            st.abs_seq_s = rec.tcp_seq as u64;
            st.set_active_s(true);
            st.last_raw_c = 0;
            st.abs_seq_c = 0;
            st.set_active_c(false);
        }
        st.state = ConnStateKind::HalfOpen as u8; // 新代际从握手重启。
        st.consumed_ack_c = 0; // 新代际新数空间：消费基准归零，杜绝旧空间幽灵 ack 污染。
        st.consumed_ack_s = 0;

        let detail = if rec.tcp_flags & TCP_SYN != 0 {
            "EPOCH_REBIRTH_SYN"
        } else {
            "EPOCH_REBIRTH_JUMP"
        };
        self.anomalies.push(AnomalyEvent {
            ts: rec.timestamp_ns as i64,
            kind: ANOM_EPOCH_REBIRTH,
            dev_id: None,
            segment_seq: None,
            conn_hash: Some(h.to_be_bytes().to_vec()),
            qr_id: None,
            detail: Some(format!("{} pending={}", detail, hits.len())),
        });
        Ok(())
    }

    /// RST 级联：当前代际全部 PENDING → RST_ABORT（迁移到 epoch，08 §5.4，不留超时）。
    fn rst_cascade(&mut self, h: u64, st: &mut ConnState, rec: &WalRecord) -> Result<()> {
        let inc = st.incarnation;
        let hits = self.scan_pending_upto(h, inc, U48_MAX)?;
        for hit in &hits {
            self.migrate_terminal(hit.q_first_idx, |pair| {
                pair.status = QrStatus::RstAbort as u8;
            })?;
            // P4：终态事件逐 Q 串接审计台账。
            self.anomalies.push(AnomalyEvent {
                ts: rec.timestamp_ns as i64,
                kind: ANOM_QR_RST_ABORT,
                dev_id: None,
                segment_seq: None,
                conn_hash: Some(h.to_be_bytes().to_vec()),
                qr_id: Some(hit.q_first_idx as i64),
                detail: Some(format!("inc={} rst_cascade", inc)),
            });
            let dpp = self.live_dbs[LIVE_QR_PENDING];
            dpp.delete(&mut self.live_txn, &hit.key)?;
            let dtt = self.live_dbs[LIVE_PENDING_TTL];
            dtt.delete(&mut self.live_txn, &k_pending_ttl(hit.q_ts, h))?;
        }
        st.qr_open = st.qr_open.saturating_sub(hits.len() as u64);
        self.anomalies.push(AnomalyEvent {
            ts: rec.timestamp_ns as i64,
            kind: ANOM_CONN_RST,
            dev_id: None,
            segment_seq: None,
            conn_hash: Some(h.to_be_bytes().to_vec()),
            qr_id: None,
            detail: Some(format!("RST cascade pending={}", hits.len())),
        });
        Ok(())
    }

    /// QR_PAIR 在途→终态迁移（09 §13.4.2 幂等规则，五条终态路径统一实现）：
    ///
    /// ```text
    /// 崩溃窗口                 重放时的状态              重放动作
    /// ─────────────────────────────────────────────────────────────────
    /// 迁移前崩溃              live 有 PENDING            正常迁移
    /// 写 epoch 后、删 live 前  live 有 PENDING           先查 epoch：已有 → 跳过迁移（幂等）
    ///                          epoch 已有终态            再删 live 残留
    /// 删 live 后、水位线前       live 无、epoch 有终态     已收敛，水位线推进即完成
    /// ```
    ///
    /// - 先查 epoch：已有终态 → 跳过迁移（不重复写），返回 false；
    /// - 不存在 → 读 live(PENDING) → `flip` 变更终态字段 → 写 epoch（NO_OVERWRITE）→ 删 live，返回 true。
    fn migrate_terminal<F>(&mut self, q_first_idx: u64, flip: F) -> Result<bool>
    where
        F: FnOnce(&mut QrPairValue),
    {
        let kp = k_qr_pair(q_first_idx);

        // ① 幂等判定：先查 epoch（历史库追加后只读，已有终态则不再写）。
        if self.epoch_dbs[EPOCH_QR_PAIR]
            .get(&self.epoch_txn, &kp)?
            .is_some()
        {
            // 仅清理 live 残留（幂等）。
            self.live_dbs[LIVE_QR_PAIR].delete(&mut self.live_txn, &kp)?;
            return Ok(false);
        }

        // ② 读 live(PENDING)。
        let Some(v) = self.live_dbs[LIVE_QR_PAIR].get(&self.live_txn, &kp)? else {
            return Ok(false); // 主键缺失（幂等）。
        };
        let Some(mut pair) = QrPairValue::decode(v) else {
            return Ok(false);
        };
        if pair.status != QrStatus::Pending as u8 {
            return Ok(false); // 已终态（幂等重放）。
        }

        flip(&mut pair);

        // ③ 写 epoch（NO_OVERWRITE 幂等）+ ④ 删 live。
        put_no_overwrite(
            &self.epoch_dbs[EPOCH_QR_PAIR],
            &mut self.epoch_txn,
            &kp,
            &pair.encode(),
        )?;
        self.live_dbs[LIVE_QR_PAIR].delete(&mut self.live_txn, &kp)?;
        Ok(true)
    }

    /// 范围扫描 live QR_PENDING：[conn][inc] 前缀下 abs_q_end ≤ limit 的全部 PENDING。
    fn scan_pending_upto(&self, h: u64, inc: u16, abs_limit: u64) -> Result<Vec<PendingHit>> {
        let db = self.live_dbs[LIVE_QR_PENDING];
        let lo = k_qr_pending_prefix(h, inc);
        let hi = k_qr_pending(h, inc, abs_limit.min(U48_MAX));
        let mut out = Vec::new();
        let range = (Bound::Included(lo.as_slice()), Bound::Included(hi.as_slice()));
        let rng = db.range(&self.live_txn, &range)?;
        for item in rng {
            let (k, v) = item?;
            if let Some((q_first_idx, q_ts, _)) = v_qr_pending_decode(v) {
                out.push(PendingHit {
                    key: k.to_vec(),
                    q_first_idx,
                    q_ts,
                });
            }
        }
        Ok(out)
    }

    fn persist_state(&mut self, h: u64, st: &ConnState) {
        self.conns.get_mut(&h).unwrap().state = *st;
    }

    /// 写回连接热状态（live 库）。qr_open 以「live QR_PENDING 行数」兜底校准：
    /// 崩溃窗口下增量递减可能漂移，但 QR_PENDING 是"在途"的单一真源，重算即幂等收敛。
    fn writeback_conns(&mut self) -> Result<()> {
        let db = self.live_dbs[LIVE_CONN_STATE];
        let mut keys: Vec<u64> = self.conns.keys().copied().collect();
        keys.sort_unstable();
        for h in keys {
            let mut st = self.conns.get(&h).unwrap().state;
            st.qr_open = self.count_live_pending(h)?;
            db.put(&mut self.live_txn, &k_conn_state(h), &st.to_bytes())?;
        }
        Ok(())
    }

    /// 统计某连接全部代际的 live QR_PENDING 行数（qr_open 真源）。
    fn count_live_pending(&self, h: u64) -> Result<u64> {
        let db = self.live_dbs[LIVE_QR_PENDING];
        let mut lo = [0u8; 16];
        lo[0..8].copy_from_slice(&h.to_be_bytes());
        let mut hi = [0u8; 16];
        hi[0..8].copy_from_slice(&h.to_be_bytes());
        hi[8..].fill(0xFF);
        let range = (Bound::Included(lo.as_slice()), Bound::Included(hi.as_slice()));
        let n = db.range(&self.live_txn, &range)?.count() as u64;
        Ok(n)
    }
}

/// Req_KEY 种子：载荷前 32 字节（L7 解码器 P5 引入；P3 起保证可确定性回溯）。
fn req_key_of(rec: &WalRecord) -> Vec<u8> {
    let n = rec.payload.len().min(32);
    rec.payload[..n].to_vec()
}

/// PACKET_QR value（q_first_idx 8B BE，与 §13.4.1 次级索引 value 语义一致）。
fn v_packet_qr_enc(q_first_idx: u64) -> [u8; 8] {
    q_first_idx.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::LIVE_QR_PAIR;
    use sov_probe::wal::header::TCP_ACK;
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
        let p = std::env::temp_dir().join(format!("sovvault-qr-{}-{}", tag, ts));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[allow(clippy::too_many_arguments)] // 测试报文构造器，8 参数直白。
    fn pkt(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8, seq: u32, ack: u32, payload: &[u8]) -> WalRecord {
        WalRecord {
            timestamp_ns: seq as u64,
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

    fn c2s(seq: u32, ack: u32, payload: &[u8]) -> WalRecord {
        pkt(CIP, SIP, CPORT, SPORT, TCP_ACK, seq, ack, payload)
    }

    fn s2c(seq: u32, ack: u32, payload: &[u8]) -> WalRecord {
        pkt(SIP, CIP, SPORT, CPORT, TCP_ACK, seq, ack, payload)
    }

    struct Offset(u32);
    impl Offset {
        fn next(&mut self, r: &WalRecord) -> u32 {
            let o = self.0;
            self.0 += 64 + r.payload.len() as u32;
            o
        }
    }

    fn run(reg: &DbRegistry, params: &QrParams, recs: &[(WalRecord, u32)]) -> Vec<AnomalyEvent> {
        let mut m = QrMatcher::begin(reg, params).unwrap();
        for (rec, off) in recs {
            let r = IndexedRecord {
                dev_id: 1,
                file_id: 1,
                offset: *off,
                rec: rec.clone(),
            };
            m.ingest(&r).unwrap();
        }
        m.commit().unwrap()
    }

    fn ch() -> u64 {
        conn_hash(1, u32::from_be_bytes(CIP), CPORT, u32::from_be_bytes(SIP), SPORT, 6)
    }

    fn pair_at(reg: &DbRegistry, q_first_idx: u64) -> Option<QrPairValue> {
        reg.qr_pair_at(q_first_idx).unwrap()
    }

    fn pending_len(reg: &DbRegistry, h: u64, inc: u16) -> u64 {
        let txn = reg.live_read_txn().unwrap();
        let db = reg.live_dbs()[LIVE_QR_PENDING];
        let lo = k_qr_pending_prefix(h, inc);
        let hi = k_qr_pending(h, inc, U48_MAX);
        let range = (Bound::Included(lo.as_slice()), Bound::Included(hi.as_slice()));
        db.range(&txn, &range).unwrap().count() as u64
    }

    fn conn_state_at(reg: &DbRegistry, h: u64) -> ConnState {
        let txn = reg.live_read_txn().unwrap();
        let v = reg.live_dbs()[LIVE_CONN_STATE]
            .get(&txn, &k_conn_state(h))
            .unwrap()
            .unwrap();
        ConnState::from_bytes(v).unwrap()
    }

    fn qr_pair_count(reg: &DbRegistry) -> u64 {
        reg.qr_pair_count().unwrap()
    }

    /// 终态 QR_PAIR 应迁移到 epoch 库（§13.3），live 库仅留在途 PENDING。
    #[test]
    fn terminal_migrates_to_epoch_and_live_holds_pending_only() {
        let dir = tmpdir("migrate");
        let reg = DbRegistry::open(&dir.join("qridx"), 10 * 1024 * 1024).unwrap();
        let params = QrParams::default();
        let mut o = Offset(0);
        // 握手 + Q1（PENDING 留 live）。
        let q = c2s(1001, 5001, b"GET /a");
        let q_idx = (1u64 << 32) | o.next(&q) as u64;
        run(
            &reg,
            &params,
            &[
                (pkt(CIP, SIP, CPORT, SPORT, TCP_SYN, 1000, 0, b""), o.next(&c2s(1000, 0, b""))),
                (pkt(SIP, CIP, SPORT, CPORT, TCP_SYN | TCP_ACK, 5000, 1001, b""), o.next(&s2c(5000, 1001, b""))),
                (q.clone(), q_idx as u32),
            ],
        );
        // PENDING 在 live，epoch 无该行。
        let lt = reg.live_read_txn().unwrap();
        assert!(reg.live_dbs()[LIVE_QR_PAIR]
            .get(&lt, &k_qr_pair(q_idx))
            .unwrap()
            .is_some());
        drop(lt);
        let et = reg.epoch_read_txn().unwrap();
        assert!(reg.epoch_dbs()[EPOCH_QR_PAIR]
            .get(&et, &k_qr_pair(q_idx))
            .unwrap()
            .is_none());
        drop(et);

        // R 消费 → 终态 MATCHED 迁移到 epoch；live 行已删。
        let r = s2c(5001, 1007, b"200");
        let r_idx = (1u64 << 32) | o.next(&r) as u64;
        run(&reg, &params, &[(r, r_idx as u32)]);
        let lt = reg.live_read_txn().unwrap();
        assert!(reg.live_dbs()[LIVE_QR_PAIR]
            .get(&lt, &k_qr_pair(q_idx))
            .unwrap()
            .is_none());
        drop(lt);
        let p = pair_at(&reg, q_idx).unwrap();
        assert_eq!(p.status, QrStatus::Matched as u8);
        assert_eq!(p.r_idx, vec![r_idx]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seq_stream_wrap_retransmit_and_abs_of() {
        let mut s = SeqStream { last_raw: 0, last_abs: 0, active: false };
        // 首包基线
        let (a, w) = s.feed_packet(0xFFFF_FFF0, 32);
        assert_eq!((a, w), (0xFFFF_FFF0, 32));
        // wrap 前向：0xFFFF_FFF0 → 0x0000_0010 = +32
        let (a, w) = s.feed_packet(0x0000_0010, 16);
        assert_eq!((a, w), (0x1_0000_0010, 16));
        // 完全重复 → wire_new=0
        let (a, w) = s.feed_packet(0x0000_0010, 16);
        assert_eq!(w, 0);
        assert_eq!(a, 0x1_0000_0020);
        // 部分重叠尾部 [0x0F..0x2F)：head=0x20，新尾部 0x20..0x2F = 15B
        let (a, w) = s.feed_packet(0x0000_000F, 32);
        assert_eq!(w, 15);
        assert_eq!(a, 0x1_0000_0020);
        // abs_of：Ack 落在流头附近
        let _ = s.abs_of(0x0000_0020);
        // d 检测：随机 ISN 跳变（非 wrap 大跳）必须显见
        let d = s.diff(0xABCD_0000);
        assert!(i64::from(d).abs() > i64::from(EPOCH_JUMP_THRESHOLD));
    }

    #[test]
    fn handshake_qr_match() {
        let dir = tmpdir("handshake");
        let reg = DbRegistry::open(&dir.join("qridx"), 10 * 1024 * 1024).unwrap();
        let params = QrParams::default();
        let mut o = Offset(0);
        // SYN c2s seq=1000；SYN+ACK s2c seq=5000 ack=1001；ACK c2s seq=1001 ack=5001
        let recs = vec![
            (pkt(CIP, SIP, CPORT, SPORT, TCP_SYN, 1000, 0, b""), o.next(&c2s(1000, 0, b""))),
            (pkt(SIP, CIP, SPORT, CPORT, TCP_SYN | TCP_ACK, 5000, 1001, b""), o.next(&s2c(5000, 1001, b""))),
            (c2s(1001, 5001, b""), o.next(&c2s(1001, 5001, b""))),
            (c2s(1001, 5001, b"GET /a"), o.next(&c2s(1001, 5001, b"GET /a"))),
            (s2c(5001, 1011, b"HTTP/1.1 200"), o.next(&s2c(5001, 1011, b"HTTP/1.1 200"))),
        ];
        let q_idx = recs[3].1 as u64 | (1u64 << 32);
        let r_idx = recs[4].1 as u64 | (1u64 << 32);
        run(&reg, &params, &recs);
        let h = ch();
        let cs = conn_state_at(&reg, h);
        assert_eq!(cs.state, ConnStateKind::Established as u8);
        assert_eq!(cs.req_cnt, 1);
        assert_eq!(cs.resp_cnt, 1);
        assert_eq!(cs.qr_open, 0);
        assert_eq!(pending_len(&reg, h, 0), 0);
        let p = pair_at(&reg, q_idx).unwrap();
        assert_eq!(p.status, QrStatus::Matched as u8);
        assert_eq!(p.abs_q_end, 1001 + 6); // 1001..1007
        assert_eq!(p.r_idx, vec![r_idx]);
        assert_eq!(p.q_idx, vec![q_idx]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pipelining_batched_ack_aggregates() {
        let dir = tmpdir("pipeline");
        let reg = DbRegistry::open(&dir.join("qridx"), 10 * 1024 * 1024).unwrap();
        let params = QrParams::default();
        let mut o = Offset(0);
        let mut recs = vec![(c2s(1001, 5001, b""), 0)];
        recs.clear();
        // 握手
        recs.push((pkt(CIP, SIP, CPORT, SPORT, TCP_SYN, 1000, 0, b""), o.next(&c2s(1000, 0, b""))));
        recs.push((pkt(SIP, CIP, SPORT, CPORT, TCP_SYN | TCP_ACK, 5000, 1001, b""), o.next(&s2c(5000, 1001, b""))));
        recs.push((c2s(1001, 5001, b""), o.next(&c2s(1001, 5001, b""))));
        // 3 个流水 Q：seq 1001/1011/1021 各 10B
        let q1 = o.next(&c2s(1001, 5001, &[1u8; 10]));
        recs.push((c2s(1001, 5001, &[1u8; 10]), q1));
        let q2 = o.next(&c2s(1011, 5001, &[2u8; 10]));
        recs.push((c2s(1011, 5001, &[2u8; 10]), q2));
        let q3 = o.next(&c2s(1021, 5001, &[3u8; 10]));
        recs.push((c2s(1021, 5001, &[3u8; 10]), q3));
        // 单个累积 ACK ack=1031 覆盖全部
        let r1 = o.next(&s2c(5001, 1031, b"OK"));
        recs.push((s2c(5001, 1031, b"OK"), r1));
        run(&reg, &params, &recs);

        let h = ch();
        assert_eq!(pending_len(&reg, h, 0), 0);
        assert_eq!(qr_pair_count(&reg), 3); // 每 Q 一行
        let prim = pair_at(&reg, (1u64 << 32) | q1 as u64).unwrap();
        assert_eq!(prim.status, QrStatus::Matched as u8);
        assert_eq!(prim.q_idx.len(), 3); // 批量 ACK 聚合进 primary
        assert_eq!(prim.r_idx, vec![(1u64 << 32) | r1 as u64]);
        // 后继行也终态
        assert_eq!(pair_at(&reg, (1u64 << 32) | q2 as u64).unwrap().status, QrStatus::Matched as u8);
        assert_eq!(pair_at(&reg, (1u64 << 32) | q3 as u64).unwrap().status, QrStatus::Matched as u8);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cross_batch_slow_path() {
        let dir = tmpdir("slow");
        let reg = DbRegistry::open(&dir.join("qridx"), 10 * 1024 * 1024).unwrap();
        let params = QrParams::default();
        // 批 1：握手 + Q（Q 落 PENDING live，跨批待消费）
        let mut o = Offset(0);
        let q_rec = c2s(1001, 5001, b"GET /slow");
        let q_idx = (1u64 << 32) | o.next(&q_rec) as u64;
        run(
            &reg,
            &params,
            &[
                (pkt(CIP, SIP, CPORT, SPORT, TCP_SYN, 1000, 0, b""), o.next(&c2s(1000, 0, b""))),
                (pkt(SIP, CIP, SPORT, CPORT, TCP_SYN | TCP_ACK, 5000, 1001, b""), o.next(&s2c(5000, 1001, b""))),
                (q_rec.clone(), q_idx as u32),
            ],
        );
        let h = ch();
        assert_eq!(pending_len(&reg, h, 0), 1);
        assert_eq!(pair_at(&reg, q_idx).unwrap().status, QrStatus::Pending as u8);

        // 批 2：全新 matcher（重载连接状态），晚到 R 消费慢路径 Q。
        let r_rec = s2c(5001, 1010, b"late-200");
        let r_idx = (1u64 << 32) | 4096;
        run(&reg, &params, &[(r_rec, r_idx as u32)]);
        assert_eq!(pending_len(&reg, h, 0), 0);
        let p = pair_at(&reg, q_idx).unwrap();
        assert_eq!(p.status, QrStatus::Matched as u8);
        assert_eq!(p.r_idx, vec![r_idx]);
        assert_eq!(p.abs_q_end, 1001 + 9); // "GET /slow"=9B
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrap_case_qr_match() {
        let dir = tmpdir("wrap");
        let reg = DbRegistry::open(&dir.join("qridx"), 10 * 1024 * 1024).unwrap();
        let params = QrParams::default();
        let mut o = Offset(0);
        // 流头置于 wrap 前 32B 处：SYN seq=0xFFFF_FFE0，Q 落在 0xFFFF_FFF0（32B）
        // → abs_end 自然 wrap 到 0x1_0000_0010（绝对号连续，无模运算跳变）。
        let syn = pkt(CIP, SIP, CPORT, SPORT, TCP_SYN, 0xFFFF_FFE0, 0, b"");
        let syn_off = o.next(&syn);
        let q = c2s(0xFFFF_FFF0, 5001, &[7u8; 32]);
        let q_idx = (1u64 << 32) | o.next(&q) as u64;
        let r = s2c(5001, 0x0000_0010, b"ok"); // ack 恰为 wrap 后的下一 seq
        let r_idx = (1u64 << 32) | o.next(&r) as u64;
        run(
            &reg,
            &params,
            &[
                (syn, syn_off),
                (pkt(SIP, CIP, SPORT, CPORT, TCP_SYN | TCP_ACK, 5000, 0xFFFF_FFE1, b""), o.next(&s2c(5000, 1, b""))),
                (q.clone(), q_idx as u32),
                (r.clone(), r_idx as u32),
            ],
        );
        let h = ch();
        let p = pair_at(&reg, q_idx).unwrap();
        assert_eq!(p.status, QrStatus::Matched as u8);
        assert_eq!(p.abs_q_end, 0x1_0000_0010); // wrap 后绝对号连续
        assert_eq!(pending_len(&reg, h, 0), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn epoch_rebirth_flips_and_isolates_ghost() {
        let dir = tmpdir("epoch");
        let reg = DbRegistry::open(&dir.join("qridx"), 10 * 1024 * 1024).unwrap();
        let params = QrParams::default();
        let mut o = Offset(0);

        // 代际 0：握手 + Q（pending inc=0）
        let q0 = c2s(1001, 5001, b"GET /old");
        let q0_idx = (1u64 << 32) | o.next(&q0) as u64;
        run(
            &reg,
            &params,
            &[
                (pkt(CIP, SIP, CPORT, SPORT, TCP_SYN, 1000, 0, b""), o.next(&c2s(1000, 0, b""))),
                (pkt(SIP, CIP, SPORT, CPORT, TCP_SYN | TCP_ACK, 5000, 1001, b""), o.next(&s2c(5000, 1001, b""))),
                (q0.clone(), q0_idx as u32),
            ],
        );
        let h = ch();
        assert_eq!(pending_len(&reg, h, 0), 1);
        assert_eq!(conn_state_at(&reg, h).incarnation, 0);

        // 代际 1：同一 5-tuple 异窗新 SYN（随机 ISN）→ 强制重代。
        let new_isn = 0xABCD_1234u32;
        let a = run(
            &reg,
            &params,
            &[(pkt(CIP, SIP, CPORT, SPORT, TCP_SYN, new_isn, 0, b""), o.next(&c2s(1000, 0, b"")))],
        );
        // 旧 PENDING 立即 UNMATCHED（迁移 epoch）+ 清理（物理隔离），审计落一条。
        assert_eq!(pending_len(&reg, h, 0), 0);
        let p0 = pair_at(&reg, q0_idx).unwrap();
        assert_eq!(p0.status, QrStatus::Unmatched as u8);
        let cs = conn_state_at(&reg, h);
        assert_eq!(cs.incarnation, 1);
        assert!(a.iter().any(|e| e.kind == ANOM_EPOCH_REBIRTH));

        // 幽灵包免疫：旧连接迟到 R（ack 指向旧代际数据，seq 属旧 s→c 空间）
        // 在新代际 c→s 基线（new_isn）下翻译，绝不可能命中新 PENDING。
        let ghost = s2c(5000, 1011, b"ghost"); // 旧 ack=1011（旧 Q 的 end）
        run(&reg, &params, &[(ghost, o.next(&s2c(5000, 1011, b"ghost")))]);
        assert_eq!(pending_len(&reg, h, 1), 0);
        assert_eq!(pair_at(&reg, q0_idx).unwrap().status, QrStatus::Unmatched as u8); // 未被幽灵标记 MATCH

        // 新代际正常匹配：新 Q + 新 R。
        let q1 = c2s(new_isn + 1, 0, b"GET /new");
        let q1_idx = (1u64 << 32) | o.next(&q1) as u64;
        let r1 = s2c(6000, new_isn + 1 + 8, b"200new");
        let r1_idx = (1u64 << 32) | o.next(&r1) as u64;
        run(
            &reg,
            &params,
            &[
                (q1.clone(), q1_idx as u32),
                (r1.clone(), r1_idx as u32),
            ],
        );
        let p1 = pair_at(&reg, q1_idx).unwrap();
        assert_eq!(p1.status, QrStatus::Matched as u8);
        assert_eq!(p1.abs_q_end, (new_isn as u64) + 1 + 8);
        assert_eq!(pending_len(&reg, h, 1), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn large_jump_marks_seq_gap_without_rebirth() {
        let dir = tmpdir("jump");
        let reg = DbRegistry::open(&dir.join("qridx"), 10 * 1024 * 1024).unwrap();
        let params = QrParams::default();
        let mut o = Offset(0);
        // 代际 0 有挂起 Q
        let q0 = c2s(1001, 5001, b"GET /a");
        let q0_idx = (1u64 << 32) | o.next(&q0) as u64;
        run(
            &reg,
            &params,
            &[
                (pkt(CIP, SIP, CPORT, SPORT, TCP_SYN, 1000, 0, b""), o.next(&c2s(1000, 0, b""))),
                (pkt(SIP, CIP, SPORT, CPORT, TCP_SYN | TCP_ACK, 5000, 1001, b""), o.next(&s2c(5000, 1001, b""))),
                (q0.clone(), q0_idx as u32),
            ],
        );
        // 非 SYN 大跳变（d>2^30）：绝不触发重代，仅标 SEQ_GAP；PENDING 原样保留。
        let jump = c2s(0x8000_0101, 5001, b"post-jump");
        run(&reg, &params, &[(jump, o.next(&c2s(0, 0, b"")))]);
        let h = ch();
        let cs = conn_state_at(&reg, h);
        assert_eq!(cs.incarnation, 0); // 数据流回绕/跳变绝不递增代际
        assert_eq!(pair_at(&reg, q0_idx).unwrap().status, QrStatus::Pending as u8); // 不翻转
        // 不清 PENDING：老 Q 保留 + 跳变包的可见数据按旧代际空间正常开 Q（不重代，数据不漏）。
        assert_eq!(pending_len(&reg, h, 0), 2);
        assert_ne!(cs.anomaly_flags & anomaly::SEQ_GAP, 0); // 大跳变仅标记 SEQ_GAP
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rst_cascade_aborts_pending() {
        let dir = tmpdir("rst");
        let reg = DbRegistry::open(&dir.join("qridx"), 10 * 1024 * 1024).unwrap();
        let params = QrParams::default();
        let mut o = Offset(0);
        let q = c2s(1001, 5001, b"GET /a");
        let q_idx = (1u64 << 32) | o.next(&q) as u64;
        let r = pkt(SIP, CIP, SPORT, CPORT, TCP_RST | TCP_ACK, 5001, 1011, b"");
        run(
            &reg,
            &params,
            &[
                (pkt(CIP, SIP, CPORT, SPORT, TCP_SYN, 1000, 0, b""), o.next(&c2s(1000, 0, b""))),
                (pkt(SIP, CIP, SPORT, CPORT, TCP_SYN | TCP_ACK, 5000, 1001, b""), o.next(&s2c(5000, 1001, b""))),
                (q.clone(), q_idx as u32),
                (r, o.next(&s2c(5001, 1011, b""))),
            ],
        );
        let h = ch();
        let p = pair_at(&reg, q_idx).unwrap();
        assert_eq!(p.status, QrStatus::RstAbort as u8);
        assert_eq!(pending_len(&reg, h, 0), 0);
        let cs = conn_state_at(&reg, h);
        assert_eq!(cs.state, ConnStateKind::Reset as u8);
        assert_ne!(cs.anomaly_flags & anomaly::RESET, 0);
        assert_eq!(cs.qr_open, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn replay_idempotent_no_dup() {
        let dir = tmpdir("replay");
        let reg = DbRegistry::open(&dir.join("qridx"), 10 * 1024 * 1024).unwrap();
        let params = QrParams::default();
        let mut o = Offset(0);
        let q = c2s(1001, 5001, b"GET /a");
        let q_idx = (1u64 << 32) | o.next(&q) as u64;
        let r = s2c(5001, 1007, b"200");
        let r_idx = (1u64 << 32) | o.next(&r) as u64;
        let recs = vec![
            (pkt(CIP, SIP, CPORT, SPORT, TCP_SYN, 1000, 0, b""), o.next(&c2s(1000, 0, b""))),
            (pkt(SIP, CIP, SPORT, CPORT, TCP_SYN | TCP_ACK, 5000, 1001, b""), o.next(&s2c(5000, 1001, b""))),
            (q.clone(), q_idx as u32),
            (r.clone(), r_idx as u32),
        ];
        run(&reg, &params, &recs);
        let before_pairs = qr_pair_count(&reg);
        assert_eq!(before_pairs, 1);
        // 2PC-Lite 崩溃窗口重放：同批重放 → 零翻倍、零脏。
        run(&reg, &params, &recs);
        assert_eq!(qr_pair_count(&reg), before_pairs);
        let h = ch();
        assert_eq!(pending_len(&reg, h, 0), 0);
        assert_eq!(pair_at(&reg, q_idx).unwrap().status, QrStatus::Matched as u8);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// P5：MetaRegistry 绑定连接 + HTTP 请求行提取 + 二进制伪键。
    #[test]
    fn meta_bind_binds_conn_and_extracts_keys() {
        use crate::config::MetaBind;
        use crate::meta::MetaRegistry;
        let dir = tmpdir("metabind");
        let reg = DbRegistry::open(&dir.join("qridx"), 10 * 1024 * 1024).unwrap();
        let params = QrParams::default();
        let binds = vec![MetaBind {
            name: "web".into(),
            proto: 6,
            dst_port: 80,
            fingerprint: "http".into(),
            extractor: "http_line".into(),
        }];
        let mr = MetaRegistry::from_binds(&binds);
        let mut o = Offset(0);

        // HTTP 连接：握手 + 请求 → 绑定 web 规则（meta_bind_id=1），req_key=请求行，pseudo=0。
        let q = pkt(CIP, SIP, CPORT, 80, TCP_ACK, 1001, 5001, b"GET /a/b HTTP/1.1\r\n");
        let q_idx = (1u64 << 32) | o.next(&q) as u64;
        let mut m = QrMatcher::begin_with_meta(&reg, &params, Some(&mr)).unwrap();
        for (rec, off) in [
            (pkt(CIP, SIP, CPORT, 80, TCP_SYN, 1000, 0, b""), o.next(&c2s(1000, 0, b""))),
            (pkt(SIP, CIP, 80, CPORT, TCP_SYN | TCP_ACK, 5000, 1001, b""), o.next(&s2c(5000, 1001, b""))),
            (q.clone(), q_idx as u32),
        ] {
            m.ingest(&IndexedRecord { dev_id: 1, file_id: 1, offset: off, rec }).unwrap();
        }
        let events = m.ext_meta_events().to_vec();
        m.commit().unwrap();
        let h = conn_hash(1, u32::from_be_bytes(CIP), CPORT, u32::from_be_bytes(SIP), 80, 6);
        let cs = conn_state_at(&reg, h);
        assert_eq!(cs.meta_bind_id, 1, "连接应绑定 web 规则");
        assert_eq!(cs.protocol_hint, 1, "protocol_hint=http");
        let p = pair_at(&reg, q_idx).unwrap();
        assert_eq!(p.pseudo, 0);
        assert_eq!(p.req_key, b"GET /a/b HTTP/1.1");
        // EXT META 指纹：HTTP 低熵 + magic "GET "。
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].protocol_hint, 1);
        assert_eq!(events[0].magic_prefix, b"GET ");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// P5：无规则端口 → 二进制伪键稳定（同签名同 KEY），pseudo=1。
    #[test]
    fn meta_bind_binary_pseudo_key_stable() {
        use crate::meta::MetaRegistry;
        let dir = tmpdir("pseudo");
        let reg = DbRegistry::open(&dir.join("qridx"), 10 * 1024 * 1024).unwrap();
        let params = QrParams::default();
        let sig: Vec<u8> = (0..64u32).map(|i| (i.wrapping_mul(0x9E3779B9) >> 16) as u8).collect();
        let mut o = Offset(0);

        // 两连接（不同客户端口）同签名请求 → 伪键跨连接一致。
        let mr = MetaRegistry::from_binds(&[]);
        let mut q_idx_by_conn: Vec<u64> = Vec::new();
        for (i, cport) in [30001u16, 30002u16].iter().enumerate() {
            let mut m = QrMatcher::begin_with_meta(&reg, &params, Some(&mr)).unwrap();
            let syn = pkt(CIP, SIP, *cport, 9999, TCP_SYN, 1000 + i as u32, 0, b"");
            let synack = pkt(SIP, CIP, 9999, *cport, TCP_SYN | TCP_ACK, 5000 + i as u32, 1001, b"");
            let ack = pkt(CIP, SIP, *cport, 9999, TCP_ACK, 1001 + i as u32, 5001 + i as u32, b"");
            let q = pkt(CIP, SIP, *cport, 9999, TCP_ACK, 1001 + i as u32, 5001 + i as u32, &sig);
            let syn_off = o.next(&syn);
            let synack_off = o.next(&synack);
            let ack_off = o.next(&ack);
            let q_off = o.next(&q);
            for (rec, off) in [
                (syn, syn_off),
                (synack, synack_off),
                (ack, ack_off),
                (q, q_off),
            ] {
                m.ingest(&IndexedRecord { dev_id: 1, file_id: 1, offset: off, rec }).unwrap();
            }
            m.commit().unwrap();
            q_idx_by_conn.push((1u64 << 32) | q_off as u64);
        }
        let p1 = pair_at(&reg, q_idx_by_conn[0]).unwrap();
        let p2 = pair_at(&reg, q_idx_by_conn[1]).unwrap();
        assert_eq!(p1.pseudo, 1);
        assert_eq!(p2.pseudo, 1);
        assert_eq!(p1.req_key, p2.req_key, "同签名二进制必须同伪键（跨连接）");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 次级索引 status 去重（§13.4.1）：CONN_QR/QR_TIME 打开写一次、永不更新——终态翻转后
    /// 索引 value 仍为 q_first_idx（非 status），status 语义只在 QR_PAIR 主行。
    #[test]
    fn secondary_index_no_status_semantics() {
        let dir = tmpdir("secidx");
        let reg = DbRegistry::open(&dir.join("qridx"), 10 * 1024 * 1024).unwrap();
        let params = QrParams::default();
        let mut o = Offset(0);
        let q = c2s(1001, 5001, b"GET /a");
        let q_idx = (1u64 << 32) | o.next(&q) as u64;
        run(
            &reg,
            &params,
            &[
                (pkt(CIP, SIP, CPORT, SPORT, TCP_SYN, 1000, 0, b""), o.next(&c2s(1000, 0, b""))),
                (pkt(SIP, CIP, SPORT, CPORT, TCP_SYN | TCP_ACK, 5000, 1001, b""), o.next(&s2c(5000, 1001, b""))),
                (q.clone(), q_idx as u32),
            ],
        );
        let et = reg.epoch_read_txn().unwrap();
        // CONN_QR 索引行存在且 value = q_first_idx（纯定位，无 status 位）。
        let key = k_conn_qr(ch(), 1001, q_idx);
        let v = reg.epoch_dbs()[EPOCH_CONN_QR].get(&et, &key).unwrap().unwrap();
        assert_eq!(v.len(), 8, "次级索引 value 为 q_first_idx 8B");
        assert_eq!(u64::from_be_bytes(v[0..8].try_into().unwrap()), q_idx);
        // QR_TIME 索引行同样为定位 value。
        let key = k_qr_time(1001, q_idx);
        let v = reg.epoch_dbs()[EPOCH_QR_TIME].get(&et, &key).unwrap().unwrap();
        assert_eq!(u64::from_be_bytes(v[0..8].try_into().unwrap()), q_idx);
        drop(et);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
