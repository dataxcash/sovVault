//! 重组引擎：段状态机 + 乱序暂存（BTreeMap 按绝对偏移）+ L2/L2.5/L3 四层预算检疫。
//! 设计依据：09_sovVault_实施方案.md §5.6（评审④ L2.5 连接级 OOO 字节预算）。
//!
//! 核心决策：
//! - 暂存结构：每段 `BTreeMap<u64 绝对字节偏移, Vec<u8>>`——有序迭代天然做缺口对账，
//!   乱序插入 O(log n) 且被预算封顶；连续快路径（offset==next_expected）直接穿透。
//! - 内存安全：预算在**写入前强制检查**（先查预算再插缓冲），恶意流量烧不掉主进程内存；
//!   超限动作全是内部动作（逐出最旧 / 段 ERROR / 检疫），**绝不注入线上 RST**（红线三理由）。

use std::collections::{BTreeMap, HashMap, HashSet};

/// 段标识：(dev_id, segment_seq)。
pub type SegmentKey = (u32, u32);

/// 段状态机（09 §六：NEW → UNFINISHED ⇄ SEALED → SKIPPED/ERROR）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentState {
    New = 0,
    Unfinished = 1,
    Sealed = 2,
    Skipped = 3,
    Error = 4,
}

/// 重组事件（交给下游流水线消费：写数据平面 / 发 GapQuery / 落审计）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// 连续落位数据，数据平面据此 append 到 hot WAL。
    Append {
        dev_id: u32,
        segment_seq: u32,
        offset: u64,
        data: Vec<u8>,
    },
    /// 幂等去重（整体已被已落位区间覆盖）。
    Dup { dev_id: u32, segment_seq: u32 },
    /// 缺口（Seal 对账或逐出产生）→ GapQuery 回源自愈。
    Gap {
        dev_id: u32,
        segment_seq: u32,
        start_offset: u64,
    },
    /// 段封盘完整。
    Sealed {
        dev_id: u32,
        segment_seq: u32,
        size: u64,
    },
    /// 段封盘缺口（等待回源，段暂留 UNFINISHED）。
    SealGap {
        dev_id: u32,
        segment_seq: u32,
        next_expected: u64,
        sealed_size: u64,
    },
    /// 段号跳空（Unlink-Oldest）：本段 seal 时发现中间段缺失，缺失段判为已淘汰。
    SeqSkipped { dev_id: u32, segment_seq: u32 },
    /// 段超 L2 → 标 ERROR + 丢该段 pending。
    SegmentError {
        dev_id: u32,
        segment_seq: u32,
        reason: &'static str,
    },
    /// 连接（dev）超 L2.5 → 逐出最旧 / 检疫。
    Evict {
        dev_id: u32,
        segment_seq: u32,
        offset: u64,
        bytes: u64,
    },
    /// 连接检疫（CONN_OOO_FLOOD），在途段全标 SKIPPED。
    Quarantine { dev_id: u32 },
    /// 检疫态下到达的数据（仅计数）。
    QuarantinedDrop { dev_id: u32, bytes: u64 },
}

/// 四层预算（§5.6）。
#[derive(Debug, Clone, Copy)]
pub struct Budgets {
    /// L2 单段 pending 字节硬上限（0 → 默认 8MB）。
    pub l2_segment_cap: u64,
    /// L2.5 单连接（dev_id）OOO 字节硬闸。
    pub l25_conn_cap: u64,
    /// L3 全局 pending 字节兜底。
    pub l3_global_cap: u64,
    /// L2.5 配额耗尽计数窗口（秒）。
    pub evict_window_secs: u64,
    /// 窗口内耗尽次数达此值 → 升级内部检疫。
    pub evict_threshold: u32,
}

impl Budgets {
    /// 从配置构造（segment_pending_cap=0 → 默认 8MB）。
    pub fn from_config(
        segment_pending_cap: u64,
        conn_pending_cap_bytes: u64,
        pending_budget_bytes: u64,
        evict_window_secs: u64,
        evict_threshold: u32,
    ) -> Budgets {
        Budgets {
            l2_segment_cap: if segment_pending_cap == 0 {
                8 * 1024 * 1024
            } else {
                segment_pending_cap
            },
            l25_conn_cap: conn_pending_cap_bytes,
            l3_global_cap: pending_budget_bytes,
            evict_window_secs,
            evict_threshold,
        }
    }
}

/// 单段重组缓冲。
#[derive(Debug)]
pub struct SegmentBuf {
    pub key: SegmentKey,
    pub state: SegmentState,
    /// 已连续落位游标（下一个期望偏移）。
    pub next_expected: u64,
    /// 封盘声明的段大小（SealFrame.sealed_size）。
    pub sealed_size: Option<u64>,
    /// 乱序暂存：绝对偏移 → chunk 明文。
    pub pending: BTreeMap<u64, Vec<u8>>,
    /// 该段累计 OOO 字节。
    pub pending_bytes: u64,
    pub dup_count: u64,
    pub gap_count: u64,
}

impl SegmentBuf {
    fn new(key: SegmentKey) -> SegmentBuf {
        SegmentBuf {
            key,
            state: SegmentState::New,
            next_expected: 0,
            sealed_size: None,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            dup_count: 0,
            gap_count: 0,
        }
    }
}

/// L2.5 配额耗尽状态（窗口滑窗）。
#[derive(Debug, Clone, Copy)]
struct EvictState {
    streak: u32,
    window_start: u64,
}

/// 重组器（单线程 ingest 串行消费，无锁）。
pub struct Reassembler {
    segs: HashMap<SegmentKey, SegmentBuf>,
    /// dev_id → 该 dev 全部在途段 OOO 字节。
    conn_pending: HashMap<u32, u64>,
    /// dev_id → 检疫标记。
    quarantined: HashSet<u32>,
    /// dev_id → 逐出计数状态。
    evict: HashMap<u32, EvictState>,
    /// 全局 OOO 字节。
    global_pending: u64,
    /// dev_id → 已见最大段号（段号跳空判定依据）。
    last_seq: HashMap<u32, u32>,
    budgets: Budgets,
    /// 注入时钟（秒），可测试。
    now: u64,
}

impl Reassembler {
    pub fn new(budgets: Budgets) -> Reassembler {
        Reassembler {
            segs: HashMap::new(),
            conn_pending: HashMap::new(),
            quarantined: HashSet::new(),
            evict: HashMap::new(),
            global_pending: 0,
            last_seq: HashMap::new(),
            budgets,
            now: 0,
        }
    }

    /// 注入时钟（秒），测试用。
    pub fn set_now(&mut self, now: u64) {
        self.now = now;
    }

    pub fn global_pending(&self) -> u64 {
        self.global_pending
    }

    pub fn conn_pending(&self, dev_id: u32) -> u64 {
        self.conn_pending.get(&dev_id).copied().unwrap_or(0)
    }

    pub fn is_quarantined(&self, dev_id: u32) -> bool {
        self.quarantined.contains(&dev_id)
    }

    /// 落位一个解密后的 chunk。返回本步产生的事件。
    pub fn place_chunk(
        &mut self,
        dev_id: u32,
        segment_seq: u32,
        offset: u64,
        data: &[u8],
    ) -> Vec<Event> {
        let mut events = Vec::new();

        if self.quarantined.contains(&dev_id) {
            events.push(Event::QuarantinedDrop {
                dev_id,
                bytes: data.len() as u64,
            });
            return events;
        }

        let len = data.len() as u64;
        let key = (dev_id, segment_seq);

        // 读取当前段状态（复制，避免跨调用持有可变借用）。
        let (next_expected, pending_bytes) = self
            .segs
            .get(&key)
            .map(|s| (s.next_expected, s.pending_bytes))
            .unwrap_or((0, 0));

        // 幂等去重：整体已被已落位区间覆盖。
        if offset + len <= next_expected {
            if let Some(s) = self.segs.get_mut(&key) {
                s.dup_count += 1;
            }
            events.push(Event::Dup {
                dev_id,
                segment_seq,
            });
            return events;
        }

        // 部分覆盖：截取新增区 [next_expected, offset+len)。
        let data = if offset < next_expected {
            let cut = (next_expected - offset) as usize;
            if cut >= data.len() {
                if let Some(s) = self.segs.get_mut(&key) {
                    s.dup_count += 1;
                }
                events.push(Event::Dup {
                    dev_id,
                    segment_seq,
                });
                return events;
            }
            &data[cut..]
        } else {
            data
        };
        let len = data.len() as u64;
        let offset = offset.max(next_expected);

        // L2 段预算前置检查（仅真乱序需要暂存时）。
        if offset > next_expected && pending_bytes + len > self.budgets.l2_segment_cap {
            self.mark_segment_error(&mut events, key, "L2 segment cap exceeded");
            return events;
        }

        // L2.5 连接预算前置检查（仅真乱序）。
        if offset > next_expected {
            let conn_used = *self.conn_pending.get(&dev_id).unwrap_or(&0);
            if conn_used + len > self.budgets.l25_conn_cap {
                self.evict_oldest_in_dev(&mut events, dev_id);
            }
        }

        // L3 全局预算兜底（连接感知逐出）。
        if self.global_pending + len > self.budgets.l3_global_cap {
            self.evict_oldest_global(&mut events);
        }

        // 落位（entry 借用仅限此块，随后立即释放再排水）。
        {
            let entry = self.segs.entry(key).or_insert_with(|| SegmentBuf::new(key));
            entry.pending_bytes += len;
            entry.pending.insert(offset, data.to_vec());
        }
        self.global_pending += len;
        *self.conn_pending.entry(dev_id).or_insert(0) += len;

        // 连续推进：从 next_expected 起排水。
        self.drain_contiguous(&mut events, key);
        events
    }

    /// 段标 ERROR + 丢 pending + SEGMENT_GAP（L2 超限响应）。
    fn mark_segment_error(
        &mut self,
        events: &mut Vec<Event>,
        key: SegmentKey,
        reason: &'static str,
    ) {
        let (dev_id, segment_seq) = key;
        let bytes = self.segs.get(&key).map(|s| s.pending_bytes).unwrap_or(0);
        if let Some(s) = self.segs.get_mut(&key) {
            s.state = SegmentState::Error;
            s.pending.clear();
            s.pending_bytes = 0;
        }
        self.global_pending = self.global_pending.saturating_sub(bytes);
        if let Some(c) = self.conn_pending.get_mut(&dev_id) {
            *c = c.saturating_sub(bytes);
        }
        events.push(Event::SegmentError {
            dev_id,
            segment_seq,
            reason,
        });
        events.push(Event::Gap {
            dev_id,
            segment_seq,
            start_offset: self.segs.get(&key).map(|s| s.next_expected).unwrap_or(0),
        });
    }

    /// 连续排水：自 next_expected 起，把连续可写的 pending 移出并产出 Append。
    fn drain_contiguous(&mut self, events: &mut Vec<Event>, key: SegmentKey) {
        let (dev_id, segment_seq) = key;
        loop {
            let popped = {
                let seg = match self.segs.get_mut(&key) {
                    Some(s) => s,
                    None => return,
                };
                match seg.pending.remove(&seg.next_expected) {
                    Some(c) => {
                        let sz = c.len() as u64;
                        let off = seg.next_expected;
                        seg.next_expected += sz;
                        seg.pending_bytes -= sz;
                        seg.state = SegmentState::Unfinished;
                        Some((off, c))
                    }
                    None => return,
                }
            };
            let (off, chunk) = popped.unwrap();
            let sz = chunk.len() as u64;
            self.global_pending -= sz;
            let c = self.conn_pending.get_mut(&dev_id).unwrap();
            *c = c.saturating_sub(sz);
            events.push(Event::Append {
                dev_id,
                segment_seq,
                offset: off,
                data: chunk,
            });
        }
    }

    /// 段封盘：对账（next_expected vs sealed_size）+ 段号跳空（Unlink-Oldest）。
    pub fn seal(&mut self, dev_id: u32, segment_seq: u32, sealed_size: u64) -> Vec<Event> {
        let mut events = Vec::new();

        // 段号跳空检测：seal 的段号比已见最大段号超出 >1 → 中间段判为已淘汰。
        let last = self.last_seq.get(&dev_id).copied().unwrap_or(0);
        if segment_seq > 0 && last > 0 && segment_seq > last + 1 {
            for miss in (last + 1)..segment_seq {
                events.push(Event::SeqSkipped {
                    dev_id,
                    segment_seq: miss,
                });
            }
        }
        if segment_seq > last {
            self.last_seq.insert(dev_id, segment_seq);
        }

        let key = (dev_id, segment_seq);
        let next_expected = match self.segs.get(&key) {
            Some(s) => s.next_expected,
            None => return events,
        };
        if next_expected == sealed_size {
            self.release_segment(key);
            events.push(Event::Sealed {
                dev_id,
                segment_seq,
                size: sealed_size,
            });
        } else {
            if let Some(s) = self.segs.get_mut(&key) {
                s.sealed_size = Some(sealed_size);
            }
            events.push(Event::SealGap {
                dev_id,
                segment_seq,
                next_expected,
                sealed_size,
            });
        }
        events
    }

    /// 逐出指定 dev 的最旧 OOO 数据（L2.5 第一级响应），并做耗尽计数。
    fn evict_oldest_in_dev(&mut self, events: &mut Vec<Event>, dev_id: u32) {
        // 找该 dev 最小偏移的最旧 pending。
        let mut target: Option<(SegmentKey, u64)> = None; // (key, offset)
        for (key, seg) in &self.segs {
            if key.0 != dev_id || seg.pending.is_empty() {
                continue;
            }
            if let Some((&off, _)) = seg.pending.first_key_value() {
                if target.is_none_or(|(_, to)| off < to) {
                    target = Some((*key, off));
                }
            }
        }
        let Some((key, offset)) = target else { return };
        let chunk = self
            .segs
            .get_mut(&key)
            .unwrap()
            .pending
            .remove(&offset)
            .unwrap();
        let sz = chunk.len() as u64;
        self.segs.get_mut(&key).unwrap().pending_bytes -= sz;
        self.global_pending -= sz;
        let c = self.conn_pending.get_mut(&dev_id).unwrap();
        *c = c.saturating_sub(sz);
        events.push(Event::Evict {
            dev_id,
            segment_seq: key.1,
            offset,
            bytes: sz,
        });

        // L2.5 持续病态 → 升级检疫。
        let st = self.evict.entry(dev_id).or_insert(EvictState {
            streak: 0,
            window_start: self.now,
        });
        if self.now.saturating_sub(st.window_start) > self.budgets.evict_window_secs {
            st.streak = 1;
            st.window_start = self.now;
        } else {
            st.streak += 1;
        }
        if st.streak >= self.budgets.evict_threshold {
            self.quarantine(dev_id, events);
        }
    }

    /// L3 全局兜底：连接感知逐出——优先清已检疫 dev，否则清全局最旧。
    fn evict_oldest_global(&mut self, events: &mut Vec<Event>) {
        let mut target: Option<(SegmentKey, u64)> = None;
        for (key, seg) in &self.segs {
            if seg.pending.is_empty() {
                continue;
            }
            if let Some((&off, _)) = seg.pending.first_key_value() {
                // 已检疫 dev 优先。
                let quarantined = self.quarantined.contains(&key.0);
                let better = match target {
                    None => true,
                    Some((tk, to)) => {
                        let tq = self.quarantined.contains(&tk.0);
                        (quarantined && !tq) || (quarantined == tq && off < to)
                    }
                };
                if better {
                    target = Some((*key, off));
                }
            }
        }
        let Some((key, offset)) = target else { return };
        let chunk = self
            .segs
            .get_mut(&key)
            .unwrap()
            .pending
            .remove(&offset)
            .unwrap();
        let sz = chunk.len() as u64;
        self.segs.get_mut(&key).unwrap().pending_bytes -= sz;
        self.global_pending -= sz;
        let dev_id = key.0;
        let c = self.conn_pending.get_mut(&dev_id).unwrap();
        *c = c.saturating_sub(sz);
        events.push(Event::Evict {
            dev_id,
            segment_seq: key.1,
            offset,
            bytes: sz,
        });
    }

    /// 内部检疫（CONN_OOO_FLOOD）：该 dev 在途段全标 SKIPPED、清 pending，数据平面由 Gap 兜底。
    fn quarantine(&mut self, dev_id: u32, events: &mut Vec<Event>) {
        if self.quarantined.contains(&dev_id) {
            return;
        }
        self.quarantined.insert(dev_id);
        let keys: Vec<SegmentKey> = self
            .segs
            .keys()
            .cloned()
            .filter(|k| k.0 == dev_id)
            .collect();
        for key in keys {
            self.drop_segment_pending(key);
            if let Some(seg) = self.segs.get_mut(&key) {
                seg.state = SegmentState::Skipped;
            }
        }
        self.conn_pending.remove(&dev_id);
        self.evict.remove(&dev_id);
        events.push(Event::Quarantine { dev_id });
    }

    /// 释放段并回收其 pending 字节。
    fn release_segment(&mut self, key: SegmentKey) {
        if let Some(seg) = self.segs.remove(&key) {
            self.global_pending = self.global_pending.saturating_sub(seg.pending_bytes);
            if let Some(c) = self.conn_pending.get_mut(&key.0) {
                *c = c.saturating_sub(seg.pending_bytes);
            }
        }
    }

    fn drop_segment_pending(&mut self, key: SegmentKey) {
        if let Some(seg) = self.segs.get_mut(&key) {
            let bytes = seg.pending_bytes;
            seg.pending.clear();
            seg.pending_bytes = 0;
            self.global_pending = self.global_pending.saturating_sub(bytes);
            if let Some(c) = self.conn_pending.get_mut(&key.0) {
                *c = c.saturating_sub(bytes);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decrypt::Decryptor;
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    use slim_common::framing::{decode_chunk_frame, encode_chunk_frame};

    fn budgets() -> Budgets {
        Budgets {
            l2_segment_cap: 1024,
            l25_conn_cap: 256,
            l3_global_cap: 1024,
            evict_window_secs: 30,
            evict_threshold: 3,
        }
    }

    fn appends(events: &[Event]) -> Vec<(u64, usize)> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::Append { offset, data, .. } => Some((*offset, data.len())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn in_order_contiguous_flow() {
        let mut r = Reassembler::new(budgets());
        let e = r.place_chunk(1, 0, 0, &[1u8; 10]);
        assert_eq!(appends(&e), vec![(0, 10)]);
        let e = r.place_chunk(1, 0, 10, &[2u8; 20]);
        assert_eq!(appends(&e), vec![(10, 20)]);
        assert_eq!(r.global_pending(), 0);
    }

    #[test]
    fn out_of_order_then_fill() {
        let mut r = Reassembler::new(budgets());
        // 乱序：先来 [20..30)
        let e = r.place_chunk(1, 0, 20, &[9u8; 10]);
        assert!(appends(&e).is_empty()); // 未连续，暂存
        assert_eq!(r.global_pending(), 10);
        // 补 [0..20) → 连续推进并带出 [20..30)
        let e = r.place_chunk(1, 0, 0, &[1u8; 20]);
        assert_eq!(appends(&e), vec![(0, 20), (20, 10)]);
        assert_eq!(r.global_pending(), 0);
    }

    #[test]
    fn idempotent_dup_and_partial_overlap() {
        let mut r = Reassembler::new(budgets());
        r.place_chunk(1, 0, 0, &[1u8; 100]);
        // 整体重复 → Dup
        let e = r.place_chunk(1, 0, 0, &[2u8; 100]);
        assert_eq!(
            e,
            vec![Event::Dup {
                dev_id: 1,
                segment_seq: 0
            }]
        );
        // 部分覆盖 [80..150)：只取新增 [100..150)
        let e = r.place_chunk(1, 0, 80, &[3u8; 70]);
        assert_eq!(appends(&e), vec![(100, 50)]);
    }

    #[test]
    fn seal_verify_gap() {
        let mut r = Reassembler::new(budgets());
        r.place_chunk(1, 0, 0, &[1u8; 100]);
        // 完整封盘
        let e = r.seal(1, 0, 100);
        assert_eq!(
            e,
            vec![Event::Sealed {
                dev_id: 1,
                segment_seq: 0,
                size: 100
            }]
        );
        // 缺洞封盘
        r.place_chunk(1, 1, 0, &[1u8; 100]);
        let e = r.seal(1, 1, 200);
        assert_eq!(
            e,
            vec![Event::SealGap {
                dev_id: 1,
                segment_seq: 1,
                next_expected: 100,
                sealed_size: 200
            }]
        );
    }

    #[test]
    fn end_to_end_encrypted_chunk_reassembly() {
        // 构造段明文（WAL 字节流），切成两个 chunk 并故意乱序投递。
        let plain = (0..4u8).flat_map(|i| [i; 256]).collect::<Vec<u8>>(); // 1024B
        let key = [9u8; 32];
        let decryptor = Decryptor::new(key);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

        // chunk0 = [0..512)，chunk1 = [512..1024)。先投递 chunk1（乱序）。
        let chunks = [(0u64, &plain[0..512]), (512u64, &plain[512..1024])];
        let mut r = Reassembler::new(budgets());
        for (offset, data) in chunks.into_iter().rev() {
            // 发送端加密：nonce(12) + 密文+tag。
            let mut payload = vec![0u8; crate::decrypt::NONCE_LEN];
            let nonce = Nonce::from_slice(&payload);
            let ct = cipher.encrypt(nonce, data).unwrap();
            payload.extend_from_slice(&ct);
            let frame = encode_chunk_frame(1, 7, offset, data.len() as u32, &payload, false);
            // 接收端：解帧 → 解密 → 落位（payload 位于帧头 28B 之后）。
            let f = decode_chunk_frame(&frame).unwrap();
            let payload = &frame[slim_common::framing::CHUNK_FRAME_HEADER_LEN..];
            let plain_chunk = decryptor
                .decrypt_chunk_payload(payload, f.chunk_len)
                .unwrap();
            let events = r.place_chunk(f.dev_id, f.segment_seq, f.start_offset, &plain_chunk);
            let _ = events;
        }
        // 乱序补齐后数据完整连续。
        let appends = r.segs.get(&(1, 7)).map(|s| s.next_expected).unwrap();
        assert_eq!(appends, 1024);
        assert_eq!(r.global_pending(), 0);
        // 封盘对账通过。
        let e = r.seal(1, 7, 1024);
        assert_eq!(
            e,
            vec![Event::Sealed {
                dev_id: 1,
                segment_seq: 7,
                size: 1024
            }]
        );
    }

    #[test]
    fn l2_segment_cap_triggers_error() {
        let mut r = Reassembler::new(budgets()); // L2=1024
                                                 // 连续落位 1000B（走快路径，不进 pending）。
        r.place_chunk(1, 0, 0, &[1u8; 1000]);
        // 真乱序：offset 2000（与 1000 之间留 1000B 缺口）→ 需暂存 1100B > L2 → ERROR。
        let e = r.place_chunk(1, 0, 2000, &[2u8; 1100]);
        assert!(e.iter().any(|x| matches!(x, Event::SegmentError { .. })));
        assert!(e.iter().any(|x| matches!(x, Event::Gap { .. })));
        assert_eq!(r.global_pending(), 0);
    }

    #[test]
    fn l25_evict_then_quarantine() {
        let mut r = Reassembler::new(budgets()); // L2.5=256, threshold=3, window=30
        r.set_now(100);
        // 每步插入 200B 真乱序：第 2/3/4 次触发逐出，第 4 次 streak=3 → 检疫。
        let mut off = 1000u64;
        let mut guard = 0;
        loop {
            let e = r.place_chunk(1, 0, off, &[200u8; 200]);
            if e.iter()
                .any(|x| matches!(x, Event::Quarantine { dev_id: 1 }))
            {
                break;
            }
            off += 200;
            guard += 1;
            assert!(guard < 8, "始终未触发检疫");
        }
        assert!(r.is_quarantined(1));
        // 检疫后仅计数。
        let e = r.place_chunk(1, 0, off, &[5u8; 5]);
        assert_eq!(
            e,
            vec![Event::QuarantinedDrop {
                dev_id: 1,
                bytes: 5
            }]
        );
    }

    #[test]
    fn segment_seq_skip_detected() {
        let mut r = Reassembler::new(budgets());
        // seg 1 完整封盘。
        r.place_chunk(1, 1, 0, &[1u8; 10]);
        let e = r.seal(1, 1, 10);
        assert_eq!(
            e,
            vec![Event::Sealed {
                dev_id: 1,
                segment_seq: 1,
                size: 10
            }]
        );
        // seg 3 封盘：中间 seg 2 缺失 → SeqSkipped。
        r.place_chunk(1, 3, 0, &[2u8; 10]);
        let e = r.seal(1, 3, 10);
        assert_eq!(
            e,
            vec![
                Event::SeqSkipped {
                    dev_id: 1,
                    segment_seq: 2
                },
                Event::Sealed {
                    dev_id: 1,
                    segment_seq: 3,
                    size: 10
                },
            ]
        );
    }

    #[test]
    fn l3_global_evict_oldest() {
        let b = Budgets {
            l2_segment_cap: 1024,
            l25_conn_cap: 4096, // 放宽连接级，让 L3 成为唯一约束
            l3_global_cap: 600,
            evict_window_secs: 30,
            evict_threshold: 3,
        };
        let mut r = Reassembler::new(b);
        // dev1 @off100(300B)、dev2 @off200(300B) → 恰好顶到 L3=600。
        r.place_chunk(1, 0, 100, &[1u8; 300]);
        r.place_chunk(2, 0, 200, &[2u8; 300]);
        assert_eq!(r.global_pending(), 600);
        // dev3 再插 300 → 900>600 → 逐出全局最旧（dev1 @off100），dev3 顶位。
        let e = r.place_chunk(3, 0, 300, &[3u8; 300]);
        assert!(e
            .iter()
            .any(|x| matches!(x, Event::Evict { dev_id: 1, .. })));
        assert_eq!(r.global_pending(), 600);
        assert_eq!(r.conn_pending(1), 0);
        assert_eq!(r.conn_pending(3), 300);
    }
}
