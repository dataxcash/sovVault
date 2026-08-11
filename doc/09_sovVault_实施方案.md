# sovVault 详细实施方案（实施白皮书 v0.2）

> 状态：**待评审** | 版本：v0.2 | 前置依赖：`08_sovVault_设计与实施方案.md`（v0.4）
> v0.2 变更：新增 **L2.5 单连接 OOO 字节预算**（填补 L1/L2 间的连接维度字节硬闸）——超限先连接内逐出最旧，持续病态升级内部检疫；明确超限绝不注入线上 RST（红线三理由）；L3 升级为连接感知逐出。
> 本文档把架构设计翻译为**可下发的工程实施说明书**：依赖选型 → Crate 结构与职责 → 二进制数据规格 → 核心算法伪代码 → 状态机规格 → 测试清单 → 分阶段里程碑 → 风险与验收。

---

## 一、本期实施范围

- **覆盖**：P0（三平面骨架）→ P1（重组底座）→ P2（批量原子性）→ P3（QR 匹配）→ P3.5（查询索引）→ P4（异常与慢路径）→ P5（导出与 E2E）。
- **明确不做（本期）**：Parquet（feature `parquet-export` 门控，默认关）；`DBI_RECORD_5TUPLE`（阶段二）；任何线上 RST 注入（检疫为内部动作）。
- **实施约束（继承设计红线）**：只增不改（Append-Only）；一个 Batch = 一个 LMDB 事务；LMDB 先行 / SQLite 水位线殿后；文件切换 = 提交屏障；QRPAIR 主键 = `q_first_idx` 确定性派生。

---

## 二、工程环境与依赖选型

| 项 | 选型 | 说明 |
|---|---|---|
| Rust | 1.94+，edition 2021 | 与 sovProbe/slimRAG 工具链一致 |
| 工作区 | 独立 crate `sov-vault`（bin `sovvault` + lib `sov_vault`），`[workspace]` 自闭环 | 依赖 sov-probe / slim-common 走 path |
| **LMDB** | `heed = "0.20"`（typed 封装），fallback `lmdb = "0.8"` | 需 `big-endian` 自定义 `Encode/Decode`；heed 无 BE 内建类型时用 byteorder 手写 |
| SQLite | `rusqlite = { version = "0.32", features = ["bundled"] }` | 管理平面，批事务写入 |
| Zenoh | `zenoh = "1.9.0"` | 订阅 batch/segments + gaps 回源 |
| 加密 | `chacha20poly1305 = "0.10"` | 与 slimSync 对称 |
| 序列化 | 键：byteorder 手写大端；值：定长结构体手写 / `bincode = "1.3"`（变长 QRPAIR） | 零序列化拷贝优先（mmap 直读定长结构） |
| 其他 | `tokio`(full)、`clap`(derive)、`anyhow`、`tracing`、`serde`、`serde_json`、`hex`、`crc32fast`、`pcap-file="2"` | — |
| Hash | 连接键先用 `fnv-1a-64`（零依赖），性能不足换 `xxhash-rust` | 同一哈希在 8 个 DBI 间一致 |

**版本红线**：与 `e2e-tools/Cargo.lock`、`slimSync/Cargo.lock` 已锁定版本对齐，避免协议/依赖分叉。

---

## 三、Crate 结构与模块职责

```
sovVault/
├── Cargo.toml                     # 依赖 + features{default=[], parquet-export=[]}
├── config.example.toml
├── src/
│   ├── main.rs                    # CLI 入口 + tokio 编排（serve/ingest/export/query/qr/anomaly/stat）
│   ├── lib.rs                     # 模块声明 + Pipeline 编排
│   ├── config.rs                  # 配置加载（TOML+CLI，CLI 优先）+ 校验
│   ├── id.rs                      # IDX=(FILE_ID<<32)|OFFSET 编解码 + FILE_ID 分配
│   ├── seq.rs                     # SeqStream 绝对序列号流翻译器（回绕根治）
│   ├── decrypt.rs                 # ChaCha20 解密（nonce12+ct+tag16）
│   ├── reassembly.rs              # 重组引擎：SegmentState/SegmentBuf/Reassembler + L2/L3/L2.5 预算 + 段检疫
│   ├── walscan.rs                 # 段字节流 → WalRecord 流（Magic→Version→Length→CRC32 四重校验）
│   ├── connection.rs              # ConnState + ConnectionTracker + 方向计数 + conn_hash
│   ├── qr.rs                      # QrPair 实体 + 累积ACK消费匹配（快/慢路径、批量ACK聚合）
│   ├── meta.rs                    # MetaRegistry + Fingerprint + Extractor + ExtMetaBind（伪KEY）
│   ├── anomaly.rs                 # AnomalyKind + AnomalyEvent + 聚合计数（只计数不逐条落库）
│   ├── db.rs                      # 8 DBI 句柄 + 键值编解码（db/ 子模块可拆）
│   ├── ledger.rs                  # SQLite 管理平面（files/anomalies/ext_meta/meta_binds + 水位线）
│   ├── batch.rs                   # BatchCommit 提交协议（LMDB先行→SQLite殿后→游标推进）
│   ├── quarantine.rs              # L1/L2.5 连接检疫（ABORTED_RESOURCE）+ CONN_QR_FLOOD/CONN_OOO_FLOOD
│   ├── ingest/
│   │   ├── mod.rs                 # IngestSource trait：分帧 → 解密 → 重组 → 段终态 → RecordSink
│   │   ├── zenoh.rs               # 在线订阅（batch+seal+gap自愈）→ Reassembler
│   │   └── offline.rs             # WAL 目录 / PCAP 文件 → 同一 Record 流水线
│   ├── export.rs                  # PCAP（复用 sov-probe 合成语义）/ Parquet(feature)
│   ├── query.rs                   # 过滤语言 + 查询路由（按 §4 DBI 矩阵）
│   └── util.rs                    # ip4 编解码、时间格式、ts→RFC3339
└── tests/
    ├── e2e_batch_atomicity.rs     # 注入提交失败 → 水位线不动、重放收敛
    ├── e2e_qr_matching.rs         # 握手+管道化+跨文件慢响应+回绕 → QRPair 断言
    └── e2e_export.rs              # PCAP 读回断言 orig_len/tcp_flags
```

---

## 四、二进制数据规格（实现依据，改动需回归单测）

### 4.1 IDX

```
IDX(u64) = (FILE_ID:u32 as u64) << 32 | (OFFSET:u32 as u64)     // 大端存 LMDB
硬不变量：单文件 ≤4GB；OFFSET=记录起始字节偏移。
```

### 4.2 8 DBI 键值布局（键一律大端）

| DBI | Key | Value |
|---|---|---|
| `CONN_STATE` | `conn_hash:u64` | 定长 ConnState（§4.3） |
| `QR_PAIR` | `q_first_idx:u64` | status:u8 \| conn_hash:u64 \| q_ts:u64 \| r_ts:u64 \| latency_ms:u64 \| q_len:u32 \| r_len:u32 \| abs_q_seq:u64 \| abs_q_end:u64 \| pseudo:u8 \| q_cnt:u16 \| r_cnt:u16 \| [q_idx:u64;q_cnt] \| [r_idx:u64;r_cnt] \| req_key:u32len+bytes \| resp_key:u32len+bytes |
| `QR_PENDING` | `conn_hash:u64` \| `abs_q_end:u64` | q_first_idx:u64 \| q_ts:u64 \| q_len:u32 |
| `CONN_QR` | `conn_hash:u64` \| `q_ts:u64` \| `q_first_idx:u64` | status:u8 |
| `QR_KEY` | `reqkey_hash:u64` \| `q_ts:u64` \| `q_first_idx:u64` | status:u8 |
| `QR_TIME` | `q_ts:u64` \| `q_first_idx:u64` | status:u8 |
| `PACKET_QR` | `packet_idx:u64` | q_first_idx:u64 |
| `PENDING_TTL` | `q_ts:u64` \| `conn_hash:u64` | q_first_idx:u64 \| abs_q_end:u64 |

> `status` 枚举：0=PENDING 1=MATCHED 2=TIMEOUT 3=UNMATCHED 4=RST_ABORT 5=ABORTED_RESOURCE。

### 4.3 ConnState 定长 Value（内存布局，字段自大至小防 padding 浪费）

```
state:u8 | reserved[7]
client_ip:u32 | client_port:u16 | server_ip:u32 | server_port:u16 | proto:u8 | reserved[1]
first_ts:u64 | last_ts:u64
syn_seen:u64 | synack_seen:u64 | fin_seen:u64 | rst_seen:u64
req_cnt:u64 | resp_cnt:u64 | bytes_c:u64 | bytes_s:u64 | pkts_c:u64 | pkts_s:u64
abs_seq_c:u64 | abs_seq_s:u64 | consumed_ack_c:u64 | consumed_ack_s:u64
meta_bind_id:i64 | protocol_hint:u8 | anomaly_flags:u32 | qr_open:u64
```

### 4.4 SQLite 管理平面 DDL

```sql
PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
CREATE TABLE files(
  file_id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT NOT NULL UNIQUE,
  kind INTEGER NOT NULL,            -- 0=WAL 1=PCAP
  dev_id INTEGER NOT NULL DEFAULT 1, segment_seq INTEGER,
  size_bytes INTEGER NOT NULL DEFAULT 0, sha256 BLOB,
  first_ts INTEGER, last_ts INTEGER,
  state INTEGER NOT NULL DEFAULT 0, -- 0=OPEN 1=SEALED 2=ARCHIVED
  analysis_offset INTEGER NOT NULL DEFAULT 0,   -- 水位线：已提交 LMDB 的字节边界
  created_at INTEGER NOT NULL);
CREATE INDEX idx_files_state ON files(state);
CREATE TABLE anomalies(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
  kind INTEGER NOT NULL, dev_id INTEGER, segment_seq INTEGER,
  conn_hash BLOB, qr_id INTEGER, detail TEXT);
CREATE INDEX idx_anomalies_kind ON anomalies(kind,ts);
CREATE TABLE ext_meta(
  meta_bind_id INTEGER PRIMARY KEY AUTOINCREMENT, protocol_hint INTEGER NOT NULL,
  magic_prefix BLOB, entropy REAL, has_fixed_header INTEGER NOT NULL DEFAULT 0,
  dst_port INTEGER, hit_count INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
CREATE TABLE meta_binds(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
  proto INTEGER, dst_port INTEGER, dst_ip TEXT, fingerprint TEXT, extractor TEXT, enabled INTEGER DEFAULT 1);
```

### 4.5 conn_hash 派生（一致性关键）

```
conn_key = dev_id:u32 BE | client_ip:u32 | client_port:u16 | server_ip:u32 | server_port:u16 | proto:u8
client/server 判定：首个 SYN 的 src=client；无 SYN（中流抓包）→ 按 (ip,port) 字典序小者为 client。
conn_hash = fnv1a64(conn_key)
```

> 已知局限：中流开始抓包时方向可能反置，`meta_binds.dst_port` 规则可校正；文档标注。

---

## 五、核心算法伪代码

### 5.1 SeqStream（回绕根治）

```rust
struct SeqStream { last_raw: u32, last_abs: u64 }
fn on_raw(&mut self, raw: u32) -> u64 {
    let d = raw.wrapping_sub(self.last_raw) as i32;   // 有符号模差
    if d > 0 { self.last_abs = self.last_abs.wrapping_add(d as u64); }
    self.last_raw = raw;
    self.last_abs                                       // d≤0 → 重传/重复，不后退
}
// abs_ack 用对向流翻译器换算；abs_q_end = abs_q_seq + orig_len
```

### 5.2 Batch 主循环 + 提交协议

```rust
fn process_batch(recs: &[WalRecord], env: &LmdbEnv, sql: &mut SqliteLedger) -> Result<()> {
    let txn = env.begin_rw_txn()?;
    for rec in recs {
        let conn = conn_tracker.get_or_insert(&txn, rec);       // read-modify-write
        if conn.quarantined { count_only(conn, rec); continue; }
        let abs = translate(conn, rec);                          // SeqStream × 方向
        match direction(rec) {
            ClientToServer if payload > 0 => {
                if conn.qr_open >= cfg.qr_pending_budget { quarantine(conn, &txn, CONN_QR_FLOOD)?; continue; }
                write_q_pending(conn, rec, abs, &txn)?;          // QR_PAIR(PENDING)+QR_PENDING+CONN_QR+QR_KEY+QR_TIME+PACKET_QR
            }
            ServerToClient if abs.ack > 0 =>
                consume_q_pending(conn, abs.ack, &txn)?,         // 区间消费+批量ACK聚合
            _ => {}
        }
        if rec.tcp_flags & RST != 0 { cascade_abort(conn, &txn)?; }
        update_state(conn, rec, abs);                           // 计数/anomaly_flags
        conn_tracker.write_back(&txn, conn);
    }
    txn.commit()?;                                              // ① LMDB 先行
    sql.advance_watermarks(&files_watermark)?;                  // ② SQLite 殿后
    advance_memory_cursors();                                   // ③ 游标推进（成功才执行）
    Ok(())
}
// 失败路径：txn.abort()/sql.rollback() → 丢弃内存态 → 日志 → 下轮从原水位线重放（幂等自愈）
```

### 5.3 累积 ACK 消费（R 到达）

```rust
fn consume_q_pending(conn, abs_ack, txn) {
    let mut cur = txn.cursor(DBI_QR_PENDING).seek_range(conn.hash, 0)?;  // 从最低 abs_q_end 起
    while let Some((k, v)) = cur.get()? {
        if k.abs_q_end > abs_ack + tol { break; }              // 单区间，B+树数值序==流序
        let qr = load_qr_pair(v.q_first_idx);
        if qr.status == PENDING {
            if qr.r_idx_list.is_empty() {                      // 首个消费 → 缝合
                qr.status = MATCHED; qr.r_idx_list.push(current_r_idx);
                qr.r_ts = now; qr.latency_ms = now - qr.q_ts;
            } else { qr.r_idx_list.push(current_r_idx); }      // 批量ACK聚合
            write_qr_pair(qr); update CONN_QR status;
        }
        delete pending entry; delete PENDING_TTL entry;        // 同事务
        cur = cur.next()?;
    }
    conn.consumed_ack_abs = max(conn.consumed_ack_abs, abs_ack);
}
```

### 5.4 RST 级联熔断 & 检疫

```rust
fn cascade_abort(conn, txn) {
    // 区间扫 DBI_QR_PENDING[conn_hash]，全部 → status=RST_ABORT，删挂起/TTL/更新 CONN_QR
    conn.state = RESET;
}
fn quarantine(conn, txn, reason: AnomalyKind) {   // reason: CONN_QR_FLOOD | CONN_OOO_FLOOD
    conn.quarantined = true; conn.anomaly_flags |= reason;
    // 在途 Q 全翻 ABORTED_RESOURCE（Q_IDX 保留）；此后该连接仅 count_only
    // 数据平面照常落 WAL/PCAP + DBI_RECORD_TS；连接关闭时聚合归档一次
}
```

### 5.5 回放自愈（提交窗口期）

```
崩溃于 LMDB 提交后、SQLite 水位线前 → 水位线指旧位 → 重放同批记录
→ QRPAIR 主键 q_first_idx 确定性 + MDB_NOOVERWRITE → 同键写覆盖为幂等 → 收敛
```

### 5.6 乱序缓存预算与连接检疫（L1/L2/L2.5/L3 四层）★

**四层预算，逐级拦截恶意/病态流量（超限动作全部为内部动作，绝不线上注入 RST）**：

| 层级 | 预算 | 默认 | 超限动作 |
|---|---|---|---|
| L1 单连接未决 Q 计数 | `qr_pending_budget` | 4096 | 置 `CONN_QR_FLOOD` → 内部检疫（见 5.4） |
| L2 单段 pending 字节 | `segment_pending_cap` | = segment_size | 段标 `ERROR` + `SEGMENT_GAP` + 丢段 pending + GapQuery 自愈 |
| **L2.5 单连接 OOO 字节** | `conn_pending_cap_bytes` | 16MB | ① 连接内逐出最旧 → ② 窗口内持续耗尽升级内部检疫 |
| L3 全局 pending 字节 | `pending_budget_bytes` | 256MB | **连接感知逐出**：优先清已检疫/标记连接的缓存，无辜连接最后碰 |

> L2.5 填补 L1（按 Q 计数）与 L2（按段）之间的连接维度字节硬闸：恶意连接无法以"单段压在 L2 上限内、横跨大量段"的方式独占全局 L3，也不受全局逐出误伤无辜连接。

```rust
struct ConnOOOBudget { used_bytes: u64, evict_streak: u32, window_start: u64 }

fn on_ooo_overflow(conn, txn) {
    // ① 连接内逐出最旧 OOO 段（abs_seq 最小），置 SEQ_GAP → GapQuery 回源自愈
    //    数据平面照常落 WAL/PCAP + DBI_RECORD_TS，仅省下重组/匹配成本
    evict_oldest_in_conn(conn, txn);
    // ② 窗口内持续耗尽（conn_evict_threshold 次）→ 升级内部检疫，语义同 L1
    if conn.ooo.quota_exhausted_in_window(cfg) {
        quarantine(conn, txn, CONN_OOO_FLOOD);   // 见 5.4
    }
}
```

**为何超限"绝不注入 RST"（红线三理由）**：
1. **旁路带外被动探针**：硬红线"永不扰动生产"，注入 RST 违反系统定位；
2. **RST 可伪造**：建立"超限即注入"行为等于把防御机制变成攻击面，恶意者可借此切断受害连接；
3. **零收益**：恶意连接两端皆受攻击者控制，RST 杀不掉资源开销，只会误伤高压压测下的正常乱序流量。

---

## 六、状态机规格

| 状态机 | 取值 |
|---|---|
| SegmentState | `NEW → UNFINISHED ⇄ SEALED → SKIPPED/ERROR` |
| ConnState | `SYN_SENT → SYN_RCVD → ESTABLISHED →(FIN×2/RST/TIMEOUT)→ CLOSED/RESET/TIMEOUT`；`HALF_OPEN`（数据无 SYN）；`QUARANTINED`（L1/L2.5 超限） |
| QrStatus | `PENDING → MATCHED`；`PENDING → TIMEOUT`（TTL）；`PENDING → UNMATCHED`（关闭）；`PENDING → RST_ABORT`（RST 级联）；`PENDING → ABORTED_RESOURCE`（检疫） |

**QrStatus 迁移表**：从 PENDING 出发的五条出边，全部保留 Q_IDX + Req_KEY；无任何"消失"路径。

---

## 七、错误处理与可观测性

- **错误分类**：传输帧坏（丢弃计数）/ 解密失败（丢弃计数）/ 重组缺口（GapQuery 自愈）/ 段校验失败（CRC_DROP）/ LMDB 提交失败（批次回滚+日志+重放）/ SQLite 失败（不推进水位线）。
- **指标**（text 暴露，仿 sovProbe metrics）：`sovvault_batches_total / committed / rolled_back / qr_matched / qr_pending / qr_timeout / qr_aborted / conn_active / conn_quarantined / conn_ooo_evicts / conn_ooo_quarantined / dup_count / retrans_count / zero_win_count / lmdb_map_used_bytes`。
- **日志**：仅批级别（每批一行摘要），不逐包打日志。

---

## 八、测试计划

### 8.1 单元测试清单

| 模块 | 用例 |
|---|---|
| seq.rs | 回绕前进（0xFFFF_FFF0→0x10=+32）；重传 d≤0 不后退；连续多包绝对号递增 |
| id.rs | IDX 往返；4GB 边界不变量 |
| reassembly | 乱序回填；幂等去重；Seal 缺口对账；四重校验脏尾退栈；L2/L3 预算超限段检疫；L2.5 单连接字节超限→连接内逐出最旧；窗口内持续耗尽→升级检疫；段号跳空 |
| qr.rs | 精确匹配；批量 ACK 聚合单 QRPAIR；跨批（写 LMDB 后新事务消费）；回绕；tolerance 边界；RST 级联；检疫 |
| connection | 状态机迁移；方向计数；conn_hash 稳定 |
| meta | HTTP/TLS/DNS/JSON 指纹；伪 KEY 稳定性（同签名同 KEY） |
| db.rs | 8 DBI 键值编解码往返 |
| ledger.rs | DDL 建表；files/水位线/异常幂等重入 |

### 8.2 集成测试

- **batch_atomicity**：注入 `txn.commit` 失败 → 断言水位线不推进；同一批重放两次 → QRPAIR 数量不变（幂等）。
- **qr_matching**：构造握手 + 管道化双 Q + 跨文件慢响应 + SEQ 回绕场景，断言各 QRPair 状态/延迟。
- **export**：导出 PCAP 后用 `pcap-file` 读回，断言 orig_len/tcp_flags/seq/ack/window。

### 8.3 双 VM E2E（P5，复用 M7 框架）

VM-1：sovProbe + slimSync；VM-2：sovVault。断言：重组 MD5 与源段 100% 一致；QR 命中率（精确 ≥99%、管道化 ≥95%）；异常台账可查询可回跳；回放 PENDING+异常 Q 零遗漏。

---

## 九、分阶段里程碑（单人约 17 人日）

| 阶段 | 任务 | 交付 | 验收 | 估时 |
|---|---|---|---|---|
| P0 | 三平面骨架：File 分层 + SQLite DDL + LMDB 8 DBI + IDX/conn_hash | 可建库可读写 | IDX 往返、8 DBI 编解码单测绿 | 2d |
| P1 | 重组底座：解密/落位/段状态机/四重校验/Gap 自愈 + L2/L3/L2.5 预算 | Reassembler + walscan | §8.1 reassembly 全绿 | 3d |
| P2 | 批量原子性：BatchCommit 提交协议 + 回放自愈 | batch.rs | §8.2 atomicity 绿 | 2d |
| P3 | QR 匹配：SeqStream + 累积ACK消费 + 快/慢路径 + 聚合 + 连接状态机 | seq.rs/qr.rs/connection.rs | §8.1 qr 全绿 | 3d |
| P3.5 | 查询索引：CONN_QR/QR_TIME/PACKET_QR/RECORD_TS + 单 CONN 检索链路 | db.rs 扩充 + query.rs | 单 CONN 查询毫秒级；IDX 反查命中 | 2d |
| P4 | 异常与慢路径：RST 级联 + 只计数 + FIN 缩短超时 + TTL + 检疫 | anomaly/quarantine | §8.1 异常用例绿；RST 不等超时 | 2d |
| P5 | 导出与 E2E：PCAP/Parquet + MetaBind/EXT META + 双输入 + 双 VM 压测 | export/ingest/offline | §8.3 全达标 | 3d |

---

## 十、风险与缓解

| 风险 | 缓解 |
|---|---|
| LMDB 数据文件损坏 | 从 SQLite 水位线全量重放重建索引（自愈路径，P2 必测） |
| 中流抓包方向歧义 | meta_binds.dst_port 校正 + 文档标注局限 |
| 批量 ACK 聚合语义边界 | 已定"单 ACK 单响应=单 QRPAIR"，E2E 专测 keep-alive 管道化 |
| LMDB map_size 不足 | 稀疏 mmap + `lmdb_map_used_bytes` 监控 + 扩容量指引（扩容需重开 env，规划热切换） |
| heed 版本/BE 类型缺失 | 锁版本 + 手写 byteorder 编解码 + fallback `lmdb` crate |
| SQLite 写放大 | 批事务（每批一次）+ 水位线单行更新 + "网络天气"只计数 |

---

## 十一、配置 Schema（完整）

```toml
[zenoh]
connect = ["tcp/10.0.0.2:7447"]   # client 端点（显式 connect）
listen = []                        # peer/listener

[crypto]
key_file = "/etc/sovvault/keys/slimsync.key"   # 32B，与 slimSync 一致
# key_hex = "…"   # 二选一，hex 优先

[storage]
root = "/var/lib/sovvault"
hot_dir = "hot"            # WAL 重组中
warm_dir = "warm"          # WAL/PCAP 归档（经典 PCAP，切段 ≤4GB）
ledger_db = "ledger.db"    # SQLite 管理平面
lmdb_dir = "qridx"         # LMDB 索引平面
lmdb_map_size = "64GB"     # 稀疏 mmap；杜绝 MDB_MAP_FULL

[ingest]
subscribe_batches = true   # 批量帧
subscribe_chunks = false   # 单帧兼容（默认关）
gap_self_heal = true
batch_size = 10000         # 一个 LMDB 事务的报文数（文件边界优先截断）
pending_budget_bytes = "256MB"   # L3 全局乱序兜底
segment_pending_cap = 0          # L2 单段硬上限；0=默认 segment_size
conn_pending_cap_bytes = "16MB"  # L2.5 单连接 OOO 字节硬闸；0=不限制
conn_evict_window_secs = 30      # L2.5 配额耗尽计数窗口
conn_evict_threshold = 3         # 窗口内耗尽次数达此值 → 升级内部检疫

[analysis]
conn_idle_timeout_secs = 300
qr_pending_budget = 4096    # L1 单连接未决 Q 硬上限 → 内部检疫
ack_tolerance = 4
qr_timeout_secs = 30
ttl_scan_secs = 1
fin_short_timeout_secs = 5
meta_binds = [ { name="web", proto=6, dst_port=80, fingerprint="http", extractor="http_line" },
               { name="https", proto=6, dst_port=443, fingerprint="tls", extractor="sni" },
               { name="dns", proto=17, dst_port=53, fingerprint="dns", extractor="qname" } ]

[query]
export_buf_size = 4096      # PCAP 流式导出缓冲（包）
```

---

## 十二、验收标准（自 08 v0.4 继承）

| 指标 | 目标 |
|---|---|
| 重组正确性 | 与源段 MD5 字节级 100% 一致 |
| 批量原子性 | 任一批失败 → 水位线不回退、重放幂等收敛 |
| QR 匹配 | 精确 ≥99%；管道化/批量 ACK ≥95%；SEQ 回绕零误判；PENDING+异常 Q 零遗漏 |
| 单 CONN 查询 | DBI_CONN_QR 前缀扫描毫秒级；FILE_ID.OFFSET 反查 O(logN) |
| RST/检疫 | RST 到达 → PENDING 原子翻 RST_ABORT 不等超时；L1/L2.5 超限 → 内部检疫无线上 RST，恶意连接只能烧自身预算、不误伤无辜 |
| 异常 | DUP/SEQ_GAP/ZERO_WIN 只计数，关闭聚合归档；CRC_DROP/RST/QR_TIMEOUT 可统计可回跳 |
| PCAP | Wireshark 还原握手 + `[Packet size limited]` 精准出现 |
| 资源 | RSS ≤256MB；CPU ≤20%（4 核）；LMDB map_size 稀疏不占物理 |

---

> 相关文档：`08_sovVault_设计与实施方案.md`（v0.4，本白皮书的架构依据）
