# sovVault 详细实施方案（实施白皮书 v0.2）

> 状态：**待评审** | 版本：v0.4 | 前置依赖：`08_sovVault_设计与实施方案.md`（v0.6）
> v0.2 变更：新增 **L2.5 单连接 OOO 字节预算**（填补 L1/L2 间的连接维度字节硬闸）——超限先连接内逐出最旧，持续病态升级内部检疫；明确超限绝不注入线上 RST（红线三理由）；L3 升级为连接感知逐出。
> v0.3 变更：P2 批量原子性落地——`RECORD_TS` 写入提前至 P2（第 9 个 DBI，作为逐条确定性索引锚点/回放收敛依据，查询消费仍留 P3.5）；SQLite 水位线同步策略拍板（常规 NORMAL + 文件边界屏障 durable + hot 截断到水位线重启规则）。
> **v0.4 变更（核心架构修订）：双库分库轮转——解决 M7 资源红线「sovVault 常驻 RSS ≤ 256MB」**。M7 实测发现 LMDB 共享 mmap 页驻留 RSS ≈ 数据量且内核不可回收（MADV_DONTNEED/MADV_FREE/posix_fadvise/内存压力实测全部无效），单 env 下 RSS 随数据量线性增长必然超红线。v0.4 将索引平面拆分为**常驻活状态库（live）+ 历史分库（epoch）**：活状态（连接状态/在途请求/TTL）永久留驻 live 库（数据量有界），历史索引按 `epoch_max_bytes` 封顶轮转新 env（关闭旧 env 即 munmap 完整回收 RSS）。QR 匹配的跨 epoch 连接通过「QR_PAIR 在途→终态迁移」与「双事务顺序提交 + 确定性键幂等收敛」保证正确性。详见 [§十三](#十三双库分库轮转设计修订v04核心架构修订)。
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
| Hash | 连接键先用 `fnv-1a-64`（零依赖），性能不足换 `xxhash-rust` | 同一哈希在 9 个 DBI 间一致 |

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
│   ├── db.rs                      # 9 DBI 句柄 + 键值编解码（db/ 子模块可拆）
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

### 4.2 9 DBI 键值布局（键一律大端）

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
| `RECORD_TS` | `ts_ns:u64` \| `packet_idx:u64` | 紧凑摘要：proto:u8 \| flags:u8 \| src_ip:u32 \| dst_ip:u32 \| sport:u16 \| dport:u16 \| len:u32（18B） |

> `status` 枚举：0=PENDING 1=MATCHED 2=TIMEOUT 3=UNMATCHED 4=RST_ABORT 5=ABORTED_RESOURCE。
> **v0.3 决策**：`RECORD_TS` 的**写入**提前至 P2（作为逐条确定性索引锚点，支撑批量原子性与回放收敛断言）；其**查询/导出消费层**仍在 P3.5 落地（原决议不变）。

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

**SQLite 水位线同步策略（v0.3 拍板）**：
- 常规批次：`WAL + synchronous=NORMAL`（不逐提交 fsync，吞吐优先）。
- **正确性论证**：SQLite 是"殿后"，**永不越过已落盘的 LMDB 提交**；唯一失败方向是"水位线落后"→ 重放幂等收敛。故逐提交 FULL 无正确性收益，只付吞吐代价。
- **文件边界屏障处升级 durable**：切换文件时 `synchronous=FULL` 提交 + 数据平面文件 `sync_all()`，把"本文件 100% 已入库"固化，杜绝重启后跨文件消费。
- **不与物理 Close 挂钩**：Close 仅句柄动作，锚定语义是"文件边界"（切换时顺带触发旧文件 Close：先 flush 数据 → durable 水位线 → 再切句柄）。
- **崩溃重启规则**：hot 文件**截断到 SQLite 水位线**（数据平面写入无事务性，未提交尾部必须丢弃），再重放。

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
| db.rs | 9 DBI 键值编解码往返 |
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
| P0 | 三平面骨架：File 分层 + SQLite DDL + LMDB 8 DBI（P2 扩至 9）+ IDX/conn_hash | 可建库可读写 | IDX 往返、8 DBI 编解码单测绿 | 2d |
| P1 | 重组底座：解密/落位/段状态机/四重校验/Gap 自愈 + L2/L3/L2.5 预算 | Reassembler + walscan | §8.1 reassembly 全绿 | 3d |
| P2 | 批量原子性：BatchCommit 提交协议（①LMDB→②SQLite→③游标）+ 文件边界屏障 + RECORD_TS 写入 + 崩溃窗口重放自愈 | batch.rs + db.rs（第 9 DBI） | §8.2 atomicity 绿（含崩溃模拟单测） | 2d |
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
epoch_max_bytes = "128MB"  # v0.4：单历史 epoch 数据量上限（双库分库轮转，见 §13）
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

---

## 十三、双库分库轮转设计修订（v0.4，核心架构修订）★

> **修订动机（M7 实测硬数据）**：
> - 现象：sovVault 常驻 RSS 随 LMDB 数据量线性增长（467MB 数据 → 457MB RSS），M7 红线 **RSS ≤ 256MB** 不可达成。
> - 根因：LMDB 采用 `MAP_SHARED` 共享 mmap，其 mmap 页一旦写入即永久驻留 RSS。实测 MADV_DONTNEED / MADV_FREE / posix_fadvise(POSIX_FADV_DONTNEED) / 3GB 内存压力**全部无效**（RSS 纹丝不动）；`MDB_WRITEMAP` 与稀疏 mmap 只解决磁盘占用、不解决 RSS。
> - 结论：RSS ≈ 数据量是 LMDB 架构的**数学必然**，单 env 下不可治理。必须**分库**：把"活状态"（量有界）与"历史索引"（量增长）分离，历史按量封顶轮转新 env，关闭旧 env（munmap）即完整回收其 RSS（已验证：drop env 后 RSS 25.9MB→2.2MB）。

### 13.1 双库目录布局

```
qridx/
├── live/                 ← 常驻，永不轮转（只存"在途状态"，数据量有界）
│   ├── data.mdb          DBI: CONN_STATE + QR_PENDING + PENDING_TTL + 在途 QR_PAIR
│   └── lock.mdb
├── epoch_0000/           ← 历史分库，追加后只读
│   ├── data.mdb          DBI: 终态 QR_PAIR + CONN_QR/QR_KEY/QR_TIME/PACKET_QR/RECORD_TS
│   └── ...
├── epoch_0001/
│   └── ...
└── ledger.db             ← SQLite 管理平面（文件清单/水位线/epoch 边界/审计）
```

### 13.2 数据归属（9 DBI 生命周期分类 ★ 回答「哪些数据需要延续」）

| DBI | 库 | 写入时机 | 生命周期判定 |
|---|---|---|---|
| CONN_STATE | **live** | 每批 `writeback_conns` 覆盖写 | **活状态**：abs_seq 翻译器/计数反复改写；连接关闭/空闲超时清理，量=活跃连接数 |
| QR_PENDING | **live** | Q 打开写、消费删 | **活状态**：在途请求；量=并发在途（`qr_pending_budget` 已限单连接） |
| PENDING_TTL | **live** | Q 打开写、消费/TTL 删 | **活状态**：TTL 扫描依据；量=并发在途 |
| QR_PAIR（status=PENDING） | **live** | Q 打开写 | **半活**：在途；终态时**迁移到 epoch**（见 13.3） |
| QR_PAIR（status=终态） | **epoch** | 终态迁移写入 | **历史**：追加归档，不再改 |
| CONN_QR / QR_KEY / QR_TIME | **epoch** | Q 打开写一次（**不含 status**，见 13.4.1） | **历史**：纯追加索引 |
| PACKET_QR | **epoch** | Q 打开写 | **历史**：追加索引 |
| RECORD_TS | **epoch** | 每报文写 | **历史**：追加索引 |

**设计原则（回答「保留活状态降低查询工作量」）**：
- **活状态不复制、永久留驻 live 库**。它本身就是查询热点（在途请求/TTL/连接审计/QR 匹配读-改-写循环）——留驻 live 使这些查询**只查单库、零跨库合并**。
- **历史索引分 epoch 轮转**。它们纯追加，封存后只读；轮转关闭旧 env 回收 RSS。
- **live 库大小 = 在途量（有界）**；epoch 库大小按 `epoch_max_bytes` 封顶。常驻 RSS = live 库数据量 + 单 epoch 数据量 + 固定开销，有界可算。

### 13.3 QR_PAIR 在途→终态迁移（正确性核心 ★）

QR 匹配的读-改-写循环跨请求生命周期。Q 打开时 QR_PAIR 处于 PENDING（在途），配完后进入终态（MATCHED/TIMEOUT/UNMATCHED/RST_ABORT/ABORTED_RESOURCE）。双库下：

```
Q 打开:   QR_PAIR(PENDING) → live 库
R 消费:   QR_PAIR 读 live → 翻转终态 → 写 epoch 库（当前 epoch）+ 从 live 删
TTL超时:  QR_PAIR 读 live → 翻转 TIMEOUT → 写 epoch 库 + 从 live 删
RST级联:  同上（RST_ABORT）
代际翻转: 同上（UNMATCHED）
检疫:     同上（ABORTED_RESOURCE）
```

**跨 epoch 连接延续**：epoch 轮转只发生在历史库；live 库的在途 QR_PAIR 天然延续（迁移写入的是"当时的当前 epoch"）。故 **Q 在 epoch0 打开、R 在 epoch1 到达** → QR_PAIR 始终在 live 被消费 → 终态迁入 epoch1。连接状态（CONN_STATE）同理永不离开 live。**跨 epoch 连接正确性不破坏**。

**代价**：同一连接的不同 Q 可能分散在不同 epoch 库。查询按 `q_first_idx` 主键定位 + 跨库枚举即可，对调用方透明。

### 13.4 双事务顺序提交（原子性模型修订 ★）

`QrMatcher` 由「单 env 单事务」改为「双 env 双事务顺序提交」。**LMDB 不支持跨 env 原子事务**，复用现有 2PC-Lite 的「确定性键 + NO_OVERWRITE + 水位线回放」幂等收敛哲学：

```
QrMatcher 持有两个 txn：
  ① live_txn   ← live env 写事务
  ② epoch_txn  ← 当前 epoch env 写事务

ingest 每条报文：
  - RECORD_TS → epoch_txn
  - 连接热状态/QR 匹配读-改-写：
      CONN_STATE / QR_PENDING / PENDING_TTL / 在途 QR_PAIR 读写在 live_txn
      终态 QR_PAIR 迁移 + CONN_QR/QR_KEY/QR_TIME/PACKET_QR 写 epoch_txn

commit 顺序（不可颠倒）：
  ② epoch_txn.commit()     （历史索引，NO_OVERWRITE 幂等）
  ① live_txn.commit()      （在途状态/残留删除，量小，快）
  ③ SQLite 水位线 advance   （管理平面殿后）

> **实现裁决（epoch 先行）**：§13.4.2 幂等表明确列出「写 epoch 后、删 live 前」为可达崩溃窗口——
> 重放时 live 仍 PENDING、epoch 已有终态 → 先查 epoch 跳过迁移、仅清 live 残留。该窗口要求
> epoch 必须先于 live 残留删除持久（迁移的 live QR_PAIR 删除与 CONN_STATE 在同一 live txn 原子）。
> 若 live 先行删除 PENDING QR_PAIR 而 epoch 未持久，崩溃即丢 Q（违反「PENDING+异常 Q 零遗漏」）。
> 故 commit 顺序取 **epoch 先行 → live 殿后**；epoch 只写「追加后只读」历史，先行提交不引入写锁竞争
> （单写者串行化由 LMDB 保证）。详见 src/db.rs 模块注释。

失败收敛（回放自愈，同 §5.5）：
  - ②失败 → ①②③未执行 → 整批 abort → 下轮从原水位线重放
  - ②成功①失败 → ③未执行 → 水位线未动 → 重放同批：
      QR_PAIR 确定性键 `q_first_idx` + 先查 epoch（已有则跳过迁移、仅清 live 残留）→ 收敛零脏数据
  - 崩溃于①后③前 → 水位线指旧位 → 重放收敛（同现有协议）
```

**原子性语义变化**：从「全有全无」变为「可重放收敛」。正确性由确定性主键 + 幂等写入保证（与现有 SQLite 殿后模型一致），审计事件 best-effort 落库不阻塞协议。

### 13.4.1 次级索引 status 去重（设计点①：跨 epoch 更新矛盾消除）★

**矛盾**：CONN_QR / QR_KEY / QR_TIME 的 value 原存 status（`v_status_encode`），Q 打开时写当前 epoch（PENDING），终态翻转（消费 / TTL / RST / 代际）需更新 status → 但历史 epoch 已冻结关闭，**跨 epoch 无法更新**。

**裁决：次级索引不存 status 语义（解法 B）**：
- CONN_QR / QR_KEY / QR_TIME / PACKET_QR 的 value 仅作为**存在性 + 定位**（写 q_first_idx 或常量占位），**Q 打开时写一次，永不更新**（纯追加）。
- status 过滤查询（`qr --status X`）流程改为：**次级索引定位候选 q_first_idx → 回查 QR_PAIR 主行判 status**（`qr_by_idx` 现查）。
- **依据**：次级索引 status 仅是查询优化（先粗筛避免全量翻页），最终正确性以 QR_PAIR 主行为准（`--detail` 本就回查主行）。删除 status 更新**消除跨 epoch 更新矛盾**，历史库回归「追加后只读」。
- **代价**：带 `--status` 过滤的查询多一次 O(logN) 主行回查（仅过滤时发生，detail 本需回查）。
- **实现**：删除 `sync_secondary_status` / `write_secondary_status` 的全部调用（ingest consume/flip 3 处 + TTL timeout 1 处）；`scan_conn_qr` / `scan_time_qr` 的 status 过滤改为「索引定位 + 主行现查」。

### 13.4.2 QR_PAIR 迁移幂等规则（设计点②：重放时序）★

迁移动作 = 「读 live(PENDING) → 写 epoch(终态) → 删 live」，跨两个 txn。**重放时序必须幂等**：

```
崩溃窗口                 重放时的状态              重放动作
─────────────────────────────────────────────────────────────────
迁移前崩溃              live 有 PENDING            正常迁移
写 epoch 后、删 live 前  live 有 PENDING           先查 epoch：已有 → 跳过迁移（幂等）
                          epoch 已有终态            再删 live 残留
删 live 后、水位线前       live 无、epoch 有终态     已收敛，水位线推进即完成
```

**幂等规则**：重放时对每个 q_first_idx，**先查 epoch 库 QR_PAIR**——存在则跳过迁移（不重复写）、仅清理 live 残留；不存在才走「读 live → 写 epoch → 删 live」。此规则在 ingest 消费/TTL/级联/代际/检疫 五条终态路径统一实现。

### 13.4.3 TTL 扫描跨库读写（补全）★

TTL 扫描（`anomaly.rs`）复用同一套双库模型：
- **读**：`PENDING_TTL` / `QR_PENDING` / `CONN_STATE` / 在途 `QR_PAIR` 全部在 **live 库**。
- **写**：翻转终态 QR_PAIR → 迁入 **当前 epoch 库**（同 §13.4.2 幂等规则）；`write_secondary_status` 调用**删除**（§13.4.1）。
- TTL 扫描本身是后台协程（`run_ttl_loop`），持有 live + 当前 epoch 两个 env 的只读/写事务，与 ingest 主循环的写事务由 LMDB 单写者串行化保证互斥。

### 13.5 epoch 轮转触发与查询路由

**轮转触发**：
- 每个 epoch 库的 `data.mdb` 实际占用达 `ingest.epoch_max_bytes`（默认 128MB，见 §11 配置）→ 冻结当前 epoch（Ledger 标 ARCHIVED）→ 开新 epoch env。
- **live 库永不轮转**（在途状态天然有界）。
- 轮转动作：`flush` 当前批 → 关旧 epoch env（drop → munmap 回收 RSS）→ 建新 epoch env。

**查询路由**：
| 查询 | 路由 |
|---|---|
| 在途请求 / TTL / 连接审计 / QR 匹配 | **只查 live 库**（单库，无跨库） |
| 历史时间窗 / 连接回溯 / PCAP 导出 | 枚举 `qridx/epoch_*/` 逐个打开聚合（低频交互） |
| QR 详情（`qr --detail`） | live 库查在途 + epoch 库查终态，按 `q_first_idx` 定位 |

### 13.5.1 epoch 时间边界索引 + 惰性打开（v0.4.1 L1+L2 落地）★

> 背景：REPLAY/AUDIT/DIAG 是 v0.4 的核心消费方。旧 `QuerySession::open` 每次全量打开 live +
> 全部历史 epoch，每个持 `static_read_txn` 直到会话结束——epoch 数一多，REPLAY 吞吐掉、DIAG 点查慢、
> 句柄/mmap/reader slot 线性涨，违背「RSS 有界」初衷。v0.4.1 两刀治根：

**L1 epoch 时间边界索引**：历史 epoch 数据冻结，唯一裁剪依据是时间。Ledger 加 `epochs` 表：
`epoch_id | dir | min_ts | max_ts | record_count | state(FROZEN/ACTIVE)`。轮转冻结时
（`ingest/zenoh.rs::maybe_rotate_epoch`，先读 `DbRegistry::current_epoch_bounds()` 再 upsert 再 rotate，
失败不轮转下轮重试）写入边界。查询 `QuerySession::open_with_window(reg, ledger, start, end)`
按 `[start_ts, end_ts]` 只挑命中的 epoch——从「全量打开 N 个」降到「窗口内 k 个」。
规则：无时间窗 → 全保留；当前 epoch（max_ts 未知）→ 恒保留；无边界行（旧库/未冻结）→ 保留（宁可多扫）。

**L2 惰性打开 + 短事务**：`QuerySession` 不再持有全部 epoch 的静态只读事务。
历史 epoch 用即开、用完即关（数据冻结，随时读到最终态，无需持久 txn；env 句柄随函数返回即 drop →
reader slot/mmap 随用随放）；仅 live + 当前 epoch 克隆 `DbRegistry` 已开 env 的短 txn（一致快照）。
`page_rows_epochs` 扫到哪个 epoch 才 `open_epoch`，扫完 drop——峰值 = live + 当前 + 1 个历史。

> 约束：heed/LMDB TLS reader 下同线程同一 env 并发开第二个会话会 `MDB_BAD_RSLOT`；
> 使用约束为「同线程同时至多一个 QuerySession 存活」，CLI/export 单会话短生命周期天然满足。

| 模块 | 改动 |
|---|---|
| `ledger.rs` | `epochs` 表 + `EpochBoundary/EpochState` + `upsert_epoch_boundary` / `epoch_boundaries` |
| `db.rs` | `current_epoch_bounds()`（RECORD_TS first/last/len）；`epoch_targets()` / `epoch_num_of` |
| `query.rs` | `QuerySession` 惰性打开重构；`open_with_window`（L1 裁剪）；`epoch_get`/`scan_epoch_range`/`prune_targets_by_window` |
| `ingest/zenoh.rs` | `maybe_rotate_epoch` 冻结前写边界（先写后转，失败不轮转） |
| `export.rs` / `main.rs` | `export_pcap` / `cmd_query` / `cmd_qr` 走 `open_with_window`（时间窗裁剪） |

### 13.5.2 REPLAY 专用流式路径（v0.4.1 L3 落地）★

> 背景：REPLAY 要的是「按时间序连续字节流 + 数据平面回读」，不是分页列表。
> 旧 `export_pcap` 走分页框架（`scan_records` + `Page`/`PageRows`/游标往返），每页重建迭代器、
> 重建 `RawEpochRow` 中间行——窗口大时吞吐受分页开销拖累。

**L3 `replay_scan(reg, ledger, start, end, sink)`**（`query.rs`）：
- 直接按 epoch 边界裁剪（L1）→ 每个 epoch 内**单次 range** 迭代 `RECORD_TS`，
  键值就地解码（零额外分配喂行）连续喂 `sink.record`——**不做分页、不重建迭代器、无游标往返**；
- 输出即「时间序连续原始流量」（epoch 升序 + 库内键序），供 REPLAY 加速回放直连；
- `PcapSink` 适配 `ExportSink`（`qr` 维度不适用恒 Ok；`record` 走 BPF 过滤 + WalResolver 回读 + 帧合成）；
- `export_pcap` / `stream_records` 统一改走该路径（`QuerySession::replay_into_sink`）。

| 模块 | 改动 |
|---|---|
| `query.rs` | `replay_scan` / `QuerySession::replay_into_sink` / `replay_epoch_range`（单次 range 流式喂行） |
| `export.rs` | `PcapSink` 实现 `ExportSink`；`export_pcap` 改用 `replay_scan`（删分页循环） |

### 13.5.3 连接维度路由（v0.4.1 L4 落地）★

> 背景：历史 conn 检索（DIAG/ROOT CAUSE）跨 epoch 枚举 CONN_QR，epoch 数一多即退化全扫。
> 且 QR_PAIR 终态可能因 **TTL 扫描在墙钟时刻**迁移到连接记录时间窗之外的晚 epoch——纯按
> 时间窗裁剪点查会丢数据。

**L4 `open_for_conn(reg, ledger, conn_hash)`**（`query.rs`）：
- **档案写**：`QrMatcher::writeback_conns` 对到终态（Closed/Reset/Timeout/Quarantined）的连接产出
  `ConnArchiveEvent`，`commit_batch_with_meta` 幂等 upsert 进 Ledger `conns` 表
  （first_ts/last_ts 取 MIN/MAX 并集，五元组复用收敛到并集时间窗）。
- **档案读**：连接时间窗 = live `CONN_STATE` first_ts..last_ts（真源，热状态常驻 live）→ 兜底
  Ledger `conns` 档案。窗口命中 L1 边界索引 → 只挑 epoch 子集再扫，避免全 epoch 枚举。
- **正确性（★）**：会话分两表——**范围扫描用裁剪后的 `targets`**，**点查用全量 `all_targets`**。
  TTL 迁移到裁剪集外晚 epoch 的 QR_PAIR 终态，点查仍全量枚举回跳（O(logN) 惰性重开，成本可控）；
  范围扫描（CONN_QR/QR_TIME/RECORD_TS）才是裁剪赢面所在。

| 模块 | 改动 |
|---|---|
| `ledger.rs` | `conns` 表 + `ConnArchive` + `upsert_conn_archive`（MIN/MAX 并集）/ `conn_archive` |
| `qr.rs` | `ConnArchiveEvent`/`CommitOutcome`；`writeback_conns` 终态连接产出档案事件 |
| `batch.rs` | `stage_lmdb_with_meta` 返回 3 元组；`commit_batch_with_meta` 落 conns 表 |
| `query.rs` | `open_for_conn`/`conn_window`；会话分 `targets`（扫描）/`all_targets`（点查） |
| `main.rs` | `cmd_qr` 连接维度无显式窗 → `open_for_conn` |

### 13.6 配置与 CLI

```toml
[ingest]
epoch_max_bytes = "128MB"   # 单历史 epoch 数据量上限（默认；RSS = live + 单epoch + 固定开销）
```

- `--lmdb-dir` 语义不变（qridx 父目录）；epoch 子目录 `qridx/epoch_<NNNN>/` 自动管理。
- 查询/导出子命令自动枚举全部 epoch，无需手动指定。

### 13.7 资源红线推算（M7 验收依据）

| 组成 | 估算 |
|---|---|
| live 库（在途状态） | 并发在途请求数 × 变长值，常态数 MB~数十 MB |
| 当前 epoch 库 | ≤ `epoch_max_bytes`（128MB） |
| 固定开销（heap/Zenoh/运行时） | 实测 ≈120MB |
| **常驻 RSS** | **≤ 128MB + 在途 + 120MB ≈ 256MB**（按 128MB epoch 配置） |

> 实测基准（v0.3 单 env）：467MB 数据 → 457MB RSS。v0.4 双库后单 epoch 封顶 128MB，RSS 有界不随历史总量增长。

### 13.8 实现改动清单（工程说明书）

| 模块 | 改动 |
|---|---|
| `db.rs` | `DbRegistry` 支持双 env 打开（live + 当前 epoch）；epoch 目录枚举；`real_disk_size()` 暴露（轮转判定） |
| `qr.rs` | `QrMatcher` 双事务（live_txn + epoch_txn）；QR_PAIR 迁移逻辑；DBI 归属重排；**删除 `sync_secondary_status` 调用（§13.4.1）** |
| `batch.rs` | `commit_batch` 拆双事务顺序提交；`stage_lmdb` 拆 stage_live / stage_epoch |
| `anomaly.rs` | TTL 扫描双库模型：读全在 live，终态迁移写当前 epoch（§13.4.3）；**删除 `write_secondary_status` 调用** |
| `ingest/zenoh.rs` | 轮转触发：epoch 库达上限 → 冻结/开新；持有可替换 `Box<DbRegistry>` |
| `query.rs` / `export.rs` | 历史查询跨 epoch 枚举聚合；**status 过滤改为「索引定位 + QR_PAIR 主行现查」** |
| `config.rs` | `epoch_max_bytes`；`lmdb_epoch_dir(s)` |
| `main.rs` | serve 持有双库；查询子命令枚举 epoch |

### 13.9 风险与回归

1. **QrMatcher 双事务**是核心重构，回归面最大——必须全量 E2E（atomicity/qr_match/ttl_audit/export/meta/p5_stress）回归。
2. **QR_PAIR 迁移**：迁移动作必须「先查 epoch（幂等判定）→ 读 live(PENDING) → 写 epoch(终态) → 删 live」同序执行，重放时 epoch 已有则跳过（§13.4.2）。
3. **次级索引 status 去重**：删除 status 更新后，带 `--status` 过滤的查询必须回查 QR_PAIR 主行，防止 status 过滤失效（§13.4.1）。
4. **查询跨 epoch**：历史查询需枚举所有 epoch 目录，保证确定性排序（epoch 序号升序 + 库内主键序）。
5. **旧数据兼容**：既有 `qridx/data.mdb` 单库数据需迁移为 `qridx/live/` + `qridx/epoch_0000/`（提供一次性迁移工具，或直接重建索引）。

---
