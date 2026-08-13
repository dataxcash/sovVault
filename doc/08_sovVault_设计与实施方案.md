# sovVault 设计与实施方案（评审稿 v0.7）

> 状态：**待评审** | 版本：v0.7 | 所属：IronSovereign 开源底座（datax.cash）
> 本文档定义存储中枢 **sovVault**：Zenoh 字节流 → 重组解密 → TCP 连接/QR 对匹配 → 分级存储 → 司法级导出与查询。
>
> **v0.7 修订（双库分库轮转，M7 资源红线治本）：**
> 1. **索引平面拆双库**：常驻 `live` 库（连接热状态 / 在途 QR / TTL，量有界，永不轮转）+ 历史 `epoch_*` 分库（终态 QR / 二级索引 / RECORD_TS，按 `epoch_max_bytes` 封顶轮转）。
> 2. **动机（M7 实测）**：LMDB `MAP_SHARED` 共享 mmap 页驻留 RSS ≈ 数据量，MADV_DONTNEED/MADV_FREE/posix_fadvise/内存压力实测全部不可回收（467MB 数据 → 457MB RSS，单 env 必超 256MB 红线）；关闭 env（munmap）可完整回收（实测 25.9MB→2.2MB）→ 分库轮转是唯一治本路径。
> 3. **QR_PAIR 在途→终态迁移**：Q 打开写 live（PENDING），配完/超时/级联/检疫时迁入当前 epoch（终态）；跨 epoch 连接因活状态永居 live 而不破坏。
> 4. **双事务顺序提交**：`QrMatcher` 由单 env 单事务改为 live_txn 先行 + epoch_txn 殿后，复用确定性键 + NO_OVERWRITE + 水位线回放的幂等收敛哲学，原子性语义从「全有全无」变为「可重放收敛」。
> 5. 详见 [§十三 双库分库轮转设计修订](#十三双库分库轮转设计修订v07核心架构修订)。
>
> **v0.2 修订（响应评审①）：**
> 1. 存储三平面：数据（File WAL/PCAP）+ 索引（LMDB QRIDX）+ 管理（SQLite 文件清单/水位线/审计）。
> 2. QRPAIR 首发生命周期实体（PENDING 自 Q 诞生）。
> 3. QR 匹配升级累积 ACK 消费模型；批量原子性（Batch=一个 LMDB 事务，LMDB 先行/SQLite 殿后，文件边界屏障）。
>
> **v0.4 修订（响应评审③）：**
> 1. **两项决议定案**：DUP/RETRANS/ZERO_WIN 等"网络天气"型异常**只计数、连接关闭时聚合归档一次**，绝不逐条落 SQLite；定向五元组索引（DBI_RECORD_5TUPLE）**延期至阶段二**，PCAP 导出保持 `DBI_RECORD_TS` 时间游标 + 内存 BPF 过滤。
> 2. **资源防御与连接检疫**：三层乱序缓存预算（单连接 QR 挂起硬上限 / 单段 pending 字节硬上限 / 全局兜底预算）。超限触发**内部检疫**（暂停该连接 QR 分析，数据平面不受影响），**绝不向线上注入 RST**——sovVault 为旁路带外被动探针，硬红线"永不扰动生产"。
>
> **v0.3 修订（响应评审②）：**
> 1. **SEQ 回绕根治**：每连接每方向引入 `raw(u32)→abs(48b)` 绝对序列号流翻译器，QR 挂起/消费 Key 全部用绝对号，B+树扫描免模差、无断层；DUP/RETRANS 判定同时落地。
> 2. **RST 级联熔断**：RST 帧到达 → 同事务内将该连接全部 PENDING Q 翻转为 `RST_ABORT`，不等待超时。
> 3. **EXT META 伪 Key 兜底**：无 L7 解码器时以 `[magic_prefix + entropy]` 特征生成伪 Key 入 `DBI_QR_KEY`，私有 Binary 协议同样可追溯。
> 4. **查询维度矩阵补齐**：新增 `DBI_CONN_QR`（单 CONN 反查）、`DBI_QR_TIME`（全局时间窗）、`DBI_PACKET_QR`（报文 IDX 逆向反查所属 QR）、`DBI_RECORD_TS`（报文时间窗导出），回答"单连接 QRIDX 如何查询"。
>
> **v0.5 修订（响应评审④ — L2.5 连接级 OOO 字节预算）：**
> 1. **L2.5 单连接 OOO 字节硬闸**（`conn_pending_cap_bytes`，默认 16MB）：填补 L1（按 Q 计数）与 L2（按段）之间的连接维度字节预算空洞——恶意连接无法以"单段压在 L2 上限内、横跨大量段"的方式独占全局 L3，也不受全局逐出误伤无辜连接。
> 2. **逐级响应**：超限先**连接内逐出最旧**（置 `SEQ_GAP` → GapQuery 回源自愈，数据平面照常落盘）；窗口（`conn_evict_window_secs`）内持续耗尽（`conn_evict_threshold` 次）升级**内部检疫**（`CONN_OOO_FLOOD`，语义同 L1）。
> 3. **L3 升级连接感知逐出**：全局兜底优先清已检疫/标记连接缓存，无辜连接最后碰。
> 4. **超限"强 RST"明确否决（红线三理由）**：旁路带外被动探针不扰动生产 / RST 可伪造会被恶意者利用成攻击面 / 恶意连接两端皆受控、注入 RST 零收益。
>
> **v0.6 修订（P2 批量原子性落地）：**
> 1. **DBI 8 → 9**：`RECORD_TS` 写入提前至 P2（逐条确定性索引锚点，支撑批量原子性与回放收敛）；查询消费层仍在 P3.5。
> 2. **SQLite 水位线同步策略**：常规批次 `synchronous=NORMAL`；文件边界屏障处升级 durable（FULL + 数据平面 `sync_all`），固化"本文件 100% 已入库"；崩溃重启把 hot 文件截断到水位线后重放。

---

## 一、目标与非目标

### 1.1 目标

- 接收端核心服务：Zenoh → **解密 → 乱序重组 → 段终态校验 → 分析索引 → 归档 → 司法级导出查询**。
- **TCP 连接台账**：生命周期状态机 + 双向往来统计 + 绝对序列号流，作为性能/故障分析底座。
- **QRPair 匹配（核心算法）**：TCP 累积 ACK 消费模型；QRPAIR 从 Q 诞生即存在，慢响应/超时/异常 Q 永不丢失。
- **Meta Bind / EXT META**：连接 ↔ 协议元数据绑定；无协议明细时按内容指纹（magic/熵/文本二进制/端口）识别并提取 KEY（或伪 KEY）。
- **异常采集/统计/查询**：丢包（Gap）、重复/重传、零窗口、超时、RST、脏尾全量落审计台账。
- **批量原子性**：BATCHSIZE 个报文在一个 LMDB 事务内提交；失败整体回滚，水位线不推进；文件边界为提交屏障。
- 司法级导出：时间窗 + 五元组过滤的 PCAP（orig_len/tcp_flags 100% 还原）/ Parquet（阶段二）；PROBE(WAL) 与 PCAP 双输入格式。

### 1.2 非目标（本期不做）

- Zenoh / FastCDC 发送端（slimSync）；eBPF 采集（sovProbe）；SLIMRAG 语义理解；Suricata 规则引擎；完整 L7 解码器（仅特征级识别）。

---

## 二、系统边界与数据流

```
[ Zenoh ] ── batches/** · segments/** · gaps/**
     ▼
┌─────────────────────────────────────────────────────────────┐
│ sovVault 流水线                                              │
│  ① Ingest（Zenoh / 离线 WAL / 离线 PCAP）                     │
│  ② Reassembly（解密→(dev,seg,offset)幂等落位→段状态机→四重校验） │
│  ③ Record 流 → 绝对 SEQ 翻译 → 连接状态机 → 累积ACK QR 匹配      │
│     → MetaBind/EXT META 指纹与 KEY/伪KEY 提取                   │
│  ④ 批量提交（BATCH=一个LMDB事务 + SQLite水位线，文件边界屏障）    │
│  ⑤ 导出/查询（时间窗+五元组 → PCAP/Parquet/JSON；单CONN QR 反查）│
└─────────────────────────────────────────────────────────────┘
        │                 │                   │
        ▼                 ▼                   ▼
   [ FILE 数据平面 ]  [ LMDB 索引平面 ]   [ SQLite 管理平面 ]
   hot/warm *.wal      9 个 DBI            files 文件清单
   *.pcap(经典格式)    见 §四               analysis_watermark
                                           lmdb_env 实例信息
                                           anomalies 审计
                                           meta_binds / ext_meta
```

---

## 三、存储介质三平面定调

| 平面 | 介质 | 承载内容 | 定位 |
|---|---|---|---|
| 数据平面 | 纯文件（Append-Only） | WAL / PCAP 原始报文字节流 | 顺序写走 OS Page Cache，无可超越 |
| 索引平面 | **LMDB** | QRIDX 包级索引、QRPAIR 实体、QR 挂起池、连接热状态（含绝对 SEQ 流）、8 类查询索引 | MVCC 无锁读、mmap 零拷贝、B+树前缀/区间扫描、单写者批量事务 |
| 管理平面 | **SQLite** | WAL/PCAP 文件清单（FILE_ID）、分析水位线、LMDB 实例信息、审计异常、MetaBind/EXT META 注册 | 低频管理/审计；**绝不承载逐包热路径** |

**SQLite 不弃**：FILE_ID 分配、文件状态机、水位线、异常审计是低频全局元数据，SQLite 的 ACID + SQL 查询在此最省；同时管理 LMDB 数据文件生命周期（实例路径、map_size、备份/压缩点）。

### 3.1 IDX 报文物理定位符（司法溯源唯一基因）

```
IDX (u64) = (FILE_ID : u32) << 32 | (FILE_OFFSET : u32)
```

- `FILE_ID`：SQLite `files` 表分配，单调递增；`FILE_OFFSET`：记录在文件内的起始字节偏移（WAL=64B Header 偏移；经典 PCAP=包记录偏移）。
- **硬不变量**：单文件 ≤ 4GB；PCAP 归档强制切段 + **统一经典 PCAP**（pcapng 不可随机寻址，IDX 跳跃读失效）。
- 一个报文一个 IDX；一个 QRPAIR 携带 **Q_IDX 列表 + R_IDX 列表**（多报文聚合）。

---

## 四、LMDB DBI Schema（键一律大端，共 9 个 DBI）

### 4.0 绝对序列号流翻译器（QR 匹配的回绕根治）★

TCP seq 为 u32，长连接/大流量必回绕。**不在扫描时做模差补丁，而是写入时即把序列号翻译为绝对号入键**：

```
每连接每方向（C→S 流 / S→C 流）各维护一个翻译器：
Stream { last_raw: u32, last_abs: u48 }

fn on_raw(raw: u32) -> u64 {
    let d = raw.wrapping_sub(self.last_raw) as i32;   // 有符号模差：前进为正，回退为负
    if d > 0 { self.last_abs = self.last_abs.wrapping_add(d as u64); }
    self.last_raw = raw;
    self.last_abs                                   // 重传(d≤0)不后退，天然检测 DUP/RETRANS
}
```

- **回绕天然正确**：`0xFFFF_FFF0 → 0x0000_0010` 的 wrapping 差为 +32（前进），无需任何特判。
- **入键全绝对**：`abs_q_end = abs_q_seq + orig_len`，`abs_ack` 用对向流翻译器换算（R.ack 属对向流空间）。
- **消费扫描零断层**：B+树数值序 == 流序，`[ConnHash][0..=abs_ack+tol]` 单区间 MDB_SET_RANGE 即达。
- 模差 `Δ=(ack−q_end) mod 2^32` 仅保留作内存快检（tolerance 边界）。

### 4.1 DBI_CONN_STATE — 连接热状态
```
Key:   [ConnHash: u64]
Value: state:u8 | 5-tuple(client_ip/port, server_ip/port, proto) |
       first_ts:u64 | last_ts:u64 | syn/synack/fin/rst_seen:u64 |
       req_cnt:u64 | resp_cnt:u64 | bytes_c/s:u64 | pkts_c/s:u64 |
       abs_seq_c:u48 | abs_seq_s:u48 | consumed_ack_c:u48 | consumed_ack_s:u48 |
       meta_bind_id:i64 | protocol_hint:u8 | anomaly_flags:u32 | qr_open:u64
```

**anomaly_flags 统一位掩码**（连接事件/结局，v0.2 与评审②合并）：
```
bit0 INCOMPLETE（段被跳过，数据不全）   bit1 RESET（RST 终态）
bit2 HALF_OPEN（数据无 SYN）            bit3 QR_UNMATCHED（关闭时未决）
bit4 SYN_SEEN                           bit5 FIN_SEEN（半关闭）
bit6 ZERO_WIN（零窗口阻塞）             bit7 RETRANS（重传/重复）
bit8 SEQ_GAP（乱序/缺包）               bit9 DEGRADED（探针降级）
```

### 4.2 DBI_QR_PAIR — QRPAIR 首发生命周期实体（主表）
```
Key:   [q_first_idx: u64]                  // 确定性主键（回放幂等）
Value: status:u8(0=PENDING 1=MATCHED 2=TIMEOUT 3=UNMATCHED 4=RST_ABORT 5=ABORTED_RESOURCE) |
       conn_hash:u64 | q_idx_list:[u64;N] | r_idx_list:[u64;M] |
       q_ts:u64 | r_ts:u64 | latency_ms:u64 | q_len:u32 | r_len:u32 |
       abs_q_seq:u48 | abs_q_end:u48 |
       req_key_var | resp_key_var | pseudo_key_flag:u8
```
**铁律：Q 被解析 → 立即写入 PENDING（Q_IDX + Req_KEY 锁死），R_IDX=0。** 此后 MATCHED/TIMEOUT/UNMATCHED/RST_ABORT 皆可见。

### 4.3 DBI_QR_PENDING — 迟到 R 的区间寻址（匹配引擎核心）
```
Key:   [ConnHash: u64][abs_q_end: u48]
Value: q_first_idx: u64 | q_ts: u64 | q_len: u32
```
R 到达 → `[ConnHash][0..=abs_ack+tol]` 前缀区间扫描消费（累积/批量 ACK 天然支持）。

### 4.4 DBI_CONN_QR — 单 CONN 二级索引（评审②：如何查单连接 QRIDX）★
```
Key:   [ConnHash: u64][q_ts: u64][q_first_idx: u64]
Value: status: u8（软缓存，同事务维护，恒与主表一致）
```
- 写入：Q 落地生成 QRPAIR 时，同 LMDB 事务追加一条；
- 查询：`[ConnHash]` 前缀 MDB_SET_RANGE，q_ts 段天然按时序递增，支持 `[ConnHash][start_ts]` 时间界游标 → 取 q_first_idx → 点查主表取全实体 → IDX 跳跃读原文；
- 状态翻转（MATCHED/TIMEOUT/RST_ABORT）时同事务更新 status 字节（可选：仅点查主表，此处留空）。

### 4.5 DBI_QR_KEY — KEY 反查索引（含伪 KEY）
```
Key:   [ReqKeyHash: u64][q_ts: u64][q_first_idx: u64]
Value: status: u8
```
L7 KEY（HTTP path / SNI / qname）与 **EXT META 伪 KEY**（`[magic_prefix+entropy]`）统一入此索引。

### 4.6 DBI_QR_TIME — 全局时间窗 QR 索引
```
Key:   [q_ts: u64][q_first_idx: u64]
Value: status: u8
```
支撑跨连接"近 1 小时所有慢 Q / 某时间窗全部 QR"查询（`DBI_CONN_QR` 以 ConnHash 开头无法覆盖）。

### 4.7 DBI_PACKET_QR — 报文 IDX 逆向反查（司法溯源闭环）★
```
Key:   [packet_idx: u64]
Value: q_first_idx: u64
```
每个 Q/R 报文的 IDX 一行（约 24B，1M 包≈24MB，同事务写入）。给定任意 `FILE_ID.OFFSET` 可 O(logN) 反查所属 QRPAIR。

### 4.8 DBI_PENDING_TTL — 超时扫描时间序索引
```
Key:   [q_ts: u64][ConnHash: u64]
Value: q_first_idx: u64 | abs_q_end: u48
```
后台 RO_TXN 顺时间前缀扫描过期项 → 批转 RW_TXN 置 TIMEOUT 并剔除挂起池。

### 4.9 DBI_RECORD_TS — 报文时间窗索引（PCAP 导出）
```
Key:   [ts_ns: u64][packet_idx: u64]
Value: 紧凑摘要（proto|flags|src_ip|dst_ip|sport|dport|len，18B）
```
> **v0.6 决策**：`RECORD_TS` 的**写入**提前至 P2（第 9 个 DBI）——作为批量原子性/回放收敛的逐条确定性索引锚点；PCAP 导出等**查询消费层**仍在 P3.5 落地。
PCAP 导出 = 时间窗游标 + **内存 BPF 过滤**（流式，免索引爆炸）。指定五元组高频查询可追加规范化前缀索引（阶段二可选）。

---

## 五、核心算法 ★

### 5.1 批量原子性：一个 Batch = 一个 LMDB 事务

```
内存解析 BATCHSIZE(=10000) 条 Record（或到文件边界截断）
        ▼
开启 LMDB RW_TXN（batch_transaction）
   ├─ 每条：绝对 SEQ 翻译 → 更新 DBI_CONN_STATE（状态机/游标/计数）
   ├─ Q → 写 DBI_QR_PAIR(PENDING) + DBI_QR_PENDING + DBI_CONN_QR + DBI_QR_KEY + DBI_QR_TIME + DBI_PACKET_QR
   ├─ R → 区间消费 DBI_QR_PENDING → 缝合 DBI_QR_PAIR(MATCHED) → 清挂起/TTL → 更新 CONN_QR
   ├─ RST → 级联熔断（见 5.4）→ 全部 PENDING 翻 RST_ABORT
   └─ 异常 → 计数（审计延迟到提交后统一落 SQLite）
commit()
   ├─ 成功 → SQLite 事务：files.analysis_offset 水位线推进 + 文件状态 + 审计异常落库
   └─ 失败 → txn.abort() 全批零残留 → 水位线不动 → 下轮从原水位线重放（幂等自愈）
```

**提交协议（顺序不可颠倒）**：① LMDB 先行（本批全部 QRIDX/状态在一个 RW_TXN 提交）；② SQLite 殿后（水位线 + 文件状态 + 审计）；③ **文件切换 = 强制提交屏障**（逻辑事务绝不跨物理文件，损坏隔离单文件内）。

**回放自愈**：LMDB 成而 SQLite 崩（窗口期）→ 水位线指旧位 → 重放同批 → **QRPAIR 主键 = q_first_idx 确定性派生 + MDB_NOOVERWRITE** → 写入幂等收敛。这是选确定性主键而非随机 QR_ID 的根本原因。

### 5.2 TCP 公理复核与 QR 匹配（绝对号累积 ACK 消费）★

**公理（已复核）**：TCP 累积确认 —— ACK=期望的下一个序列号。单包 `R.ack = Q.seq + Q.len`；多包 `R.ack = Q_init_seq + ΣQ.len`。**累积语义，非精确对等**。

```
每连接维护 consumed_ack_abs（对向流绝对号）+ 按 abs_q_end 升序的开放 QR 集合。

Q 到达（payload>0）：
  若 abs_q_seq > consumed_ack（新数据）→ 新开 QRPAIR(PENDING)，写挂起/各索引。

R 到达（ack=A，翻译为 abs_ack）：
  1) abs_ack ≤ consumed_ack_abs            → 重复/空 ACK，计 DUP_ACK，忽略
  2) 区间扫描 [ConnHash][0..=abs_ack+tol] 消费全部 abs_q_end ≤ abs_ack+tol 的挂起 Q：
       · 首个 → 该 QRPAIR 置 MATCHED，追加 R_IDX/R_TS/Resp_KEY，算 latency_ms
       · 后继（批量 ACK 聚合）→ 并入同一 QRPAIR 的 Q 列表（不新建，回放不重）
  3) consumed_ack_abs = max(consumed_ack_abs, abs_ack)
```

- 快路径（同批）：Q/R 同批缝合，零额外 IO；
- 慢路径（跨批/跨文件）：Q 的 PENDING 已落 LMDB，迟到 R 在下一事务内原子消费缝合清理；
- 批量 ACK 单响应 → **聚合为单 QRPAIR（q_idx_list 多条）**，避免回放重复注入同一响应。

### 5.3 连接状态机（同事务 read-modify-write）

```
SYN(c→s)         SYN|ACK(s→c)       ACK(c→s)
─────► SYN_SENT ──────► SYN_RCVD ──────► ESTABLISHED ──►(FIN×2/RST/TIMEOUT)→ CLOSED/RESET/TIMEOUT
数据无 SYN → HALF_OPEN · 空闲超时 → TIMEOUT · 段被跳过 → INCOMPLETE
```
计数与绝对 SEQ 流全部在 Batch 的 LMDB 事务内累加，**无内存/LMDB 双态分叉**。

### 5.4 异常处理（丢包 / 重复 / 超时 / RST 级联 / 脏尾）

| 异常 | 判定 | 处理 |
|---|---|---|
| `SEGMENT_SKIPPED` | Seal 段号跳空（Unlink-Oldest） | 连接标 INCOMPLETE，平滑跳过 |
| `SEGMENT_GAP` | Seal 缺口 | GapQuery 回源自愈；失败落审计 |
| `CRC_DROP` | 四重校验脏尾退栈 | 计字节，零静默吃包 |
| `DUP/RETRANS` | 绝对 SEQ 翻译器 `d≤0` | **只计数**（anomaly_flags + 每连接计数器），`MDB_NOOVERWRITE` 幂等跳过 |
| `SEQ_GAP/乱序` | `d>0 且 abs_seq > last+len` | 计数 + 置位，等待/回源自愈 |
| `ZERO_WIN` | `window==0` | **只计数**零窗口阻塞，不误判丢包 |
| **`CONN_RST` 级联熔断** | RST 帧 | **同事务原子**：该连接全部 PENDING Q 翻 `RST_ABORT` + 清理挂起/TTL + 记异常，不等超时 |
| `FIN` 半关闭 | FIN 帧 | 标记 HALF_CLOSED；未决 Q 启用缩短超时（如 min(qr_timeout,5s)） |
| `QR_TIMEOUT` | TTL 扫描超阈值（默认 30s） | QRPAIR→TIMEOUT，保留 Q_IDX+Req_KEY |
| `QR_UNMATCHED` | 连接关闭仍有未决 Q | 同上，附连接终态 |
| `DEGRADED` | Record flags bit0 | 时序完整性受损标记 |

审计异常统一落 **SQLite `anomalies`**（低频可 SQL 查询）；LMDB 仅维护工作态，超时由 `DBI_PENDING_TTL` 驱动（后台协程每 1s 开 RO_TXN 扫头部，按百条批转 RW_TXN 翻 TIMEOUT，短事务不锁库）。

> **"网络天气"型异常只计数，不逐条落 SQLite（评审③定案）**：DUP/RETRANS/ZERO_WIN 在高压网络中是常态而非致命异常，逐条入库会造成管理平面写放大、反向阻塞 Ingest。它们仅累加进 `DBI_CONN_STATE.anomaly_flags` 与每连接计数器，**连接关闭/RST 时聚合归档一次**——离线 SQL 统计看的是"该连接重传率"，不是"第 3421 个包是否重传"。

### 5.7 资源防御：乱序缓存预算与连接检疫 ★（评审③④）

**四层预算，硬上限逐级拦截恶意/病态流量（超限动作全部为内部动作，绝不线上注入 RST）**：

| 层级 | 预算 | 默认 | 超限动作 |
|---|---|---|---|
| L1 单连接 QR 挂起 | `qr_pending_budget`（未决 Q 数） | 4096 | 置 `CONN_QR_FLOOD` 异常 → **内部检疫**该连接 |
| L2 单段 pending 字节 | `segment_pending_cap` | = segment_size | 段标 `ERROR` + `SEGMENT_GAP` + 丢弃该段 pending + GapQuery 自愈 |
| **L2.5 单连接 OOO 字节** | `conn_pending_cap_bytes` | 16MB | ① 连接内逐出最旧（置 `SEQ_GAP` → GapQuery 自愈）→ ② 窗口内持续耗尽升级**内部检疫**（`CONN_OOO_FLOOD`） |
| L3 全局 pending 字节 | `pending_budget_bytes` | 256MB | **连接感知逐出**：优先清已检疫/标记连接的缓存，无辜连接最后碰（安全网） |

> **L2.5 填补连接维度字节硬闸**（评审④）：L1 按未决 Q 计数、L2 按段为粒度，均无法限制"单连接持有海量 OOO 字节"。恶意连接可令每段压着 L2 上限、横跨大量段吃满全局 L3，且 L3 逐出最旧是全局粒度、会误伤无辜连接。L2.5 按 `conn_hash` 记账 OOO 字节，把恶意流量挡在连接维度之内：**恶意发包只能烧掉自己的分析预算**。

**连接检疫（Quarantine）语义**——硬阈值必须存在，但**动作绝不是线上 RST**：

- sovVault 是**旁路带外、Fail-Open 被动探针**，硬红线"永不扰动生产"：向线上连接注入 RST 既违反原则，也会被恶意发包者利用来切断受害连接（RST 注入面）；
- **L2.5 升级路径**：超限先**连接内逐出最旧** OOO 段（不动全局），置 `SEQ_GAP` 交 GapQuery 回源自愈，数据平面照常落盘；窗口（`conn_evict_window_secs`）内配额耗尽达 `conn_evict_threshold` 次 → 升级**内部检疫**，语义同 L1（`CONN_OOO_FLOOD`）；
- 检疫 = **内部资源回收**：该连接全部在途 Q 翻 `ABORTED_RESOURCE`（保留 Q_IDX 基因锚点），暂停其 QR 分析；**数据平面不受影响**——报文照常落 WAL/PCAP + `DBI_RECORD_TS`，仅索引/匹配成本被省下；
- 连接关闭时把聚合计数（重传/缺口/洪水）与检疫事件一次性归档 SQLite，可统计可回跳原文；
- 阈值意义：恶意发包只能**烧掉自己的分析预算**，无法耗尽全局资源或拖垮其他连接；
- **为何绝不注入 RST（红线三理由）**：① 旁路带外被动探针，"永不扰动生产"是定位；② RST 可伪造——"超限即注入"等于把防御机制变成攻击面，恶意者可伪造 RST 切断受害连接；③ 零收益——恶意连接两端皆受攻击者控制，RST 杀不掉资源开销，只会误伤高压压测下的正常乱序流量。

### 5.5 慢响应 SLOW RESPONSE（独立路径，基因锚定）

- Q 生成即落 `DBI_QR_PAIR(PENDING)` + `DBI_QR_KEY`（含伪 KEY），Q_IDX=FILE_ID.OFFSET 基因锚点；
- 超时/RST 仅翻状态，Q_IDX/Req_KEY 原样保留；
- SQLite `anomalies` 记录 `(q_first_idx, q_file_id, q_offset, kind)`，秒级跳转原文；
- **回放引擎按 q_first_idx 必然检索到慢/异常 Q，绝不被当作无主噪点 SKIP**。

### 5.6 查询维度矩阵（回答"单 CONN 的 QRIDX 怎么查"）★

| 查询需求 | 索引 DBI | 扫描方式 |
|---|---|---|
| **单连接全部 QR** | `DBI_CONN_QR` | `[ConnHash]` 前缀 MDB_SET_RANGE → q_first_idx 列表 → 点查主表 |
| 单连接指定时间窗 | `DBI_CONN_QR` | `[ConnHash][start_ts]` 起游标，至 `end_ts` 停 |
| 按 KEY / 伪 KEY 反查 | `DBI_QR_KEY` | `[ReqKeyHash]` 前缀，含 PENDING/TIMEOUT 态 |
| 全局时间窗 QR | `DBI_QR_TIME` | `[start_ts]` 起扫至 `end_ts` |
| 单报文 IDX → 所属 QR | `DBI_PACKET_QR` | MDB_GET 点查 |
| 报文时间窗导出 PCAP | `DBI_RECORD_TS` | 时间游标 + 内存 BPF 流式过滤 |
| 指定五元组（可选阶段二） | 规范化前缀索引 | `[ip][ip][port][port][proto]` 前缀 |

单连接检索示例：`MDB_SET_RANGE([ConnHash][t0])` → 迭代 `(q_ts,q_first_idx,status)` → 按需 `MDB_GET(DBI_QR_PAIR, q_first_idx)` 取全实体 → `IDX→(FILE_ID,OFFSET)` seek 跳读 WAL/PCAP。

---

## 六、流式重组与解密引擎（承接 v0.2）

- 解密（ChaCha20）→ `(dev,seg,offset)` 幂等落位，乱序暂存有界预算（L2 单段 `segment_pending_cap` + L2.5 单连接 `conn_pending_cap_bytes` + L3 全局 `pending_budget_bytes`，见 §5.7），超限连接内逐出最旧/段检疫/升级内部检疫；
- 段状态机 `NEW→UNFINISHED⇄SEALED→SKIPPED/ERROR`；Seal 全段四重校验；
- GapQuery 回源自愈；段号跳空判 Unlink-Oldest。

## 七、Meta Bind / EXT META（无协议特征绑定）★

```
报文进入 → 已绑定 meta_bind_id？
  ├─ 是 → 按协议规则提取 KEY
  └─ 否 → 指纹抽取（Magic Bytes 8B + Shannon 熵 + Text/Binary + 端口）
          → ExtMetaBind 落库 SQLite ext_meta + 写 DBI_CONN_STATE
          → 绑定后预处理加速（entropy/magic 切包定位 + 初步过滤）
```

```rust
struct ExtMetaBind {
    meta_bind_id: i64,
    protocol_hint: u8,        // 0=Unknown 1=HTTP 2=TLS 3=JSON 4=LineText 5=RawBin
    magic_prefix: [u8; 8],    // 前 8B 签名（"POST "、0x16 03 01、0x7b 22 …）
    entropy: f32,             // Shannon 熵，>7.5 判加密/压缩流
    has_fixed_header: bool,   // 前导长度字段（切包依据）
}
```

- **伪 KEY 兜底**：私有 Binary 协议无 L7 解码器时，以 `[magic_prefix + entropy]` 生成稳定伪 KEY 写 `DBI_QR_KEY`，保证查询与回放 100% 基因可追溯；
- **挂起主键不受污染**：伪 KEY 只进 `DBI_QR_KEY` 与 QRPAIR Value，**不改 `DBI_QR_PENDING` 的 `[ConnHash][abs_q_end]` 主键**（否则 R 到达按 ACK 寻址失效）。

## 八、司法级导出与查询接口

- **PCAP**：`DBI_RECORD_TS` 时间窗游标 + 内存 BPF 过滤，流式异步导出；`orig_len = L2+L3+L4+orig_payload_len`，`orig>incl` 触发 Wireshark 裁切提示；握手序列（SYN/SYNACK/ACK、seq/ack/window）可还原。
- **Parquet**：阶段二，feature `parquet-export` 门控。
- **双输入格式**：`.wal` 走 `WalRecord::decode_stream`；`.pcap` 走包读取转 Record，同一流水线。
- **查询命令**：`query`（报文）、`qr --conn-id/--key/--time-range/--status`（QR 对）、`anomaly`（审计聚合）、`export`（PCAP/Parquet）。

## 九、核心数据结构

```rust
struct FilesRec { file_id: u32, path, kind: Wal|Pcap, dev_id, segment_seq, size,
                  sha256, first_ts, last_ts, state: Open|Sealed|Archived, analysis_offset: u64 }

// —— 绝对 SEQ 流翻译器（回绕根治） ——
struct SeqStream { last_raw: u32, last_abs: u64 }
impl SeqStream { fn on_raw(&mut self, raw: u32) -> u64 { /* d=wrapping diff; d>0 前进; */ } }

struct QrPair { status: QrStatus, conn_hash: u64,
                q_idx_list: Vec<u64>, r_idx_list: Vec<u64>,
                q_ts: u64, r_ts: u64, latency_ms: u64, q_len: u32, r_len: u32,
                abs_q_seq: u64, abs_q_end: u64,
                req_key: Option<String>, resp_key: Option<String>, pseudo_key: bool }

struct ConnState { state, 5-tuple, counters, abs_seq_c/s, consumed_ack_c/s,
                   meta_bind_id, protocol_hint, anomaly_flags: u32 }

// —— 连接级 OOO 字节预算（L2.5，见 §5.7） ——
struct ConnOOOBudget { used_bytes: u64, evict_streak: u32, window_start: u64 }

// 9 个 DBI 句柄常量 + 批量提交
struct BatchCommit { lmdb_txn, files_watermark: Vec<(file_id, analysis_offset)> }
// 提交协议：lmdb.commit() 成功 → sqlite 水位线事务 → 推进内存游标
```

## 十、配置与 CLI

```bash
sovvault serve   --config sovvault.toml
sovvault ingest  --wal-dir <dir> | --pcap <file>
sovvault export  --start .. --end .. --dst-port 443 --format pcap -o /tmp/
sovvault query   --start .. --src-ip 192.168.1.0/24 --format json
sovvault qr      --conn-id 7 | --key 0x… | --time-range .. | --status TIMEOUT
sovvault anomaly --since .. --kind QR_TIMEOUT
sovvault stat    --interval 5
```

```toml
[storage]
root = "/var/lib/sovvault"
hot_dir = "hot"         # WAL 重组中
warm_dir = "warm"       # WAL/PCAP 归档（经典 PCAP，切段 ≤4GB）
ledger_db = "ledger.db" # SQLite 管理平面
lmdb_dir = "qridx"      # LMDB 索引平面
lmdb_map_size = "64GB"  # 稀疏 mmap，虚拟内存；杜绝 MDB_MAP_FULL

[ingest]
subscribe_batches = true
gap_self_heal = true
batch_size = 10000      # 一个 LMDB 事务的报文数（文件边界优先截断）
pending_budget_bytes = "256MB"  # L3 全局乱序兜底预算
segment_pending_cap = 0         # L2 单段 pending 硬上限；0 = 默认取 segment_size
conn_pending_cap_bytes = "16MB" # L2.5 单连接 OOO 字节硬闸；0 = 不限制
conn_evict_window_secs = 30     # L2.5 配额耗尽计数窗口
conn_evict_threshold = 3        # 窗口内耗尽次数达此值 → 升级内部检疫

[analysis]
conn_idle_timeout_secs = 300
qr_pending_budget = 4096   # L1 单连接未决 Q 硬上限（超限 → 内部检疫，非线上 RST）
ack_tolerance = 4
qr_timeout_secs = 30     # 慢响应判超时
ttl_scan_secs = 1        # TTL 后台扫描周期
fin_short_timeout_secs = 5  # FIN 半关闭后未决 Q 缩短超时
```

## 十一、分阶段落地 Task List

| 阶段 | 任务 | 验收 |
|---|---|---|
| P0 存储三平面 | File 分层 + SQLite files/水位线/审计/ext_meta + LMDB 8 DBI 骨架 | IDX 编码往返；三平面落位 |
| P1 重组底座 | 解密+乱序落位+段状态机+四重校验+Gap 自愈+**L2 单段/L2.5 单连接/L3 全局乱序预算与段检疫** | 单测：乱序/幂等/缺口/脏尾/预算超限检疫全绿 |
| P2 批量原子性 | Batch=一个 LMDB 事务；LMDB 先行/SQLite 殿后；文件边界屏障；确定性主键 + MDB_NOOVERWRITE 重放自愈；hot 截断到水位线重启规则 | 注入提交失败 → 水位线不动、重放收敛（崩溃窗口模拟单测） |
| P3 QR 匹配 | 绝对 SEQ 翻译器 + 累积 ACK 消费 + 快/慢路径 + 批量 ACK 聚合 + 连接状态机（同事务） | 握手+管道化+跨批响应+回绕用例断言 QRPair |
| P3.5 查询索引 | DBI_CONN_QR / DBI_QR_TIME / DBI_PACKET_QR / DBI_RECORD_TS + 单 CONN 检索链路 | 单 CONN 查询毫秒级；报文 IDX 反查命中 |
| P4 异常与慢路径 | RST 级联熔断 + DUP/SEQ_GAP/ZERO_WIN 只计数 + FIN 缩短超时 + TTL 扫描 + SQLite 审计锚定 IDX + **L1/L2.5 连接检疫（ABORTED_RESOURCE）** | 异常可统计可回跳原文；RST 不等待超时；恶意发包只烧自己预算、不误伤无辜 |
| P5 导出查询 E2E | MetaBind/EXT META（含伪 KEY）+ PCAP/Parquet + 双输入格式 | 双 VM E2E：MD5 一致 + QR 命中 + 回放不丢慢 Q |

## 十二、验收标准

| 指标 | 目标 |
|---|---|
| 重组正确性 | 与源段 MD5 字节级 100% 一致 |
| 批量原子性 | 任一批失败 → 水位线不回退、重放幂等收敛 |
| QR 匹配 | 精确 ≥99%；管道化/批量 ACK ≥95%；**SEQ 回绕场景零误判**；回放/查询 PENDING+异常 Q 零遗漏 |
| 单 CONN 查询 | DBI_CONN_QR 前缀扫描毫秒级；`FILE_ID.OFFSET` 反查所属 QR O(logN) |
| RST 处理 | RST 到达 → 该连接全部 PENDING 原子翻 RST_ABORT，不等 30s |
| 异常 | DUP/SEQ_GAP/ZERO_WIN/CRC_DROP/RST/QR_TIMEOUT 全量可统计可回跳；**"网络天气"型只计数不逐条落库** |
| 资源防御 | 四层预算超限 → 内部检疫/段 ERROR/连接内逐出最旧；**无线上 RST 注入**；恶意连接无法耗尽全局资源、不误伤无辜连接 |
| PCAP | Wireshark 还原握手 + `[Packet size limited]` 精准出现 |
| 资源 | RSS ≤ 256MB；CPU ≤ 20%（4 核单节点）；LMDB map_size 稀疏不占物理 |

---

## 十三、双库分库轮转设计修订（v0.7，核心架构修订）★

> 本节是 v0.7 对 §5.1「一个 Batch = 一个 LMDB 事务」与 §三「存储三平面定调」的**架构级修订**。
> 完整工程实施说明见 `09_sovVault_实施方案.md` §十三（DBI 归属表 / QR_PAIR 迁移 / 双事务协议 / 轮转触发 / 资源推算 / 改动清单）。

### 13.1 修订动机（M7 实测）

LMDB `MAP_SHARED` 共享 mmap 页驻留 RSS ≈ 数据量，且**用户态与内核均不可回收**：

| 治理手段 | 实测结果 |
|---|---|
| `madvise(MADV_DONTNEED)` | 返回 0，RSS 纹丝不动（仅对私有匿名映射生效） |
| `madvise(MADV_FREE)` | 返回 0，RSS 不变 |
| `posix_fadvise(POSIX_FADV_DONTNEED)` | 返回 0，RSS 不变 |
| 3GB 内存压力（VM 共 4GB） | RSS 457MB 纹丝不动 |
| `MDB_WRITEMAP` + 稀疏 mmap | 只省磁盘，不省 RSS |
| **关闭 env（munmap）** | **RSS 25.9MB → 2.2MB 立即回收** ✅ |

→ 唯一治本路径：**分库轮转**。历史数据按量封顶轮转新 env，关闭旧 env 即回收其全部 RSS；活状态留驻常驻小库。

### 13.2 核心设计

**双库布局**：`qridx/live/`（常驻，量有界）+ `qridx/epoch_N/`（历史，追加后只读）。

**数据归属**：活状态（CONN_STATE / QR_PENDING / PENDING_TTL / 在途 QR_PAIR）永久留驻 live；终态 QR_PAIR + 二级索引（CONN_QR / QR_KEY / QR_TIME / PACKET_QR）+ RECORD_TS 按 epoch 追加归档。

**QR_PAIR 迁移**：Q 打开写 live（PENDING）；配完/超时/级联/检疫时读 live → 翻转终态 → 写当前 epoch + 从 live 删。跨 epoch 连接因活状态永居 live 而不破坏正确性。

**双事务顺序提交**：live_txn 先行 → epoch_txn 殿后 → SQLite 水位线；确定性键（`q_first_idx`）+ NO_OVERWRITE + 水位线回放保证幂等收敛。原子性语义从「全有全无」变为「可重放收敛」。

### 13.3 设计文档一致性声明

- **§5.1「一个 Batch = 一个 LMDB 事务」→ 修订为「一个 Batch = live 事务 + epoch 事务顺序提交」**，回放自愈机制（确定性主键 + NO_OVERWRITE）不变、收敛语义不变。
- **§三「索引平面 LMDB」→ 修订为「索引平面 = 常驻 live 库 + 历史 epoch 分库」**，稀疏 mmap 语义不变。
- 9 个 DBI 的键值布局（§四）**不变**，仅 DBI 归属 env 变化（见 09 §13.2 表）。
- 验收标准「资源 RSS ≤ 256MB」在双库下可达成（推算见 09 §13.7）。

### 13.4 设计点裁决（评审补全）★

**① 次级索引 status 去重**：CONN_QR / QR_KEY / QR_TIME 原存 status 需在终态时更新，但历史 epoch 冻结后无法跨 epoch 更新。裁决：**次级索引不存 status 语义**（纯追加定位索引），status 过滤查询改为「索引定位候选 → QR_PAIR 主行现查」。次级索引回归「追加后只读」，彻底消除跨 epoch 更新矛盾。详见 09 §13.4.1。

**② QR_PAIR 迁移幂等**：迁移 =「读 live(PENDING) → 写 epoch(终态) → 删 live」跨两 txn。重放规则：**先查 epoch 已有 → 跳过迁移（幂等）；不存在才迁移**，五条终态路径统一实现。崩溃于「写 epoch 后删 live 前」时靠此收敛。详见 09 §13.4.2。

**③ TTL 扫描跨库读写**：TTL 扫描（anomaly.rs）与 ingest 共用双库模型——读全部 live，终态迁移写当前 epoch，`write_secondary_status` 调用删除。详见 09 §13.4.3。

---

> 相关文档：[01_产品定位与架构](./01_产品定位与架构.md) · [06_sovProbe_设计与实施方案](./06_sovProbe_设计与实施方案.md) · [07_M7_E2E_双VM测试方案](./07_M7_E2E_双VM测试方案.md)
