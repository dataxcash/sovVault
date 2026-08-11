# sovVault Design & Implementation (Review Draft v0.3)

> Status: **Pending Review** | Version: v0.3 | Component: IronSovereign open-source foundation (datax.cash)
> This document defines **sovVault**, the storage hub: Zenoh byte stream → reassembly & decryption → TCP connection / QR-pair matching → tiered storage → forensics-grade export & query.
>
> **v0.2 changes (response to review ①):**
> 1. Three storage planes: Data (File WAL/PCAP) + Index (LMDB QRIDX) + Management (SQLite file registry / watermark / audit).
> 2. QRPAIR promoted to a first-class lifecycle entity (PENDING from the moment a Q is born).
> 3. QR matching upgraded to a cumulative-ACK consumption model; batch atomicity (a Batch = one LMDB transaction, LMDB-first / SQLite-watermark-last, file boundary as commit barrier).
>
> **v0.3 changes (response to review ②):**
> 1. **SEQ wrap-hardening**: a per-connection, per-direction `raw(u32)→abs(48b)` absolute sequence stream translator; all QR pending/consume keys use absolute numbers — B+tree scans need no modular arithmetic and have no wrap discontinuity; DUP/RETRANS detection lands at the same time.
> 2. **RST cascade breaker**: on an RST frame, all PENDING Qs of that connection flip to `RST_ABORT` in the same transaction — no waiting for the timeout.
> 3. **EXT META pseudo-key fallback**: with no L7 decoder, a stable pseudo-key derived from `[magic_prefix + entropy]` is written to `DBI_QR_KEY` so private binary protocols remain traceable.
> 4. **Query-dimension matrix completed**: adds `DBI_CONN_QR` (per-connection reverse lookup), `DBI_QR_TIME` (global time window), `DBI_PACKET_QR` (packet IDX → owning QR), `DBI_RECORD_TS` (packet time-window export) — answering "how do I query the QRIDX of a single CONN".

---

## 1. Goals and Non-Goals

### 1.1 Goals

- Receiver-side core service: Zenoh → **decrypt → out-of-order reassembly → segment final validation → analysis & indexing → archive → forensics-grade export/query**.
- **TCP connection ledger**: lifecycle state machine + bidirectional traffic statistics + absolute sequence streams, as the factual base for performance/fault analysis.
- **QRPair matching (core algorithm)**: TCP cumulative-ACK consumption model; a QRPAIR exists from the moment the Q is born, so slow/unmatched/abnormal Qs are never lost.
- **Meta Bind / EXT META**: connection ↔ protocol metadata binding; without protocol details, fingerprint content (magic/entropy/text-vs-binary/port) to identify characteristics and extract KEYs (or pseudo-KEYs).
- **Anomaly capture/statistics/query**: gaps (loss), duplicates/retransmissions, zero-window, timeouts, RST, dirty tails all recorded in an auditable ledger.
- **Batch atomicity**: `BATCHSIZE` packets committed in one LMDB transaction; on failure the whole batch rolls back and the watermark does not advance; file boundary acts as the commit barrier.
- Forensics-grade export: PCAP (orig_len / tcp_flags 100% faithful) and Parquet (phase 2) with time-window + 5-tuple filtering; both PROBE(WAL) and PCAP input formats.

### 1.2 Non-Goals (out of scope this phase)

- Zenoh / FastCDC sender (slimSync); eBPF capture (sovProbe); SLIMRAG semantics; Suricata rule engine; full L7 decoders (feature-level identification only).

---

## 2. System Boundary & Data Flow

```
[ Zenoh ] ── batches/** · segments/** · gaps/**
     ▼
┌─────────────────────────────────────────────────────────────┐
│ sovVault pipeline                                           │
│  ① Ingest (Zenoh / offline WAL / offline PCAP)               │
│  ② Reassembly (decrypt → (dev,seg,offset) idempotent place → │
│      segment state machine → quadruple validation)            │
│  ③ Record stream → absolute-SEQ translation → connection     │
│      state machine → cumulative-ACK QR matching              │
│      → MetaBind/EXT META fingerprint & KEY/pseudo-KEY         │
│  ④ Batch commit (BATCH = one LMDB txn + SQLite watermark,    │
│      file boundary barrier)                                   │
│  ⑤ Export/Query (time window + 5-tuple → PCAP/Parquet/JSON;  │
│      single-CONN QR reverse lookup)                           │
└─────────────────────────────────────────────────────────────┘
        │                 │                   │
        ▼                 ▼                   ▼
   [ FILE plane ]    [ LMDB plane ]      [ SQLite plane ]
   hot/warm *.wal      8 DBIs              files registry
   *.pcap (classic)    see §4             analysis_watermark
                                           lmdb_env metadata
                                           anomalies audit
                                           meta_binds / ext_meta
```

---

## 3. Three Storage Planes (File + LMDB + SQLite)

| Plane | Medium | Contents | Role |
|---|---|---|---|
| Data plane | Plain files (Append-Only) | Raw WAL / PCAP packet byte stream | Sequential writes ride the OS Page Cache; no database beats raw `write()` |
| Index plane | **LMDB** | QRIDX packet-level index, QRPAIR entities, QR pending pool, connection hot state (incl. absolute SEQ streams), 8 query DBIs | MVCC lock-free reads, mmap zero-copy, B+tree prefix/range scans, single-writer batch transactions |
| Management plane | **SQLite** | WAL/PCAP file registry (FILE_ID), analysis watermark, LMDB instance info, audit anomalies, MetaBind/EXT META registry | Low-frequency management/audit; **never on the per-packet hot path** |

**Why SQLite stays**: FILE_ID allocation, file state machine, watermark, and audit anomalies are low-frequency global metadata — SQLite's ACID + SQL is the most efficient here, and it manages the LMDB data file lifecycle (instance path, map_size, backup/compaction points).

### 3.1 IDX — Physical Locator of a Packet (the forensic genetic anchor)

```
IDX (u64) = (FILE_ID : u32) << 32 | (FILE_OFFSET : u32)
```

- `FILE_ID`: allocated by the SQLite `files` table, monotonically increasing; `FILE_OFFSET`: byte offset of the record start within the file (WAL = 64B-header offset; classic PCAP = packet-record offset).
- **Hard invariants**: single file ≤ 4GB; PCAP archiving enforces segmenting + **classic PCAP only** (pcapng is not randomly seekable — IDX jump-read would fail).
- One packet → one IDX; one QRPAIR carries a **Q_IDX list + R_IDX list** (multi-packet aggregation).

---

## 4. LMDB DBI Schema (big-endian keys, 8 DBIs)

### 4.0 Absolute Sequence Stream Translator (the wrap-proof core) ★

TCP seq is u32; long-lived connections / high-volume transfers will wrap. Instead of a modular patch at scan time, **translate to absolute numbers at write time**:

```
Each direction per connection (C→S stream / S→C stream) keeps a translator:
Stream { last_raw: u32, last_abs: u48 }

fn on_raw(raw: u32) -> u64 {
    let d = raw.wrapping_sub(self.last_raw) as i32;   // signed modular diff: forward +, backward −
    if d > 0 { self.last_abs = self.last_abs.wrapping_add(d as u64); }
    self.last_raw = raw;
    self.last_abs                                   // retransmission (d≤0) never rewinds → DUP/RETRANS detection
}
```

- **Wrapping is naturally correct**: `0xFFFF_FFF0 → 0x0000_0010` yields a diff of +32 (forward), no special case.
- **All index keys are absolute**: `abs_q_end = abs_q_seq + orig_len`; `abs_ack` is translated via the *opposite* stream translator (an R.ack belongs to the opposite stream's number space).
- **Consumption scans are discontinuity-free**: B+tree numeric order == stream order, a single `[ConnHash][0..=abs_ack+tol]` MDB_SET_RANGE suffices.
- The modular diff `Δ=(ack−q_end) mod 2^32` is kept only for in-memory fast checks (tolerance boundary).

### 4.1 DBI_CONN_STATE — Connection Hot State
```
Key:   [ConnHash: u64]
Value: state:u8 | 5-tuple(client_ip/port, server_ip/port, proto) |
       first_ts:u64 | last_ts:u64 | syn/synack/fin/rst_seen:u64 |
       req_cnt:u64 | resp_cnt:u64 | bytes_c/s:u64 | pkts_c/s:u64 |
       abs_seq_c:u48 | abs_seq_s:u48 | consumed_ack_c:u48 | consumed_ack_s:u48 |
       meta_bind_id:i64 | protocol_hint:u8 | anomaly_flags:u32 | qr_open:u64
```

**Unified anomaly_flags bitmask** (connection events/outcomes, merged v0.2 + review ②):
```
bit0 INCOMPLETE (segment skipped, data loss)  bit1 RESET (RST terminal)
bit2 HALF_OPEN (data without SYN)             bit3 QR_UNMATCHED (pending at close)
bit4 SYN_SEEN                                 bit5 FIN_SEEN (half-closed)
bit6 ZERO_WIN (zero-window stall)             bit7 RETRANS (retransmission/duplicate)
bit8 SEQ_GAP (out-of-order/missing)           bit9 DEGRADED (probe degraded)
```

### 4.2 DBI_QR_PAIR — QRPAIR First-Class Lifecycle Entity (primary)
```
Key:   [q_first_idx: u64]                  // deterministic primary key (replay-idempotent)
Value: status:u8(0=PENDING 1=MATCHED 2=TIMEOUT 3=UNMATCHED 4=RST_ABORT) |
       conn_hash:u64 | q_idx_list:[u64;N] | r_idx_list:[u64;M] |
       q_ts:u64 | r_ts:u64 | latency_ms:u64 | q_len:u32 | r_len:u32 |
       abs_q_seq:u48 | abs_q_end:u48 |
       req_key_var | resp_key_var | pseudo_key_flag:u8
```
**Iron rule: as soon as a Q is parsed → immediately persist a PENDING QRPAIR (Q_IDX + Req_KEY locked in), R_IDX=0.** Thereafter MATCHED/TIMEOUT/UNMATCHED/RST_ABORT are all visible.

### 4.3 DBI_QR_PENDING — Range-addressing index for late Rs (matching engine core)
```
Key:   [ConnHash: u64][abs_q_end: u48]
Value: q_first_idx: u64 | q_ts: u64 | q_len: u32
```
On R arrival → prefix range scan `[ConnHash][0..=abs_ack+tol]` (cumulative/batched ACKs supported naturally).

### 4.4 DBI_CONN_QR — Per-CONN Secondary Index (review ②: how to query a single CONN's QRIDX) ★
```
Key:   [ConnHash: u64][q_ts: u64][q_first_idx: u64]
Value: status: u8 (soft cache, maintained in the same txn — always consistent with the primary)
```
- Write: when a QRPAIR is created, one entry is appended in the same LMDB transaction;
- Query: `[ConnHash]` prefix MDB_SET_RANGE; the q_ts segment orders by time; supports `[ConnHash][start_ts]` time-bounded cursors → collect q_first_idx → point-query the primary for the full entity → IDX jump-read the raw packet;
- Status flips (MATCHED/TIMEOUT/RST_ABORT) update the status byte in the same transaction (optional: leave blank and point-query the primary).

### 4.5 DBI_QR_KEY — KEY Reverse Index (incl. pseudo-KEYs)
```
Key:   [ReqKeyHash: u64][q_ts: u64][q_first_idx: u64]
Value: status: u8
```
L7 KEYs (HTTP path / SNI / qname) and **EXT META pseudo-KEYs** (`[magic_prefix+entropy]`) share this index.

### 4.6 DBI_QR_TIME — Global Time-Window QR Index
```
Key:   [q_ts: u64][q_first_idx: u64]
Value: status: u8
```
Supports cross-connection queries such as "all slow Qs in the last hour" or "every QR in a time window" (`DBI_CONN_QR` cannot because its key starts with ConnHash).

### 4.7 DBI_PACKET_QR — Packet IDX Reverse Lookup (forensic traceability closure) ★
```
Key:   [packet_idx: u64]
Value: q_first_idx: u64
```
One row per Q/R packet (~24 B; 1M packets ≈ 24 MB, written in the same txn). Given any `FILE_ID.OFFSET`, O(log N) lookup finds the owning QRPAIR.

### 4.8 DBI_PENDING_TTL — Time-Ordered Index for Timeout Scanning
```
Key:   [q_ts: u64][ConnHash: u64]
Value: q_first_idx: u64 | abs_q_end: u48
```
Background task: RO_TXN cursor from the head of the time prefix → batch-convert to RW_TXN, flip to TIMEOUT, purge pending.

### 4.9 DBI_RECORD_TS — Packet Time-Window Index (PCAP export)
```
Key:   [ts_ns: u64][packet_idx: u64]
Value: compact digest (proto|flags|src_ip|dst_ip|sport|dport|len)
```
PCAP export = time-window cursor + **in-memory BPF filtering** (streamed, avoids index explosion). A normalized-prefix 5-tuple index may be added later (phase-2 optional) if specific-tuple lookups dominate.

---

## 5. Core Algorithms ★

### 5.1 Batch Atomicity: One Batch = One LMDB Transaction

```
Parse BATCHSIZE(=10000) records in memory (or truncated at a file boundary)
        ▼
Open LMDB RW_TXN (batch_transaction)
   ├─ per record: absolute-SEQ translation → update DBI_CONN_STATE (state machine / cursors / counters)
   ├─ Q → write DBI_QR_PAIR(PENDING) + DBI_QR_PENDING + DBI_CONN_QR + DBI_QR_KEY + DBI_QR_TIME + DBI_PACKET_QR
   ├─ R → range-consume DBI_QR_PENDING → stitch DBI_QR_PAIR(MATCHED) → clear pending/TTL → update CONN_QR
   ├─ RST → cascade breaker (see 5.4) → all PENDING flip to RST_ABORT
   └─ anomalies → counted (audit persisted to SQLite only after commit)
commit()
   ├─ success → SQLite txn: advance files.analysis_offset watermark + file state + audit anomalies
   └─ failure → txn.abort() (zero residue) → watermark unmoved → next round replays from the old watermark (idempotent self-heal)
```

**Commit protocol (order is fixed)**: ① LMDB first (all QRIDX/state for the batch in one RW_TXN); ② SQLite watermark last (watermark + file state + audit); ③ **file switch = forced commit barrier** (a logical transaction never spans physical files; damage isolation is single-file).

**Replay self-heal**: if LMDB committed but SQLite crashed (window) → watermark still points to the old position → replay re-processes the same batch → since **the QRPAIR primary key = q_first_idx (deterministically derived) + MDB_NOOVERWRITE**, writes are idempotent and converge. This is the fundamental reason for a deterministic primary key instead of a random QR_ID.

### 5.2 TCP Axiom & QR Matching (absolute-number cumulative-ACK consumption) ★

**Axiom (verified)**: TCP cumulative acknowledgment — ACK = the next expected sequence number. Single packet: `R.ack = Q.seq + Q.len`; multi-packet: `R.ack = Q_init_seq + ΣQ.len`. **Cumulative semantics, not exact equality.**

```
Per connection: consumed_ack_abs (opposite stream, absolute) + the open-QR set ordered by abs_q_end.

Q arrives (payload>0):
  if abs_q_seq > consumed_ack (new data) → open a new QRPAIR(PENDING), write pending + all indexes.

R arrives (ack=A, translated to abs_ack):
  1) abs_ack ≤ consumed_ack_abs           → duplicate/empty ACK, count DUP_ACK, ignore
  2) range scan [ConnHash][0..=abs_ack+tol] consumes every pending Q with abs_q_end ≤ abs_ack+tol:
       · first → mark that QRPAIR MATCHED, append R_IDX/R_TS/Resp_KEY, compute latency_ms
       · successors (batched-ACK aggregation) → merged into the same QRPAIR's Q list (no new entity, replay does not repeat)
  3) consumed_ack_abs = max(consumed_ack_abs, abs_ack)
```

- Fast path (same batch): Q/R stitched within the batch, zero extra IO;
- Slow path (cross-batch / cross-file): the Q's PENDING already lives in LMDB; a late R is consumed, stitched, and cleaned atomically in the next transaction;
- A batched ACK with a single response → **aggregated into one QRPAIR (multi-entry q_idx_list)**, so replay never re-injects the same response.

### 5.3 Connection State Machine (read-modify-write in the same txn)

```
SYN(c→s)         SYN|ACK(s→c)       ACK(c→s)
─────► SYN_SENT ──────► SYN_RCVD ──────► ESTABLISHED ──►(FIN×2/RST/TIMEOUT)→ CLOSED/RESET/TIMEOUT
data without SYN → HALF_OPEN · idle timeout → TIMEOUT · skipped segment → INCOMPLETE
```
Counters and absolute SEQ streams accumulate inside the batch's LMDB transaction — **no memory/LMDB dual-state divergence** (the root of replay consistency).

### 5.4 Anomaly Handling (loss / duplicates / timeout / RST cascade / dirty tail)

| Anomaly | Detection | Handling |
|---|---|---|
| `SEGMENT_SKIPPED` | Seal segment-number gap (Unlink-Oldest) | mark conn INCOMPLETE, skip smoothly |
| `SEGMENT_GAP` | Seal gap (sealed_size > received) | GapQuery self-heal; audit on failure |
| `CRC_DROP` | quadruple-validation dirty tail | count bytes, zero silent corruption |
| `DUP/RETRANS` | absolute-SEQ translator `d≤0` | count, idempotent skip (`MDB_NOOVERWRITE`) |
| `SEQ_GAP/out-of-order` | `d>0 and abs_seq > last+len` | record gap, wait / self-heal |
| `ZERO_WIN` | `window==0` | record zero-window stall, not misjudged as loss |
| **`CONN_RST` cascade breaker** | RST frame | **atomically in the same txn**: all PENDING Qs → `RST_ABORT` + purge pending/TTL + audit, no timeout wait |
| `FIN` half-closed | FIN frame | mark HALF_CLOSED; unresolved Qs get shortened timeout (e.g. min(qr_timeout, 5s)) |
| `QR_TIMEOUT` | TTL scan past threshold (default 30s) | QRPAIR→TIMEOUT, Q_IDX+Req_KEY retained |
| `QR_UNMATCHED` | connection closes with pending Qs | same as above, with connection terminal state |
| `DEGRADED` | Record flags bit0 | temporal-integrity damage marker |

Audit anomalies are persisted uniformly in **SQLite `anomalies`** (low-frequency, SQL-queryable); LMDB keeps only working state. Timeout is driven by `DBI_PENDING_TTL` (background task: every 1 s open an RO_TXN, scan the head, convert in batches of ~100 via short RW_TXNs to flip TIMEOUT — short transactions, no long-held locks).

### 5.5 Slow Responses (independent path, genetically anchored)

- On creation the Q lands in `DBI_QR_PAIR(PENDING)` + `DBI_QR_KEY` (incl. pseudo-KEY); Q_IDX = FILE_ID.OFFSET is the genetic anchor;
- Timeout/RST only flips status; Q_IDX/Req_KEY stay intact;
- SQLite `anomalies` records `(q_first_idx, q_file_id, q_offset, kind)` for second-level jump to the raw packet;
- **The replay engine always finds slow/abnormal Qs by q_first_idx — they are never skipped as ownerless noise.**

### 5.6 Query-Dimension Matrix (answers "how to query a single CONN's QRIDX") ★

| Query need | Index DBI | Scan method |
|---|---|---|
| **All QR of one connection** | `DBI_CONN_QR` | `[ConnHash]` prefix MDB_SET_RANGE → q_first_idx list → point-query primary |
| One connection, a time window | `DBI_CONN_QR` | cursor from `[ConnHash][start_ts]`, stop at `end_ts` |
| Reverse by KEY / pseudo-KEY | `DBI_QR_KEY` | `[ReqKeyHash]` prefix, incl. PENDING/TIMEOUT |
| Global time window QR | `DBI_QR_TIME` | scan `[start_ts]` → `end_ts` |
| Single packet IDX → owning QR | `DBI_PACKET_QR` | MDB_GET point lookup |
| Packet time-window PCAP export | `DBI_RECORD_TS` | time cursor + in-memory BPF streaming |
| Specific 5-tuple (phase-2 optional) | normalized-prefix index | `[ip][ip][port][port][proto]` prefix |

Single-connection example: `MDB_SET_RANGE([ConnHash][t0])` → iterate `(q_ts, q_first_idx, status)` → `MDB_GET(DBI_QR_PAIR, q_first_idx)` for the full entity as needed → `IDX→(FILE_ID,OFFSET)` seek-jump into the WAL/PCAP.

---

## 6. Reassembly & Decryption Engine (from v0.2)

- Decrypt (ChaCha20) → `(dev,seg,offset)` idempotent placement, bounded out-of-order staging budget, evict oldest on overflow;
- Segment state machine `NEW→UNFINISHED⇄SEALED→SKIPPED/ERROR`; full-segment quadruple validation on Seal;
- GapQuery self-heal; segment-number gap ⇒ Unlink-Oldest.

## 7. Meta Bind / EXT META (protocol-free feature binding) ★

```
packet in → meta_bind_id already bound?
  ├─ yes → extract KEY by protocol rules
  └─ no → fingerprint extraction (Magic Bytes 8B + Shannon entropy + Text/Binary + port)
         → ExtMetaBind persisted to SQLite ext_meta + written to DBI_CONN_STATE
         → post-binding preprocessing acceleration (entropy/magic packet-locating + preliminary filter)
```

```rust
struct ExtMetaBind {
    meta_bind_id: i64,
    protocol_hint: u8,        // 0=Unknown 1=HTTP 2=TLS 3=JSON 4=LineText 5=RawBin
    magic_prefix: [u8; 8],    // leading 8-byte signature ("POST ", 0x16 03 01, 0x7b 22 …)
    entropy: f32,             // Shannon entropy, >7.5 ⇒ encrypted/compressed stream
    has_fixed_header: bool,   // leading length field (packet-splitting hint)
}
```

- **Pseudo-key fallback**: for private binary protocols without an L7 decoder, a stable pseudo-KEY from `[magic_prefix + entropy]` goes into `DBI_QR_KEY`, guaranteeing 100% genetic traceability for query and replay;
- **The pending primary key is never polluted**: pseudo-KEYs go only into `DBI_QR_KEY` and the QRPAIR value — **never into `DBI_QR_PENDING`'s `[ConnHash][abs_q_end]` key** (otherwise an R's ACK-based addressing would break).

## 8. Forensics-Grade Export & Query Interface

- **PCAP**: `DBI_RECORD_TS` time-window cursor + in-memory BPF filter, streamed async export; `orig_len = L2+L3+L4+orig_payload_len`; `orig>incl` triggers Wireshark's truncation hint; handshake sequences (SYN/SYNACK/ACK, seq/ack/window) are reproducible.
- **Parquet**: phase 2, gated by feature `parquet-export`.
- **Dual input formats**: `.wal` via `WalRecord::decode_stream`; `.pcap` via packet read → Record; both feed the same pipeline.
- **Query commands**: `query` (packets), `qr --conn-id/--key/--time-range/--status` (QR pairs), `anomaly` (audit aggregation), `export` (PCAP/Parquet).

## 9. Core Data Structures

```rust
struct FilesRec { file_id: u32, path, kind: Wal|Pcap, dev_id, segment_seq, size,
                  sha256, first_ts, last_ts, state: Open|Sealed|Archived, analysis_offset: u64 }

// Absolute-SEQ stream translator (wrap-proof)
struct SeqStream { last_raw: u32, last_abs: u64 }
impl SeqStream { fn on_raw(&mut self, raw: u32) -> u64 { /* d=wrapping diff; advance iff d>0 */ } }

struct QrPair { status: QrStatus, conn_hash: u64,
                q_idx_list: Vec<u64>, r_idx_list: Vec<u64>,
                q_ts: u64, r_ts: u64, latency_ms: u64, q_len: u32, r_len: u32,
                abs_q_seq: u64, abs_q_end: u64,
                req_key: Option<String>, resp_key: Option<String>, pseudo_key: bool }

struct ConnState { state, 5-tuple, counters, abs_seq_c/s, consumed_ack_c/s,
                   meta_bind_id, protocol_hint, anomaly_flags: u32 }

// 8 DBI handle constants + batch commit
struct BatchCommit { lmdb_txn, files_watermark: Vec<(file_id, analysis_offset)> }
// Commit protocol: lmdb.commit() success → sqlite watermark txn → advance in-memory cursor
```

## 10. Config & CLI

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
hot_dir = "hot"         # WAL being reassembled
warm_dir = "warm"       # archived WAL/PCAP (classic PCAP, segmented ≤4GB)
ledger_db = "ledger.db" # SQLite management plane
lmdb_dir = "qridx"      # LMDB index plane
lmdb_map_size = "64GB"  # sparse mmap, virtual memory; eliminates MDB_MAP_FULL

[ingest]
subscribe_batches = true
gap_self_heal = true
batch_size = 10000      # packets per one LMDB transaction (file boundary truncates first)

[analysis]
conn_idle_timeout_secs = 300
qr_pending_budget = 4096
ack_tolerance = 4
qr_timeout_secs = 30     # slow-response timeout
ttl_scan_secs = 1        # TTL background scan period
fin_short_timeout_secs = 5  # shortened timeout for pending Qs after FIN half-close
```

## 11. Phased Task List

| Phase | Task | Acceptance |
|---|---|---|
| P0 storage planes | File tiering + SQLite files/watermark/audit/ext_meta + LMDB 8-DBI skeleton | IDX encode round-trip; planes in place |
| P1 reassembly | decrypt + out-of-order placement + segment state machine + quadruple validation + Gap self-heal | unit tests: out-of-order/idempotent/gap/dirty-tail green |
| P2 batch atomicity | Batch = one LMDB txn; LMDB-first/SQLite-last; file-boundary barrier; deterministic q_first_idx + replay self-heal | inject commit failure → watermark unmoved, replay converges |
| P3 QR matching | absolute-SEQ translator + cumulative-ACK consumption + fast/slow paths + batched-ACK aggregation + connection state machine (same txn) | handshake + pipelining + cross-batch response + wrap cases assert QRPair |
| P3.5 query indexes | DBI_CONN_QR / DBI_QR_TIME / DBI_PACKET_QR / DBI_RECORD_TS + single-CONN lookup chain | single-CONN query ms-level; packet-IDX reverse lookup hits |
| P4 anomalies & slow path | RST cascade breaker + DUP/SEQ_GAP/ZERO_WIN + FIN shortened timeout + TTL scan + SQLite audit anchored by IDX | anomalies countable & jump-back; RST never waits for timeout |
| P5 export/query E2E | MetaBind/EXT META (incl. pseudo-KEY) + PCAP/Parquet + dual input formats | dual-VM E2E: MD5 identical + QR hit + replay never drops slow Qs |

## 12. Acceptance Criteria

| Metric | Target |
|---|---|
| Reassembly correctness | byte-for-byte MD5 identical to the source segment |
| Batch atomicity | any batch failure → watermark never regresses, replay converges idempotently |
| QR matching | exact ≥99%; pipelined/batched-ACK ≥95%; **zero misjudgment on SEQ wrap**; replay/query zero loss of PENDING & abnormal Qs |
| Single-CONN query | DBI_CONN_QR prefix scan ms-level; `FILE_ID.OFFSET` → owning QR in O(log N) |
| RST handling | RST arrival → all PENDING Qs of the connection flip RST_ABORT atomically, never waiting 30 s |
| Anomalies | DUP/SEQ_GAP/ZERO_WIN/CRC_DROP/RST/QR_TIMEOUT all countable and jump-back-able |
| PCAP | Wireshark reproduces handshake + `[Packet size limited]` appears precisely |
| Resources | RSS ≤ 256 MB; CPU ≤ 20% (4-core single node); LMDB map_size sparse (no physical cost) |

---

> Related docs: [01_产品定位与架构](./01_产品定位与架构.md) · [06_sovProbe_设计与实施方案](./06_sovProbe_设计与实施方案.md) · [07_M7_E2E_双VM测试方案](./07_M7_E2E_双VM测试方案.md)
