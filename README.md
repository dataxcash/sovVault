# sovVault

**Storage hub for the IronSovereign out-of-band zero-trust platform.**

sovVault is a forensics-grade storage and analysis hub for passive network capture. It ingests encrypted WAL segment streams (from the **sovProbe** eBPF capture + **slimSync** shipping components of the IronSovereign stack), decrypts, reassembles out-of-order TCP streams, matches request/response **QR pairs**, and lands everything into three storage planes — then serves judicial-grade PCAP export and multi-dimensional query.

It is designed as a **fail-open, out-of-band passive probe**: it never injects on-wire RST, never perturbs production traffic, and never loses a slow or unmatched request.

> Part of the **IronSovereign / datax.cash** open-source foundation. Design specs: [`doc/`](doc/) (Chinese and English).

---

## Highlights

- **TCP connection ledger** — lifecycle state machine, bidirectional counters, and per-direction **absolute-sequence stream translators** (`raw u32 → abs u48`) that are wrap-proof and retransmit-safe.
- **QR pair matching** — cumulative-ACK consumption model. A QRPAIR exists from the moment the request (`Q`) is born, so **slow, unmatched, and abnormal requests are never lost**. Batch ACKs aggregate into a single QRPAIR.
- **Batch atomicity (2PC-lite)** — one *Batch* = one LMDB transaction: LMDB-first → SQLite watermark-last → cursor advance. Deterministic keys + `MDB_NOOVERWRITE` make crash-window replay **idempotent and convergent**.
- **Incarnation (epoch) isolation** — 5-tuple reuse / mid-stream SYN forces an epoch flip that **physically separates** old-generation pending entries in the B+ tree, sealing off ghost packets from late ACK/RSTs.
- **Resource defense & quarantine** — four-tier out-of-order budgets (per-conn QR pending, per-segment bytes, per-conn OOO bytes, global fallback). Overflow triggers **internal quarantine only** — never an on-wire RST.
- **MetaBind / EXT META** — protocol fingerprinting from `magic_prefix + Shannon entropy + fixed-header` detection (HTTP / TLS-SNI / DNS-qname / JSON), plus a **stable pseudo-key** for private binary protocols (same signature ⇒ same key).
- **Forensics-grade PCAP export** — streams over the `RECORD_TS` time cursor with in-memory BPF pre-filtering, re-reads the original WAL payloads (Magic→Version→Length→CRC32 quadruple validation), and reproduces `orig_len` vs `incl_len` so Wireshark renders `[Packet size limited]` faithfully.
- **Terminal-state audit** — QR `TIMEOUT / UNMATCHED / RST_ABORT` events are persisted per-request to the SQLite ledger, enabling `O(log N)` point-query jump-back from SQL to the raw packet bytes.
- **Zero-allocation hot path** — fixed-size BE key/value codecs, mmap direct reads, page-cursor streaming, no per-packet logging.

---

## Architecture

```
 [ sovProbe eBPF capture ] → [ slimSync (Zenoh) ] → encrypted WAL segments
                                                          │
                                                          ▼
┌─────────────────────────────── sovVault pipeline ───────────────────────────────┐
│  ① Ingest   (Zenoh live subscription / offline WAL / offline PCAP)              │
│  ② Reassembly (decrypt → idempotent placement → segment state machine →        │
│                 quadruple validation → Gap self-heal)                           │
│  ③ Record → absolute-SEQ translation → connection state machine →              │
│                 cumulative-ACK QR matching → MetaBind / pseudo-key extraction   │
│  ④ Batch commit (one LMDB txn + SQLite watermark, file boundary = commit barrier)│
│  ⑤ Export / Query (time window + in-memory BPF → PCAP/JSON; single-CONN lookup) │
└───────────────────────────────┬────────────┬──────────────────────────────────┘
                                │            │
              [ FILE plane ]  [ LMDB plane ]  [ SQLite plane ]
              hot/warm *.wal   QRIDX: 9 DBIs   file registry,
              *.pcap archive   packet index    watermark,
                               QRPAIR, QR      anomaly audit,
                               pending pool,   meta_binds /
                               conn state      ext_meta
```

### Three storage planes

| Plane | Medium | Contents | Role |
|---|---|---|---|
| Data | Append-only files | Raw WAL / PCAP byte stream | Sequential writes ride the OS page cache |
| Index | **LMDB** | 9 DBIs: packet index, QRPAIR entities, QR pending pool, connection hot state (incl. absolute SEQ streams), query DBIs | MVCC lock-free reads, mmap zero-copy, B+tree range scans, single-writer batch transactions |
| Management | **SQLite** | File registry (`FILE_ID`), analysis watermark, anomaly audit, MetaBind / EXT META registry | Low-frequency management/audit — never on the per-packet hot path |

### QR status lifecycle

```
PENDING ──(TTL)→ TIMEOUT
  │   ──(conn close)→ UNMATCHED
  │   ──(RST cascade)→ RST_ABORT
  │   ──(quarantine)→ ABORTED_RESOURCE
  │   ──(cumulative ACK)→ MATCHED   ← every state keeps the Q_IDX + request key (no vanishing path)
```

---

## Quick Start

Requires **Rust 1.94+** (edition 2021), a Linux host.

```bash
cargo build --release

# Initialize the three planes + register protocol bindings from config
sovvault --config config.example.toml --root /var/lib/sovvault meta --register

```bash
# Run the resident service (live Zenoh ingest + background TTL scan)
# Requires [zenoh].connect/listen + [crypto].key_file matching slimSync.
sovvault --config config.example.toml serve

# Offline WAL ingest (report only in this milestone)
sovvault --config config.example.toml ingest --wal-dir /var/lib/sovvault/hot

# Forensic PCAP export with in-memory BPF filter
sovvault --config config.example.toml export \
    --dport 443 --proto 6 --flags syn,ack \
    --start 1700000000000000000 --end 1700000000100000000 \
    --output handshake.pcap

# Query: RECORD_TS time window / QR four-dimensional matrix / anomaly audit
sovvault --config config.example.toml query --start 1700000000000000000
sovvault --config config.example.toml qr --conn 0xDEADBEEF --detail
sovvault --config config.example.toml qr --status timeout --detail
sovvault --config config.example.toml anomaly

# Inspect protocol fingerprint ledger
sovvault --config config.example.toml meta --list
```

### CLI reference

| Subcommand | Purpose |
|---|---|
| `serve` | Resident service: initialize the three planes, start the **live Zenoh ingest** (online subscription) and the background TTL scan |
| `ingest` | Offline WAL directory → quadruple-validation decode → scan report |
| `export` | Forensic PCAP export over the `RECORD_TS` time cursor with in-memory BPF filter (`--proto --src-ip --dst-ip --sport --dport --flags`) |
| `query` | Packet time-window query (`DBI_RECORD_TS`) |
| `qr` | QR four-dimensional lookup: `--conn` (connection), time window, `--packet` reverse lookup, `--idx` primary-key, `--status` filter |
| `anomaly` | Terminal-state event aggregation + SQL jump-back to raw packets |
| `meta` | `--register` config `meta_binds` (idempotent) / `--list` fingerprint ledger |
| `stat` | Runtime metrics |

Global overrides (highest precedence): `--root --hot-dir --warm-dir --ledger-db --lmdb-dir --lmdb-map-size` (CLI > `SOVVAULT_*` env > TOML > defaults).

---

## Configuration

See [`config.example.toml`](config.example.toml) for the full schema. Key sections:

```toml
[zenoh]      # batch/segment/gap subscription endpoints
[crypto]     # 32-byte ChaCha20 key file (must match slimSync)
[storage]    # root + hot/warm dirs + SQLite ledger + LMDB dir & sparse map_size
[ingest]     # batch_size, L2/L2.5/L3 out-of-order budgets, eviction window
[analysis]   # qr_timeout, ttl_scan, fin_short_timeout, qr_pending_budget,
             # meta_binds: [{name, proto, dst_port, fingerprint, extractor}]
[query]      # PCAP export buffer size
```

---

## Testing

```bash
cargo test                 # unit + integration suites
cargo clippy --all-targets # zero warnings
```

| Suite | Covers |
|---|---|
| `e2e_batch_atomicity` | Watermark freeze on failed commit; replay idempotence |
| `e2e_qr_match` | ≥10 GB long-connection SEQ rewrap (incarnation stays 0); 5-tuple reuse ghost-packet isolation |
| `e2e_ttl_audit` | Ingest → TTL timeout → SQLite terminal-state audit → four-dimensional query jump-back |
| `e2e_export` | PCAP read-back: handshake `seq/ack/window/flags` fidelity, `orig_len > incl_len` truncation flag, BPF filtering |
| `e2e_meta` | HTTP request-line / TLS-SNI extraction, stable pseudo-keys across connections, `ext_meta` idempotent hit bumps |
| `e2e_p5_stress` | 64-connection high-pressure: **source payload vs exported-pcap MD5 byte-identical**, QR hit-rate 100 % (≥99 %), slow Qs zero-loss across batches, `qr_open`/PENDING drained to zero |

---

## Storage layout & invariants

- `IDX(u64) = (FILE_ID:u32) << 32 | OFFSET:u32` — the forensic gene that maps any QR back to its raw packet bytes in `O(log N)`.
- Single file ≤ 4 GB; `OFFSET` = record start byte offset; all LMDB keys are big-endian for natural B+tree ordering.
- Append-only data plane; one Batch = one LMDB transaction; file switch = commit barrier; hot file is truncated to the SQLite watermark on crash recovery, then replayed idempotently.

---

## Project layout

```
src/
├── main.rs        # CLI entry + orchestration
├── lib.rs
├── config.rs      # layered config (CLI > env > TOML > defaults)
├── id.rs          # IDX encode/decode
├── decrypt.rs     # ChaCha20 decrypt
├── walscan.rs     # WAL → record stream (quadruple validation)
├── reassembly.rs  # out-of-order reassembly + L2/L2.5/L3 budgets
├── connection.rs  # ConnState, conn_hash (fnv-1a-64), anomaly flags
├── qr.rs          # absolute-SEQ translator + cumulative-ACK matching + epochs
├── meta.rs        # fingerprint (magic + entropy) + protocol keys / pseudo-keys
├── anomaly.rs     # TTL scan + terminal-state audit events
├── db.rs          # 9-DBI registry + BE codecs
├── ledger.rs      # SQLite management plane
├── batch.rs       # 2PC-lite commit protocol + hot-file writer
├── export.rs      # forensic PCAP streaming export
├── query.rs       # four-dimensional query matrix + JSONL export
└── ingest/          # offline WAL input + live Zenoh subscription (batch/segment/gap self-heal)
tests/             # E2E acceptance suites
doc/               # design & implementation specs (EN + 中文)
```

---

## Roadmap

- **Phase 2**: Parquet export (`parquet-export` feature), directed 5-tuple index (`DBI_RECORD_5TUPLE`), full L7 decoders.
- **Done**: live Zenoh ingest (`ingest/zenoh.rs`) — batch/chunk subscription, ChaCha20 decrypt, out-of-order reassembly, GapQuery self-heal, quadruple-validation WAL streaming, 2PC-lite batch commit.

## License

[Apache-2.0](LICENSE)
