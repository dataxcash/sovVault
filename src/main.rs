//! sovVault CLI 入口：serve/ingest/export/query/qr/anomaly/stat。
//! serve：三平面初始化 + 启动 P4 TTL 扫描协程；ingest：离线注入；query/qr/anomaly：P3.5 查询矩阵。

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use sov_vault::anomaly::run_ttl_loop;
use sov_vault::config::{Config, PathOverrides};
use sov_vault::db::{DbRegistry, QrStatus};
use sov_vault::ingest::offline::OfflineScanner;
use sov_vault::ledger::Ledger;
use sov_vault::query::{Page, QrFilter, QuerySession, RecordFilter};
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "sovvault",
    version,
    about = "铁幕·带外零信任主权平台 - 存储中枢"
)]
struct Cli {
    /// 配置文件（TOML）。缺省使用内置默认值。
    #[arg(short, long, global = true)]
    config: Option<std::path::PathBuf>,

    /// 日志级别（error/warn/info/debug/trace）。
    #[arg(short, long, global = true, default_value = "info")]
    log: String,

    /// 存储根目录（CLI 覆盖，优先级最高）。
    #[arg(long, global = true)]
    root: Option<std::path::PathBuf>,
    /// 热目录（重组中）。
    #[arg(long, global = true)]
    hot_dir: Option<String>,
    /// 温目录（归档）。
    #[arg(long, global = true)]
    warm_dir: Option<String>,
    /// SQLite 管理平面文件。
    #[arg(long, global = true)]
    ledger_db: Option<String>,
    /// LMDB 索引平面目录。
    #[arg(long, global = true)]
    lmdb_dir: Option<String>,
    /// LMDB 稀疏 mmap 大小（如 64GB）。
    #[arg(long, global = true)]
    lmdb_map_size: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// 常驻服务：初始化三平面、启动 Ingest（P1 起承载流量）与 P4 TTL 扫描协程。
    Serve,
    /// 离线注入：WAL 目录 → 四重校验扫描 → 报告统计（PCAP 输入 P5）。
    Ingest {
        /// WAL 目录（缺省用配置的 hot_dir）。
        #[arg(long)]
        wal_dir: Option<std::path::PathBuf>,
    },
    /// 司法级导出 PCAP/Parquet（P5）。
    Export,
    /// 报文时间窗查询（DBI_RECORD_TS，P3.5）。
    Query {
        /// 起始时间戳（ns，含）。
        #[arg(long)]
        start: Option<u64>,
        /// 截止时间戳（ns，含）。
        #[arg(long)]
        end: Option<u64>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// QR 查询（P3.5）：连接维度 / 时间维度 / 报文反查 / 主键直查。
    Qr {
        /// 连接哈希（hex u64）。指定后走 DBI_CONN_QR，否则走 DBI_QR_TIME。
        #[arg(long)]
        conn: Option<String>,
        /// QRPAIR 主键直查（q_first_idx）。
        #[arg(long)]
        idx: Option<u64>,
        /// 报文 IDX 反查所属 Q（DBI_PACKET_QR）。
        #[arg(long)]
        packet: Option<u64>,
        /// 起始时间戳（ns，含）。
        #[arg(long)]
        start: Option<u64>,
        /// 截止时间戳（ns，含）。
        #[arg(long)]
        end: Option<u64>,
        /// 状态过滤：pending/matched/timeout/unmatched/rst_abort/aborted_resource。
        #[arg(long)]
        status: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// 附带 QRPAIR 全量详情。
        #[arg(long)]
        detail: bool,
    },
    /// 异常审计：终态事件聚合 + 回跳查询（P4）。
    Anomaly {
        #[arg(long)]
        kind: Option<i64>,
        /// 起始时间戳（ns，含）。
        #[arg(long)]
        start: Option<i64>,
        /// 截止时间戳（ns，含）。
        #[arg(long)]
        end: Option<i64>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// 运行时指标（P1 起）。
    Stat,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(cli.log.as_str())
        .init();

    let overrides = PathOverrides {
        root: cli.root.clone(),
        hot_dir: cli.hot_dir.clone(),
        warm_dir: cli.warm_dir.clone(),
        ledger_db: cli.ledger_db.clone(),
        lmdb_dir: cli.lmdb_dir.clone(),
        lmdb_map_size: cli.lmdb_map_size.clone(),
    };
    let cfg = Config::load(cli.config.as_deref(), &overrides)?;

    match cli.command {
        Command::Serve => cmd_serve(&cfg),
        Command::Ingest { wal_dir } => cmd_ingest(&cfg, wal_dir),
        Command::Query {
            start,
            end,
            limit,
        } => cmd_query(&cfg, start, end, limit),
        Command::Qr {
            conn,
            idx,
            packet,
            start,
            end,
            status,
            limit,
            detail,
        } => cmd_qr(&cfg, conn, idx, packet, start, end, status, limit, detail),
        Command::Anomaly {
            kind,
            start,
            end,
            limit,
        } => cmd_anomaly(&cfg, kind, start, end, limit),
        other => bail!("子命令 {:?} 尚未在本期落地，按 09 白皮书阶段推进", other),
    }
}

/// P1：离线 WAL 注入——扫描目录 → 四重校验解码 → 报告统计与脏尾。
fn cmd_ingest(cfg: &Config, wal_dir: Option<std::path::PathBuf>) -> Result<()> {
    let dir = wal_dir.unwrap_or_else(|| cfg.hot_dir());
    let scanner = OfflineScanner::new(&dir);
    let scans = scanner.scan_all()?;

    let mut records = 0u64;
    let mut bytes = 0u64;
    let mut dirty = 0u64;
    for s in &scans {
        records += s.stats.records;
        bytes += s.stats.payload_bytes;
        dirty += s.stats.dirty_tail_bytes;
        let state = if s.stats.dirty_tail_bytes > 0 {
            "脏尾"
        } else {
            "完好"
        };
        tracing::info!(
            "  {}: {} 条 / {}B payload / {}（{}B 脏尾）",
            s.path.display(),
            s.stats.records,
            s.stats.payload_bytes,
            state,
            s.stats.dirty_tail_bytes
        );
    }
    tracing::info!(
        "离线扫描完成：{} 文件 / {} 条记录 / {}B / 脏尾 {}B",
        scans.len(),
        records,
        bytes,
        dirty
    );
    Ok(())
}

/// P0/P4：三平面初始化验证 + 启动后台 TTL 扫描协程（常驻守护进程）。
fn cmd_serve(cfg: &Config) -> Result<()> {
    for d in [cfg.hot_dir(), cfg.warm_dir(), cfg.lmdb_dir()] {
        std::fs::create_dir_all(&d)?;
    }

    let ledger = Ledger::open(&cfg.ledger_path())?;
    let map_size = cfg.lmdb_map_size_bytes()? as usize;
    let reg = DbRegistry::open(&cfg.lmdb_dir(), map_size)?;
    let env_stat = reg.env().stat();

    tracing::info!("sovVault 三平面就绪");
    tracing::info!(
        "  数据平面: {} / {}",
        cfg.hot_dir().display(),
        cfg.warm_dir().display()
    );
    tracing::info!(
        "  索引平面: {} (map_size={}, DBI=9, 数据项={})",
        cfg.lmdb_dir().display(),
        map_size,
        env_stat.entries
    );
    tracing::info!(
        "  管理平面: {} (meta_binds={})",
        cfg.ledger_path().display(),
        ledger.meta_bind_count()?
    );

    // P4：后台 TTL 扫描协程（同步 std 线程；TTL 关闭时协程空转）。
    let shutdown = Arc::new(AtomicBool::new(false));
    let s2 = shutdown.clone();
    let ttl_scan_secs = cfg.analysis.ttl_scan_secs;
    let qr_timeout_secs = cfg.analysis.qr_timeout_secs;
    let fin_short_timeout_secs = cfg.analysis.fin_short_timeout_secs;
    std::thread::Builder::new()
        .name("ttl-scan".into())
        .spawn(move || {
            run_ttl_loop(reg, ledger, ttl_scan_secs, qr_timeout_secs, fin_short_timeout_secs, s2)
        })?;
    tracing::info!(
        "TTL 扫描协程已启动 (qr_timeout={}s fin_short={}s ttl_scan={}s)",
        qr_timeout_secs,
        fin_short_timeout_secs,
        ttl_scan_secs
    );
    tracing::info!("sovVault serve 常驻中（Ctrl-C 退出）");
    loop {
        std::thread::sleep(Duration::from_secs(3600));
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
    }
    Ok(())
}

/// P3.5：RECORD_TS 时间窗报文查询（JSONL 输出）。
fn cmd_query(cfg: &Config, start: Option<u64>, end: Option<u64>, limit: usize) -> Result<()> {
    let reg = DbRegistry::open(&cfg.lmdb_dir(), cfg.lmdb_map_size_bytes()? as usize)?;
    let s = QuerySession::open(&reg)?;
    let f = RecordFilter {
        start_ts: start,
        end_ts: end,
    };
    let r = s.scan_records(&f, &Page { limit, ..Default::default() })?;
    let stdout = std::io::stdout();
    let mut w = BufWriter::new(stdout.lock());
    for row in &r.rows {
        writeln!(w, "{}", serde_json::to_string(row)?)?;
    }
    w.flush()?;
    tracing::info!(
        "RECORD_TS 命中 {} 条{}",
        r.rows.len(),
        if r.has_more { "（未取满，可携带上一页末键继续翻页）" } else { "" }
    );
    Ok(())
}

/// P3.5：QR 四维检索（连接/时间/报文反查/主键直查）。
#[allow(clippy::too_many_arguments)] // CLI 子命令参数位，扁平可读优先。
fn cmd_qr(
    cfg: &Config,
    conn: Option<String>,
    idx: Option<u64>,
    packet: Option<u64>,
    start: Option<u64>,
    end: Option<u64>,
    status: Option<String>,
    limit: usize,
    detail: bool,
) -> Result<()> {
    let reg = DbRegistry::open(&cfg.lmdb_dir(), cfg.lmdb_map_size_bytes()? as usize)?;
    let s = QuerySession::open(&reg)?;
    let status = match status {
        Some(raw) => Some(
            QrStatus::parse(&raw)
                .ok_or_else(|| anyhow::anyhow!("非法 status: {}", raw))?,
        ),
        None => None,
    };
    let stdout = std::io::stdout();
    let mut w = BufWriter::new(stdout.lock());

    // 主键直查。
    if let Some(q) = idx {
        match s.qr_by_idx(q)? {
            Some(pair) => writeln!(w, "{}", serde_json::to_string(&pair)?)?,
            None => tracing::warn!("QRPAIR 不存在: idx={}", q),
        }
        w.flush()?;
        return Ok(());
    }
    // 报文反查。
    if let Some(p) = packet {
        match s.qr_by_packet(p)? {
            Some(q) => {
                writeln!(w, "{{\"packet_idx\":{},\"q_first_idx\":{}}}", p, q)?;
                if detail {
                    if let Some(pair) = s.qr_by_idx(q)? {
                        writeln!(w, "{}", serde_json::to_string(&pair)?)?;
                    }
                }
            }
            None => tracing::warn!("报文不属于任何 Q: packet_idx={}", p),
        }
        w.flush()?;
        return Ok(());
    }

    // 连接维度 / 时间维度。
    let conn_hash = match &conn {
        Some(h) => Some(
            u64::from_str_radix(h, 16)
                .map_err(|_| anyhow::anyhow!("非法连接哈希: {}（需 hex u64）", h))?,
        ),
        None => None,
    };
    let f = QrFilter {
        conn_hash,
        start_ts: start,
        end_ts: end,
        status,
    };
    let r = match conn_hash {
        Some(_) => s.scan_conn_qr(&f, &Page { limit, ..Default::default() })?,
        None => s.scan_time_qr(&f, &Page { limit, ..Default::default() })?,
    };
    for row in &r.rows {
        writeln!(w, "{}", serde_json::to_string(row)?)?;
        if detail {
            if let Some(pair) = s.qr_by_idx(row.q_first_idx)? {
                writeln!(w, "{}", serde_json::to_string(&pair)?)?;
            }
        }
    }
    w.flush()?;
    tracing::info!(
        "QR 命中 {} 条{}",
        r.rows.len(),
        if r.has_more { "（未取满，可继续翻页）" } else { "" }
    );
    Ok(())
}

/// P4：异常审计——终态事件聚合 + 回跳查询。
fn cmd_anomaly(
    cfg: &Config,
    kind: Option<i64>,
    start: Option<i64>,
    end: Option<i64>,
    limit: usize,
) -> Result<()> {
    let ledger = Ledger::open(&cfg.ledger_path())?;
    let summary = ledger.anomaly_summary(start, end)?;
    println!("=== 异常聚合（按 kind） ===");
    if summary.is_empty() {
        println!("（无记录）");
    }
    for (k, c) in summary {
        println!("  kind={:<3} count={}", k, c);
    }
    println!("=== 最近 {} 条 ===", limit);
    let rows = ledger.query_anomalies(kind, start, end, limit)?;
    for e in &rows {
        println!("{}", serde_json::to_string(e)?);
    }
    Ok(())
}
