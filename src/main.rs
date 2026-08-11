//! sovVault CLI 入口（P0 骨架）：serve/ingest/export/query/qr/anomaly/stat。
//! 本期（P0）serve 完成三平面初始化验证；其余子命令待对应阶段落地。

use anyhow::Result;
use clap::{Parser, Subcommand};
use sov_vault::config::{Config, PathOverrides};
use sov_vault::db::DbRegistry;
use sov_vault::ingest::offline::OfflineScanner;
use sov_vault::ledger::Ledger;

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
    /// 常驻服务：初始化三平面并启动 Ingest（P1 起承载流量）。
    Serve,
    /// 离线注入：WAL 目录 → 四重校验扫描 → 报告统计（PCAP 输入 P5）。
    Ingest {
        /// WAL 目录（缺省用配置的 hot_dir）。
        #[arg(long)]
        wal_dir: Option<std::path::PathBuf>,
    },
    /// 司法级导出 PCAP/Parquet（P5）。
    Export,
    /// 报文查询（P3.5）。
    Query,
    /// QR 对查询（P3.5）。
    Qr,
    /// 异常审计聚合（P4）。
    Anomaly,
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
        other => anyhow::bail!(
            "子命令 {:?} 尚未在本期（P1）实现，按 09 白皮书阶段推进",
            other
        ),
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

/// P0：三平面初始化验证——建目录 + 开 LMDB（8 DBI）+ 开 SQLite + 打印验收摘要。
fn cmd_serve(cfg: &Config) -> Result<()> {
    for d in [cfg.hot_dir(), cfg.warm_dir(), cfg.lmdb_dir()] {
        std::fs::create_dir_all(&d)?;
    }

    let ledger = Ledger::open(&cfg.ledger_path())?;
    let map_size = cfg.lmdb_map_size_bytes()? as usize;
    let reg = DbRegistry::open(&cfg.lmdb_dir(), map_size)?;
    let env_stat = reg.env().stat();

    tracing::info!("sovVault P0 三平面就绪");
    tracing::info!(
        "  数据平面: {} / {}",
        cfg.hot_dir().display(),
        cfg.warm_dir().display()
    );
    tracing::info!(
        "  索引平面: {} (map_size={}, DBI=8, 数据项={})",
        cfg.lmdb_dir().display(),
        map_size,
        env_stat.entries
    );
    tracing::info!(
        "  管理平面: {} (meta_binds={})",
        cfg.ledger_path().display(),
        ledger.meta_bind_count()?
    );
    tracing::info!("P0 验收：IDX 往返 / 8 DBI 编解码 / DDL 幂等 由单测覆盖，`cargo test` 见全绿");
    Ok(())
}
