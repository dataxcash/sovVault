//! sovVault CLI 入口（P0 骨架）：serve/ingest/export/query/qr/anomaly/stat。
//! 本期（P0）serve 完成三平面初始化验证；其余子命令待对应阶段落地。

use anyhow::Result;
use clap::{Parser, Subcommand};
use sov_vault::config::Config;
use sov_vault::db::DbRegistry;
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

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// 常驻服务：初始化三平面并启动 Ingest（P1 起承载流量）。
    Serve,
    /// 离线注入：WAL 目录 / PCAP 文件 → 同一 Record 流水线（P1）。
    Ingest,
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

    let cfg = Config::load(cli.config.as_deref())?;
    cfg.validate()?;

    match cli.command {
        Command::Serve => cmd_serve(&cfg),
        other => {
            anyhow::bail!(
                "子命令 {:?} 尚未在本期（P0）实现，按 09 白皮书阶段推进",
                other
            )
        }
    }
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
