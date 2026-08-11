//! 配置加载：TOML + CLI（CLI 优先）。Schema 对齐 09_sovVault_实施方案.md §11。

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub zenoh: ZenohConfig,
    pub crypto: CryptoConfig,
    pub storage: StorageConfig,
    pub ingest: IngestConfig,
    pub analysis: AnalysisConfig,
    pub query: QueryConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ZenohConfig {
    pub connect: Vec<String>,
    pub listen: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CryptoConfig {
    pub key_file: PathBuf,
    pub key_hex: Option<String>,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        CryptoConfig {
            key_file: PathBuf::from("/etc/sovvault/keys/slimsync.key"),
            key_hex: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub root: PathBuf,
    pub hot_dir: String,
    pub warm_dir: String,
    pub ledger_db: String,
    pub lmdb_dir: String,
    pub lmdb_map_size: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig {
            root: PathBuf::from("/var/lib/sovvault"),
            hot_dir: "hot".into(),
            warm_dir: "warm".into(),
            ledger_db: "ledger.db".into(),
            lmdb_dir: "qridx".into(),
            lmdb_map_size: "64GB".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct IngestConfig {
    pub subscribe_batches: bool,
    pub subscribe_chunks: bool,
    pub gap_self_heal: bool,
    pub batch_size: u32,
    pub pending_budget_bytes: String,
    pub segment_pending_cap: u64,
    pub conn_pending_cap_bytes: String,
    pub conn_evict_window_secs: u64,
    pub conn_evict_threshold: u32,
}

impl Default for IngestConfig {
    fn default() -> Self {
        IngestConfig {
            subscribe_batches: true,
            subscribe_chunks: false,
            gap_self_heal: true,
            batch_size: 10000,
            pending_budget_bytes: "256MB".into(),
            segment_pending_cap: 0,
            conn_pending_cap_bytes: "16MB".into(),
            conn_evict_window_secs: 30,
            conn_evict_threshold: 3,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct MetaBind {
    pub name: String,
    pub proto: u8,
    pub dst_port: u16,
    pub fingerprint: String,
    pub extractor: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AnalysisConfig {
    pub conn_idle_timeout_secs: u64,
    pub qr_pending_budget: u64,
    pub ack_tolerance: u32,
    pub qr_timeout_secs: u64,
    pub ttl_scan_secs: u64,
    pub fin_short_timeout_secs: u64,
    pub meta_binds: Vec<MetaBind>,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        AnalysisConfig {
            conn_idle_timeout_secs: 300,
            qr_pending_budget: 4096,
            ack_tolerance: 4,
            qr_timeout_secs: 30,
            ttl_scan_secs: 1,
            fin_short_timeout_secs: 5,
            meta_binds: vec![],
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct QueryConfig {
    pub export_buf_size: u32,
}

impl Default for QueryConfig {
    fn default() -> Self {
        QueryConfig {
            export_buf_size: 4096,
        }
    }
}

/// CLI 全局覆盖项（优先级：CLI > 环境变量 SOVVAULT_* > TOML > 默认值）。
#[derive(Debug, Clone, Default)]
pub struct PathOverrides {
    pub root: Option<std::path::PathBuf>,
    pub hot_dir: Option<String>,
    pub warm_dir: Option<String>,
    pub ledger_db: Option<String>,
    pub lmdb_dir: Option<String>,
    pub lmdb_map_size: Option<String>,
}

impl Config {
    /// 分层加载：TOML（或默认值）→ 环境变量 → CLI 覆盖 → 校验。
    pub fn load(path: Option<&Path>, cli: &PathOverrides) -> Result<Config> {
        let mut cfg = match path {
            Some(p) => {
                let text = std::fs::read_to_string(p)
                    .with_context(|| format!("读取配置失败: {}", p.display()))?;
                toml::from_str(&text).with_context(|| format!("解析配置失败: {}", p.display()))?
            }
            None => Config::default(),
        };
        cfg.apply_env();
        cfg.apply_cli(cli);
        cfg.validate()?;
        Ok(cfg)
    }

    /// 环境变量层：`SOVVAULT_<KEY>`。
    fn apply_env(&mut self) {
        self.storage.root = env_str("SOVVAULT_ROOT")
            .map(std::path::PathBuf::from)
            .unwrap_or(self.storage.root.clone());
        set_env(&mut self.storage.hot_dir, "SOVVAULT_HOT_DIR");
        set_env(&mut self.storage.warm_dir, "SOVVAULT_WARM_DIR");
        set_env(&mut self.storage.ledger_db, "SOVVAULT_LEDGER_DB");
        set_env(&mut self.storage.lmdb_dir, "SOVVAULT_LMDB_DIR");
        set_env(&mut self.storage.lmdb_map_size, "SOVVAULT_LMDB_MAP_SIZE");
    }

    /// CLI 层（最高优先级）。
    fn apply_cli(&mut self, cli: &PathOverrides) {
        if let Some(root) = &cli.root {
            self.storage.root = root.clone();
        }
        if let Some(v) = &cli.hot_dir {
            self.storage.hot_dir = v.clone();
        }
        if let Some(v) = &cli.warm_dir {
            self.storage.warm_dir = v.clone();
        }
        if let Some(v) = &cli.ledger_db {
            self.storage.ledger_db = v.clone();
        }
        if let Some(v) = &cli.lmdb_dir {
            self.storage.lmdb_dir = v.clone();
        }
        if let Some(v) = &cli.lmdb_map_size {
            self.storage.lmdb_map_size = v.clone();
        }
    }

    /// 存储根目录（绝对化）。
    pub fn storage_root(&self) -> PathBuf {
        if self.storage.root.is_absolute() {
            self.storage.root.clone()
        } else {
            std::env::current_dir()
                .map(|c| c.join(&self.storage.root))
                .unwrap_or_else(|_| self.storage.root.clone())
        }
    }

    /// 校验配置语义（不变量），违例直接报错拒绝启动。
    pub fn validate(&self) -> Result<()> {
        if self.storage.lmdb_map_size.is_empty() {
            bail!("storage.lmdb_map_size 不能为空");
        }
        if self.ingest.batch_size == 0 {
            bail!("ingest.batch_size 必须 > 0");
        }
        if self.analysis.qr_pending_budget == 0 {
            bail!("analysis.qr_pending_budget 必须 > 0");
        }
        Ok(())
    }

    pub fn hot_dir(&self) -> PathBuf {
        self.storage_root().join(&self.storage.hot_dir)
    }

    pub fn warm_dir(&self) -> PathBuf {
        self.storage_root().join(&self.storage.warm_dir)
    }

    pub fn ledger_path(&self) -> PathBuf {
        self.storage_root().join(&self.storage.ledger_db)
    }

    pub fn lmdb_dir(&self) -> PathBuf {
        self.storage_root().join(&self.storage.lmdb_dir)
    }

    pub fn lmdb_map_size_bytes(&self) -> Result<u64> {
        parse_size(&self.storage.lmdb_map_size)
    }

    pub fn pending_budget_bytes(&self) -> Result<u64> {
        parse_size(&self.ingest.pending_budget_bytes)
    }

    pub fn conn_pending_cap_bytes(&self) -> Result<u64> {
        parse_size(&self.ingest.conn_pending_cap_bytes)
    }
}

/// 读取环境变量（非空才覆盖）。
fn env_str(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

/// 环境变量非空时覆盖目标字段。
fn set_env(dst: &mut String, key: &str) {
    if let Some(v) = env_str(key) {
        *dst = v;
    }
}

/// 解析人类可读字节大小："256MB" / "64GB" / "1024"（无后缀=字节）。
pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        bail!("空字节大小串");
    }
    let (num, mult) = match s.to_ascii_uppercase().as_str() {
        _ if s.ends_with("KB") => (&s[..s.len() - 2], 1024u64),
        _ if s.ends_with("MB") => (&s[..s.len() - 2], 1024u64 * 1024),
        _ if s.ends_with("GB") => (&s[..s.len() - 2], 1024u64 * 1024 * 1024),
        _ if s.ends_with('B') => (&s[..s.len() - 1], 1u64),
        _ => (s, 1u64),
    };
    let n: u64 = num
        .trim()
        .parse()
        .with_context(|| format!("非法字节大小: {}", s))?;
    n.checked_mul(mult)
        .with_context(|| format!("字节大小溢出: {}", s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_basic() {
        assert_eq!(parse_size("256MB").unwrap(), 256 * 1024 * 1024);
        assert_eq!(parse_size("64GB").unwrap(), 64u64 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("512B").unwrap(), 512);
        assert_eq!(parse_size(" 1KB ").unwrap(), 1024);
    }

    #[test]
    fn parse_size_errors() {
        assert!(parse_size("").is_err());
        assert!(parse_size("abc").is_err());
        assert!(parse_size("18446744073709551616").is_err()); // 2^64 超出 u64
        assert!(parse_size("99999999999999999999GB").is_err()); // 乘后溢出
    }

    #[test]
    fn default_config_loads_and_validates() {
        let cfg = Config::load(None, &PathOverrides::default()).unwrap();
        assert_eq!(cfg.ingest.batch_size, 10000);
        assert_eq!(cfg.analysis.qr_pending_budget, 4096);
        assert_eq!(
            cfg.lmdb_map_size_bytes().unwrap(),
            64u64 * 1024 * 1024 * 1024
        );
        assert_eq!(cfg.pending_budget_bytes().unwrap(), 256 * 1024 * 1024);
        assert_eq!(cfg.conn_pending_cap_bytes().unwrap(), 16 * 1024 * 1024);
    }

    #[test]
    fn toml_roundtrip_matches_example() {
        let text = std::fs::read_to_string("config.example.toml").unwrap();
        let cfg: Config = toml::from_str(&text).unwrap();
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.analysis.meta_binds.len(), 3);
        assert_eq!(cfg.zenoh.connect, vec!["tcp/10.0.0.2:7447".to_string()]);
        assert_eq!(cfg.ingest.conn_evict_window_secs, 30);
        assert_eq!(cfg.ingest.conn_evict_threshold, 3);
    }

    #[test]
    fn precedence_cli_over_env_over_toml() {
        let text = std::fs::read_to_string("config.example.toml").unwrap();
        let p = std::env::temp_dir().join(format!("sovvault-cfg-{}.toml", std::process::id()));
        std::fs::write(&p, &text).unwrap();

        // 基线：TOML 的 root=/var/lib/sovvault。
        let cfg = Config::load(Some(&p), &PathOverrides::default()).unwrap();
        assert_eq!(
            cfg.storage.root,
            std::path::PathBuf::from("/var/lib/sovvault")
        );

        // CLI 覆盖 root + hot_dir。
        let over = PathOverrides {
            root: Some("/tmp/sovvault-test".into()),
            hot_dir: Some("ht".into()),
            ..Default::default()
        };
        let cfg = Config::load(Some(&p), &over).unwrap();
        assert_eq!(
            cfg.storage.root,
            std::path::PathBuf::from("/tmp/sovvault-test")
        );
        assert_eq!(cfg.storage.hot_dir, "ht");

        // 环境变量层压过 TOML。
        std::env::set_var("SOVVAULT_LMDB_MAP_SIZE", "8GB");
        let cfg = Config::load(Some(&p), &PathOverrides::default()).unwrap();
        assert_eq!(cfg.storage.lmdb_map_size, "8GB");
        // CLI 仍压过环境变量。
        let over = PathOverrides {
            lmdb_map_size: Some("16GB".into()),
            ..Default::default()
        };
        let cfg = Config::load(Some(&p), &over).unwrap();
        assert_eq!(cfg.storage.lmdb_map_size, "16GB");
        std::env::remove_var("SOVVAULT_LMDB_MAP_SIZE");

        let _ = std::fs::remove_file(&p);
    }
}
