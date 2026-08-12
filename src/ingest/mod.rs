//! Ingest 输入源：离线 WAL 目录 / 在线 Zenoh 订阅（batch+chunk+seal+gaps 回源自愈）。
//! 统一输出 Record 流供下游（重组 → 段终态 → 分析索引）消费。

pub mod offline;
pub mod zenoh;

/// 一段 WAL 文件的解码结果。
pub use offline::WalFileScan;
