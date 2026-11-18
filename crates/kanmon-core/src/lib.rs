//! kanmon-core — OS 非依存の判定ロジック。
//!
//! 設計方針：イベントは ECS 寄せの JSON（`serde_json::Value`）として扱い、
//! 検知ルール（YAML）はそのドット区切りフィールドを参照する。
//! これにより、ライブ監視・過去ログの再生（replay）・手書きフィクスチャを
//! 同じエンジンで評価できる。

pub mod beacon;
pub mod detect;
pub mod dga;
pub mod dnsguard;
pub mod event;
pub mod format;
pub mod intel;
pub mod jsonl;
pub mod names;
pub mod netclass;
pub mod rotate;
pub mod rules;
pub mod scoring;
#[cfg(feature = "sqlite")]
pub mod store;
pub mod volume;
pub mod wire;

pub use detect::{DetectionSet, SignalHit};
pub use scoring::Level;
