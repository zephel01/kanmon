//! 設定（TOML）。すべて既定値あり。

use anyhow::{Context, Result};
use kanmon_core::scoring::Thresholds;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// learning（導入直後：ベースライン作成、warn 以上のみ通知）/ observe（通常）
    pub mode: String,
    /// learning を自動で終える日数（0 なら手動）
    pub learning_days: u32,
    pub interval_ms: u64,
    pub data_dir: PathBuf,
    pub detections_dir: PathBuf,
    pub rules_file: PathBuf,
    /// root 実行時、検知ルール・許可ルールは root 所有・他者書込不可でなければ読まない
    pub strict_owner: bool,
    /// ループバック宛の接続を記録するか（待受は常に記録）
    pub include_loopback: bool,
    pub host_name: Option<String>,
    /// proc_key を「インタプリタ＋スクリプト」単位にするコマンド名
    pub interpreters: Vec<String>,
    pub thresholds: Thresholds,
    pub retention_days: u32,
    pub jsonl: JsonlCfg,
    pub notify: NotifyCfg,
    pub feeds: Vec<Feed>,
    pub feeds_refresh_hours: u32,
    /// 改行区切りの拒否リスト（IP / CIDR / ドメイン）
    pub local_blocklists: Vec<PathBuf>,
    /// ビーコン報告を出す最小スコア
    pub beacon_report_min: f64,
    /// ビーコン集計の間隔（秒）
    pub beacon_interval_s: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct JsonlCfg {
    pub path: PathBuf,
    pub max_mb: u64,
    pub keep: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotifyCfg {
    /// OS の通知（macOS 通知センター / Linux D-Bus notify-send）
    pub local: bool,
    /// 通知する最低レベル（learning 中は warn に引き上げ）
    pub min_level: String,
    pub dedup_minutes: u64,
    /// 例 "https://ntfy.sh" または自前サーバー。空なら送らない
    pub ntfy_url: String,
    pub ntfy_topic: String,
    pub ntfy_token: String,
    /// 死活監視用 URL（healthchecks.io / Uptime Kuma の push URL 等）。空なら送らない
    pub heartbeat_url: String,
    pub heartbeat_minutes: u64,
    /// このレベル以上は消えない表示にする（macOS：閉じるまで残るダイアログ、Linux：期限なし通知）
    pub alert_level: String,
    /// ダイアログを自動で閉じるまでの秒数
    pub alert_timeout_s: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Feed {
    pub name: String,
    pub url: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

fn default_base() -> (PathBuf, PathBuf, PathBuf) {
    if cfg!(target_os = "macos") {
        (
            "/Library/Application Support/kanmon".into(),
            "/Library/Application Support/kanmon/etc".into(),
            "/Library/Logs/kanmon".into(),
        )
    } else {
        ("/var/lib/kanmon".into(), "/etc/kanmon".into(), "/var/log/kanmon".into())
    }
}

impl Default for JsonlCfg {
    fn default() -> Self {
        Self { path: default_base().2.join("events.jsonl"), max_mb: 50, keep: 5 }
    }
}

impl Default for NotifyCfg {
    fn default() -> Self {
        Self {
            local: true,
            min_level: "notice".into(),
            dedup_minutes: 10,
            ntfy_url: String::new(),
            ntfy_topic: String::new(),
            ntfy_token: String::new(),
            heartbeat_url: String::new(),
            heartbeat_minutes: 5,
            alert_level: "warn".into(),
            alert_timeout_s: 600,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        let (data, etc, _) = default_base();
        Self {
            mode: "learning".into(),
            learning_days: 7,
            interval_ms: 500,
            data_dir: data,
            detections_dir: etc.join("detections"),
            rules_file: etc.join("rules.json"),
            strict_owner: true,
            include_loopback: false,
            host_name: None,
            interpreters: [
                "python",
                "python2",
                "python3",
                "node",
                "bun",
                "deno",
                "ruby",
                "perl",
                "php",
                "bash",
                "sh",
                "zsh",
                "dash",
                "fish",
                "ksh",
                "osascript",
                "pwsh",
                "powershell",
                "lua",
                "tclsh",
                "java",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            thresholds: Thresholds::default(),
            retention_days: 90,
            jsonl: JsonlCfg::default(),
            notify: NotifyCfg::default(),
            feeds: vec![
                Feed {
                    name: "feodo".into(),
                    url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt".into(),
                    enabled: true,
                },
                Feed {
                    name: "spamhaus_drop_v4".into(),
                    url: "https://www.spamhaus.org/drop/drop_v4.json".into(),
                    enabled: true,
                },
            ],
            feeds_refresh_hours: 24,
            local_blocklists: vec![etc.join("blocklist.txt")],
            beacon_report_min: 0.6,
            beacon_interval_s: 300,
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(p) => {
                let t = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
                let c: Config = toml::from_str(&t).with_context(|| format!("parse {}", p.display()))?;
                Ok(c)
            }
            None => Ok(Config::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_config_parses() {
        let t = include_str!("../../../packaging/kanmon.toml");
        let c: Config = toml::from_str(t).unwrap();
        assert_eq!(c.thresholds.warn, 60);
        assert!(!c.feeds.is_empty());
    }
}
