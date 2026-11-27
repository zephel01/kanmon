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
    /// kanmond の動作ログ
    pub log: LogCfg,
    pub notify: NotifyCfg,
    pub feeds: Vec<Feed>,
    pub feeds_refresh_hours: u32,
    /// 改行区切りの拒否リスト（IP / CIDR / ドメイン）
    pub local_blocklists: Vec<PathBuf>,
    /// ビーコン報告を出す最小スコア
    pub beacon_report_min: f64,
    /// ビーコン集計の間隔（秒）
    pub beacon_interval_s: u64,
    /// 状態ソケット（読み取り専用、メニューバーアプリ用）。空文字で無効
    pub status_socket: String,
    /// 状態ソケットへの接続を追加で許す uid（root とログイン中のユーザーは常に可）
    pub status_allowed_uids: Vec<u32>,
    /// 宛先の名前付け（DNS・SNI の受け身の観測）と DNS の改ざん検知
    pub dns: DnsCfg,
    /// 送信量（プロセス × 宛先）の集計と報告
    pub volume: VolumeCfg,
    /// 居座り（開発ツールの設定・自動起動への仕込み）の走査
    pub persistence: PersistCfg,
    /// プロセスごとの「いつもの形」との違い
    pub profile: ProfileCfg,
    /// 宛先の AS（回線の種類・国）。データは kanmon-data の Release から取る
    pub asn: AsnCfg,
}

/// 宛先の AS の照合。iptoasn.com のデータを kanmon-data の CI が週 1 回取って縮めたもの（KASN1）を使う。
/// 利用者が iptoasn.com から直接取ると運営者の負荷になるので、既定の取得元は kanmon-data にしている
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AsnCfg {
    pub enabled: bool,
    /// KASN1（gzip）の URL。https のみ。同じ場所に `<url>.sha256` を置く
    pub url: String,
    /// 取り直す間隔（日）。端末ごとに最大 1 日ずらす
    pub refresh_days: u32,
    /// 手元のファイル（KASN1、gzip 可）。指定すると取得しない（社内ミラー・テスト用）
    pub file: Option<PathBuf>,
}

impl Default for AsnCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            url: "https://github.com/zephel01/kanmon-data/releases/download/asn-data/asn.kasn.gz".into(),
            refresh_days: 7,
            file: None,
        }
    }
}

/// プロセスごとの「いつもの形」（宛先・時間帯・親子・送信量）。形が安定しているプロセスで違いが出たときだけ点数を付ける
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProfileCfg {
    pub enabled: bool,
    /// 観測を始めてからこの日数たったプロセスだけを「安定」と見る
    pub min_age_days: u32,
    /// 最後に新しい宛先が増えてからこの日数たっていれば「安定」
    pub quiet_days: u32,
    /// 知っている宛先がこれより多いプロセス（ブラウザ等）は対象外
    pub max_dests: u32,
    /// 親が起動する子の種類がこれより多い親（シェル・ランチャー等）は対象外
    pub max_children: u32,
    /// 時間帯は、観測がこの日数以上のプロセスだけで見る
    pub hour_min_age_days: u32,
    /// 送信量は、この MB 以上のときだけ見る
    pub volume_min_mb: u64,
}

impl Default for ProfileCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            min_age_days: 3,
            quiet_days: 2,
            max_dests: 30,
            max_children: 10,
            hour_min_age_days: 7,
            volume_min_mb: 10,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PersistCfg {
    pub enabled: bool,
    /// 走査するプロジェクトのディレクトリ。`~/` はログイン中のユーザーのホーム
    pub roots: Vec<String>,
    /// 走査の間隔（秒）
    pub interval_s: u64,
    /// プロジェクトのディレクトリを潜る深さ
    pub max_depth: usize,
    /// /Library/LaunchDaemons・/etc/systemd/system 等、システム全体の自動起動と、
    /// システムの Python（Homebrew 等）の site-packages も見る
    pub system: bool,
    /// site-packages の更新時刻を見る間隔（秒）。変わったら間隔を待たずに走査し直す。0 で無効
    pub watch_s: u64,
    /// 起動の仕掛けが増えてから、そのあとの通信と結び付けて見る期間（秒）
    pub recent_window_s: u64,
}

impl Default for PersistCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            roots: vec!["~/kanmon-work".into()],
            interval_s: 3600,
            max_depth: 6,
            system: true,
            watch_s: 60,
            recent_window_s: 86_400,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VolumeCfg {
    pub enabled: bool,
    /// 接続ごとの送信量を読む間隔（秒）
    pub interval_s: u64,
    /// 合計する窓（秒）
    pub window_s: u64,
    /// この量（KB）以上送ったら報告イベント（bytes_report）を作る。判定は検知ルールで行う
    pub min_report_kb: u64,
    /// 同じプロセス・宛先の報告の間隔（分）
    pub report_every_min: u64,
}

impl Default for VolumeCfg {
    fn default() -> Self {
        Self { enabled: true, interval_s: 10, window_s: 600, min_report_kb: 1024, report_every_min: 30 }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsCfg {
    /// DNS 応答と TLS の SNI を受け身で読み、宛先 IP にドメイン名を付ける（設定は変えない）
    pub enabled: bool,
    /// 読むインターフェース。空なら自動（Linux は any、macOS は稼働中の全インターフェース）
    pub interfaces: Vec<String>,
    pub hosts_path: PathBuf,
    /// Linux で DNS サーバーを読むファイル（macOS は `scutil --dns`）
    pub resolv_conf: Vec<PathBuf>,
    /// hosts・DNS サーバー設定を確かめる間隔（秒）
    pub check_interval_s: u64,
    /// 監視リストのドメインを暗号化 DNS（DoH）で引き直して照合する
    pub crosscheck: bool,
    /// DoH の URL（https のみ。JSON 形式に対応したもの）
    pub doh_url: String,
    /// 同じドメインを引き直す間隔（分）
    pub crosscheck_interval_min: u64,
    /// 書き換えや食い違いを特に重く見るドメイン（サブドメインも含む）
    pub watch_domains: Vec<String>,
    /// プライベート IP に解決されても知らせない接尾辞（社内ドメイン等）
    pub private_ok_suffixes: Vec<String>,
}

impl Default for DnsCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            interfaces: vec![],
            hosts_path: "/etc/hosts".into(),
            resolv_conf: vec!["/etc/resolv.conf".into(), "/run/systemd/resolve/resolv.conf".into()],
            check_interval_s: 60,
            crosscheck: true,
            doh_url: "https://cloudflare-dns.com/dns-query".into(),
            crosscheck_interval_min: 30,
            watch_domains: [
                "registry.npmjs.org",
                "registry.yarnpkg.com",
                "pypi.org",
                "files.pythonhosted.org",
                "crates.io",
                "static.crates.io",
                "index.crates.io",
                "rubygems.org",
                "proxy.golang.org",
                "github.com",
                "githubusercontent.com",
                "ghcr.io",
                "huggingface.co",
                "api.anthropic.com",
                "api.openai.com",
                "accounts.google.com",
                "login.microsoftonline.com",
                "apple.com",
                "icloud.com",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            private_ok_suffixes: vec![],
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct JsonlCfg {
    pub path: PathBuf,
    pub max_mb: u64,
    pub keep: usize,
    /// "daily"（日付ごと：events.YYYY-MM-DD.jsonl、既定）/ "size"（サイズごと：events.jsonl.1 …）
    pub rotate: String,
    /// daily のときに残す日数
    pub keep_days: u32,
    /// daily のとき、切り替えた前の日のファイルを gzip にする（events.YYYY-MM-DD.jsonl.gz）。size では使わない
    pub compress: bool,
    /// events.jsonl に書く最低のレベル（info / notice / warn / critical）。既定は info（全部）。
    /// notice にすると記録だけの接続は書かない。SQLite（保存期間ぶん）には全部残り、ベースラインと alerts は変わらない。
    /// ただし `kanmonctl replay` は JSONL を読むので、新しいルールを試せるのは書いたイベントだけになる
    pub min_level: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogCfg {
    /// 動作ログのファイル。空なら標準エラー（Linux の systemd では journald）
    pub path: PathBuf,
    /// 日付ごとのファイルを残す日数
    pub keep_days: u32,
    /// 切り替えた前の日のファイルを gzip にする（kanmond.YYYY-MM-DD.log.gz）
    pub compress: bool,
}

impl Default for LogCfg {
    fn default() -> Self {
        Self {
            path: if cfg!(target_os = "macos") { default_base().2.join("kanmond.log") } else { PathBuf::new() },
            keep_days: 14,
            compress: true,
        }
    }
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
    /// メニューバーアプリが接続中は、OS ローカル通知（ダイアログ・バナー）をアプリに任せる
    pub defer_to_app: bool,
    /// Webhook（汎用 JSON・Slack・Discord）。`[[notify.webhooks]]` で複数書ける
    pub webhooks: Vec<WebhookCfg>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookCfg {
    /// 送り先。https のみ（ループバックだけは http も可：手元の中継・テスト用）
    pub url: String,
    /// json（汎用）/ slack / discord
    #[serde(default = "default_webhook_format")]
    pub format: String,
    /// この送り先に送る最低レベル（省略時は notify.min_level と同じ）
    #[serde(default)]
    pub min_level: Option<String>,
    /// ホスト名を入れる（社外のサービスに送るので既定は入れない）
    #[serde(default)]
    pub include_host: bool,
    /// `Authorization: Bearer …`（汎用 JSON の受け口用。空なら付けない）
    #[serde(default)]
    pub token: String,
}

fn default_webhook_format() -> String {
    "json".into()
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
        Self {
            path: default_base().2.join("events.jsonl"),
            max_mb: 50,
            keep: 5,
            rotate: "daily".into(),
            keep_days: 14,
            compress: true,
            min_level: "info".into(),
        }
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
            defer_to_app: true,
            webhooks: vec![],
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
            status_socket: if cfg!(target_os = "macos") {
                "/var/run/kanmond.sock".into()
            } else {
                "/run/kanmon/kanmond.sock".into()
            },
            status_allowed_uids: vec![],
            dns: DnsCfg::default(),
            volume: VolumeCfg::default(),
            log: LogCfg::default(),
            persistence: PersistCfg::default(),
            profile: ProfileCfg::default(),
            asn: AsnCfg::default(),
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(p) => {
                let t = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
                let c: Config = toml::from_str(&t).with_context(|| format!("parse {}", p.display()))?;
                if c.dns.crosscheck && !c.dns.doh_url.starts_with("https://") {
                    anyhow::bail!("dns.doh_url は https:// で始めてください");
                }
                if kanmon_core::scoring::Level::parse(&c.jsonl.min_level).is_none() {
                    anyhow::bail!("jsonl.min_level は info / notice / warn / critical のどれかにしてください");
                }
                if !matches!(c.jsonl.rotate.as_str(), "daily" | "size") {
                    anyhow::bail!("jsonl.rotate は daily / size のどちらかにしてください");
                }
                if c.asn.enabled && c.asn.file.is_none() && !c.asn.url.starts_with("https://") {
                    anyhow::bail!("asn.url は https:// で始めてください");
                }
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
        assert_eq!(c.jsonl.min_level, "info");
        assert_eq!((c.jsonl.rotate.as_str(), c.jsonl.keep_days, c.jsonl.compress), ("daily", 14, true));
    }

    #[test]
    fn jsonl_rotate_defaults_and_check() {
        let d = Config::default();
        assert_eq!((d.jsonl.rotate.as_str(), d.jsonl.keep_days, d.jsonl.compress), ("daily", 14, true));
        assert!(d.log.compress);
        let dir = std::env::temp_dir().join(format!("kanmon-cfg-rot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("k.toml");
        std::fs::write(&p, "[jsonl]\nrotate = \"size\"\ncompress = false\n").unwrap();
        let c = Config::load(Some(&p)).unwrap();
        assert_eq!((c.jsonl.rotate.as_str(), c.jsonl.compress), ("size", false));
        std::fs::write(&p, "[jsonl]\nrotate = \"weekly\"\n").unwrap();
        assert!(Config::load(Some(&p)).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn jsonl_min_level() {
        let dir = std::env::temp_dir().join(format!("kanmon-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("k.toml");
        std::fs::write(&p, "[jsonl]\nmin_level = \"notice\"\n").unwrap();
        assert_eq!(Config::load(Some(&p)).unwrap().jsonl.min_level, "notice");
        std::fs::write(&p, "[jsonl]\nmin_level = \"loud\"\n").unwrap();
        assert!(Config::load(Some(&p)).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
