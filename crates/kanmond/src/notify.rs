//! 通知：OS ローカル通知・ntfy・Webhook（汎用 JSON / Slack / Discord）、死活監視ハートビート。
//! 送信は別スレッドで行い、監視ループを止めない。外部へは「情報のみ」（遠隔で許可する機能は持たない）。
//!
//! `alert_level` 以上は消えない表示にする：
//! - macOS：通常のバナーに加え、閉じるまで残るダイアログ（`display alert`、`alert_timeout_s` で自動クローズ）。
//!   ダイアログは非同期に起動し、同時表示は最大 3 つ。超えた分はバナーのみ。
//! - Linux：notify-send の urgency=critical・期限なし。

use crate::config::NotifyCfg;
use kanmon_core::Level;
use std::collections::HashMap;
#[allow(unused_imports)]
use std::process::{Child, Command};
use std::sync::mpsc::{channel, Sender};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Message {
    pub level: Level,
    pub title: String,
    pub body: String,
    /// 抑制キー（同じキーは dedup_minutes に 1 回）
    pub dedup_key: String,
}

pub struct Notifier {
    tx: Sender<Message>,
    seen: HashMap<String, Instant>,
    dedup: Duration,
    pub min_level: Level,
}

/// 通知スレッドの状態（開いているダイアログの管理）
#[derive(Default)]
struct Local {
    #[allow(dead_code)]
    dialogs: Vec<Child>,
}

impl Notifier {
    pub fn new(cfg: &NotifyCfg, app: Option<std::sync::Arc<crate::status::Shared>>) -> Self {
        let (tx, rx) = channel::<Message>();
        let cfg2 = cfg.clone();
        let alert_level = Level::parse(&cfg.alert_level).unwrap_or(Level::Warn);
        let base_min = Level::parse(&cfg.min_level).unwrap_or(Level::Notice);
        let host = crate::monitor::hostname();
        for w in &cfg.webhooks {
            if let Err(e) = check_webhook(w) {
                logln!("Webhook の設定を使いません（{}）: {e}", redact_url(&w.url));
            }
        }
        std::thread::Builder::new()
            .name("notify".into())
            .spawn(move || {
                let mut st = Local::default();
                for m in rx {
                    let deferred = cfg2.defer_to_app && app.as_ref().is_some_and(|a| a.app_active());
                    if cfg2.local && !deferred {
                        st.show(&m, m.level >= alert_level, cfg2.alert_timeout_s);
                    }
                    if !cfg2.ntfy_url.is_empty() && !cfg2.ntfy_topic.is_empty() {
                        if let Err(e) = ntfy(&cfg2, &m) {
                            logln!("ntfy 送信失敗: {e}");
                        }
                    }
                    for w in &cfg2.webhooks {
                        let min = w.min_level.as_deref().and_then(Level::parse).unwrap_or(base_min);
                        if m.level < min {
                            continue;
                        }
                        let host = if w.include_host { Some(host.as_str()) } else { None };
                        if let Err(e) = webhook(w, &m, host) {
                            logln!("Webhook 送信失敗（{}）: {e}", redact_url(&w.url));
                        }
                    }
                }
            })
            .expect("spawn notify thread");
        Self {
            tx,
            seen: HashMap::new(),
            dedup: Duration::from_secs(cfg.dedup_minutes * 60),
            min_level: Level::parse(&cfg.min_level).unwrap_or(Level::Notice),
        }
    }

    /// 送ったら true（レベル不足・抑制中なら false）
    pub fn send(&mut self, m: Message, min: Level) -> bool {
        if m.level < min {
            return false;
        }
        let now = Instant::now();
        if let Some(t) = self.seen.get(&m.dedup_key) {
            if now.duration_since(*t) < self.dedup {
                return false;
            }
        }
        self.seen.insert(m.dedup_key.clone(), now);
        if self.seen.len() > 10_000 {
            let d = self.dedup;
            self.seen.retain(|_, t| now.duration_since(*t) < d);
        }
        self.tx.send(m).is_ok()
    }
}

fn ntfy(cfg: &NotifyCfg, m: &Message) -> anyhow::Result<()> {
    let prio = match m.level {
        Level::Info => 2,
        Level::Notice => 3,
        Level::Warn => 4,
        Level::Critical => 5,
    };
    let body = serde_json::json!({
        "topic": cfg.ntfy_topic,
        "title": m.title,
        "message": m.body,
        "priority": prio,
        "tags": ["kanmon", m.level.as_str()],
    });
    let mut req = ureq::post(cfg.ntfy_url.trim_end_matches('/')).timeout(Duration::from_secs(10));
    if !cfg.ntfy_token.is_empty() {
        req = req.set("Authorization", &format!("Bearer {}", cfg.ntfy_token));
    }
    req.send_json(body)?;
    Ok(())
}

/// Webhook の設定を確かめる：https（ループバックのみ http 可）、形式
pub fn check_webhook(w: &crate::config::WebhookCfg) -> anyhow::Result<()> {
    if !matches!(w.format.as_str(), "json" | "slack" | "discord") {
        anyhow::bail!("format は json / slack / discord のどれか");
    }
    let u = w.url.as_str();
    let host_of = |rest: &str| rest.split(['/', '?', '#']).next().unwrap_or("").to_string();
    if let Some(rest) = u.strip_prefix("https://") {
        if host_of(rest).is_empty() {
            anyhow::bail!("URL にホストがない");
        }
        return Ok(());
    }
    if let Some(rest) = u.strip_prefix("http://") {
        let h = host_of(rest);
        let name = h.rsplit_once(':').map(|(a, _)| a).unwrap_or(&h);
        if matches!(name, "127.0.0.1" | "localhost" | "[::1]") {
            return Ok(());
        }
    }
    anyhow::bail!("https の URL だけを使う（ループバックだけは http 可）")
}

/// ログに出すための URL（パスとクエリは伏せる。Slack・Discord の URL は秘密の鍵を含む）
pub fn redact_url(u: &str) -> String {
    match u.split_once("://") {
        Some((s, rest)) => format!("{s}://{}/…", rest.split(['/', '?', '#']).next().unwrap_or("")),
        None => "(不正な URL)".into(),
    }
}

/// Slack の mrkdwn の制御文字を逃がす（`<!channel>` 等の一斉通知やリンクの偽装を防ぐ）
fn slack_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn clip_chars(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        format!("{}…", s.chars().take(n).collect::<String>())
    } else {
        s.to_string()
    }
}

/// 送る JSON を作る（純関数。通知の本文はプロセス名・ドメイン等、外から来た文字列を含むので、
/// Slack は制御文字を逃がし、Discord は一斉通知（@everyone 等）を無効にする）
pub fn webhook_payload(format: &str, m: &Message, host: Option<&str>) -> serde_json::Value {
    let level = m.level.as_str();
    match format {
        "slack" => serde_json::json!({
            "text": clip_chars(&format!(
                "*[kanmon {level}] {}*{}\n{}",
                slack_escape(&m.title),
                host.map(|h| format!("（{}）", slack_escape(h))).unwrap_or_default(),
                slack_escape(&m.body)
            ), 3500),
        }),
        "discord" => serde_json::json!({
            "content": clip_chars(&format!(
                "**[kanmon {level}] {}**{}\n{}",
                m.title,
                host.map(|h| format!("（{h}）")).unwrap_or_default(),
                m.body
            ), 1900),
            "allowed_mentions": { "parse": [] },
        }),
        _ => {
            let mut v = serde_json::json!({
                "source": "kanmon",
                "level": level,
                "title": m.title,
                "body": clip_chars(&m.body, 8000),
                "time": chrono::Utc::now().to_rfc3339(),
            });
            if let Some(h) = host {
                v["host"] = serde_json::json!(h);
            }
            v
        }
    }
}

fn webhook(w: &crate::config::WebhookCfg, m: &Message, host: Option<&str>) -> anyhow::Result<()> {
    check_webhook(w)?;
    let body = webhook_payload(&w.format, m, host);
    let mut last = None;
    for _ in 0..2 {
        let mut req = ureq::post(&w.url).timeout(Duration::from_secs(10));
        if !w.token.is_empty() && w.format == "json" {
            req = req.set("Authorization", &format!("Bearer {}", w.token));
        }
        match req.send_json(body.clone()) {
            Ok(_) => return Ok(()),
            Err(e) => last = Some(e),
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    Err(anyhow::anyhow!("{}", last.map(|e| e.to_string()).unwrap_or_default()))
}

pub fn heartbeat(url: &str) {
    if let Err(e) = ureq::get(url).timeout(Duration::from_secs(10)).call() {
        logln!("heartbeat 失敗: {e}");
    }
}

/// osascript の引数（-e の各行のあとに argv）。文字列は引数として渡し、
/// シェル解釈・AppleScript への埋め込みをしない（ファイル名等による注入対策）。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn osascript_args(script: &[&str], argv: &[&str]) -> Vec<String> {
    let mut args = vec![];
    for s in script {
        args.push("-e".to_string());
        args.push(s.to_string());
    }
    args.extend(argv.iter().map(|s| s.to_string()));
    args
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn alert_script(critical: bool) -> [&'static str; 4] {
    [
        "on run argv",
        "activate",
        if critical {
            "display alert (item 1 of argv) message (item 2 of argv) as critical buttons {\"OK\"} default button \"OK\" giving up after ((item 3 of argv) as integer)"
        } else {
            "display alert (item 1 of argv) message (item 2 of argv) as warning buttons {\"OK\"} default button \"OK\" giving up after ((item 3 of argv) as integer)"
        },
        "end run",
    ]
}

#[cfg(target_os = "macos")]
impl Local {
    const MAX_DIALOGS: usize = 3;

    fn osascript(args: &[String]) -> Command {
        let is_root = unsafe { libc::geteuid() } == 0;
        if is_root {
            // root の launchd デーモンからは、ログイン中ユーザーのセッションで出す
            let mut c = Command::new("/bin/launchctl");
            c.arg("asuser").arg(console_uid().unwrap_or(0).to_string()).arg("/usr/bin/osascript").args(args);
            c
        } else {
            let mut c = Command::new("/usr/bin/osascript");
            c.args(args);
            c
        }
    }

    fn show(&mut self, m: &Message, alert: bool, timeout_s: u64) {
        if unsafe { libc::geteuid() } == 0 && console_uid().is_none() {
            return; // ログイン中のユーザーがいない
        }
        // バナー（通知センターにも残る）。本文は先頭数行だけ
        let short: String = m.body.lines().take(4).collect::<Vec<_>>().join("\n");
        let banner = ["on run argv", "display notification (item 1 of argv) with title (item 2 of argv)", "end run"];
        if let Err(e) = Self::osascript(&osascript_args(&banner, &[&short, &m.title])).output() {
            logln!("通知失敗: {e}");
        }
        if !alert {
            return;
        }
        // 閉じたダイアログを回収
        self.dialogs.retain_mut(|c| matches!(c.try_wait(), Ok(None)));
        if self.dialogs.len() >= Self::MAX_DIALOGS {
            logln!("ダイアログが {} 件表示中のため、バナーのみ", self.dialogs.len());
            return;
        }
        let t = timeout_s.max(5).to_string();
        let args = osascript_args(&alert_script(m.level >= Level::Critical), &[&m.title, &m.body, &t]);
        match Self::osascript(&args).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn() {
            Ok(c) => self.dialogs.push(c),
            Err(e) => logln!("ダイアログ表示失敗: {e}"),
        }
    }
}

#[cfg(target_os = "macos")]
fn console_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    let uid = std::fs::metadata("/dev/console").ok()?.uid();
    (uid != 0).then_some(uid)
}

#[cfg(target_os = "linux")]
impl Local {
    fn show(&mut self, m: &Message, alert: bool, _timeout_s: u64) {
        let urgency = match m.level {
            _ if alert => "critical",
            Level::Critical | Level::Warn => "critical",
            Level::Notice => "normal",
            Level::Info => "low",
        };
        // alert は期限なし（閉じるまで残る）。それ以外はデスクトップ環境の既定
        let expire = if alert { "0" } else { "-1" };
        let base = ["-u", urgency, "-t", expire, "-a", "kanmon", m.title.as_str(), m.body.as_str()];
        let is_root = unsafe { libc::geteuid() } == 0;
        if !is_root {
            let _ = Command::new("notify-send").args(base).output();
            return;
        }
        // root からはログイン中の各ユーザーのセッションバスへ
        let Ok(rd) = std::fs::read_dir("/run/user") else { return };
        for e in rd.flatten() {
            let Some(uid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
            if uid == 0 || !e.path().join("bus").exists() {
                continue;
            }
            let Some(user) = crate::procinfo::user_name(uid) else { continue };
            let _ = Command::new("runuser")
                .args(["-u", &user, "--", "env"])
                .arg(format!("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus"))
                .arg("notify-send")
                .args(base)
                .output();
        }
    }
}

/// Windows：サービスは利用者の画面に出せない（セッション 0）。画面の通知はトレイ（kanmon-tray）が出すので、
/// ここでは Windows のイベントログ（アプリケーション、ソース `kanmon`）に書く。
/// ソースは kanmon-setup.ps1 が登録する。無ければ Windows が既定の扱いで書く（説明の文が付かないだけ）
#[cfg(windows)]
impl Local {
    fn show(&mut self, m: &Message, _alert: bool, _timeout_s: u64) {
        use windows_sys::Win32::System::EventLog::{
            DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE,
            EVENTLOG_WARNING_TYPE,
        };
        let w = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
        let src = w("kanmon");
        // 本文は 1 件 31,839 文字までなので、余裕を持って切る
        let text: String = format!("{}\n\n{}", m.title, m.body).chars().take(8000).collect();
        let msg = w(&text);
        let ty = match m.level {
            Level::Critical => EVENTLOG_ERROR_TYPE,
            Level::Warn => EVENTLOG_WARNING_TYPE,
            _ => EVENTLOG_INFORMATION_TYPE,
        };
        // イベント ID：notice 1、warn 2、critical 3（イベント ビューアーでの絞り込み用）
        let id = match m.level {
            Level::Critical => 3,
            Level::Warn => 2,
            _ => 1,
        };
        unsafe {
            let h = RegisterEventSourceW(std::ptr::null(), src.as_ptr());
            if h.is_null() {
                logln!("イベントログに書けません");
                return;
            }
            let strs = [msg.as_ptr()];
            ReportEventW(h, ty, 0, id, std::ptr::null_mut(), 1, 0, strs.as_ptr(), std::ptr::null());
            DeregisterEventSource(h);
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
impl Local {
    fn show(&mut self, _m: &Message, _alert: bool, _timeout_s: u64) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WebhookCfg;

    fn wh(url: &str, format: &str) -> WebhookCfg {
        WebhookCfg {
            url: url.into(),
            format: format.into(),
            min_level: None,
            include_host: false,
            token: String::new(),
        }
    }

    #[test]
    fn webhook_urls() {
        assert!(check_webhook(&wh("https://hooks.slack.com/services/T/B/x", "slack")).is_ok());
        assert!(check_webhook(&wh("http://127.0.0.1:18091/hook", "json")).is_ok());
        assert!(check_webhook(&wh("http://localhost/hook", "json")).is_ok());
        assert!(check_webhook(&wh("http://203.0.113.9/hook", "json")).is_err());
        assert!(check_webhook(&wh("ftp://x", "json")).is_err());
        assert!(check_webhook(&wh("https://x/y", "teams")).is_err());
        assert_eq!(redact_url("https://hooks.slack.com/services/T/B/secret?x=1"), "https://hooks.slack.com/…");
    }

    #[test]
    fn webhook_payloads_neutralize_mentions() {
        let m = Message {
            level: Level::Critical,
            title: "<!channel> evil".into(),
            body: "@everyone process <https://203.0.113.9|click> & more".into(),
            dedup_key: "k".into(),
        };
        let s = webhook_payload("slack", &m, Some("host1"));
        let t = s["text"].as_str().unwrap();
        assert!(!t.contains("<!channel>") && !t.contains("<https://") && t.contains("&lt;!channel&gt;"), "{t}");
        assert!(t.contains("host1"));
        let d = webhook_payload("discord", &m, None);
        assert_eq!(d["allowed_mentions"]["parse"], serde_json::json!([]));
        assert!(!d["content"].as_str().unwrap().contains("host1"));
        let j = webhook_payload("json", &m, None);
        assert_eq!(j["level"], "critical");
        assert!(j.get("host").is_none());
        let long = Message { body: "あ".repeat(5000), ..m };
        assert!(webhook_payload("discord", &long, None)["content"].as_str().unwrap().chars().count() <= 1901);
    }

    #[test]
    fn osascript_args_keep_text_out_of_script() {
        let evil = "\" & (do shell script \"id\") & \"";
        let a = osascript_args(&alert_script(true), &["t", evil, "600"]);
        // スクリプト行は固定文字列のみ。利用者由来の文字列は argv 側にだけある
        let script_lines: Vec<&String> = a.iter().skip(1).step_by(2).take(4).collect();
        assert!(script_lines.iter().all(|l| !l.contains("do shell script")));
        assert_eq!(a.last().unwrap(), "600");
        assert!(a.contains(&evil.to_string()));
        assert_eq!(a.iter().filter(|x| *x == "-e").count(), 4);
    }
}
