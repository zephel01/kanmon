//! 通知：OS ローカル通知と ntfy、死活監視ハートビート。
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
    pub fn new(cfg: &NotifyCfg) -> Self {
        let (tx, rx) = channel::<Message>();
        let cfg2 = cfg.clone();
        let alert_level = Level::parse(&cfg.alert_level).unwrap_or(Level::Warn);
        std::thread::Builder::new()
            .name("notify".into())
            .spawn(move || {
                let mut st = Local::default();
                for m in rx {
                    if cfg2.local {
                        st.show(&m, m.level >= alert_level, cfg2.alert_timeout_s);
                    }
                    if !cfg2.ntfy_url.is_empty() && !cfg2.ntfy_topic.is_empty() {
                        if let Err(e) = ntfy(&cfg2, &m) {
                            eprintln!("kanmond: ntfy 送信失敗: {e}");
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

pub fn heartbeat(url: &str) {
    if let Err(e) = ureq::get(url).timeout(Duration::from_secs(10)).call() {
        eprintln!("kanmond: heartbeat 失敗: {e}");
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
            eprintln!("kanmond: 通知失敗: {e}");
        }
        if !alert {
            return;
        }
        // 閉じたダイアログを回収
        self.dialogs.retain_mut(|c| matches!(c.try_wait(), Ok(None)));
        if self.dialogs.len() >= Self::MAX_DIALOGS {
            eprintln!("kanmond: ダイアログが {} 件表示中のため、バナーのみ", self.dialogs.len());
            return;
        }
        let t = timeout_s.max(5).to_string();
        let args = osascript_args(&alert_script(m.level >= Level::Critical), &[&m.title, &m.body, &t]);
        match Self::osascript(&args).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn() {
            Ok(c) => self.dialogs.push(c),
            Err(e) => eprintln!("kanmond: ダイアログ表示失敗: {e}"),
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

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl Local {
    fn show(&mut self, _m: &Message, _alert: bool, _timeout_s: u64) {}
}

#[cfg(test)]
mod tests {
    use super::*;

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
