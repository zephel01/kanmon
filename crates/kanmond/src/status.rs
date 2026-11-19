//! 状態ソケット（読み取り専用）。メニューバーアプリ等が kanmond の状態と直近の警告を取得する。
//!
//! - Unix ドメインソケット。1 行の JSON 要求に 1 行の JSON で答えて閉じる
//!   - `{"cmd":"status"}` → 状態スナップショット
//!   - `{"cmd":"ping"}`   → `{"ok":true}`
//!   - `{"cmd":"alerts","level":"notice","hours":24,"limit":500}` → 期間内の警告の一覧とルール別の件数
//!   - `{"cmd":"export","hours":24,"min_level":"notice","format":"summary","domains":"registered",
//!     "paths":"full","round_time":false}` → 共有用に伏せた集計（Markdown）とログ（v0.5.3）。
//!     伏せるのは kanmond（root）の中で行い、ソケットの外へは伏せた後のデータだけを出す
//!     （DB を読み取り専用で開いて読む。level は all / notice / warn / critical）
//! - 設定は変更できない（読み取り専用）。モード変更などは管理者認証つきの別経路で行う
//! - 接続相手の uid を検証する：root・ログイン中のユーザー・`status_allowed_uids` のみ
//! - アプリが接続している間（直近 15 秒以内に要求あり）は、OS ローカル通知をアプリに任せる

use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const MAX_ALERTS: usize = 50;
const MAX_REQUEST: u64 = 4096;
/// この秒数以内に要求があれば「アプリ接続中」とみなす
pub const APP_ACTIVE_SECS: i64 = 15;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AlertItem {
    pub id: String,
    pub ts: String,
    pub level: String,
    pub score: i32,
    pub kind: String,
    pub title: String,
    pub body: String,
    /// 当たった検知ルールの ID（一覧での絞り込み・件数の集計用）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<String>,
}

/// イベントの JSON から、当たった検知ルールの ID を取り出す
pub fn signal_ids(v: &serde_json::Value) -> Vec<String> {
    kanmon_core::event::get_path(v, "kanmon.signals")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|h| h.get("id").and_then(|i| i.as_str()).map(str::to_string)).collect())
        .unwrap_or_default()
}

/// 保存済みイベントから状態ソケット用の警告を作る（DB からの読み戻し・一覧用）
pub fn alert_item_from_event(v: &serde_json::Value) -> Option<AlertItem> {
    let s = |p: &str| kanmon_core::event::get_path(v, p).and_then(|x| x.as_str()).map(str::to_string);
    let level = s("kanmon.level")?;
    let (title, body) = kanmon_core::format::alert_text(v);
    Some(AlertItem {
        id: s("event.id")?,
        ts: s("@timestamp").unwrap_or_default(),
        score: kanmon_core::event::get_path(v, "kanmon.score").and_then(|x| x.as_i64()).unwrap_or(0) as i32,
        kind: s("network.kind").unwrap_or_default(),
        level,
        title,
        body,
        rules: signal_ids(v),
    })
}

/// `{"cmd":"alerts"}` の応答
#[derive(Debug, Clone, Serialize, Default)]
pub struct AlertList {
    pub level: String,
    pub hours: i64,
    /// 新しい順
    pub alerts: Vec<AlertItem>,
    /// ルール ID ごとの件数（返した警告の中で）
    pub by_rule: BTreeMap<String, i64>,
    /// 上限で切ったか
    pub truncated: bool,
}

const MAX_LIST: i64 = 2000;

fn list_alerts(db: &Path, req: &serde_json::Value) -> Result<AlertList> {
    let level = req.get("level").and_then(|v| v.as_str()).unwrap_or("all");
    let levels: Vec<&str> = match level {
        "notice" | "warn" | "critical" => vec![level],
        _ => vec!["notice", "warn", "critical"],
    };
    let hours = req.get("hours").and_then(|v| v.as_i64()).unwrap_or(24).clamp(1, 24 * 30);
    let limit = req.get("limit").and_then(|v| v.as_i64()).unwrap_or(500).clamp(1, MAX_LIST);
    let store = kanmon_core::store::Store::open_readonly(db)?;
    let since = chrono::Utc::now().timestamp() - hours * 3600;
    let evs = store.recent_events(since, &levels, limit + 1)?;
    let truncated = evs.len() as i64 > limit;
    let alerts: Vec<AlertItem> = evs.iter().take(limit as usize).filter_map(alert_item_from_event).collect();
    let mut by_rule = BTreeMap::new();
    for a in &alerts {
        for r in &a.rules {
            *by_rule.entry(r.clone()).or_insert(0) += 1;
        }
    }
    Ok(AlertList {
        level: if levels.len() == 1 { level.into() } else { "all".into() },
        hours,
        alerts,
        by_rule,
        truncated,
    })
}

/// 書き出しの上限（件数・ログの大きさ）
const MAX_EXPORT: i64 = 20_000;
const MAX_EXPORT_BYTES: usize = 8 * 1024 * 1024;

fn export(db: &Path, req: &serde_json::Value) -> Result<serde_json::Value> {
    use kanmon_core::redact::{summarize, DomainMode, Options, Redactor};
    use kanmon_core::scoring::Level;
    let hours = req.get("hours").and_then(|v| v.as_i64()).unwrap_or(24).clamp(1, 24 * 30);
    let min = req.get("min_level").and_then(|v| v.as_str()).and_then(Level::parse).unwrap_or(Level::Notice);
    let levels: Vec<&str> = ["info", "notice", "warn", "critical"]
        .into_iter()
        .filter(|l| Level::parse(l).is_some_and(|x| x >= min))
        .collect();
    let opts = Options {
        domains: req
            .get("domains")
            .and_then(|v| v.as_str())
            .and_then(DomainMode::parse)
            .unwrap_or(DomainMode::Registered),
        paths_basename: req.get("paths").and_then(|v| v.as_str()) == Some("basename"),
        round_time: req.get("round_time").and_then(|v| v.as_bool()).unwrap_or(false),
    };
    let want_log = req.get("format").and_then(|v| v.as_str()) == Some("jsonl");
    let store = kanmon_core::store::Store::open_readonly(db)?;
    let since = chrono::Utc::now().timestamp() - hours * 3600;
    let mut evs = store.recent_events(since, &levels, MAX_EXPORT + 1)?;
    let mut truncated = evs.len() as i64 > MAX_EXPORT;
    evs.truncate(MAX_EXPORT as usize);
    evs.reverse(); // 古い順
    let mut r = Redactor::new(opts);
    let red: Vec<serde_json::Value> = evs.iter().map(|e| r.event(e)).collect();
    let summary = summarize(&red, hours, min.as_str());
    let sample: Vec<String> = red.iter().rev().take(20).map(|e| e.to_string()).collect();
    let mut log = String::new();
    if want_log {
        for e in &red {
            let line = e.to_string();
            if log.len() + line.len() + 1 > MAX_EXPORT_BYTES {
                truncated = true;
                break;
            }
            log.push_str(&line);
            log.push('\n');
        }
    }
    Ok(serde_json::json!({
        "count": red.len(),
        "truncated": truncated,
        "markdown": summary.markdown(),
        "summary": summary,
        "sample": sample,
        "jsonl": if want_log { serde_json::Value::String(log) } else { serde_json::Value::Null },
    }))
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Snapshot {
    pub version: String,
    pub host: String,
    pub os: String,
    pub mode: String,
    pub learning: bool,
    /// 学習期間の終了予定（RFC 3339）。learning_days=0 なら None
    pub learning_until: Option<String>,
    pub started_at: String,
    pub detections: usize,
    pub intel: usize,
    /// 直近 24 時間のレベル別件数
    pub counts_24h: BTreeMap<String, i64>,
    /// 直近の警告（notice 以上、新しい順、最大 50 件）
    pub alerts: VecDeque<AlertItem>,
    pub last_event_at: Option<String>,
    pub events_path: String,
}

pub struct Shared {
    snap: Mutex<Snapshot>,
    last_client: AtomicI64,
    /// 警告の一覧（`alerts`）を読む DB
    db: Option<PathBuf>,
}

impl Shared {
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new(base: Snapshot) -> Arc<Self> {
        Self::with_db(base, None)
    }

    pub fn with_db(base: Snapshot, db: Option<PathBuf>) -> Arc<Self> {
        Arc::new(Self { snap: Mutex::new(base), last_client: AtomicI64::new(0), db })
    }

    pub fn update<F: FnOnce(&mut Snapshot)>(&self, f: F) {
        if let Ok(mut s) = self.snap.lock() {
            f(&mut s);
        }
    }

    pub fn push_alert(&self, a: AlertItem) {
        self.update(|s| {
            s.alerts.push_front(a);
            s.alerts.truncate(MAX_ALERTS);
        });
    }

    pub fn snapshot(&self) -> Snapshot {
        self.snap.lock().map(|s| s.clone()).unwrap_or_default()
    }

    pub fn touch_client(&self) {
        self.last_client.store(chrono::Utc::now().timestamp(), Ordering::Relaxed);
    }

    /// メニューバーアプリが接続中か
    pub fn app_active(&self) -> bool {
        chrono::Utc::now().timestamp() - self.last_client.load(Ordering::Relaxed) <= APP_ACTIVE_SECS
    }
}

/// 要求 1 行に対する応答（純関数。テスト用に分離）
pub fn respond(req: &str, shared: &Shared) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(req.trim()).unwrap_or_default();
    let cmd = parsed.get("cmd").and_then(|c| c.as_str()).map(str::to_string);
    match cmd.as_deref() {
        Some("alerts") => {
            shared.touch_client();
            let Some(db) = &shared.db else { return r#"{"error":"no database"}"#.into() };
            match list_alerts(db, &parsed) {
                Ok(l) => serde_json::to_string(&l).unwrap_or_else(|_| r#"{"error":"serialize"}"#.into()),
                Err(e) => serde_json::json!({ "error": format!("{e:#}") }).to_string(),
            }
        }
        Some("export") => {
            shared.touch_client();
            let Some(db) = &shared.db else { return r#"{"error":"no database"}"#.into() };
            match export(db, &parsed) {
                Ok(v) => v.to_string(),
                Err(e) => serde_json::json!({ "error": format!("{e:#}") }).to_string(),
            }
        }
        Some("status") => {
            shared.touch_client();
            serde_json::to_string(&shared.snapshot()).unwrap_or_else(|_| r#"{"error":"serialize"}"#.into())
        }
        Some("ping") => r#"{"ok":true}"#.into(),
        _ => r#"{"error":"unknown command"}"#.into(),
    }
}

/// 接続相手の uid
#[cfg(target_os = "macos")]
pub fn peer_uid(s: &UnixStream) -> Option<u32> {
    use std::os::unix::io::AsRawFd;
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let r = unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) };
    (r == 0).then_some(uid)
}

#[cfg(target_os = "linux")]
pub fn peer_uid(s: &UnixStream) -> Option<u32> {
    use std::os::unix::io::AsRawFd;
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    (r == 0).then_some(cred.uid)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn peer_uid(_s: &UnixStream) -> Option<u32> {
    None
}

/// 接続を許す uid か：root、ログイン中のユーザー、設定で許可した uid
pub fn uid_allowed(uid: u32, extra: &[u32]) -> bool {
    if uid == 0 || extra.contains(&uid) {
        return true;
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt;
        if std::fs::metadata("/dev/console").map(|m| m.uid()).ok() == Some(uid) {
            return true;
        }
    }
    #[cfg(target_os = "linux")]
    {
        if Path::new(&format!("/run/user/{uid}")).exists() {
            return true;
        }
    }
    false
}

fn handle(mut s: UnixStream, shared: &Shared, extra: &[u32]) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
    let uid = peer_uid(&s);
    if !uid.is_some_and(|u| uid_allowed(u, extra)) {
        let _ = s.write_all(b"{\"error\":\"forbidden\"}\n");
        return;
    }
    let mut line = String::new();
    let mut r = BufReader::new((&s).take(MAX_REQUEST));
    if r.read_line(&mut line).is_err() {
        return;
    }
    let mut out = respond(&line, shared);
    out.push('\n');
    if out.len() > 64 * 1024 {
        // 書き出しは大きいので、書き込みの待ちを長くする
        let _ = s.set_write_timeout(Some(Duration::from_secs(30)));
    }
    let _ = s.write_all(out.as_bytes());
}

/// ソケットを作って待ち受けスレッドを起動する
pub fn serve(path: &Path, shared: Arc<Shared>, extra_uids: Vec<u32>) -> Result<PathBuf> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
    }
    // 前回の残骸（ソケットのみ）を消す。通常ファイルなら消さずにエラー
    if let Ok(md) = std::fs::symlink_metadata(path) {
        use std::os::unix::fs::FileTypeExt;
        if md.file_type().is_socket() {
            std::fs::remove_file(path)?;
        } else {
            anyhow::bail!("{} はソケットではありません。削除しません", path.display());
        }
    }
    let listener = UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        // 接続自体は誰でも可。uid の検証は接続後に行う
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    }
    let p = path.to_path_buf();
    std::thread::Builder::new().name("status".into()).spawn(move || {
        for s in listener.incoming().flatten() {
            handle(s, &shared, &extra_uids);
        }
    })?;
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(i: usize) -> AlertItem {
        AlertItem {
            id: format!("e{i}"),
            ts: "t".into(),
            level: "warn".into(),
            score: 60,
            kind: "connect".into(),
            title: "t".into(),
            body: "b".into(),
            rules: vec![],
        }
    }

    #[test]
    fn alerts_command_reads_db() {
        let dir = std::env::temp_dir().join(format!("kanmon-status-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("kanmon.db");
        let _ = std::fs::remove_file(&db);
        {
            let st = kanmon_core::store::Store::open(&db).unwrap();
            let now = chrono::Utc::now().timestamp();
            for (i, (lv, rule)) in
                [("notice", "N3"), ("notice", "N3"), ("warn", "D9"), ("info", "S12")].iter().enumerate()
            {
                let v = serde_json::json!({
                    "@timestamp": "2026-11-18T16:00:00+09:00", "event": {"id": format!("e{i}")},
                    "network": {"kind": "connect"},
                    "kanmon": {"level": lv, "score": 40, "signals": [{"id": rule, "name": "x", "points": 40}]}
                });
                st.insert_event(&v, now - i as i64).unwrap();
            }
        }
        let sh = Shared::with_db(Snapshot::default(), Some(db.clone()));
        let v: serde_json::Value = serde_json::from_str(&respond(r#"{"cmd":"alerts","level":"notice"}"#, &sh)).unwrap();
        assert_eq!(v["alerts"].as_array().unwrap().len(), 2, "{v}");
        assert_eq!(v["by_rule"]["N3"], 2);
        assert_eq!(v["alerts"][0]["rules"][0], "N3");
        let v: serde_json::Value = serde_json::from_str(&respond(r#"{"cmd":"alerts","limit":1}"#, &sh)).unwrap();
        assert_eq!(v["level"], "all");
        assert_eq!(v["truncated"], true);
        // Swift 側と同じ形か（取り決めのフィクスチャ）
        let fx: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/status-alerts.json")).unwrap();
        for k in ["level", "hours", "alerts", "by_rule", "truncated"] {
            assert!(fx.get(k).is_some() && v.get(k).is_some(), "{k}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn respond_and_ring() {
        let sh = Shared::new(Snapshot { version: "0.1.0".into(), ..Default::default() });
        for i in 0..60 {
            sh.push_alert(item(i));
        }
        assert!(!sh.app_active());
        let v: serde_json::Value = serde_json::from_str(&respond(r#"{"cmd":"status"}"#, &sh)).unwrap();
        assert_eq!(v["version"], "0.1.0");
        assert_eq!(v["alerts"].as_array().unwrap().len(), MAX_ALERTS);
        assert_eq!(v["alerts"][0]["id"], "e59", "新しい順");
        assert!(sh.app_active(), "status 要求でアプリ接続中になる");
        assert_eq!(respond(r#"{"cmd":"ping"}"#, &sh), r#"{"ok":true}"#);
        assert!(respond("garbage", &sh).contains("unknown"));
    }

    /// メニューバーアプリ（Swift）との取り決め。キー名を変えたら Swift 側の CodingKeys と
    /// tests/fixtures/status-snapshot.json も直すこと（Swift 側のテストが同じファイルを読む）
    #[test]
    fn snapshot_matches_contract_fixture() {
        let mut alerts = VecDeque::new();
        alerts.push_back(AlertItem {
            id: "e_1".into(),
            ts: "2026-11-18T12:30:00.123+09:00".into(),
            level: "critical".into(),
            score: 160,
            kind: "connect".into(),
            title: "kanmon CRITICAL 160点: updater → 198.51.100.7:443".into(),
            body: "【理由】合計 160 点（critical）".into(),
            rules: vec![],
        });
        let snap = Snapshot {
            version: "0.1.0".into(),
            host: "mbp-alice".into(),
            os: "macos".into(),
            mode: "learning".into(),
            learning: true,
            learning_until: Some("2026-11-25T10:00:00+09:00".into()),
            started_at: "2026-11-18T12:00:00+09:00".into(),
            detections: 30,
            intel: 1744,
            counts_24h: [("critical".to_string(), 1), ("notice".to_string(), 3), ("warn".to_string(), 2)]
                .into_iter()
                .collect(),
            alerts,
            last_event_at: Some("2026-11-18T12:30:00.123+09:00".into()),
            events_path: "/Library/Logs/kanmon/events.jsonl".into(),
        };
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/status-snapshot.json");
        let fixture: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(serde_json::to_value(&snap).unwrap(), fixture);
    }

    #[test]
    fn socket_roundtrip_and_uid() {
        let dir = std::env::temp_dir().join(format!("kanmon-sock-{}", std::process::id()));
        let path = dir.join("k.sock");
        let sh = Shared::new(Snapshot { host: "h".into(), ..Default::default() });
        // テストを実行する uid を許可リストに入れる
        let me = unsafe { libc::geteuid() };
        serve(&path, sh.clone(), vec![me]).unwrap();
        let mut c = UnixStream::connect(&path).unwrap();
        c.write_all(b"{\"cmd\":\"status\"}\n").unwrap();
        let mut s = String::new();
        BufReader::new(&c).read_line(&mut s).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["host"], "h");
        assert_eq!(peer_uid(&c), Some(me));
        assert!(uid_allowed(0, &[]));
        assert!(!uid_allowed(4_000_000_000, &[]));
        // 通常ファイルは消さない
        let f = dir.join("plain");
        std::fs::write(&f, "x").unwrap();
        assert!(serve(&f, sh, vec![]).is_err());
        assert!(f.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn export_redacts_inside_daemon() {
        let dir = std::env::temp_dir().join(format!("kanmon-export-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("kanmon.db");
        let _ = std::fs::remove_file(&db);
        {
            let st = kanmon_core::store::Store::open(&db).unwrap();
            let now = chrono::Utc::now().timestamp();
            for (i, lv) in ["notice", "warn", "info"].iter().enumerate() {
                let v = serde_json::json!({
                    "@timestamp": "2026-11-19T18:16:12.123+09:00", "event": {"id": format!("x{i}")},
                    "host": {"name": "alice-mbp.local"},
                    "network": {"kind": "connect", "scope": "internet"},
                    "process": {"name": "helper", "executable": "/Users/alice/bin/helper", "user": "alice",
                        "args": ["helper", "--token", "secret123"]},
                    "destination": {"ip": "8.8.4.4", "port": 443, "domain": "a.b.example.com"},
                    "kanmon": {"level": lv, "score": 40, "signals": [{"id": "R1", "description": "住宅用", "points": 25}]}
                });
                st.insert_event(&v, now - i as i64).unwrap();
            }
        }
        let sh = Shared::with_db(Snapshot::default(), Some(db.clone()));
        let out = respond(r#"{"cmd":"export","hours":24,"min_level":"notice","format":"jsonl"}"#, &sh);
        for leak in ["alice", "8.8.4.4", "secret123", "a.b.example"] {
            assert!(!out.contains(leak), "{leak} が残っている: {out}");
        }
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["count"], 2, "info は含めない");
        assert_eq!(v["jsonl"].as_str().unwrap().lines().count(), 2);
        assert!(v["markdown"].as_str().unwrap().contains("| R1 | 2 | 住宅用 |"));
        // 既定（集計だけ）はログを返さない
        let v: serde_json::Value =
            serde_json::from_str(&respond(r#"{"cmd":"export","min_level":"info"}"#, &sh)).unwrap();
        assert_eq!(v["count"], 3);
        assert!(v["jsonl"].is_null());
        assert_eq!(v["sample"].as_array().unwrap().len(), 3);
        // Swift 側と同じ形か（取り決めのフィクスチャ）
        let fx: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/status-export.json")).unwrap();
        for k in ["count", "truncated", "markdown", "sample", "jsonl"] {
            assert!(fx.get(k).is_some() && v.get(k).is_some(), "{k}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
