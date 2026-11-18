//! 監視ループ本体：スナップショット差分 → 識別 → 事実（facts）付与 → 検知ルール評価 → 保存・通知。

use crate::config::Config;
use crate::identity::{self, IdCache};
use crate::notify::{self, Message, Notifier};
use crate::procinfo::{basename, user_name, ProcCache};
use crate::sockets::{listen_ports, Collector, Proto, Sock, State};
use crate::status::{AlertItem, Shared, Snapshot};
use anyhow::{Context, Result};
use chrono::{Local, SecondsFormat, Utc};
use kanmon_core::detect::{DetectionSet, Reloader};
use kanmon_core::event::{self as ev, Event};
use kanmon_core::intel::Intel;
use kanmon_core::jsonl::JsonlWriter;
use kanmon_core::rules::RuleSet;
use kanmon_core::scoring::{self, Level};
use kanmon_core::store::{ProcRow, Store};
use kanmon_core::{beacon, netclass};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

type Key = (Proto, SocketAddr, Option<SocketAddr>, Option<u32>);

pub struct Monitor {
    cfg: Config,
    host: String,
    os: &'static str,
    collector: Collector,
    procs: ProcCache,
    ids: IdCache,
    store: Store,
    jsonl: JsonlWriter,
    dets: DetectionSet,
    reloader: Reloader,
    rules: RuleSet,
    rules_mtime: Option<SystemTime>,
    intel: Intel,
    intel_dirty: Arc<AtomicBool>,
    notifier: Notifier,
    prev: HashSet<Key>,
    first_tick: bool,
    counter: u32,
    installed_at: i64,
    beacon_reported: HashMap<(String, String), i64>,
    last_beacon: Instant,
    last_reload_check: Instant,
    last_prune: Instant,
    last_feed: Option<Instant>,
    last_heartbeat: Option<Instant>,
    self_pid: u32,
    shared: Arc<Shared>,
    last_counts: Instant,
    pub print: bool,
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    let r = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if r != 0 {
        return "unknown".into();
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

impl Monitor {
    pub fn new(cfg: Config) -> Result<Self> {
        std::fs::create_dir_all(&cfg.data_dir).with_context(|| format!("mkdir {}", cfg.data_dir.display()))?;
        let store = Store::open(&cfg.data_dir.join("kanmon.db"))?;
        let now = Utc::now().timestamp();
        let installed_at = match store.meta_get("installed_at")? {
            Some(v) => v.parse().unwrap_or(now),
            None => {
                store.meta_set("installed_at", &now.to_string())?;
                now
            }
        };
        let strict = cfg.strict_owner && is_root();
        let mut reloader = Reloader::new(cfg.detections_dir.clone(), strict);
        let dets = match reloader.check() {
            Some(Ok(d)) => d,
            Some(Err(e)) => return Err(e.context("検知ルールの読み込みに失敗")),
            None => DetectionSet::default(),
        };
        eprintln!("kanmond: 検知ルール {} 件を読み込み（{}）", dets.detections.len(), cfg.detections_dir.display());
        let rules = load_rules(&cfg, strict)?;
        let jsonl = JsonlWriter::open(&cfg.jsonl.path, cfg.jsonl.max_mb * 1024 * 1024, cfg.jsonl.keep)?;
        let intel = crate::feeds::load(&cfg);
        eprintln!("kanmond: 脅威インテル {} 件", intel.len());
        let host = cfg.host_name.clone().unwrap_or_else(hostname);
        let os = if cfg!(target_os = "macos") { "macos" } else { "linux" };
        let learning_until = (cfg.mode == "learning" && cfg.learning_days > 0)
            .then(|| chrono::DateTime::from_timestamp(installed_at + cfg.learning_days as i64 * 86_400, 0))
            .flatten()
            .map(|t| t.with_timezone(&Local).to_rfc3339_opts(SecondsFormat::Secs, false));
        let shared = Shared::new(Snapshot {
            version: env!("CARGO_PKG_VERSION").into(),
            host: host.clone(),
            os: os.into(),
            mode: cfg.mode.clone(),
            learning_until,
            started_at: Local::now().to_rfc3339_opts(SecondsFormat::Secs, false),
            detections: dets.detections.len(),
            intel: intel.len(),
            events_path: cfg.jsonl.path.display().to_string(),
            ..Default::default()
        });
        // 再起動しても直近の警告がメニューバーに出るよう、DB から読み戻す（新しい順）
        let since = Utc::now().timestamp() - 86_400;
        if let Ok(evs) = store.recent_events(since, &["notice", "warn", "critical"], crate::status::MAX_ALERTS as i64) {
            for v in evs.iter().rev() {
                let mut v = v.clone();
                ev::migrate_legacy(&mut v);
                if let Some(a) = alert_item_from_event(&v) {
                    shared.push_alert(a);
                }
            }
        }
        if !cfg.status_socket.is_empty() {
            match crate::status::serve(Path::new(&cfg.status_socket), shared.clone(), cfg.status_allowed_uids.clone()) {
                Ok(p) => eprintln!("kanmond: 状態ソケット {}", p.display()),
                Err(e) => eprintln!("kanmond: 状態ソケットを開けません（監視は継続）: {e:#}"),
            }
        }
        let notifier = Notifier::new(&cfg.notify, Some(shared.clone()));
        let rules_mtime = std::fs::metadata(&cfg.rules_file).and_then(|m| m.modified()).ok();
        Ok(Self {
            host,
            os,
            collector: Collector::new()?,
            procs: ProcCache::default(),
            ids: IdCache::default(),
            store,
            jsonl,
            dets,
            reloader,
            rules,
            rules_mtime,
            intel,
            intel_dirty: Arc::new(AtomicBool::new(false)),
            notifier,
            prev: HashSet::new(),
            first_tick: true,
            counter: 0,
            installed_at,
            beacon_reported: HashMap::new(),
            last_beacon: Instant::now(),
            last_reload_check: Instant::now(),
            last_prune: Instant::now() - Duration::from_secs(86_400),
            last_feed: None,
            last_heartbeat: None,
            self_pid: std::process::id(),
            shared,
            last_counts: Instant::now() - Duration::from_secs(3600),
            print: false,
            cfg,
        })
    }

    fn learning(&self) -> bool {
        if self.cfg.mode != "learning" {
            return false;
        }
        self.cfg.learning_days == 0
            || Utc::now().timestamp() - self.installed_at < self.cfg.learning_days as i64 * 86_400
    }

    fn min_notify_level(&self) -> Level {
        let m = self.notifier.min_level;
        if self.learning() {
            m.max(Level::Warn)
        } else {
            m
        }
    }

    pub fn run(&mut self) -> Result<()> {
        loop {
            if let Err(e) = self.tick() {
                eprintln!("kanmond: tick エラー: {e:#}");
            }
            self.housekeeping();
            std::thread::sleep(Duration::from_millis(self.cfg.interval_ms));
        }
    }

    pub fn tick(&mut self) -> Result<usize> {
        let socks = self.collector.snapshot()?;
        let listens = listen_ports(&socks);
        let mut cur = HashSet::with_capacity(socks.len());
        let mut n = 0;
        let initial = self.first_tick;
        for s in &socks {
            let k = s.key();
            if !self.prev.contains(&k) && self.handle_new(s, &listens, initial)? {
                n += 1;
            }
            cur.insert(k);
        }
        let alive: HashSet<u32> = socks.iter().filter_map(|s| s.pid).collect();
        self.procs.retain_alive(&alive);
        self.prev = cur;
        self.first_tick = false;
        Ok(n)
    }

    fn housekeeping(&mut self) {
        // 検知ルール・許可ルールのホットリロード（5 秒ごと）
        if self.last_reload_check.elapsed() > Duration::from_secs(5) {
            self.last_reload_check = Instant::now();
            if let Some(r) = self.reloader.check() {
                match r {
                    Ok(d) => {
                        eprintln!("kanmond: 検知ルールを再読込（{} 件）", d.detections.len());
                        let n = d.detections.len();
                        self.shared.update(|s| s.detections = n);
                        self.dets = d;
                    }
                    Err(e) => {
                        let msg = format!("検知ルールの再読込に失敗。前の設定を継続: {e:#}");
                        eprintln!("kanmond: {msg}");
                        self.notifier.send(
                            Message {
                                level: Level::Warn,
                                title: "kanmon: 検知ルールのエラー".into(),
                                body: msg,
                                dedup_key: "reload-error".into(),
                            },
                            Level::Info,
                        );
                    }
                }
            }
            let mt = std::fs::metadata(&self.cfg.rules_file).and_then(|m| m.modified()).ok();
            if mt != self.rules_mtime {
                self.rules_mtime = mt;
                match load_rules(&self.cfg, self.cfg.strict_owner && is_root()) {
                    Ok(r) => {
                        eprintln!("kanmond: 許可/拒否ルールを再読込（{} 件）", r.rules.len());
                        self.rules = r;
                    }
                    Err(e) => eprintln!("kanmond: rules 再読込失敗（前の設定を継続）: {e:#}"),
                }
            }
        }
        // フィード（起動時と 1 時間ごとに期限確認、取得は別スレッド）
        if self.last_feed.is_none_or(|t| t.elapsed() > Duration::from_secs(3600)) {
            self.last_feed = Some(Instant::now());
            let cfg = self.cfg.clone();
            let flag = self.intel_dirty.clone();
            std::thread::spawn(move || {
                crate::feeds::refresh(&cfg);
                flag.store(true, Ordering::SeqCst);
            });
        }
        if self.intel_dirty.swap(false, Ordering::SeqCst) {
            self.intel = crate::feeds::load(&self.cfg);
            eprintln!("kanmond: 脅威インテル {} 件", self.intel.len());
            let n = self.intel.len();
            self.shared.update(|s| s.intel = n);
        }
        // ビーコン（既定 5 分ごと）
        if self.last_beacon.elapsed() > Duration::from_secs(self.cfg.beacon_interval_s.max(5)) {
            self.last_beacon = Instant::now();
            if let Err(e) = self.beacon_batch() {
                eprintln!("kanmond: beacon エラー: {e:#}");
            }
        }
        // 死活監視
        let hb = &self.cfg.notify.heartbeat_url;
        if !hb.is_empty()
            && self
                .last_heartbeat
                .is_none_or(|t| t.elapsed() > Duration::from_secs(self.cfg.notify.heartbeat_minutes.max(1) * 60))
        {
            self.last_heartbeat = Some(Instant::now());
            let url = hb.clone();
            std::thread::spawn(move || notify::heartbeat(&url));
        }
        // 状態ソケット用の集計（1 分ごと）
        if self.last_counts.elapsed() > Duration::from_secs(60) {
            self.last_counts = Instant::now();
            let since = Utc::now().timestamp() - 86_400;
            let counts = self.store.level_counts(since).unwrap_or_default();
            let learning = self.learning();
            self.shared.update(|s| {
                s.counts_24h = counts.into_iter().collect();
                s.learning = learning;
            });
        }
        // 保持期間（1 日ごと）
        if self.last_prune.elapsed() > Duration::from_secs(86_400) {
            self.last_prune = Instant::now();
            let now = Utc::now().timestamp();
            let _ = self.store.prune(now - self.cfg.retention_days as i64 * 86_400, (now - 2 * 86_400) as f64);
        }
    }

    fn next_id(&mut self) -> String {
        self.counter = self.counter.wrapping_add(1);
        format!("e_{:x}{:04x}", Utc::now().timestamp_micros(), self.counter & 0xffff)
    }

    /// 新規ソケット 1 件を処理。記録したら true
    fn handle_new(&mut self, s: &Sock, listens: &HashMap<(Proto, u16), ()>, initial: bool) -> Result<bool> {
        let (kind, direction) = match (s.proto, s.state) {
            (Proto::Tcp, State::Listen) => ("listen", "inbound"),
            // UDP の未接続ソケットは一時ポートのものが大量にあるので、低いポートだけ「待受」とみなす
            (Proto::Udp, State::Unconnected) if s.local.port() != 0 && s.local.port() < 32768 => ("listen", "inbound"),
            (Proto::Tcp, State::Established) if listens.contains_key(&(Proto::Tcp, s.local.port())) => {
                ("accept", "inbound")
            }
            (Proto::Tcp, State::Established | State::SynSent) | (Proto::Udp, State::Established) => {
                ("connect", "outbound")
            }
            (Proto::Raw | Proto::Packet, _) => ("raw_socket", "none"),
            _ => return Ok(false),
        };
        if s.pid == Some(self.self_pid) {
            return Ok(false);
        }
        let remote_ip: Option<IpAddr> = s.remote.map(|r| r.ip());
        let scope = match kind {
            "listen" | "raw_socket" => {
                if s.local.ip().is_unspecified() {
                    "all".to_string()
                } else {
                    netclass::scope(&s.local.ip()).to_string()
                }
            }
            _ => remote_ip.map(|i| netclass::scope(&i).to_string()).unwrap_or_else(|| "unknown".into()),
        };
        if (kind == "connect" || kind == "accept") && scope == "loopback" && !self.cfg.include_loopback {
            return Ok(false);
        }

        let now = Utc::now();
        let now_s = now.timestamp();
        let learning = self.learning();
        let mut e = Event {
            timestamp: Local::now().to_rfc3339_opts(SecondsFormat::Millis, false),
            event: ev::EventMeta {
                id: self.next_id(),
                kind: "event".into(),
                action: format!("{}_{}", kind, if initial { "existing" } else { "observed" }),
                outcome: None,
            },
            host: ev::Host { name: self.host.clone(), os: self.os.into() },
            network: ev::Network {
                kind: kind.into(),
                direction: direction.into(),
                transport: s.proto.as_str().into(),
                scope: Some(scope.clone()),
            },
            source: Some(ev::Endpoint { ip: s.local.ip().to_string(), port: s.local.port() }),
            destination: s.remote.map(|r| ev::Destination {
                ip: Some(r.ip().to_string()),
                port: Some(r.port()),
                ..Default::default()
            }),
            ..Default::default()
        };
        e.kanmon.mode = if learning { "learning".into() } else { self.cfg.mode.clone() };
        e.kanmon.learning = learning;

        // ---- プロセス
        let mut proc_key = String::from("unknown");
        if let Some(pid) = s.pid {
            if let Some(p) = self.procs.get(pid) {
                let exe = p.exe.clone();
                let name = exe.as_deref().map(basename).or_else(|| p.args.first().map(|a| basename(a)));
                let read_path = if cfg!(target_os = "linux") {
                    format!("/proc/{pid}/exe")
                } else {
                    exe.clone().unwrap_or_default()
                };
                let id = if exe.is_some() {
                    self.ids.identify(&read_path, exe.as_deref().unwrap_or(""), p.exe_deleted || p.memfd)
                } else {
                    identity::Identity { status: "unknown".into(), ..Default::default() }
                };
                let script =
                    name.as_deref().and_then(|n| identity::interpreter_script(n, &p.args, &self.cfg.interpreters));
                let script_s = script.clone().flatten();
                proc_key = identity::proc_key(&id, exe.as_deref(), script_s.as_deref());
                let first = self.store.upsert_process(
                    &ProcRow {
                        proc_key: &proc_key,
                        executable: exe.as_deref(),
                        sha256: id.sha256.as_deref(),
                        sig_status: Some(&id.status),
                        team_id: id.team_id.as_deref(),
                        signing_id: id.signing_id.as_deref(),
                        package: id.package.as_deref(),
                    },
                    now_s,
                )?;
                let chain = self.procs.parent_chain(p.ppid, 6);
                let uid = p.uid.or(s.uid);
                e.process = ev::Process {
                    pid: Some(pid),
                    hidden: name.as_deref().is_some_and(|n| n.starts_with('.')),
                    name,
                    args: p.args.iter().take(16).map(|a| a.chars().take(512).collect()).collect(),
                    uid,
                    user: uid.and_then(user_name),
                    hash: id.sha256.clone().map(|h| ev::Hash { sha256: h }),
                    code_signature: Some(ev::CodeSignature {
                        status: id.status.clone(),
                        team_id: id.team_id.clone(),
                        signing_id: id.signing_id.clone(),
                        package: id.package.clone(),
                    }),
                    parent: chain.first().map(|(ppid, exe, _)| ev::Parent {
                        pid: *ppid,
                        name: exe.as_deref().map(basename),
                        executable: exe.clone(),
                    }),
                    parent_chain: chain_names(&chain, &self.cfg.interpreters),
                    exe_deleted: p.exe_deleted,
                    memfd: p.memfd,
                    interpreter: script.is_some(),
                    script: script_s,
                    proc_key: Some(proc_key.clone()),
                    first_seen: chrono::DateTime::from_timestamp(first, 0)
                        .map(|t| t.with_timezone(&Local).to_rfc3339_opts(SecondsFormat::Secs, false)),
                    first_seen_age_s: Some(now_s - first),
                    file_age_s: id.file_age_s,
                    executable: exe,
                };
            }
        } else {
            e.process.uid = s.uid;
            e.process.user = s.uid.and_then(user_name);
        }

        // ---- 事実（facts）
        if let Some(ip) = remote_ip {
            if let Some(src) = self.intel.lookup_ip(&ip) {
                e.kanmon.ti_match = true;
                e.kanmon.ti_source = Some(src.to_string());
            }
        }
        let dest_key = netclass::dest_key(None, remote_ip.as_ref());
        e.kanmon.dest_key = dest_key.clone();
        match kind {
            "connect" => {
                if let Some(dk) = &dest_key {
                    let first_dest = self.store.baseline_touch(&proc_key, dk, "dest", now_s)?;
                    let port = s.remote.map(|r| r.port()).unwrap_or(0).to_string();
                    let first_port = self.store.baseline_touch(&proc_key, &port, "port", now_s)?;
                    e.kanmon.dest_first_for_process = first_dest && !learning && !initial;
                    e.kanmon.port_first_for_process = first_port && !learning && !initial;
                    if scope != "loopback" {
                        let ts = now.timestamp_millis() as f64 / 1000.0;
                        self.store.conn_start(&proc_key, dk, ts, None)?;
                    }
                }
            }
            "listen" => {
                let item = format!("{}/{}/{}", s.proto.as_str(), s.local.port(), scope);
                let first = self.store.baseline_touch(&proc_key, &item, "listen", now_s)?;
                e.kanmon.listen_new = first && !learning && !initial;
            }
            _ => {}
        }

        // ---- 評価・保存・通知
        let mut v = serde_json::to_value(&e)?;
        let out = scoring::apply(&mut v, &self.dets, &self.rules, &self.cfg.thresholds);
        self.store.insert_event(&v, now_s)?;
        self.jsonl.write(&v)?;
        if self.print {
            println!("{}", serde_json::to_string(&v)?);
        }
        let sig_ids: Vec<&str> = out.signals.iter().map(|s| s.id.as_str()).collect();
        let (title, body) = kanmon_core::format::alert_text(&v);
        self.record_alert(&v, out.level, out.score, kind, &title, &body);
        let min = self.min_notify_level();
        self.notifier.send(
            Message { level: out.level, title, body, dedup_key: format!("{proc_key}|{kind}|{}", sig_ids.join(",")) },
            min,
        );
        Ok(true)
    }

    /// 状態ソケットに出す直近の警告（notice 以上）と最終イベント時刻を更新（ライブ）
    fn record_alert(&self, v: &serde_json::Value, level: Level, score: i32, kind: &str, title: &str, body: &str) {
        let ts = v.get("@timestamp").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let tsc = ts.clone();
        self.shared.update(|s| s.last_event_at = Some(tsc));
        if level < Level::Notice {
            return;
        }
        let id = ev::get_path(v, "event.id").and_then(|x| x.as_str()).unwrap_or("").to_string();
        self.shared.push_alert(AlertItem {
            id,
            ts,
            level: level.as_str().into(),
            score,
            kind: kind.into(),
            title: title.into(),
            body: body.into(),
        });
    }

    /// 直近 24h の接続開始時刻からビーコン候補を出す（判定経路には載せない）
    pub fn beacon_batch(&mut self) -> Result<usize> {
        let now = Utc::now().timestamp();
        let series = self.store.conn_series((now - 86_400) as f64)?;
        let window = ((now - self.installed_at).clamp(3600, 86_400)) as f64;
        let mut n = 0;
        for ((pk, dk), ts) in series {
            let Some(bs) = beacon::score(&ts, None, window) else { continue };
            if bs.score < self.cfg.beacon_report_min {
                continue;
            }
            let key = (pk.clone(), dk.clone());
            if self.beacon_reported.get(&key).is_some_and(|t| now - *t < 6 * 3600)
                || self.store.beacon_reported_since(&pk, &dk, now - 6 * 3600).unwrap_or(false)
            {
                continue;
            }
            self.beacon_reported.insert(key, now);
            let (exe, status) = self.store.process_info(&pk)?.unwrap_or((None, None));
            let mut e = Event {
                timestamp: Local::now().to_rfc3339_opts(SecondsFormat::Millis, false),
                event: ev::EventMeta {
                    id: self.next_id(),
                    kind: "alert".into(),
                    action: "beacon_report".into(),
                    outcome: None,
                },
                host: ev::Host { name: self.host.clone(), os: self.os.into() },
                network: ev::Network {
                    kind: "beacon_report".into(),
                    direction: "outbound".into(),
                    transport: "any".into(),
                    scope: None,
                },
                destination: Some(ev::Destination {
                    domain: (!dk.contains('/')).then(|| dk.clone()),
                    ..Default::default()
                }),
                ..Default::default()
            };
            e.process.name = exe.as_deref().map(basename);
            e.process.executable = exe.clone();
            e.process.proc_key = Some(pk.clone());
            e.process.code_signature = status.map(|s| ev::CodeSignature { status: s, ..Default::default() });
            e.kanmon.mode = self.cfg.mode.clone();
            e.kanmon.learning = self.learning();
            e.kanmon.dest_key = Some(dk.clone());
            e.kanmon.beacon = Some(bs.clone());
            let mut v = serde_json::to_value(&e)?;
            let out = scoring::apply(&mut v, &self.dets, &self.rules, &self.cfg.thresholds);
            self.store.insert_event(&v, now)?;
            self.jsonl.write(&v)?;
            if self.print {
                println!("{}", serde_json::to_string(&v)?);
            }
            let (title, body) = kanmon_core::format::alert_text(&v);
            self.record_alert(&v, out.level, out.score, "beacon_report", &title, &body);
            let min = self.min_notify_level();
            self.notifier.send(Message { level: out.level, title, body, dedup_key: format!("beacon|{pk}|{dk}") }, min);
            n += 1;
        }
        Ok(n)
    }
}

/// 保存済みイベントから状態ソケット用の警告を作る（DB からの読み戻し用）
fn alert_item_from_event(v: &serde_json::Value) -> Option<AlertItem> {
    let s = |p: &str| ev::get_path(v, p).and_then(|x| x.as_str()).map(str::to_string);
    let level = s("kanmon.level")?;
    let (title, body) = kanmon_core::format::alert_text(v);
    Some(AlertItem {
        id: s("event.id")?,
        ts: s("@timestamp").unwrap_or_default(),
        score: ev::get_path(v, "kanmon.score").and_then(|x| x.as_i64()).unwrap_or(0) as i32,
        kind: s("network.kind").unwrap_or_default(),
        level,
        title,
        body,
    })
}

/// 親プロセス列の名前。インタプリタ（node・python・bash 等）の場合はスクリプト名も加える。
/// 例：`node /usr/lib/node_modules/npm/bin/npm-cli.js install` → ["node", "npm-cli.js"]
pub fn chain_names(chain: &[(u32, Option<String>, Vec<String>)], interpreters: &[String]) -> Vec<String> {
    let mut out = vec![];
    for (_, exe, args) in chain {
        let Some(name) = exe.as_deref().map(basename) else { continue };
        let script = identity::interpreter_script(&name, args, interpreters).flatten();
        out.push(name);
        match script {
            // python -m pip install … → "pip"
            Some(s) if s.starts_with("module:") => out.push(s["module:".len()..].to_string()),
            Some(s) if !s.starts_with('<') => out.push(basename(&s)),
            _ => {}
        }
    }
    out
}

fn load_rules(cfg: &Config, strict: bool) -> Result<RuleSet> {
    if strict && cfg.rules_file.exists() {
        kanmon_core::detect::check_owner(&cfg.rules_file)?;
    }
    RuleSet::load(&cfg.rules_file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_names_include_scripts() {
        let interp: Vec<String> = ["node", "python", "bash"].iter().map(|s| s.to_string()).collect();
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let chain = vec![
            (
                10,
                Some("/usr/bin/node".to_string()),
                a(&["node", "/usr/lib/node_modules/npm/bin/npm-cli.js", "install"]),
            ),
            (9, Some("/usr/bin/python3.12".to_string()), a(&["python3", "-m", "pip", "install", "x"])),
            (8, Some("/usr/bin/bash".to_string()), a(&["bash", "/usr/bin/makepkg", "-si"])),
            (7, Some("/usr/bin/zsh".to_string()), a(&["-zsh"])),
            (1, None, vec![]),
        ];
        assert_eq!(
            chain_names(&chain, &interp),
            vec!["node", "npm-cli.js", "python3.12", "pip", "bash", "makepkg", "zsh"]
        );
    }
}
