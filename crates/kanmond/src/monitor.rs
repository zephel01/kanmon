//! 監視ループ本体：スナップショット差分 → 識別 → 事実（facts）付与 → 検知ルール評価 → 保存・通知。

use crate::capture::Obs;
use crate::config::Config;
use crate::identity::{self, IdCache};
use crate::notify::{self, Message, Notifier};
use crate::procinfo::{basename, user_name, ProcCache};
use crate::sockets::{listen_ports, Collector, Proto, Sock, State};
use crate::status::{AlertItem, Shared, Snapshot};
use anyhow::{Context, Result};
use chrono::{Local, SecondsFormat, Utc};
use kanmon_core::detect::{DetectionSet, Reloader};
use kanmon_core::dnsguard::{self, ConflictTracker};
use kanmon_core::event::{self as ev, Event};
use kanmon_core::intel::Intel;
use kanmon_core::jsonl::JsonlWriter;
use kanmon_core::names::NameCache;
use kanmon_core::rules::RuleSet;
use kanmon_core::scoring::{self, Level};
use kanmon_core::store::{ProcRow, Store};
use kanmon_core::{beacon, netclass};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
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
    // ---- 宛先の名前付けと DNS の改ざん検知
    names: NameCache,
    obs_rx: Option<Receiver<Obs>>,
    conflicts: ConflictTracker,
    known_resolvers: Vec<std::net::IpAddr>,
    last_dns_check: Option<Instant>,
    doh_tx: Sender<DohResult>,
    doh_rx: Receiver<DohResult>,
    /// ドメイン → （最後に DoH で引いた時刻, DoH で見た IP の履歴）
    doh_state: HashMap<String, (Instant, Vec<std::net::IpAddr>)>,
    doh_inflight: HashSet<String>,
    doh_fail_logged: Option<Instant>,
    /// 同じ検知を何度も出さないための最終発報時刻
    dns_emitted: HashMap<String, i64>,
    // ---- 送信量
    volume: kanmon_core::volume::VolumeTracker,
    last_volume: Option<Instant>,
    pub print: bool,
}

/// （ドメイン, 受け身で見た答え, DoH と証明書の確認結果）
type DohResult = (String, Vec<std::net::IpAddr>, std::result::Result<crate::dnswatch::Crosscheck, String>);

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
        logln!("検知ルール {} 件を読み込み（{}）", dets.detections.len(), cfg.detections_dir.display());
        let rules = load_rules(&cfg, strict)?;
        let jsonl = if cfg.jsonl.rotate == "daily" {
            JsonlWriter::open_daily(&cfg.jsonl.path, cfg.jsonl.max_mb * 1024 * 1024, cfg.jsonl.keep_days)?
        } else {
            JsonlWriter::open(&cfg.jsonl.path, cfg.jsonl.max_mb * 1024 * 1024, cfg.jsonl.keep)?
        };
        let intel = crate::feeds::load(&cfg);
        logln!("脅威インテル {} 件", intel.len());
        let host = cfg.host_name.clone().unwrap_or_else(hostname);
        let os = if cfg!(target_os = "macos") { "macos" } else { "linux" };
        let learning_until = (cfg.mode == "learning" && cfg.learning_days > 0)
            .then(|| chrono::DateTime::from_timestamp(installed_at + cfg.learning_days as i64 * 86_400, 0))
            .flatten()
            .map(|t| t.with_timezone(&Local).to_rfc3339_opts(SecondsFormat::Secs, false));
        let shared = Shared::with_db(
            Snapshot {
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
            },
            Some(cfg.data_dir.join("kanmon.db")),
        );
        // 再起動しても直近の警告がメニューバーに出るよう、DB から読み戻す（新しい順）
        let since = Utc::now().timestamp() - 86_400;
        if let Ok(evs) = store.recent_events(since, &["notice", "warn", "critical"], crate::status::MAX_ALERTS as i64) {
            for v in evs.iter().rev() {
                let mut v = v.clone();
                ev::migrate_legacy(&mut v);
                if let Some(a) = crate::status::alert_item_from_event(&v) {
                    shared.push_alert(a);
                }
            }
        }
        if !cfg.status_socket.is_empty() {
            match crate::status::serve(Path::new(&cfg.status_socket), shared.clone(), cfg.status_allowed_uids.clone()) {
                Ok(p) => logln!("状態ソケット {}", p.display()),
                Err(e) => logln!("状態ソケットを開けません（監視は継続）: {e:#}"),
            }
        }
        let notifier = Notifier::new(&cfg.notify, Some(shared.clone()));
        let rules_mtime = std::fs::metadata(&cfg.rules_file).and_then(|m| m.modified()).ok();
        let obs_rx = if cfg.dns.enabled {
            let (tx, rx) = std::sync::mpsc::sync_channel(10_000);
            let devs = crate::capture::start(cfg.dns.interfaces.clone(), tx);
            if devs.is_empty() {
                logln!("DNS・SNI の観測を開始できませんでした（宛先は IP のみ）");
            } else {
                logln!("DNS・SNI の観測: {}", devs.join(", "));
            }
            Some(rx)
        } else {
            None
        };
        let known_resolvers = crate::dnswatch::read_resolvers(&cfg.dns.resolv_conf);
        let (doh_tx, doh_rx) = std::sync::mpsc::channel();
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
            names: NameCache::default(),
            obs_rx,
            conflicts: ConflictTracker::default(),
            known_resolvers,
            last_dns_check: None,
            doh_tx,
            doh_rx,
            doh_state: HashMap::new(),
            doh_inflight: HashSet::new(),
            doh_fail_logged: None,
            dns_emitted: HashMap::new(),
            volume: Default::default(),
            last_volume: None,
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
                logln!("tick エラー: {e:#}");
            }
            self.housekeeping();
            std::thread::sleep(Duration::from_millis(self.cfg.interval_ms));
        }
    }

    pub fn tick(&mut self) -> Result<usize> {
        // 先に DNS・SNI の観測を取り込んでから、新しい接続に名前を付ける
        self.drain_obs();
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
        if self.cfg.volume.enabled
            && self.last_volume.is_none_or(|t| t.elapsed() >= Duration::from_secs(self.cfg.volume.interval_s.max(1)))
        {
            self.last_volume = Some(Instant::now());
            if let Err(e) = self.volume_tick(&socks) {
                crate::logln!("送信量の集計エラー: {e:#}");
            }
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
                        logln!("検知ルールを再読込（{} 件）", d.detections.len());
                        let n = d.detections.len();
                        self.shared.update(|s| s.detections = n);
                        self.dets = d;
                    }
                    Err(e) => {
                        let msg = format!("検知ルールの再読込に失敗。前の設定を継続: {e:#}");
                        logln!("{msg}");
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
                        logln!("許可/拒否ルールを再読込（{} 件）", r.rules.len());
                        self.rules = r;
                    }
                    Err(e) => logln!("rules 再読込失敗（前の設定を継続）: {e:#}"),
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
            logln!("脅威インテル {} 件", self.intel.len());
            let n = self.intel.len();
            self.shared.update(|s| s.intel = n);
        }
        // ビーコン（既定 5 分ごと）
        if self.last_beacon.elapsed() > Duration::from_secs(self.cfg.beacon_interval_s.max(5)) {
            self.last_beacon = Instant::now();
            if let Err(e) = self.beacon_batch() {
                logln!("beacon エラー: {e:#}");
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
        // DNS の改ざん検知（hosts・DNS サーバー設定、DoH の結果）
        if self.cfg.dns.enabled {
            if self
                .last_dns_check
                .is_none_or(|t| t.elapsed() > Duration::from_secs(self.cfg.dns.check_interval_s.max(5)))
            {
                self.last_dns_check = Some(Instant::now());
                self.dns_check();
            }
            self.drain_doh();
        }
        // 状態ソケット用の集計（1 分ごと）
        if self.last_counts.elapsed() > Duration::from_secs(60) {
            self.last_counts = Instant::now();
            self.names.prune(Utc::now().timestamp());
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
        // 宛先の名前（DNS 応答・SNI から）
        if let (Some(r), Some(d)) = (s.remote, e.destination.as_mut()) {
            if let Some(n) = self.names.lookup(Some(s.local), r, now_s) {
                d.domain = Some(n.name);
                d.domain_source = Some(n.source.into());
            }
        }

        // ---- プロセス
        let mut proc_key = String::from("unknown");
        if let Some(pid) = s.pid {
            if let Some((p, k)) = self.process_info(pid, s.uid, now_s)? {
                e.process = p;
                proc_key = k;
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
        if !e.kanmon.ti_match {
            let dom = e.destination.as_ref().and_then(|d| d.domain.clone());
            if let Some(src) = dom.as_deref().and_then(|d| self.intel.lookup_domain(d)) {
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

    /// 接続ごとの累積送信量を取り込み、窓の合計が大きいもの（プロセス × 宛先）を報告する
    fn volume_tick(&mut self, socks: &[Sock]) -> Result<()> {
        let inode_pid: HashMap<u64, u32> =
            socks.iter().filter(|s| s.inode != 0).filter_map(|s| s.pid.map(|p| (s.inode, p))).collect();
        let flows: Vec<kanmon_core::volume::FlowBytes> = crate::volume::collect(&inode_pid)
            .into_iter()
            .filter(|f| {
                // LAN（NAS へのバックアップ・AirDrop 等）は数えない。ループバックは include_loopback のときだけ
                let sc = netclass::scope(&f.remote.ip());
                f.pid != self.self_pid && (sc == "internet" || (self.cfg.include_loopback && sc == "loopback"))
            })
            .collect();
        let now = Utc::now().timestamp();
        let v = &self.cfg.volume;
        let (window, min, every) = (v.window_s as i64, v.min_report_kb * 1024, v.report_every_min as i64 * 60);
        self.volume.update(&flows, now, window);
        for d in self.volume.due(now, min, every) {
            self.emit_bytes(&d, now)?;
        }
        Ok(())
    }

    fn emit_bytes(&mut self, d: &kanmon_core::volume::Due, now_s: i64) -> Result<()> {
        let learning = self.learning();
        let scope = netclass::scope(&d.remote).to_string();
        let named = self.names.lookup(None, std::net::SocketAddr::new(d.remote, 0), now_s);
        let mut e = Event {
            timestamp: Local::now().to_rfc3339_opts(SecondsFormat::Millis, false),
            event: ev::EventMeta {
                id: self.next_id(),
                kind: "alert".into(),
                action: "bytes_report".into(),
                outcome: None,
            },
            host: ev::Host { name: self.host.clone(), os: self.os.into() },
            network: ev::Network {
                kind: "bytes_report".into(),
                direction: "outbound".into(),
                transport: "tcp".into(),
                scope: Some(scope),
            },
            destination: Some(ev::Destination {
                ip: Some(d.remote.to_string()),
                domain: named.as_ref().map(|n| n.name.clone()),
                domain_source: named.as_ref().map(|n| n.source.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        e.kanmon.mode = if learning { "learning".into() } else { self.cfg.mode.clone() };
        e.kanmon.learning = learning;
        let mut proc_key = format!("pid:{}", d.pid);
        if let Some((p, k)) = self.process_info(d.pid, None, now_s)? {
            e.process = p;
            proc_key = k;
        } else {
            e.process.pid = Some(d.pid);
        }
        let files = crate::volume::open_files(d.pid);
        let sum = kanmon_core::volume::summarize_open(&files);
        e.kanmon.bytes = Some(ev::BytesFacts {
            out: d.bytes,
            window_s: self.cfg.volume.window_s,
            open_size: sum.total_size,
            out_per_open: (sum.total_size > 0).then(|| d.bytes as f64 / sum.total_size as f64),
            open_paths: sum.paths,
            open_exts: sum.exts,
            open_top: sum.top,
        });
        if let Some(src) = self.intel.lookup_ip(&d.remote) {
            e.kanmon.ti_match = true;
            e.kanmon.ti_source = Some(src.to_string());
        }
        let mut v = serde_json::to_value(&e)?;
        let out = scoring::apply(&mut v, &self.dets, &self.rules, &self.cfg.thresholds);
        self.store.insert_event(&v, now_s)?;
        self.jsonl.write(&v)?;
        if self.print {
            println!("{}", serde_json::to_string(&v)?);
        }
        let (title, body) = kanmon_core::format::alert_text(&v);
        self.record_alert(&v, out.level, out.score, "bytes_report", &title, &body);
        let min = self.min_notify_level();
        self.notifier
            .send(Message { level: out.level, title, body, dedup_key: format!("bytes|{proc_key}|{}", d.remote) }, min);
        Ok(())
    }

    /// pid のプロセス情報（識別・署名・親の列）を集める。`proc_key` も返す。
    /// 接続イベントと送信量の報告で共通に使う
    fn process_info(
        &mut self,
        pid: u32,
        fallback_uid: Option<u32>,
        now_s: i64,
    ) -> Result<Option<(ev::Process, String)>> {
        if let Some(p) = self.procs.get(pid) {
            let exe = p.exe.clone();
            let name = exe.as_deref().map(basename).or_else(|| p.args.first().map(|a| basename(a)));
            let read_path =
                if cfg!(target_os = "linux") { format!("/proc/{pid}/exe") } else { exe.clone().unwrap_or_default() };
            let id = if exe.is_some() {
                self.ids.identify(&read_path, exe.as_deref().unwrap_or(""), p.exe_deleted || p.memfd)
            } else {
                identity::Identity { status: "unknown".into(), ..Default::default() }
            };
            let script = name.as_deref().and_then(|n| identity::interpreter_script(n, &p.args, &self.cfg.interpreters));
            let script_s = script.clone().flatten();
            let proc_key = identity::proc_key(&id, exe.as_deref(), script_s.as_deref());
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
            let uid = p.uid.or(fallback_uid);
            let process = ev::Process {
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
            return Ok(Some((process, proc_key)));
        }
        Ok(None)
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
            rules: crate::status::signal_ids(v),
        });
    }

    /// キャプチャスレッドからの観測を取り込む
    fn drain_obs(&mut self) {
        let mut items = vec![];
        if let Some(rx) = &self.obs_rx {
            while let Ok(o) = rx.try_recv() {
                items.push(o);
                if items.len() >= 20_000 {
                    break;
                }
            }
        }
        let now = Utc::now().timestamp();
        for o in items {
            match o {
                Obs::Sni { local, remote, hello } => {
                    if let Some(n) = hello.sni {
                        self.names.insert_sni(local, remote, &n, now);
                    }
                }
                Obs::Dns { server, client, client_port, msg } => self.on_dns(server, client, client_port, &msg, now),
            }
        }
    }

    fn on_dns(
        &mut self,
        server: IpAddr,
        client: IpAddr,
        client_port: u16,
        msg: &kanmon_core::wire::DnsMessage,
        now: i64,
    ) {
        let Some(q) = msg.qname.clone() else { return };
        if msg.rcode != 0 {
            return;
        }
        let ips = msg.addresses();
        if ips.is_empty() {
            return;
        }
        let ttl = msg.min_ttl().unwrap_or(60);
        for ip in &ips {
            self.names.insert_dns(*ip, &q, ttl, now);
        }
        let watched = dnsguard::watched(&q, &self.cfg.dns.watch_domains);
        // N5：同じ問い合わせに中身の違う応答
        if let Some((prev, cur)) = self.conflicts.observe(server, client, client_port, msg.id, &q, &ips, now) {
            let facts = ev::DnsFacts {
                finding: "conflicting_answer".into(),
                watched,
                server: Some(server.to_string()),
                other: prev.iter().map(|x| x.to_string()).collect(),
                ..Default::default()
            };
            self.emit_dns(facts, Some(q.clone()), &cur, None, format!("conflict|{q}"));
        }
        // N4：公開ドメインがローカルの IP に解決
        let local_ips = dnsguard::private_answers(&q, &ips, &self.cfg.dns.private_ok_suffixes);
        if !local_ips.is_empty() {
            let facts = ev::DnsFacts {
                finding: "private_answer".into(),
                watched,
                server: Some(server.to_string()),
                ..Default::default()
            };
            self.emit_dns(facts, Some(q.clone()), &local_ips, None, format!("private|{q}"));
        }
        // N6：設定にない DNS サーバーからの応答
        if dnsguard::unexpected_resolver(&server, &self.known_resolvers) {
            let facts = ev::DnsFacts {
                finding: "unexpected_resolver".into(),
                watched,
                unknown_public: !dnsguard::known_public(&server),
                server: Some(server.to_string()),
                ..Default::default()
            };
            self.emit_dns(facts, Some(q.clone()), &ips, None, format!("resolver|{server}"));
        }
        // N3：監視リストのドメインは DoH で引き直して照合
        if watched && self.cfg.dns.crosscheck {
            self.schedule_doh(q, ips);
        }
    }

    fn schedule_doh(&mut self, name: String, passive: Vec<IpAddr>) {
        if self.doh_inflight.contains(&name) || self.doh_inflight.len() >= 4 {
            return;
        }
        if let Some((t, hist)) = self.doh_state.get(&name) {
            let recent = t.elapsed() < Duration::from_secs(self.cfg.dns.crosscheck_interval_min.max(1) * 60);
            // 間隔内で、これまでの DoH の答えと食い違わなければ引き直さない
            if recent && !dnsguard::crosscheck_mismatch(&passive, hist, &[]) {
                return;
            }
            if t.elapsed() < Duration::from_secs(60) {
                return;
            }
        }
        self.doh_inflight.insert(name.clone());
        let url = self.cfg.dns.doh_url.clone();
        let tx = self.doh_tx.clone();
        let hist = self.doh_state.get(&name).map(|(_, h)| h.clone()).unwrap_or_default();
        let spawned = std::thread::Builder::new().name("kanmon-doh".into()).spawn(move || {
            let r = crate::dnswatch::crosscheck(&url, &name, &passive, &hist).map_err(|e| format!("{e:#}"));
            let _ = tx.send((name, passive, r));
        });
        if spawned.is_err() {
            logln!("DoH のスレッドを作れません");
        }
    }

    fn drain_doh(&mut self) {
        let mut done = vec![];
        while let Ok(r) = self.doh_rx.try_recv() {
            done.push(r);
        }
        for (name, passive, res) in done {
            self.doh_inflight.remove(&name);
            match res {
                Ok(cc) => {
                    let hist = self.doh_state.get(&name).map(|(_, h)| h.clone()).unwrap_or_default();
                    let doh = cc.doh.clone();
                    let mut h = hist;
                    // 正しい証明書を出した答えの IP も、以後は同じものとみなす（CDN の地域差）
                    for (ip, v) in &cc.tls {
                        if *v == crate::dnswatch::TlsVerdict::Valid && !h.contains(ip) {
                            h.push(*ip);
                        }
                    }
                    for ip in &doh {
                        if !h.contains(ip) {
                            h.push(*ip);
                        }
                    }
                    let keep = h.len().saturating_sub(64);
                    h.drain(..keep);
                    self.doh_state.insert(name.clone(), (Instant::now(), h));
                    // DoH と食い違うだけでは知らせない（CDN は問い合わせ元で答えが変わる）。
                    // 答えの IP が、そのドメインの正しい証明書を出さないときだけ知らせる
                    if cc.tampered() {
                        use crate::dnswatch::TlsVerdict;
                        let tls = cc
                            .tls
                            .iter()
                            .map(|(ip, v)| match v {
                                TlsVerdict::Valid => format!("{ip}: 正しい証明書"),
                                TlsVerdict::Invalid(e) => format!("{ip}: 証明書の検証に失敗（{e}）"),
                                TlsVerdict::Inconclusive(e) => format!("{ip}: 確認できない（{e}）"),
                            })
                            .collect();
                        let facts = ev::DnsFacts {
                            finding: "crosscheck_mismatch".into(),
                            watched: true,
                            other: doh.iter().map(|x| x.to_string()).collect(),
                            tls,
                            ..Default::default()
                        };
                        self.emit_dns(facts, Some(name.clone()), &passive, None, format!("crosscheck|{name}"));
                    }
                }
                Err(e) => {
                    if self.doh_fail_logged.is_none_or(|t| t.elapsed() > Duration::from_secs(3600)) {
                        self.doh_fail_logged = Some(Instant::now());
                        logln!("DoH での照合に失敗（{name}）: {e}");
                    }
                }
            }
        }
    }

    /// hosts と DNS サーバー設定を前回と比べる（N1・N2）
    fn dns_check(&mut self) {
        let watch = self.cfg.dns.watch_domains.clone();
        // ---- N1 hosts
        let path = self.cfg.dns.hosts_path.clone();
        if let Ok(text) = std::fs::read(&path) {
            let text = String::from_utf8_lossy(&text[..text.len().min(1 << 20)]).into_owned();
            let old = self.store.meta_get("dns.hosts").ok().flatten();
            let r = dnsguard::hosts_check(old.as_deref(), &text, &watch);
            let first = old.is_none();
            let (added, redirected) = if first {
                // 初回：前の内容が無いので、監視リストのドメインを他所へ向けている行だけを知らせる
                (r.redirected.clone(), !r.redirected.is_empty())
            } else {
                let red = r.added.iter().any(|l| r.redirected.contains(l));
                (r.added.clone(), red)
            };
            if (first && redirected) || (!first && r.changed()) {
                let watched = added
                    .iter()
                    .chain(r.removed.iter())
                    .any(|l| l.split_whitespace().nth(1).is_some_and(|n| dnsguard::watched(n, &watch)));
                let facts = ev::DnsFacts {
                    finding: "hosts_changed".into(),
                    watched,
                    redirected,
                    added,
                    removed: if first { vec![] } else { r.removed.clone() },
                    ..Default::default()
                };
                let key = format!("hosts|{}", text.len());
                self.emit_dns(facts, None, &[], Some(path.display().to_string()), key);
            }
            if first || r.changed() {
                let _ = self.store.meta_set("dns.hosts", &text);
            }
        }
        // ---- N2 DNS サーバー設定
        let new = crate::dnswatch::read_resolvers(&self.cfg.dns.resolv_conf);
        let old_s = self.store.meta_get("dns.resolvers").ok().flatten();
        let new_s = new.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",");
        if let Some(old_s) = &old_s {
            let old: Vec<IpAddr> = old_s.split(',').filter_map(|x| x.parse().ok()).collect();
            if let Some(c) = dnsguard::resolver_change(&old, &new) {
                let facts = ev::DnsFacts {
                    finding: "resolver_changed".into(),
                    added: c.added.iter().map(|x| x.to_string()).collect(),
                    removed: c.removed.iter().map(|x| x.to_string()).collect(),
                    added_scope: Some(c.added_scope.into()),
                    unknown_public: !c.unknown_public.is_empty(),
                    ..Default::default()
                };
                self.emit_dns(facts, None, &[], None, format!("resolvers|{new_s}"));
            }
        }
        if old_s.as_deref() != Some(new_s.as_str()) {
            let _ = self.store.meta_set("dns.resolvers", &new_s);
        }
        // 一度でも設定に出た DNS サーバーは覚えておく（IPv6 の RA で配られる ISP の DNS 等が、
        // 一覧から外れた後に応答しても「設定にない」としないため）
        let mut seen: Vec<IpAddr> = self
            .store
            .meta_get("dns.resolvers_seen")
            .ok()
            .flatten()
            .map(|s| s.split(',').filter_map(|x| x.parse().ok()).collect())
            .unwrap_or_default();
        let before = seen.len();
        for ip in &new {
            if !seen.contains(ip) {
                seen.push(ip.to_owned());
            }
        }
        let keep = seen.len().saturating_sub(64);
        seen.drain(..keep);
        if seen.len() != before || keep > 0 {
            let s = seen.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",");
            let _ = self.store.meta_set("dns.resolvers_seen", &s);
        }
        let mut known = seen;
        for ip in new {
            if !known.contains(&ip) {
                known.push(ip);
            }
        }
        self.known_resolvers = known;
    }

    /// DNS の改ざん検知イベントを作って評価・保存・通知する（同じ内容は 1 時間に 1 回）
    fn emit_dns(
        &mut self,
        facts: ev::DnsFacts,
        question: Option<String>,
        resolved: &[IpAddr],
        file: Option<String>,
        dedup: String,
    ) {
        let now = Utc::now().timestamp();
        if self.dns_emitted.get(&dedup).is_some_and(|t| now - *t < 3600) {
            return;
        }
        if self.dns_emitted.len() > 10_000 {
            self.dns_emitted.retain(|_, t| now - *t < 3600);
        }
        self.dns_emitted.insert(dedup.clone(), now);
        let learning = self.learning();
        let mut e = Event {
            timestamp: Local::now().to_rfc3339_opts(SecondsFormat::Millis, false),
            event: ev::EventMeta {
                id: self.next_id(),
                kind: "alert".into(),
                action: facts.finding.clone(),
                outcome: None,
            },
            host: ev::Host { name: self.host.clone(), os: self.os.into() },
            network: ev::Network {
                kind: "dns_integrity".into(),
                direction: "none".into(),
                transport: "dns".into(),
                scope: None,
            },
            dns: (question.is_some() || !resolved.is_empty()).then(|| ev::Dns {
                question: question.map(|name| ev::DnsQuestion { name }),
                resolved_ip: resolved.iter().map(|x| x.to_string()).collect(),
            }),
            file: file.map(|path| ev::File { path }),
            ..Default::default()
        };
        e.kanmon.mode = if learning { "learning".into() } else { self.cfg.mode.clone() };
        e.kanmon.learning = learning;
        e.kanmon.dns = Some(facts);
        let Ok(mut v) = serde_json::to_value(&e) else { return };
        let out = scoring::apply(&mut v, &self.dets, &self.rules, &self.cfg.thresholds);
        if let Err(err) = self.store.insert_event(&v, now).and_then(|_| self.jsonl.write(&v)) {
            logln!("DNS 検知イベントの保存に失敗: {err:#}");
        }
        if self.print {
            println!("{}", serde_json::to_string(&v).unwrap_or_default());
        }
        let (title, body) = kanmon_core::format::alert_text(&v);
        self.record_alert(&v, out.level, out.score, "dns_integrity", &title, &body);
        let min = self.min_notify_level();
        self.notifier.send(Message { level: out.level, title, body, dedup_key: format!("dns|{dedup}") }, min);
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
                    scope: Some(dest_key_scope(&dk).into()),
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

/// 宛先キー（`203.0.113.0/24`・`2001:db8::/48`・登録ドメイン）の範囲。ドメインはインターネット扱い
pub fn dest_key_scope(dk: &str) -> &'static str {
    match dk.split('/').next().and_then(|ip| ip.parse::<IpAddr>().ok()) {
        Some(ip) => netclass::scope(&ip),
        None => "internet",
    }
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
    fn dest_key_scopes() {
        assert_eq!(dest_key_scope("203.0.113.0/24"), "internet");
        assert_eq!(dest_key_scope("fe80:13:0::/48"), "lan");
        assert_eq!(dest_key_scope("192.168.4.0/24"), "lan");
        assert_eq!(dest_key_scope("example.com"), "internet");
    }

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
