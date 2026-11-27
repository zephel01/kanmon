//! 監視ループ本体：スナップショット差分 → 識別 → 事実（facts）付与 → 検知ルール評価 → 保存・通知。

use crate::capture::Obs;
use crate::config::Config;
use crate::identity::{self, IdCache};
use crate::notify::{self, Message, Notifier};
use crate::procinfo::{basename, user_name, ProcCache};
use crate::sockets::{is_accepted, listen_ports, Collector, Listens, Proto, Sock, State};
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
use std::path::{Path, PathBuf};
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
    asn: Option<kanmon_core::asn::AsnDb>,
    asn_dirty: Arc<AtomicBool>,
    last_asn: Option<Instant>,
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
    /// DNS・SNI の観測を始めた時刻（始められなかったら None）
    names_since: Option<Instant>,
    conflicts: ConflictTracker,
    known_resolvers: Vec<std::net::IpAddr>,
    last_dns_check: Option<Instant>,
    doh_tx: Sender<DohResult>,
    doh_rx: Receiver<DohResult>,
    /// ドメイン → （最後に DoH で引いた時刻, DoH で見た IP の履歴）
    doh_state: HashMap<String, (Instant, Vec<std::net::IpAddr>)>,
    doh_inflight: HashSet<String>,
    priv_tx: Sender<PrivResult>,
    priv_rx: Receiver<PrivResult>,
    priv_inflight: HashSet<String>,
    doh_fail_logged: Option<Instant>,
    /// 同じ検知を何度も出さないための最終発報時刻
    dns_emitted: HashMap<String, i64>,
    // ---- 送信量
    volume: kanmon_core::volume::VolumeTracker,
    last_volume: Option<Instant>,
    // ---- 居座りの走査（別スレッド）
    persist_tx: Sender<PersistScan>,
    persist_rx: Receiver<PersistScan>,
    persist_running: bool,
    last_persist: Option<Instant>,
    /// 直近に増えた起動の仕掛け（通信と結び付ける）
    persist_recent: Vec<kanmon_core::persist::Recent>,
    /// 見張る site-packages と、その更新時刻（.pth の追加に早く気づくため）
    persist_sites: Vec<(PathBuf, Option<std::time::SystemTime>)>,
    /// 「いつもの形」に記録済みの項目（DB に何度も書かないため）
    profile_seen: HashSet<String>,
    last_site_check: Instant,
    pub print: bool,
}

/// 居座りの走査の結果（見つけたもの, 見た site-packages）
type PersistScan = (Vec<kanmon_core::persist::Item>, Vec<PathBuf>);

/// ディレクトリの更新時刻（読めなければ None）
fn dir_mtime(p: &std::path::Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// （ドメイン, 受け身で見た答え, DoH と証明書の確認結果）
type DohResult = (String, Vec<std::net::IpAddr>, std::result::Result<crate::dnswatch::Crosscheck, String>);
/// N4 の引き直し：（名前, ローカルの答え, 応答した DNS サーバー, 監視リストか, TTL, DoH の答え）
type PrivResult = (String, Vec<IpAddr>, IpAddr, bool, u32, std::result::Result<Vec<IpAddr>, String>);

pub(crate) fn hostname() -> String {
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
            JsonlWriter::open_daily(
                &cfg.jsonl.path,
                cfg.jsonl.max_mb * 1024 * 1024,
                cfg.jsonl.keep_days,
                cfg.jsonl.compress,
            )?
        } else {
            JsonlWriter::open(&cfg.jsonl.path, cfg.jsonl.max_mb * 1024 * 1024, cfg.jsonl.keep)?
        };
        let intel = crate::feeds::load(&cfg);
        logln!("脅威インテル {} 件", intel.len());
        let asn = crate::asndata::load(&cfg);
        if let Some(db) = &asn {
            let (a, b, c) = db.counts();
            logln!("AS のデータ：範囲 {} 件・AS {c} 件", a + b);
        }
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
                // 起動直後から件数と学習期間を出す。最初の走査（macOS ではプロセスの署名の確認で
                // 数十秒かかることがある）が終わるまで、メニューに 0 件と出ないように
                counts_24h: store
                    .level_counts(Utc::now().timestamp() - 86_400)
                    .unwrap_or_default()
                    .into_iter()
                    .collect(),
                learning: cfg.mode == "learning"
                    && (cfg.learning_days == 0
                        || Utc::now().timestamp() - installed_at < cfg.learning_days as i64 * 86_400),
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
            Some((rx, !devs.is_empty()))
        } else {
            None
        };
        let names_since = obs_rx.as_ref().and_then(|(_, ok)| ok.then(Instant::now));
        let obs_rx = obs_rx.map(|(rx, _)| rx);
        let known_resolvers = crate::dnswatch::read_resolvers(&cfg.dns.resolv_conf);
        let (doh_tx, doh_rx) = std::sync::mpsc::channel();
        let (priv_tx, priv_rx) = std::sync::mpsc::channel();
        let (persist_tx, persist_rx) = std::sync::mpsc::channel();
        let persist_recent: Vec<kanmon_core::persist::Recent> = store
            .meta_get("persist.recent")
            .ok()
            .flatten()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
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
            asn,
            asn_dirty: Arc::new(AtomicBool::new(false)),
            last_asn: None,
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
            names_since,
            conflicts: ConflictTracker::default(),
            known_resolvers,
            last_dns_check: None,
            doh_tx,
            doh_rx,
            doh_state: HashMap::new(),
            doh_inflight: HashSet::new(),
            priv_tx,
            priv_rx,
            priv_inflight: HashSet::new(),
            doh_fail_logged: None,
            dns_emitted: HashMap::new(),
            volume: Default::default(),
            last_volume: None,
            persist_tx,
            persist_rx,
            persist_running: false,
            last_persist: None,
            persist_recent,
            persist_sites: vec![],
            last_site_check: Instant::now(),
            profile_seen: HashSet::new(),
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
        // AS のデータ（6 時間ごとに期限を確認。取り直しは既定 7 日ごと、別スレッド）
        if self.cfg.asn.enabled && self.last_asn.is_none_or(|t| t.elapsed() > Duration::from_secs(6 * 3600)) {
            self.last_asn = Some(Instant::now());
            let cfg = self.cfg.clone();
            let flag = self.asn_dirty.clone();
            std::thread::spawn(move || {
                if crate::asndata::refresh(&cfg) {
                    flag.store(true, Ordering::SeqCst);
                }
            });
        }
        if self.asn_dirty.swap(false, Ordering::SeqCst) {
            if let Some(db) = crate::asndata::load(&self.cfg) {
                self.asn = Some(db);
            }
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
            self.drain_private();
        }
        // 居座りの走査（別スレッドで歩き、結果を前回と比べる）
        if self.cfg.persistence.enabled {
            let iv = Duration::from_secs(self.cfg.persistence.interval_s.max(1));
            // site-packages の更新時刻が変わったら（pip install 等）、間隔を待たずに走査し直す（最短 2 分おき）
            let watch = Duration::from_secs(self.cfg.persistence.watch_s.max(10));
            if self.cfg.persistence.watch_s > 0 && self.last_site_check.elapsed() > watch {
                self.last_site_check = Instant::now();
                let changed = self.persist_sites.iter().any(|(p, t)| dir_mtime(p) != *t);
                if changed
                    && !self.persist_running
                    && self.last_persist.is_some_and(|t| t.elapsed() > Duration::from_secs(120))
                {
                    crate::logln!("居座りの走査：site-packages が変わったので走査し直します");
                    self.last_persist = None;
                }
            }
            if !self.persist_running && self.last_persist.is_none_or(|t| t.elapsed() > iv) {
                self.last_persist = Some(Instant::now());
                self.persist_running = true;
                let pc = self.cfg.persistence.clone();
                let os = self.os;
                let tx = self.persist_tx.clone();
                let r = std::thread::Builder::new().name("kanmon-persist".into()).spawn(move || {
                    let homes = crate::persistwatch::user_homes();
                    let roots = crate::persistwatch::expand_roots(&pc.roots, &homes);
                    let _ = tx.send(kanmon_core::persist::scan_with_sites(&roots, &homes, os, pc.system, pc.max_depth));
                });
                if r.is_err() {
                    self.persist_running = false;
                }
            }
            if let Ok((items, sites)) = self.persist_rx.try_recv() {
                self.persist_running = false;
                self.persist_sites = sites
                    .into_iter()
                    .map(|p| {
                        let t = dir_mtime(&p);
                        (p, t)
                    })
                    .collect();
                self.persist_result(items);
            }
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

    /// events.jsonl へ書く。`jsonl.min_level` より低いレベルは書かない（SQLite には別に入れている）
    fn jsonl_write(&mut self, v: &serde_json::Value) -> Result<()> {
        use kanmon_core::scoring::Level;
        let min = Level::parse(&self.cfg.jsonl.min_level).unwrap_or(Level::Info);
        let lv = v.pointer("/kanmon/level").and_then(|x| x.as_str()).and_then(Level::parse).unwrap_or(Level::Info);
        if lv < min {
            return Ok(());
        }
        self.jsonl.write(v)
    }

    fn next_id(&mut self) -> String {
        self.counter = self.counter.wrapping_add(1);
        format!("e_{:x}{:04x}", Utc::now().timestamp_micros(), self.counter & 0xffff)
    }

    /// 新規ソケット 1 件を処理。記録したら true
    fn handle_new(&mut self, s: &Sock, listens: &Listens, initial: bool) -> Result<bool> {
        let (kind, direction) = match (s.proto, s.state) {
            (Proto::Tcp, State::Listen) => ("listen", "inbound"),
            // UDP の未接続ソケットは一時ポートのものが大量にあるので、低いポートだけ「待受」とみなす
            (Proto::Udp, State::Unconnected) if s.local.port() != 0 && s.local.port() < 32768 => ("listen", "inbound"),
            (Proto::Tcp, State::Established) if is_accepted(listens, Proto::Tcp, s.local) => ("accept", "inbound"),
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

        if let Some(r) = s.remote {
            self.enrich_asn(&mut e, r.ip());
        }
        // 名前の観測が動いていて、起動から 5 分たっている（名前の記憶がたまっている）。
        // これが偽のときは「名前が無い」ことを判断に使わない（R2）
        e.kanmon.names_active = self.names_since.is_some_and(|t| t.elapsed() > Duration::from_secs(300));

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
                    if self.cfg.profile.enabled && proc_key != "unknown" {
                        self.profile_connect(&mut e, &proc_key, now_s, learning || initial)?;
                    }
                    e.kanmon.persist_recent = kanmon_core::persist::recent_kinds(
                        &self.persist_recent,
                        now_s,
                        self.cfg.persistence.recent_window_s as i64,
                    );
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
                e.kanmon.own_viewer = scope == "loopback"
                    && e.process.executable.as_deref().is_some_and(crate::identity::is_own_viewer_binary);
            }
            _ => {}
        }

        // ---- 評価・保存・通知
        let mut v = serde_json::to_value(&e)?;
        let out = scoring::apply(&mut v, &self.dets, &self.rules, &self.cfg.thresholds);
        self.store.insert_event(&v, now_s)?;
        self.jsonl_write(&v)?;
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
        self.enrich_asn(&mut e, d.remote);
        let mut proc_key = format!("pid:{}", d.pid);
        if let Some((p, k)) = self.process_info(d.pid, None, now_s)? {
            e.process = p;
            proc_key = k;
        } else {
            e.process.pid = Some(d.pid);
        }
        // 「いつもの形」：送信量。観測が長いプロセスで、これまでの最大の何倍か
        if self.cfg.profile.enabled && !proc_key.starts_with("pid:") {
            let prev = self.store.volume_profile(&proc_key)?;
            self.store.volume_record(&proc_key, d.bytes, now_s)?;
            let pc = &self.cfg.profile;
            let age = e.process.first_seen_age_s.unwrap_or(0);
            if !learning && age >= pc.min_age_days as i64 * 86_400 && d.bytes >= pc.volume_min_mb << 20 {
                let floor = self.cfg.volume.min_report_kb * 1024;
                e.kanmon.profile = Some(ev::ProfileFacts {
                    volume_ratio: Some(kanmon_core::profile::volume_ratio(d.bytes, prev.map(|p| p.0), floor)),
                    volume_max: prev.map(|p| p.0),
                    ..Default::default()
                });
            }
        }
        let files = crate::volume::open_files(d.pid);
        let sum = kanmon_core::volume::summarize_open(&files);
        e.kanmon.bytes = Some(ev::BytesFacts {
            out: d.bytes,
            window_s: self.cfg.volume.window_s,
            open_size: sum.total_size,
            out_per_open: (sum.total_size > 0).then(|| d.bytes as f64 / sum.total_size as f64),
            own_profile_only: e
                .process
                .executable
                .as_deref()
                .is_some_and(|x| kanmon_core::volume::own_profile_only(x, &sum.paths)),
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
        self.jsonl_write(&v)?;
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
            let ancestors: Vec<ev::Ancestor> = chain
                .iter()
                .map(|(apid, aexe, _)| ev::Ancestor {
                    pid: *apid,
                    name: aexe.as_deref().map(basename),
                    start: self.procs.get(*apid).and_then(|a| crate::procinfo::start_rfc3339(a.start)),
                })
                .collect();
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
                    start: ancestors.first().and_then(|a| a.start.clone()),
                }),
                parent_chain: chain_names(&chain, &self.cfg.interpreters),
                start: crate::procinfo::start_rfc3339(p.start),
                ancestors,
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

    /// ベースラインに記録し、初出なら true（「いつもの形」用。同じ項目はメモリで覚えて DB に何度も書かない）
    fn profile_touch(&mut self, proc_key: &str, item: &str, kind: &str, now: i64) -> Result<bool> {
        let k = format!("{kind}\u{1}{proc_key}\u{1}{item}");
        if self.profile_seen.contains(&k) {
            return Ok(false);
        }
        let first = self.store.baseline_touch(proc_key, item, kind, now)?;
        if self.profile_seen.len() > 500_000 {
            self.profile_seen.clear();
        }
        self.profile_seen.insert(k);
        Ok(first)
    }

    /// 宛先の AS・登録国・回線の種類を付ける（インターネットの宛先だけ）
    fn enrich_asn(&self, e: &mut Event, ip: std::net::IpAddr) {
        let Some(db) = &self.asn else { return };
        if e.network.scope.as_deref() != Some("internet") {
            return;
        }
        let Some(info) = db.lookup(ip) else { return };
        e.kanmon.net_type = Some(
            kanmon_core::asn::net_type(
                info.number,
                self.dets.list("cloud_asns"),
                self.dets.list("cdn_asns"),
                self.dets.list("residential_asns"),
            )
            .to_string(),
        );
        if let Some(d) = e.destination.as_mut() {
            d.as_ = Some(ev::AsField {
                number: info.number,
                organization: (!info.name.is_empty()).then(|| ev::AsOrg { name: info.name.clone() }),
            });
            d.geo = info.country.map(|c| ev::GeoField { country_iso_code: c });
        }
    }

    /// 接続のイベントに「いつもの形」との違いを付ける。`suppress`（学習期間・起動時の既存の接続）は記録だけ
    fn profile_connect(&mut self, e: &mut Event, proc_key: &str, now: i64, suppress: bool) -> Result<()> {
        use chrono::Timelike;
        use kanmon_core::profile;
        const DAY: i64 = 86_400;
        let pc = self.cfg.profile.clone();
        let age = e.process.first_seen_age_s.unwrap_or(0);
        let mut f = ev::ProfileFacts::default();
        let mut touched = false;

        // 宛先（名前が分かるインターネットの宛先だけ。CDN の IP は変わるので、IP では見ない）
        let dom = e.destination.as_ref().and_then(|d| d.domain.clone());
        if let Some(d) = dom.filter(|_| e.network.scope.as_deref() == Some("internet")) {
            let item = profile::dest_item(&d);
            let st = self.store.baseline_stats(proc_key, "pdest")?;
            let first = self.profile_touch(proc_key, &item, "pdest", now)?;
            f.stable = profile::stable(
                age,
                &st,
                now,
                pc.min_age_days as i64 * DAY,
                pc.quiet_days as i64 * DAY,
                pc.max_dests as i64,
            );
            f.known_dests = Some(st.known);
            f.quiet_days = st.newest.map(|n| profile::days(now - n));
            f.new_dest = first && f.stable && !suppress;
            touched = true;
        }

        // 宛先の AS（名前が付かない接続も含む。安定の条件は宛先と同じ）
        let asn = e.destination.as_ref().and_then(|d| d.as_.as_ref()).map(|a| a.number);
        if let Some(asn) = asn {
            let st = self.store.baseline_stats(proc_key, "pasn")?;
            let first = self.profile_touch(proc_key, &asn.to_string(), "pasn", now)?;
            let stable = profile::stable(
                age,
                &st,
                now,
                pc.min_age_days as i64 * DAY,
                pc.quiet_days as i64 * DAY,
                pc.max_dests as i64,
            );
            if first && stable && !suppress {
                f.new_asn = true;
                f.asn = Some(asn);
                touched = true;
            }
        }

        // 時間帯（観測が長いプロセスで、初めての時間帯）
        let hour = Local::now().hour();
        let st = self.store.baseline_stats(proc_key, "hour")?;
        let first = self.profile_touch(proc_key, &hour.to_string(), "hour", now)?;
        if first && !suppress && st.known > 0 && age >= pc.hour_min_age_days as i64 * DAY {
            f.new_hour = true;
            f.hour = Some(hour);
            touched = true;
        }

        // 親 → 子（子の種類が安定している親が、初めての子を起動し、その子が通信した）
        let parent = e.process.parent.as_ref().and_then(|p| p.name.clone());
        let child = e.process.name.clone();
        if let (Some(parent), Some(child)) = (parent, child) {
            let key = format!("parent:{parent}");
            let st = self.store.baseline_stats(&key, "child")?;
            let first = self.profile_touch(&key, &child, "child", now)?;
            let page = st.oldest.map(|o| now - o).unwrap_or(0);
            let stable = profile::stable(
                page,
                &st,
                now,
                pc.min_age_days as i64 * DAY,
                pc.quiet_days as i64 * DAY,
                pc.max_children as i64,
            );
            if first && stable && !suppress {
                f.new_child = true;
                f.parent = Some(parent);
                touched = true;
            }
        }

        if touched {
            e.kanmon.profile = Some(f);
        }
        Ok(())
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
            // 2 つの答えがどれも相手側と同じ AS なら、CDN が問い合わせごとに答えを変えただけ（v0.5.5）
            let same_as = self.asn.as_ref().is_some_and(|db| {
                let asns = |v: &[IpAddr]| v.iter().map(|ip| db.lookup(*ip).map(|a| a.number)).collect::<Vec<_>>();
                dnsguard::same_as_answers(&asns(&prev), &asns(&cur))
            });
            let facts = ev::DnsFacts {
                finding: if same_as { "conflicting_answer_same_as" } else { "conflicting_answer" }.into(),
                watched,
                server: Some(server.to_string()),
                other: prev.iter().map(|x| x.to_string()).collect(),
                ..Default::default()
            };
            self.emit_dns(facts, Some(q.clone()), &cur, None, format!("conflict|{q}"));
        }
        // N4：公開ドメインがローカルの IP に解決。DoH でも引き直し、同じ答えならドメインの持ち主が
        // 公開している記録（使われなくなった広告のドメイン等）として記録だけにする（v0.5.4）
        let local_ips = dnsguard::private_answers(&q, &ips, &self.cfg.dns.private_ok_suffixes);
        if !local_ips.is_empty() {
            let dedup = format!("private|{q}");
            let recently = self.dns_emitted.get(&dedup).is_some_and(|t| now - *t < 3600);
            if !recently && !self.priv_inflight.contains(&q) {
                if self.cfg.dns.crosscheck && self.priv_inflight.len() < 4 {
                    self.priv_inflight.insert(q.clone());
                    let url = self.cfg.dns.doh_url.clone();
                    let tx = self.priv_tx.clone();
                    let name = q.clone();
                    let spawned = std::thread::Builder::new().name("kanmon-doh-n4".into()).spawn(move || {
                        let r = crate::dnswatch::doh_lookup(&url, &name).map_err(|e| format!("{e:#}"));
                        let _ = tx.send((name, local_ips, server, watched, ttl, r));
                    });
                    if spawned.is_err() {
                        self.priv_inflight.remove(&q);
                    }
                } else {
                    self.emit_private(q.clone(), local_ips, server, watched, ttl, None);
                }
            }
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

    /// N4 の結果を出す。`doh` が Some のときは DoH の答え（引き直せなかったら None）
    fn emit_private(
        &mut self,
        q: String,
        local: Vec<IpAddr>,
        server: IpAddr,
        watched: bool,
        ttl: u32,
        doh: Option<Vec<IpAddr>>,
    ) {
        let published = doh.as_deref().is_some_and(|d| dnsguard::private_published(&local, d));
        let facts = ev::DnsFacts {
            finding: if published { "private_answer_published" } else { "private_answer" }.into(),
            watched,
            server: Some(server.to_string()),
            other: doh.unwrap_or_default().iter().map(|x| x.to_string()).collect(),
            ttl: Some(ttl),
            ..Default::default()
        };
        self.emit_dns(facts, Some(q.clone()), &local, None, format!("private|{q}"));
    }

    fn drain_private(&mut self) {
        let mut done = vec![];
        while let Ok(r) = self.priv_rx.try_recv() {
            done.push(r);
        }
        for (q, local, server, watched, ttl, res) in done {
            self.priv_inflight.remove(&q);
            let doh = match res {
                Ok(d) => Some(d),
                Err(e) => {
                    if self.doh_fail_logged.is_none_or(|t| t.elapsed() > Duration::from_secs(3600)) {
                        self.doh_fail_logged = Some(Instant::now());
                        logln!("DoH での引き直しに失敗（{q}。N4 として扱う）: {e}");
                    }
                    None
                }
            };
            self.emit_private(q, local, server, watched, ttl, doh);
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
                    // 見慣れないサーバーがどれも住宅用回線（回線事業者）の AS なら、DHCP で配られた
                    // 回線事業者の DNS（WARP を切ったとき等）。N2p を付けない（v0.5.5）
                    unknown_public_isp: !c.unknown_public.is_empty()
                        && self.asn.as_ref().is_some_and(|db| {
                            let res = self.dets.list("residential_asns");
                            c.unknown_public.iter().all(|ip| {
                                db.lookup(*ip).is_some_and(|a| {
                                    kanmon_core::asn::net_type(a.number, &[], &[], res) == "residential"
                                })
                            })
                        }),
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

    /// 居座りの走査結果を前回と比べ、変化をイベントにする（初回は基準を記録するだけ）
    fn persist_result(&mut self, items: Vec<kanmon_core::persist::Item>) {
        use kanmon_core::persist;
        let old: Option<Vec<persist::Item>> =
            self.store.meta_get("persist.snapshot").ok().flatten().and_then(|s| serde_json::from_str(&s).ok());
        if let Ok(s) = serde_json::to_string(&items) {
            let _ = self.store.meta_set("persist.snapshot", &s);
        }
        let ver = persist::SCAN_VERSION.to_string();
        let same_ver = self.store.meta_get("persist.scan_version").ok().flatten().as_deref() == Some(ver.as_str());
        let _ = self.store.meta_set("persist.scan_version", &ver);
        let Some(old) = old else {
            crate::logln!("居座りの走査：基準を記録しました（{} 件）", items.len());
            return;
        };
        if !same_ver {
            crate::logln!("居座りの走査：見る場所が増えたので、基準を取り直しました（{} 件）", items.len());
            return;
        }
        let changes = persist::diff(&old, &items);
        if changes.is_empty() {
            return;
        }
        let now = Utc::now().timestamp();
        persist::note_recent(&mut self.persist_recent, &changes, now, self.cfg.persistence.recent_window_s as i64);
        if let Ok(s) = serde_json::to_string(&self.persist_recent) {
            let _ = self.store.meta_set("persist.recent", &s);
        }
        crate::logln!("居座りの走査：{} 件の変化", changes.len());
        // 一度に大量に変わった（走査の場所を変えた等）ときは、最初の 50 件だけイベントにする
        for c in changes.iter().take(50) {
            if let Err(e) = self.emit_persist(c) {
                crate::logln!("居座りのイベントを保存できません: {e:#}");
            }
        }
    }

    fn emit_persist(&mut self, c: &kanmon_core::persist::Change) -> Result<()> {
        let now = Utc::now().timestamp();
        let learning = self.learning();
        let mut e = Event {
            timestamp: Local::now().to_rfc3339_opts(SecondsFormat::Millis, false),
            event: ev::EventMeta {
                id: self.next_id(),
                kind: "alert".into(),
                action: format!("persistence_{}", c.change),
                outcome: None,
            },
            host: ev::Host { name: self.host.clone(), os: self.os.into() },
            network: ev::Network {
                kind: "persistence".into(),
                direction: "none".into(),
                transport: "file".into(),
                scope: None,
            },
            file: Some(ev::File { path: c.item.path.clone() }),
            ..Default::default()
        };
        e.kanmon.mode = if learning { "learning".into() } else { self.cfg.mode.clone() };
        e.kanmon.learning = learning;
        e.kanmon.persist = Some(ev::PersistFacts {
            kind: c.item.kind.clone(),
            change: c.change.clone(),
            detail: c.item.detail.clone(),
            risky: c.item.risky.clone(),
            module: (c.item.kind == "pth_exec").then(|| kanmon_core::persist::pth_module(&c.item.detail)).flatten(),
        });
        let mut v = serde_json::to_value(&e)?;
        let out = scoring::apply(&mut v, &self.dets, &self.rules, &self.cfg.thresholds);
        self.store.insert_event(&v, now)?;
        self.jsonl_write(&v)?;
        if self.print {
            println!("{}", serde_json::to_string(&v)?);
        }
        let (title, body) = kanmon_core::format::alert_text(&v);
        self.record_alert(&v, out.level, out.score, "persistence", &title, &body);
        let min = self.min_notify_level();
        self.notifier.send(
            Message { level: out.level, title, body, dedup_key: format!("persist|{}|{}", c.change, c.item.key()) },
            min,
        );
        Ok(())
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
        if let Err(err) = self.store.insert_event(&v, now).and_then(|_| self.jsonl_write(&v)) {
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
            self.jsonl_write(&v)?;
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
