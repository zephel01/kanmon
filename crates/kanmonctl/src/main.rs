//! kanmonctl — 検知ルールの検証・過去ログ再生・イベント表示・ビーコン一覧。
//! 第1弾はデーモンと IPC せず、ルールファイル・JSONL・SQLite を直接読む（読み取り専用）。

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use kanmon_core::detect::DetectionSet;
use kanmon_core::event::get_path;
use kanmon_core::rules::RuleSet;
use kanmon_core::scoring::{self, Level, Thresholds};
use kanmon_core::store::Store;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(version, about = "kanmon CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 検知ルール（YAML）と許可/拒否ルール（JSON）を検証して一覧表示
    Check {
        #[arg(long)]
        detections: PathBuf,
        /// 追加で試すファイル/ディレクトリ（配置前の新ルール）
        #[arg(long)]
        extra: Vec<PathBuf>,
        #[arg(long)]
        rules: Option<PathBuf>,
    },
    /// 過去のイベント（JSONL）に検知ルールを当て直す。新ルールの効き目・誤検知の確認用
    Replay {
        /// JSONL（`-` で標準入力）
        #[arg(long)]
        events: PathBuf,
        #[arg(long)]
        detections: PathBuf,
        #[arg(long)]
        extra: Vec<PathBuf>,
        #[arg(long)]
        rules: Option<PathBuf>,
        /// この検知 ID に一致したイベントだけ表示
        #[arg(long)]
        only: Option<String>,
        /// 表示する最低レベル（info/notice/warn/critical）
        #[arg(long, default_value = "notice")]
        min_level: String,
        /// 結果を JSONL で出力
        #[arg(long)]
        json: bool,
    },
    /// イベント（JSONL）を見やすく表示
    Tail {
        #[arg(long, default_value = default_jsonl())]
        file: PathBuf,
        #[arg(long, default_value = "info")]
        min_level: String,
        /// 追記を待ち続ける
        #[arg(long, short)]
        follow: bool,
        /// 末尾 N 行から
        #[arg(long, short, default_value_t = 50)]
        lines: usize,
    },
    /// 直近の警告を理由の説明付きで表示（見逃した通知の確認用）
    Alerts {
        #[arg(long, default_value = default_jsonl())]
        file: PathBuf,
        /// 何時間前まで
        #[arg(long, default_value_t = 24)]
        hours: i64,
        #[arg(long, default_value = "warn")]
        min_level: String,
        /// 最大件数（新しい順）
        #[arg(long, short, default_value_t = 20)]
        limit: usize,
    },
    /// 直近の接続開始時刻からビーコン候補を計算して表示
    Beacon {
        #[arg(long, default_value = default_db())]
        db: PathBuf,
        #[arg(long, default_value_t = 24)]
        hours: i64,
        #[arg(long, default_value_t = 0.5)]
        min: f64,
    },
    /// 居座り（開発ツールの設定・自動起動への仕込み）を走査して一覧表示する。読むだけで、実行も変更もしない
    Scan {
        /// 走査するプロジェクトのディレクトリ（複数可）。省略時は ~/kanmon-work
        #[arg(long)]
        root: Vec<PathBuf>,
        /// /Library/LaunchDaemons・/etc/systemd/system 等、システム全体の自動起動と、システムの Python（Homebrew 等）も見る
        #[arg(long)]
        system: bool,
        /// 怪しい特徴（network・pipe_shell 等）のあるものだけ表示
        #[arg(long)]
        risky: bool,
        /// 種類で絞る（pth_exec・claude_hook・vscode_folderopen・workflow・git_hook・autostart・rc_pipe）。
        /// pth_exec のときは --system が無くてもシステムの Python を見る
        #[arg(long)]
        kind: Option<String>,
        /// JSON で出力
        #[arg(long)]
        json: bool,
        #[arg(long, default_value_t = 6)]
        max_depth: usize,
    },
    /// 直近のレベル別件数とスコア上位
    Status {
        #[arg(long, default_value = default_db())]
        db: PathBuf,
        #[arg(long, default_value_t = 24)]
        hours: i64,
    },
}

const fn default_jsonl() -> &'static str {
    if cfg!(target_os = "macos") {
        "/Library/Logs/kanmon/events.jsonl"
    } else {
        "/var/log/kanmon/events.jsonl"
    }
}

const fn default_db() -> &'static str {
    if cfg!(target_os = "macos") {
        "/Library/Application Support/kanmon/kanmon.db"
    } else {
        "/var/lib/kanmon/kanmon.db"
    }
}

fn load_dets(dir: &Path, extra: &[PathBuf]) -> Result<DetectionSet> {
    let mut paths = vec![dir.to_path_buf()];
    paths.extend(extra.iter().cloned());
    DetectionSet::load_paths(&paths, false)
}

fn load_rules(p: &Option<PathBuf>) -> Result<RuleSet> {
    match p {
        Some(p) => RuleSet::load(p),
        None => Ok(RuleSet::default()),
    }
}

fn s<'a>(v: &'a Value, p: &str) -> &'a str {
    get_path(v, p).and_then(|x| x.as_str()).unwrap_or("")
}

fn summary_line(v: &Value) -> String {
    let ts = s(v, "@timestamp");
    let level = s(v, "kanmon.level");
    let score = get_path(v, "kanmon.score").and_then(|x| x.as_i64()).unwrap_or(0);
    let kind = s(v, "network.kind");
    let exe = get_path(v, "process.executable")
        .and_then(|x| x.as_str())
        .or_else(|| get_path(v, "process.proc_key").and_then(|x| x.as_str()))
        .unwrap_or("?");
    let dst = match (get_path(v, "destination.ip"), get_path(v, "destination.port")) {
        (Some(i), Some(p)) => format!("{}:{}", i.as_str().unwrap_or(""), p),
        _ => match get_path(v, "kanmon.dest_key") {
            Some(d) => d.as_str().unwrap_or("").to_string(),
            None => format!(
                "{}:{}",
                s(v, "source.ip"),
                get_path(v, "source.port").map(|x| x.to_string()).unwrap_or_default()
            ),
        },
    };
    let sigs: Vec<String> = get_path(v, "kanmon.signals")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .map(|h| format!("{}{:+}", h["id"].as_str().unwrap_or("?"), h["points"].as_i64().unwrap_or(0)))
                .collect()
        })
        .unwrap_or_default();
    format!("{ts}  {level:<8} {score:>4}  {kind:<13} {exe}  {dst}  [{}]", sigs.join(" "))
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Check { detections, extra, rules } => {
            let d = load_dets(&detections, &extra)?;
            let mut by_file: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for x in &d.detections {
                by_file
                    .entry(x.source_file.display().to_string())
                    .or_default()
                    .push(format!("{}({:+})", x.id, x.points));
            }
            for (f, ids) in by_file {
                println!("{f}: {}", ids.join(" "));
            }
            println!("lists: {}", d.lists.keys().cloned().collect::<Vec<_>>().join(", "));
            println!("OK: 検知ルール {} 件", d.detections.len());
            if let Some(r) = &rules {
                let rs = RuleSet::load(r)?;
                println!("OK: 許可/拒否ルール {} 件（{}）", rs.rules.len(), r.display());
            }
        }
        Cmd::Replay { events, detections, extra, rules, only, min_level, json } => {
            let d = load_dets(&detections, &extra)?;
            let rs = load_rules(&rules)?;
            let th = Thresholds::default();
            let min = Level::parse(&min_level).context("min-level は info/notice/warn/critical")?;
            let reader: Box<dyn BufRead> = if events.as_os_str() == "-" {
                Box::new(BufReader::new(std::io::stdin()))
            } else {
                Box::new(BufReader::new(
                    std::fs::File::open(&events).with_context(|| format!("open {}", events.display()))?,
                ))
            };
            let mut total = 0usize;
            let mut bad = 0usize;
            let mut hits: BTreeMap<String, usize> = BTreeMap::new();
            let mut by_level: BTreeMap<&'static str, usize> = BTreeMap::new();
            let mut changed = 0usize;
            for line in reader.lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let Ok(mut v) = serde_json::from_str::<Value>(&line) else {
                    bad += 1;
                    continue;
                };
                kanmon_core::event::migrate_legacy(&mut v);
                total += 1;
                let old_level = s(&v, "kanmon.level").to_string();
                let out = scoring::apply(&mut v, &d, &rs, &th);
                if old_level != out.level.as_str() && !old_level.is_empty() {
                    changed += 1;
                }
                *by_level.entry(out.level.as_str()).or_default() += 1;
                for h in &out.signals {
                    *hits.entry(h.id.clone()).or_default() += 1;
                }
                let show = match &only {
                    Some(id) => out.signals.iter().any(|h| &h.id == id),
                    None => out.level >= min,
                };
                if show {
                    if json {
                        println!("{}", serde_json::to_string(&v)?);
                    } else {
                        let prev = if old_level.is_empty() { String::new() } else { format!(" (元:{old_level})") };
                        println!("{}{prev}", summary_line(&v));
                    }
                }
            }
            eprintln!("--- replay: {total} 件（解析不能 {bad}）、レベル変化 {changed} 件");
            eprintln!(
                "    レベル別: {}",
                by_level.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(" ")
            );
            eprintln!(
                "    検知別ヒット: {}",
                hits.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(" ")
            );
        }
        Cmd::Tail { file, min_level, follow, lines } => {
            let min = Level::parse(&min_level).context("min-level は info/notice/warn/critical")?;
            let mut f = std::fs::File::open(&file).with_context(|| format!("open {}", file.display()))?;
            let text = std::io::read_to_string(&mut f)?;
            let all: Vec<&str> = text.lines().collect();
            let start = all.len().saturating_sub(lines);
            let print = |line: &str| {
                if let Ok(mut v) = serde_json::from_str::<Value>(line) {
                    kanmon_core::event::migrate_legacy(&mut v);
                    let lv = Level::parse(s(&v, "kanmon.level")).unwrap_or(Level::Info);
                    if lv >= min {
                        println!("{}", summary_line(&v));
                    }
                }
            };
            for l in &all[start..] {
                print(l);
            }
            if follow {
                let mut pos = f.seek(SeekFrom::End(0))?;
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    let len = std::fs::metadata(&file)?.len();
                    if len < pos {
                        // ローテーションされた
                        f = std::fs::File::open(&file)?;
                        pos = 0;
                    }
                    if len > pos {
                        f.seek(SeekFrom::Start(pos))?;
                        let mut r = BufReader::new(&f);
                        let mut buf = String::new();
                        while r.read_line(&mut buf)? > 0 {
                            if buf.ends_with('\n') {
                                print(buf.trim_end());
                                pos += buf.len() as u64;
                            }
                            buf.clear();
                        }
                    }
                }
            }
        }
        Cmd::Alerts { file, hours, min_level, limit } => {
            let min = Level::parse(&min_level).context("min-level は info/notice/warn/critical")?;
            let since = chrono::Utc::now() - chrono::Duration::hours(hours);
            // ローテーション済み（.1）も含めて読む
            let mut paths = vec![file.with_extension("jsonl.1"), file.clone()];
            paths.retain(|p| p.exists());
            if paths.is_empty() {
                anyhow::bail!("{} がありません", file.display());
            }
            let mut found: Vec<Value> = vec![];
            for p in paths {
                let text = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
                for line in text.lines() {
                    let Ok(mut v) = serde_json::from_str::<Value>(line) else { continue };
                    kanmon_core::event::migrate_legacy(&mut v);
                    let lv = Level::parse(s(&v, "kanmon.level")).unwrap_or(Level::Info);
                    let ts = chrono::DateTime::parse_from_rfc3339(s(&v, "@timestamp")).ok();
                    if lv >= min && ts.is_some_and(|t| t >= since) {
                        found.push(v);
                    }
                }
            }
            let total = found.len();
            for v in found.iter().rev().take(limit) {
                let (title, body) = kanmon_core::format::alert_text(v);
                println!("━━ {title}\n{body}\n");
            }
            eprintln!("--- 直近 {hours} 時間の {} 以上: {total} 件（表示 {}）", min.as_str(), total.min(limit));
        }
        Cmd::Beacon { db, hours, min } => {
            let st = Store::open_readonly(&db)?;
            let now = chrono::Utc::now().timestamp();
            let since = now - hours * 3600;
            let installed = st.meta_get("installed_at")?.and_then(|v| v.parse::<i64>().ok()).unwrap_or(since);
            let window = (now - installed.max(since)).clamp(3600, hours * 3600) as f64;
            let mut rows = vec![];
            for ((pk, dk), ts) in st.conn_series(since as f64)? {
                if let Some(b) = kanmon_core::beacon::score(&ts, None, window) {
                    if b.score >= min {
                        let exe = st.process_info(&pk)?.and_then(|x| x.0).unwrap_or(pk.clone());
                        rows.push((b, exe, dk));
                    }
                }
            }
            rows.sort_by(|a, b| b.0.score.partial_cmp(&a.0.score).unwrap_or(std::cmp::Ordering::Equal));
            println!("{:>6} {:>5} {:>8} {:>7}  プロセス → 宛先", "score", "n", "中央値s", "MAD s");
            for (b, exe, dk) in rows {
                println!("{:>6.3} {:>5} {:>8.1} {:>7.1}  {exe} → {dk}", b.score, b.n, b.median_interval_s, b.mad_s);
            }
        }
        Cmd::Scan { root, system, risky, kind, json, max_depth } => {
            let home = std::env::var_os("HOME").map(PathBuf::from);
            let roots: Vec<PathBuf> = if root.is_empty() {
                home.iter().map(|h| h.join("kanmon-work")).filter(|p| p.is_dir()).collect()
            } else {
                root
            };
            let os = if cfg!(target_os = "macos") { "macos" } else { "linux" };
            let homes: Vec<PathBuf> = home.into_iter().collect();
            let mut items = kanmon_core::persist::scan(&roots, &homes, os, system, max_depth);
            if let Some(k) = &kind {
                if k == "pth_exec" && !system {
                    items.extend(kanmon_core::persist::scan_python_global(os));
                    let mut keys = std::collections::HashSet::new();
                    items.retain(|i| keys.insert(i.key()));
                    items.sort_by_key(|i| i.key());
                }
                items.retain(|i| &i.kind == k);
            }
            if risky {
                items.retain(|i| !i.risky.is_empty());
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&items)?);
                return Ok(());
            }
            println!(
                "走査: {}{}",
                roots.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", "),
                if system { "、システムの自動起動" } else { "" }
            );
            if items.is_empty() {
                println!("見つかったものはありません");
            }
            let mut last_kind = String::new();
            for i in &items {
                if i.kind != last_kind {
                    println!("\n[{}]", i.kind);
                    last_kind = i.kind.clone();
                }
                let mark = if i.risky.is_empty() { "  ".to_string() } else { format!("⚠ {} ", i.risky.join(",")) };
                let module = if i.kind == "pth_exec" {
                    kanmon_core::persist::pth_module(&i.detail)
                        .map(|m| format!("  [読み込み: {m}]"))
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                println!("  {mark}{}{module}\n      {}", i.detail, i.path);
            }
            let n = items.iter().filter(|i| !i.risky.is_empty()).count();
            println!(
                "\n合計 {} 件（怪しい特徴あり {n} 件）。kanmon は読むだけで、実行・変更はしていません",
                items.len()
            );
        }
        Cmd::Status { db, hours } => {
            let st = Store::open_readonly(&db)?;
            let since = chrono::Utc::now().timestamp() - hours * 3600;
            println!("直近 {hours} 時間:");
            for (lv, n) in st.level_counts(since)? {
                println!("  {lv:<8} {n}");
            }
            println!("スコア上位:");
            for (ts, exe, score, sigs, dst) in st.top_events(since, 15)? {
                let t = chrono::DateTime::from_timestamp(ts, 0)
                    .map(|t| t.with_timezone(&chrono::Local).format("%m-%d %H:%M:%S").to_string())
                    .unwrap_or_default();
                println!("  {t} {score:>4}  {exe}  {dst}  [{sigs}]");
            }
        }
    }
    Ok(())
}
