//! 検知ルール（YAML）エンジン。
//!
//! 新しい手口への対応は「YAML を 1 ファイル足す → `kanmonctl replay` で過去ログに当てて
//! 誤検知を確認 → 配置（デーモンが自動で再読込）」で行う。再ビルドは不要。
//!
//! ```yaml
//! lists:
//!   temp_dirs: ["/tmp/", "/var/tmp/", "~/Downloads/"]
//! detections:
//!   - id: S4
//!     name: temp_dir_exec
//!     points: 25
//!     kinds: [connect, accept, listen]   # 省略時は全種別
//!     when:
//!       all:
//!         - { field: process.executable, op: prefix, value: "@temp_dirs" }
//!         - not: { field: network.scope, op: eq, value: loopback }
//! ```
//!
//! 演算子：eq ne in not_in prefix suffix contains regex gt gte lt lte exists missing
//! `value` が `"@名前"` なら lists の値に展開。`ci: true` で大文字小文字を無視。
//! フィールドが配列の場合、文字列系演算子は「どれか 1 つが一致」。
//! `"~/"` で始まる prefix は `/Users/*/`・`/home/*/`・`/root/` に展開。

use anyhow::{anyhow, bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::event::get_path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignalHit {
    pub id: String,
    pub name: String,
    pub points: i32,
    /// 人が読む説明（検知ルールの description。通知・alerts 表示に使う）
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

// ---------------- YAML 形式 ----------------

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct DetectionFile {
    #[serde(default)]
    lists: HashMap<String, Vec<String>>,
    #[serde(default)]
    detections: Vec<DetectionDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DetectionDef {
    id: String,
    name: String,
    points: i32,
    #[serde(default)]
    description: String,
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default)]
    kinds: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    when: CondDef,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CondDef {
    All { all: Vec<CondDef> },
    Any { any: Vec<CondDef> },
    Not { not: Box<CondDef> },
    Field(FieldDef),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldDef {
    field: String,
    op: String,
    #[serde(default)]
    value: Value,
    #[serde(default)]
    ci: bool,
}

// ---------------- コンパイル済み ----------------

#[derive(Debug)]
enum Cond {
    All(Vec<Cond>),
    Any(Vec<Cond>),
    Not(Box<Cond>),
    Field { field: String, m: Matcher },
}

#[derive(Debug)]
enum Matcher {
    Exists,
    Missing,
    Eq(Value, bool),
    Ne(Value, bool),
    In(Vec<Value>, bool),
    NotIn(Vec<Value>, bool),
    /// prefix/suffix/contains/regex はすべて正規表現に変換して保持
    Re(Vec<Regex>),
    Num(NumOp, f64),
}

#[derive(Debug, Clone, Copy)]
enum NumOp {
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Debug)]
pub struct Detection {
    pub id: String,
    pub name: String,
    pub points: i32,
    pub description: String,
    pub tags: Vec<String>,
    pub source_file: PathBuf,
    kinds: Vec<String>,
    cond: Cond,
}

#[derive(Debug, Default)]
pub struct DetectionSet {
    pub detections: Vec<Detection>,
    pub lists: HashMap<String, Vec<String>>,
}

impl DetectionSet {
    /// ディレクトリ内の *.yaml / *.yml を名前順に読み、lists を共有して 1 つにまとめる。
    /// `strict_owner` が true のとき、root 以外が所有、または group/other 書込可のファイルを拒否する
    /// （一般ユーザー権限のマルウェアが「自分を減点するルール」を置くのを防ぐ）。
    pub fn load_dir(dir: &Path, strict_owner: bool) -> Result<Self> {
        Self::load_paths(&[dir.to_path_buf()], strict_owner)
    }

    /// ディレクトリ（中の *.yaml）またはファイルを順に読み、1 つのセットにまとめる。
    /// `kanmonctl check/replay --extra` で「配置前の新ルール」を既存セットと合わせて試すのに使う。
    pub fn load_paths(paths: &[PathBuf], strict_owner: bool) -> Result<Self> {
        let mut files = vec![];
        for p in paths {
            if p.is_dir() {
                files.extend(list_yaml(p)?);
            } else {
                files.push(p.clone());
            }
        }
        let mut parsed = Vec::new();
        let mut lists: HashMap<String, Vec<String>> = HashMap::new();
        for f in &files {
            if strict_owner {
                check_owner(f)?;
            }
            let text = std::fs::read_to_string(f).with_context(|| format!("read {}", f.display()))?;
            let df: DetectionFile = serde_yaml::from_str(&text).with_context(|| format!("parse {}", f.display()))?;
            for (k, v) in df.lists {
                lists.entry(k).or_default().extend(v);
            }
            parsed.push((f.clone(), df.detections));
        }
        let mut set = DetectionSet { detections: vec![], lists };
        let mut ids = HashSet::new();
        for (f, defs) in parsed {
            for d in defs {
                if !ids.insert(d.id.clone()) {
                    bail!("{}: detection id '{}' が重複しています", f.display(), d.id);
                }
                if !d.enabled {
                    continue;
                }
                let cond =
                    compile(&d.when, &set.lists).with_context(|| format!("{}: detection '{}'", f.display(), d.id))?;
                set.detections.push(Detection {
                    id: d.id,
                    name: d.name,
                    points: d.points,
                    description: d.description,
                    tags: d.tags,
                    source_file: f.clone(),
                    kinds: d.kinds,
                    cond,
                });
            }
        }
        Ok(set)
    }

    /// 単一 YAML 文字列から（テスト用）
    pub fn from_yaml(text: &str) -> Result<Self> {
        let df: DetectionFile = serde_yaml::from_str(text)?;
        let mut set = DetectionSet { detections: vec![], lists: df.lists };
        for d in df.detections {
            if !d.enabled {
                continue;
            }
            let cond = compile(&d.when, &set.lists).with_context(|| format!("detection '{}'", d.id))?;
            set.detections.push(Detection {
                id: d.id,
                name: d.name,
                points: d.points,
                description: d.description,
                tags: d.tags,
                source_file: PathBuf::new(),
                kinds: d.kinds,
                cond,
            });
        }
        Ok(set)
    }

    pub fn list(&self, name: &str) -> &[String] {
        self.lists.get(name).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn evaluate(&self, ev: &Value) -> Vec<SignalHit> {
        let kind = get_path(ev, "network.kind").and_then(|v| v.as_str()).unwrap_or("");
        self.detections
            .iter()
            .filter(|d| d.kinds.is_empty() || d.kinds.iter().any(|k| k == kind))
            .filter(|d| eval(&d.cond, ev))
            .map(|d| SignalHit {
                id: d.id.clone(),
                name: d.name.clone(),
                points: d.points,
                description: d.description.clone(),
            })
            .collect()
    }
}

fn list_yaml(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("read_dir {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("yaml") | Some("yml")))
        .collect();
    files.sort();
    Ok(files)
}

#[cfg(unix)]
pub fn check_owner(p: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(p)?;
    if md.uid() != 0 {
        bail!("{} の所有者が root ではありません（uid={}）。root 所有にしてください", p.display(), md.uid());
    }
    if md.mode() & 0o022 != 0 {
        bail!("{} が group/other 書込可です（mode={:o}）", p.display(), md.mode() & 0o777);
    }
    Ok(())
}
#[cfg(not(unix))]
pub fn check_owner(_p: &Path) -> Result<()> {
    Ok(())
}

fn expand(v: &Value, lists: &HashMap<String, Vec<String>>) -> Result<Vec<Value>> {
    match v {
        Value::String(s) if s.starts_with('@') => {
            let l = lists.get(&s[1..]).ok_or_else(|| anyhow!("list '{}' がありません", &s[1..]))?;
            Ok(l.iter().map(|x| Value::String(x.clone())).collect())
        }
        Value::Array(a) => {
            let mut out = vec![];
            for x in a {
                out.extend(expand(x, lists)?);
            }
            Ok(out)
        }
        other => Ok(vec![other.clone()]),
    }
}

fn home_prefix_re(rest: &str) -> String {
    format!("^(?:/Users/[^/]+|/home/[^/]+|/root|/var/root)/{}", regex::escape(rest))
}

fn compile(c: &CondDef, lists: &HashMap<String, Vec<String>>) -> Result<Cond> {
    Ok(match c {
        CondDef::All { all } => Cond::All(all.iter().map(|x| compile(x, lists)).collect::<Result<_>>()?),
        CondDef::Any { any } => Cond::Any(any.iter().map(|x| compile(x, lists)).collect::<Result<_>>()?),
        CondDef::Not { not } => Cond::Not(Box::new(compile(not, lists)?)),
        CondDef::Field(f) => {
            let vals = || expand(&f.value, lists);
            let strs = || -> Result<Vec<String>> {
                vals()?
                    .into_iter()
                    .map(|v| match v {
                        Value::String(s) => Ok(s),
                        other => Ok(other.to_string()),
                    })
                    .collect()
            };
            let ci = if f.ci { "(?i)" } else { "" };
            let m = match f.op.as_str() {
                "exists" => Matcher::Exists,
                "missing" => Matcher::Missing,
                "eq" => Matcher::Eq(f.value.clone(), f.ci),
                "ne" => Matcher::Ne(f.value.clone(), f.ci),
                "in" => Matcher::In(vals()?, f.ci),
                "not_in" => Matcher::NotIn(vals()?, f.ci),
                "prefix" => Matcher::Re(
                    strs()?
                        .iter()
                        .map(|s| {
                            let pat = match s.strip_prefix("~/") {
                                Some(rest) => home_prefix_re(rest),
                                None => format!("^{}", regex::escape(s)),
                            };
                            Regex::new(&format!("{ci}{pat}"))
                        })
                        .collect::<std::result::Result<_, _>>()?,
                ),
                "suffix" => Matcher::Re(
                    strs()?
                        .iter()
                        .map(|s| Regex::new(&format!("{ci}{}$", regex::escape(s))))
                        .collect::<std::result::Result<_, _>>()?,
                ),
                "contains" => Matcher::Re(
                    strs()?
                        .iter()
                        .map(|s| Regex::new(&format!("{ci}{}", regex::escape(s))))
                        .collect::<std::result::Result<_, _>>()?,
                ),
                "regex" => Matcher::Re(
                    strs()?.iter().map(|s| Regex::new(&format!("{ci}{s}"))).collect::<std::result::Result<_, _>>()?,
                ),
                op @ ("gt" | "gte" | "lt" | "lte") => {
                    let n = f.value.as_f64().ok_or_else(|| anyhow!("{op} の value は数値にしてください"))?;
                    let o = match op {
                        "gt" => NumOp::Gt,
                        "gte" => NumOp::Gte,
                        "lt" => NumOp::Lt,
                        _ => NumOp::Lte,
                    };
                    Matcher::Num(o, n)
                }
                other => bail!("未知の演算子 '{other}'（field={}）", f.field),
            };
            Cond::Field { field: f.field.clone(), m }
        }
    })
}

fn val_eq(a: &Value, b: &Value, ci: bool) -> bool {
    match (a, b) {
        (Value::String(x), Value::String(y)) if ci => x.eq_ignore_ascii_case(y),
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        // YAML で `value: "443"` と書かれても数値フィールドと比較できるように
        (Value::Number(x), Value::String(y)) | (Value::String(y), Value::Number(x)) => {
            y.parse::<f64>().ok() == x.as_f64()
        }
        _ => a == b,
    }
}

fn scalar_any<F: Fn(&Value) -> bool>(v: &Value, f: F) -> bool {
    match v {
        Value::Array(a) => a.iter().any(&f),
        other => f(other),
    }
}

fn as_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn eval(c: &Cond, ev: &Value) -> bool {
    match c {
        Cond::All(v) => v.iter().all(|x| eval(x, ev)),
        Cond::Any(v) => v.iter().any(|x| eval(x, ev)),
        Cond::Not(x) => !eval(x, ev),
        Cond::Field { field, m } => {
            let got = get_path(ev, field);
            match m {
                Matcher::Exists => got.is_some(),
                Matcher::Missing => got.is_none(),
                // 値が無いフィールドは eq/in/文字列/数値 すべて false（ne/not_in は true）
                Matcher::Eq(want, ci) => got.is_some_and(|g| scalar_any(g, |x| val_eq(x, want, *ci))),
                Matcher::Ne(want, ci) => !got.is_some_and(|g| scalar_any(g, |x| val_eq(x, want, *ci))),
                Matcher::In(set, ci) => got.is_some_and(|g| scalar_any(g, |x| set.iter().any(|w| val_eq(x, w, *ci)))),
                Matcher::NotIn(set, ci) => {
                    !got.is_some_and(|g| scalar_any(g, |x| set.iter().any(|w| val_eq(x, w, *ci))))
                }
                Matcher::Re(res) => got
                    .is_some_and(|g| scalar_any(g, |x| as_text(x).is_some_and(|s| res.iter().any(|r| r.is_match(&s))))),
                Matcher::Num(op, n) => got.and_then(|g| g.as_f64()).is_some_and(|g| match op {
                    NumOp::Gt => g > *n,
                    NumOp::Gte => g >= *n,
                    NumOp::Lt => g < *n,
                    NumOp::Lte => g <= *n,
                }),
            }
        }
    }
}

/// ディレクトリの変更を mtime/サイズ/件数で検知し、変わったら読み直す。
/// 読み直しに失敗した場合は呼び出し側が前のセットを使い続ける。
pub struct Reloader {
    dir: PathBuf,
    strict_owner: bool,
    sig: Option<(usize, u128, u64)>,
}

impl Reloader {
    pub fn new(dir: PathBuf, strict_owner: bool) -> Self {
        Self { dir, strict_owner, sig: None }
    }

    fn signature(&self) -> Result<(usize, u128, u64)> {
        let files = list_yaml(&self.dir)?;
        let mut max_m = 0u128;
        let mut total = 0u64;
        for f in &files {
            let md = std::fs::metadata(f)?;
            let m = md
                .modified()
                .unwrap_or(SystemTime::UNIX_EPOCH)
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            max_m = max_m.max(m);
            total = total.wrapping_add(md.len());
        }
        Ok((files.len(), max_m, total))
    }

    /// 変更が無ければ None。変更があれば読み込み結果。
    pub fn check(&mut self) -> Option<Result<DetectionSet>> {
        let sig = match self.signature() {
            Ok(s) => s,
            Err(e) => return Some(Err(e)),
        };
        if self.sig == Some(sig) {
            return None;
        }
        self.sig = Some(sig);
        Some(DetectionSet::load_dir(&self.dir, self.strict_owner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const Y: &str = r#"
lists:
  temp_dirs: ["/tmp/", "/private/tmp/", "~/Downloads/"]
  shells: [bash, zsh, sh]
detections:
  - id: T1
    name: temp
    points: 25
    when: { field: process.executable, op: prefix, value: "@temp_dirs" }
  - id: T2
    name: shell_parent
    points: 10
    kinds: [connect]
    when:
      all:
        - { field: process.parent_chain, op: in, value: "@shells" }
        - not: { field: network.scope, op: eq, value: loopback }
  - id: T3
    name: port
    points: 5
    when:
      all:
        - { field: destination.port, op: not_in, value: [443, 80, 53] }
        - { field: destination.port, op: exists }
  - id: T4
    name: dga
    points: 15
    when: { field: kanmon.dga_score, op: gte, value: 0.7 }
  - id: T5
    name: ci
    points: 1
    when: { field: process.name, op: contains, value: "WORD", ci: true }
  - id: T6
    name: disabled
    points: 99
    enabled: false
    when: { field: process.name, op: exists }
"#;

    fn ids(h: &[SignalHit]) -> Vec<&str> {
        h.iter().map(|x| x.id.as_str()).collect()
    }

    #[test]
    fn evaluates_ops() {
        let s = DetectionSet::from_yaml(Y).unwrap();
        let ev = json!({
            "network": {"kind": "connect", "scope": "internet"},
            "process": {"executable": "/Users/alice/Downloads/x", "name": "Microsoft Word",
                        "parent_chain": ["zsh", "Terminal"]},
            "destination": {"port": 8443},
            "kanmon": {"dga_score": 0.8}
        });
        assert_eq!(ids(&s.evaluate(&ev)), vec!["T1", "T2", "T3", "T4", "T5"]);

        let ev2 = json!({
            "network": {"kind": "listen", "scope": "loopback"},
            "process": {"executable": "/usr/bin/curl", "name": "curl", "parent_chain": ["zsh"]},
            "destination": {"port": "443"},
            "kanmon": {"dga_score": 0.1}
        });
        assert!(s.evaluate(&ev2).is_empty(), "{:?}", s.evaluate(&ev2));
    }

    #[test]
    fn unknown_list_and_op_fail() {
        assert!(DetectionSet::from_yaml(
            "detections: [{id: a, name: a, points: 1, when: {field: x, op: in, value: '@nope'}}]"
        )
        .is_err());
        assert!(DetectionSet::from_yaml(
            "detections: [{id: a, name: a, points: 1, when: {field: x, op: like, value: 1}}]"
        )
        .is_err());
        // 未知キー（typo）も拒否
        assert!(
            DetectionSet::from_yaml("detections: [{id: a, name: a, point: 1, when: {field: x, op: exists}}]").is_err()
        );
    }

    #[test]
    fn reloader_detects_change() {
        let d = std::env::temp_dir().join(format!("kanmon-test-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("a.yaml"), "detections: []\n").unwrap();
        let mut r = Reloader::new(d.clone(), false);
        assert!(r.check().unwrap().is_ok());
        assert!(r.check().is_none());
        std::fs::write(d.join("b.yaml"), "detections: [{id: n, name: n, points: 1, when: {field: x, op: exists}}]\n")
            .unwrap();
        let s = r.check().unwrap().unwrap();
        assert_eq!(s.detections.len(), 1);
        std::fs::remove_dir_all(&d).ok();
    }
}
