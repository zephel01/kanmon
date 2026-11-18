//! DNS の改ざんを見るための判定（純関数）。
//!
//! - N1 hosts の書き換え（監視リストのドメインが書かれていないか）
//! - N2 DNS サーバー設定の変更（DNSChanger 型）
//! - N3 暗号化 DNS（DoH）での引き直しと照合
//! - N4 公開ドメインがプライベート・ループバックの IP に解決される
//! - N5 同じ問い合わせに中身の違う応答が届く（偽応答の割り込み）
//! - N6 設定にない DNS サーバーからの応答
//!
//! ファイルの読み取り・パケット取得・DoH の通信はデーモン側（kanmond）が行い、ここは比較だけを持つ。

use crate::netclass;
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

/// よく使われる公開 DNS（N2 で「既知の公開 DNS への変更」は弱く扱う）
pub const KNOWN_PUBLIC_RESOLVERS: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "1.1.1.2",
    "1.0.0.2",
    "1.1.1.3",
    "1.0.0.3",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "8.8.8.8",
    "8.8.4.4",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    "9.9.9.9",
    "149.112.112.112",
    "2620:fe::fe",
    "2620:fe::9",
    "208.67.222.222",
    "208.67.220.220",
    "94.140.14.14",
    "94.140.15.15",
];

/// 公開ドメインとみなさない接尾辞（社内・ローカル開発・VPN の名前）。設定で足せる
pub const LOCAL_SUFFIXES: &[&str] = &[
    "local",
    "localhost",
    "localdomain",
    "test",
    "example",
    "invalid",
    "lan",
    "home",
    "internal",
    "intranet",
    "corp",
    "arpa",
    "ts.net",
];

fn ends_with_label(name: &str, suffix: &str) -> bool {
    let s = suffix.trim_matches('.').to_ascii_lowercase();
    name == s || name.ends_with(&format!(".{s}"))
}

/// `name` が監視リストのどれか（そのもの、またはサブドメイン）に当たるか
pub fn watched(name: &str, watch: &[String]) -> bool {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    watch.iter().any(|w| ends_with_label(&n, w))
}

fn is_sinkhole(ip: &IpAddr) -> bool {
    ip.is_unspecified()
}

// ---------------- N1 hosts ----------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsEntry {
    pub ip: IpAddr,
    pub names: Vec<String>,
}

/// hosts を読む。IP として読めない行・コメントは捨てる（行数は 2 万まで）
pub fn parse_hosts(text: &str) -> Vec<HostsEntry> {
    text.lines()
        .take(20_000)
        .filter_map(|l| {
            let l = l.split('#').next().unwrap_or("").trim();
            let mut it = l.split_whitespace();
            let ip: IpAddr = it.next()?.split('%').next()?.parse().ok()?;
            let names: Vec<String> = it.take(32).map(|n| n.trim_end_matches('.').to_ascii_lowercase()).collect();
            (!names.is_empty()).then_some(HostsEntry { ip, names })
        })
        .collect()
}

fn hosts_lines(entries: &[HostsEntry]) -> BTreeSet<String> {
    entries.iter().flat_map(|e| e.names.iter().map(move |n| format!("{} {}", e.ip, n))).collect()
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostsReport {
    /// 「IP 名前」の形の追加行・削除行
    pub added: Vec<String>,
    pub removed: Vec<String>,
    /// 監視リストのドメインが書かれている行（どの IP でも）
    pub watched: Vec<String>,
    /// そのうち、ループバック・0.0.0.0 以外へ向けられている行（別のサーバーへの誘導）
    pub redirected: Vec<String>,
}

impl HostsReport {
    pub fn changed(&self) -> bool {
        !self.added.is_empty() || !self.removed.is_empty()
    }
}

/// 前回の内容（初回は None）と今回の内容を比べる
pub fn hosts_check(old: Option<&str>, new: &str, watch: &[String]) -> HostsReport {
    let ne = parse_hosts(new);
    let nl = hosts_lines(&ne);
    let ol = old.map(|o| hosts_lines(&parse_hosts(o))).unwrap_or_else(|| nl.clone());
    let mut r = HostsReport {
        added: nl.difference(&ol).cloned().collect(),
        removed: ol.difference(&nl).cloned().collect(),
        ..Default::default()
    };
    for e in &ne {
        for n in &e.names {
            if watched(n, watch) {
                let line = format!("{} {}", e.ip, n);
                if !(e.ip.is_loopback() || is_sinkhole(&e.ip)) {
                    r.redirected.push(line.clone());
                }
                r.watched.push(line);
            }
        }
    }
    r
}

// ---------------- N2 DNS サーバー設定 ----------------

/// resolv.conf の nameserver 行
pub fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    let mut v: Vec<IpAddr> = text
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            (it.next()? == "nameserver").then_some(())?;
            it.next()?.split('%').next()?.parse().ok()
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

/// macOS の `scutil --dns` の出力から `nameserver[n] : <IP>` を集める
pub fn parse_scutil_dns(text: &str) -> Vec<IpAddr> {
    let mut v: Vec<IpAddr> = text
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            if !l.starts_with("nameserver[") {
                return None;
            }
            l.split(':').skip(1).collect::<Vec<_>>().join(":").trim().split('%').next()?.parse().ok()
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverChange {
    pub added: Vec<IpAddr>,
    pub removed: Vec<IpAddr>,
    /// 追加されたものの中で最も外側の範囲（internet / lan / loopback）
    pub added_scope: &'static str,
    /// インターネット上で、よく使われる公開 DNS でもないもの
    pub unknown_public: Vec<IpAddr>,
}

pub fn known_public(ip: &IpAddr) -> bool {
    KNOWN_PUBLIC_RESOLVERS.iter().any(|s| s.parse::<IpAddr>().ok().as_ref() == Some(ip))
}

pub fn resolver_change(old: &[IpAddr], new: &[IpAddr]) -> Option<ResolverChange> {
    let added: Vec<IpAddr> = new.iter().filter(|x| !old.contains(x)).copied().collect();
    let removed: Vec<IpAddr> = old.iter().filter(|x| !new.contains(x)).copied().collect();
    if added.is_empty() && removed.is_empty() {
        return None;
    }
    let rank = |s: &str| match s {
        "internet" => 2,
        "lan" => 1,
        _ => 0,
    };
    let added_scope = added.iter().map(netclass::scope).max_by_key(|s| rank(s)).unwrap_or("none");
    let unknown_public =
        added.iter().filter(|ip| netclass::scope(ip) == "internet" && !known_public(ip)).copied().collect();
    Some(ResolverChange { added, removed, added_scope, unknown_public })
}

// ---------------- N4 プライベート IP への解決 ----------------

/// 公開ドメインなのに、ループバック・プライベートの IP が返っている答えを返す。
/// 0.0.0.0 / `::`（広告ブロック等のシンクホール）と、ローカル用の名前は対象外。
pub fn private_answers(qname: &str, ips: &[IpAddr], extra_ok_suffixes: &[String]) -> Vec<IpAddr> {
    let q = qname.trim_end_matches('.').to_ascii_lowercase();
    if !q.contains('.')
        || LOCAL_SUFFIXES.iter().any(|s| ends_with_label(&q, s))
        || extra_ok_suffixes.iter().any(|s| ends_with_label(&q, s))
        || crate::dga::registered_domain(&q).is_none()
    {
        return vec![];
    }
    ips.iter().filter(|ip| !is_sinkhole(ip) && netclass::scope(ip) != "internet").copied().collect()
}

// ---------------- N5 応答の競合 ----------------

type ConflictKey = (IpAddr, IpAddr, u16, u16, String);

/// 同じ問い合わせ（サーバー・クライアント・ポート・ID・名前）に、数秒以内に中身の違う応答が来たら知らせる
#[derive(Debug, Default)]
pub struct ConflictTracker {
    seen: HashMap<ConflictKey, (Vec<IpAddr>, i64)>,
}

impl ConflictTracker {
    pub const WINDOW_S: i64 = 3;

    /// 競合があれば（前の答え, 今回の答え）
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &mut self,
        server: IpAddr,
        client: IpAddr,
        client_port: u16,
        id: u16,
        qname: &str,
        ips: &[IpAddr],
        now: i64,
    ) -> Option<(Vec<IpAddr>, Vec<IpAddr>)> {
        if self.seen.len() > 20_000 {
            self.seen.retain(|_, (_, t)| now - *t <= Self::WINDOW_S);
        }
        let key = (server, client, client_port, id, qname.to_ascii_lowercase());
        let mut cur = ips.to_vec();
        cur.sort();
        cur.dedup();
        let prev = self.seen.insert(key, (cur.clone(), now));
        match prev {
            Some((p, t)) if now - t <= Self::WINDOW_S && !p.is_empty() && !cur.is_empty() && p != cur => Some((p, cur)),
            _ => None,
        }
    }
}

// ---------------- N3 DoH との照合 ----------------

fn same_net(a: &IpAddr, b: &IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(x), IpAddr::V4(y)) => x.octets()[..3] == y.octets()[..3],
        (IpAddr::V6(x), IpAddr::V6(y)) => x.segments()[..3] == y.segments()[..3],
        _ => false,
    }
}

/// 受け身で見た答えが、DoH の答え（と過去に DoH で見た答え）のどれとも、
/// 同じ IP・同じ /24（IPv6 は /48）で重ならなければ true。
/// CDN は場所によって違う IP を返すので、/24 までは同じとみなす【要検証：誤検知の頻度】。
pub fn crosscheck_mismatch(passive: &[IpAddr], doh: &[IpAddr], history: &[IpAddr]) -> bool {
    if passive.is_empty() || doh.is_empty() {
        return false;
    }
    let refs: Vec<&IpAddr> = doh.iter().chain(history.iter()).collect();
    !passive.iter().any(|p| refs.iter().any(|r| *r == p || same_net(p, r)))
}

/// Cloudflare の DoH（JSON 形式、`application/dns-json`）の応答から A/AAAA を読む
pub fn parse_doh_json(v: &serde_json::Value) -> Option<Vec<IpAddr>> {
    // Status 0 = NOERROR
    if v.get("Status")?.as_u64()? != 0 {
        return None;
    }
    let mut out: Vec<IpAddr> = v
        .get("Answer")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter(|x| matches!(x.get("type").and_then(|t| t.as_u64()), Some(1) | Some(28)))
                .filter_map(|x| x.get("data")?.as_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out.dedup();
    Some(out)
}

// ---------------- N6 想定外の DNS サーバー ----------------

/// インターネット上の、設定にない DNS サーバーから応答が来た
pub fn unexpected_resolver(server: &IpAddr, known: &[IpAddr]) -> bool {
    netclass::scope(server) == "internet" && !known.contains(server)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn w() -> Vec<String> {
        vec!["registry.npmjs.org".into(), "github.com".into()]
    }

    #[test]
    fn hosts_diff_and_redirect() {
        let old = "127.0.0.1 localhost\n255.255.255.255 broadcasthost\n::1 localhost\n";
        let new = format!("{old}203.0.113.66 registry.npmjs.org # 書き換え\n0.0.0.0 ads.example.com\n");
        let r = hosts_check(Some(old), &new, &w());
        assert!(r.changed());
        assert_eq!(r.added, vec!["0.0.0.0 ads.example.com", "203.0.113.66 registry.npmjs.org"]);
        assert_eq!(r.redirected, vec!["203.0.113.66 registry.npmjs.org"]);
        // ループバックへのブロックは誘導ではない
        let r = hosts_check(None, "127.0.0.1 api.github.com", &w());
        assert!(!r.changed());
        assert_eq!(r.watched.len(), 1);
        assert!(r.redirected.is_empty());
        // 壊れた行は無視
        assert!(parse_hosts("not-an-ip foo\n# c\n\n").is_empty());
    }

    #[test]
    fn resolvers() {
        let rc = "# x\nnameserver 192.168.1.1\nnameserver fe80::1%en0\nsearch lan\n";
        assert_eq!(parse_resolv_conf(rc), vec![ip("192.168.1.1"), ip("fe80::1")]);
        let sc = "resolver #1\n  nameserver[0] : 127.0.2.2\n  nameserver[1] : 2606:4700:4700::1111\nresolver #2\n  nameserver[0] : 100.100.100.100\n";
        assert_eq!(parse_scutil_dns(sc), vec![ip("100.100.100.100"), ip("127.0.2.2"), ip("2606:4700:4700::1111")]);
        let c = resolver_change(&[ip("192.168.1.1")], &[ip("198.51.100.53")]).unwrap();
        assert_eq!(c.added_scope, "internet");
        assert_eq!(c.unknown_public, vec![ip("198.51.100.53")]);
        let c = resolver_change(&[ip("192.168.1.1")], &[ip("1.1.1.1")]).unwrap();
        assert!(c.unknown_public.is_empty());
        assert_eq!(resolver_change(&[ip("1.1.1.1")], &[ip("1.1.1.1")]), None);
    }

    #[test]
    fn private_answer_rules() {
        let ok: Vec<String> = vec!["corp.example.co.jp".into()];
        assert_eq!(private_answers("api.example.com", &[ip("127.0.0.1")], &ok), vec![ip("127.0.0.1")]);
        assert_eq!(private_answers("api.example.com", &[ip("10.0.0.5"), ip("203.0.113.1")], &ok), vec![ip("10.0.0.5")]);
        assert!(private_answers("ads.example.com", &[ip("0.0.0.0")], &ok).is_empty());
        assert!(private_answers("nas.local", &[ip("192.168.1.2")], &ok).is_empty());
        assert!(private_answers("box.tail1234.ts.net", &[ip("100.101.1.2")], &ok).is_empty());
        assert!(private_answers("git.corp.example.co.jp", &[ip("10.1.1.1")], &ok).is_empty());
        assert!(private_answers("router", &[ip("192.168.1.1")], &ok).is_empty());
    }

    #[test]
    fn conflicts() {
        let mut t = ConflictTracker::default();
        let (s, c) = (ip("192.0.2.53"), ip("192.0.2.10"));
        assert!(t.observe(s, c, 5000, 7, "a.example.com", &[ip("203.0.113.1")], 0).is_none());
        // 同じ中身の再送は競合ではない
        assert!(t.observe(s, c, 5000, 7, "a.example.com", &[ip("203.0.113.1")], 1).is_none());
        let x = t.observe(s, c, 5000, 7, "a.example.com", &[ip("198.51.100.66")], 2).unwrap();
        assert_eq!(x.0, vec![ip("203.0.113.1")]);
        // 時間が空けば別の問い合わせ
        assert!(t.observe(s, c, 5000, 7, "a.example.com", &[ip("203.0.113.1")], 30).is_none());
    }

    #[test]
    fn crosscheck() {
        let p = [ip("203.0.113.10")];
        assert!(!crosscheck_mismatch(&p, &[ip("203.0.113.99")], &[]));
        assert!(crosscheck_mismatch(&p, &[ip("198.51.100.1")], &[]));
        assert!(!crosscheck_mismatch(&p, &[ip("198.51.100.1")], &[ip("203.0.113.200")]));
        assert!(!crosscheck_mismatch(&p, &[], &[]));
        let j = serde_json::json!({"Status":0,"Answer":[
            {"name":"github.com","type":1,"TTL":60,"data":"203.0.113.3"},
            {"name":"github.com","type":5,"TTL":60,"data":"x.example."}]});
        assert_eq!(parse_doh_json(&j), Some(vec![ip("203.0.113.3")]));
        assert_eq!(parse_doh_json(&serde_json::json!({"Status":3})), None);
    }

    #[test]
    fn unexpected() {
        assert!(unexpected_resolver(&ip("198.51.100.53"), &[ip("192.168.1.1")]));
        assert!(!unexpected_resolver(&ip("192.168.1.1"), &[]));
        assert!(!unexpected_resolver(&ip("1.1.1.1"), &[ip("1.1.1.1")]));
        assert!(watched("API.GitHub.com.", &w()));
        assert!(!watched("notgithub.com", &w()));
    }
}
