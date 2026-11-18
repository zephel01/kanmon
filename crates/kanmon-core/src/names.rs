//! 宛先 IP → ドメイン名の対応表（受け身で読んだ DNS 応答と TLS の SNI から作る）。
//!
//! - 接続ごとの SNI（送信元・宛先のアドレスとポートの組）を最優先にする。
//! - 次に、DNS 応答で見た「問い合わせた名前」を使う（CNAME の先ではなく、アプリが引いた名前）。
//! - 1 つの IP を複数の名前が共有する CDN では、最後に見た名前になる（推定であることを
//!   `destination.domain_source` に残す）。
//! - 時刻は呼び出し側が渡す（UNIX 秒）。テストしやすくするため。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

/// DNS の TTL が短くても、接続は TTL 切れの後も同じ IP を使い続けるので猶予を持たせる
const GRACE_S: i64 = 3600;
const MIN_TTL: i64 = 60;
const MAX_TTL: i64 = 6 * 3600;
const MAX_IPS: usize = 50_000;
const MAX_FLOWS: usize = 20_000;
const FLOW_TTL_S: i64 = 600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Named {
    pub name: String,
    /// `sni`（接続の TLS ClientHello）/ `dns`（DNS 応答）/ `sni_ip`（同じ IP への別接続の SNI）
    pub source: &'static str,
}

#[derive(Debug, Clone)]
struct Entry {
    name: String,
    source: &'static str,
    expires: i64,
    seen: i64,
}

#[derive(Debug, Default)]
pub struct NameCache {
    by_ip: HashMap<IpAddr, Entry>,
    flows: HashMap<(SocketAddr, SocketAddr), (String, i64)>,
}

impl NameCache {
    pub fn len(&self) -> usize {
        self.by_ip.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_ip.is_empty()
    }

    /// DNS 応答で見た IP と名前
    pub fn insert_dns(&mut self, ip: IpAddr, name: &str, ttl: u32, now: i64) {
        let ttl = (ttl as i64).clamp(MIN_TTL, MAX_TTL);
        self.put(ip, name, "dns", now + ttl + GRACE_S, now);
    }

    /// TLS ClientHello の SNI（接続の組と、宛先 IP の両方に残す）
    pub fn insert_sni(&mut self, local: SocketAddr, remote: SocketAddr, name: &str, now: i64) {
        if self.flows.len() >= MAX_FLOWS {
            self.flows.retain(|_, (_, t)| now - *t < FLOW_TTL_S);
            if self.flows.len() >= MAX_FLOWS {
                self.flows.clear();
            }
        }
        self.flows.insert((local, remote), (name.to_string(), now));
        // DNS で別の名前を見ている IP は上書きしない（共有 IP では DNS の方が当てになることが多い）
        let keep_dns = self.by_ip.get(&remote.ip()).is_some_and(|e| e.source == "dns" && e.expires > now);
        if !keep_dns {
            self.put(remote.ip(), name, "sni_ip", now + MAX_TTL, now);
        }
    }

    fn put(&mut self, ip: IpAddr, name: &str, source: &'static str, expires: i64, now: i64) {
        if self.by_ip.len() >= MAX_IPS && !self.by_ip.contains_key(&ip) {
            self.prune(now);
            if self.by_ip.len() >= MAX_IPS {
                // 最も古く見たものから 1 割を捨てる
                let mut v: Vec<(IpAddr, i64)> = self.by_ip.iter().map(|(k, e)| (*k, e.seen)).collect();
                v.sort_by_key(|(_, s)| *s);
                for (k, _) in v.into_iter().take(MAX_IPS / 10) {
                    self.by_ip.remove(&k);
                }
            }
        }
        self.by_ip.insert(ip, Entry { name: name.to_string(), source, expires, seen: now });
    }

    pub fn prune(&mut self, now: i64) {
        self.by_ip.retain(|_, e| e.expires > now);
        self.flows.retain(|_, (_, t)| now - *t < FLOW_TTL_S);
    }

    /// 接続の名前を引く。`local` が分かれば SNI の組を先に見る
    pub fn lookup(&self, local: Option<SocketAddr>, remote: SocketAddr, now: i64) -> Option<Named> {
        if let Some(l) = local {
            if let Some((n, t)) = self.flows.get(&(l, remote)) {
                if now - *t < FLOW_TTL_S {
                    return Some(Named { name: n.clone(), source: "sni" });
                }
            }
        }
        let e = self.by_ip.get(&remote.ip())?;
        (e.expires > now).then(|| Named { name: e.name.clone(), source: e.source })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn sni_beats_dns_for_its_flow() {
        let mut c = NameCache::default();
        let r = sa("203.0.113.5:443");
        c.insert_dns(r.ip(), "cdn.example.com", 30, 1000);
        c.insert_sni(sa("192.0.2.10:50000"), r, "api.example.org", 1001);
        assert_eq!(
            c.lookup(Some(sa("192.0.2.10:50000")), r, 1002),
            Some(Named { name: "api.example.org".into(), source: "sni" })
        );
        // 別の接続は DNS の名前（SNI は DNS を上書きしない）
        assert_eq!(c.lookup(Some(sa("192.0.2.10:50001")), r, 1002).unwrap().name, "cdn.example.com");
    }

    #[test]
    fn ttl_and_grace() {
        let mut c = NameCache::default();
        let r = sa("203.0.113.6:443");
        c.insert_dns(r.ip(), "a.example.com", 10, 0);
        // TTL は最低 60 秒＋猶予 1 時間
        assert!(c.lookup(None, r, 60 + 3599).is_some());
        assert!(c.lookup(None, r, 60 + 3601).is_none());
        c.prune(10_000);
        assert!(c.is_empty());
    }

    #[test]
    fn sni_only_ip() {
        let mut c = NameCache::default();
        let r = sa("203.0.113.7:443");
        c.insert_sni(sa("192.0.2.10:1"), r, "s.example.com", 0);
        assert_eq!(c.lookup(None, r, 10), Some(Named { name: "s.example.com".into(), source: "sni_ip" }));
    }
}
