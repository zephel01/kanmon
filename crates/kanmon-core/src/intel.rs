//! 脅威インテリジェンス（拒否リスト）。IP・CIDR・ドメインの 3 種を 1 つの形式で読む。
//!
//! 読める形式（行単位）：
//! - `203.0.113.10` / `198.51.100.0/24` / `bad.example`（LuLu の拒否リストと同じ改行区切り）
//! - `#` `;` 以降はコメント。CSV の場合は先頭列のみ使う
//! - Spamhaus DROP の JSON 行（`{"cidr":"1.2.3.0/24",...}`）

use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Default, Clone)]
pub struct Intel {
    nets: Vec<(IpNet, String)>,
    ips: HashMap<IpAddr, String>,
    domains: HashMap<String, String>,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct LoadStats {
    pub ips: usize,
    pub nets: usize,
    pub domains: usize,
    pub skipped: usize,
}

impl LoadStats {
    pub fn total(&self) -> usize {
        self.ips + self.nets + self.domains
    }
}

fn is_domain(s: &str) -> bool {
    s.contains('.')
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        && !s.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

impl Intel {
    pub fn load_text(&mut self, text: &str, source: &str) -> LoadStats {
        let mut st = LoadStats::default();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') || line.starts_with("//") {
                continue;
            }
            let token: String = if line.starts_with('{') {
                match serde_json::from_str::<serde_json::Value>(line)
                    .ok()
                    .and_then(|v| v.get("cidr").and_then(|c| c.as_str()).map(str::to_string))
                {
                    Some(c) => c,
                    None => {
                        st.skipped += 1;
                        continue;
                    }
                }
            } else {
                let t = line.split(['#', ';', ',', ' ', '\t']).next().unwrap_or("").trim_matches('"');
                t.to_string()
            };
            if token.is_empty() {
                st.skipped += 1;
                continue;
            }
            if let Ok(ip) = token.parse::<IpAddr>() {
                self.ips.insert(ip, source.to_string());
                st.ips += 1;
            } else if let Ok(net) = token.parse::<IpNet>() {
                self.nets.push((net, source.to_string()));
                st.nets += 1;
            } else {
                let d = token.trim_start_matches("*.").trim_end_matches('.').to_ascii_lowercase();
                if is_domain(&d) {
                    self.domains.insert(d, source.to_string());
                    st.domains += 1;
                } else {
                    st.skipped += 1;
                }
            }
        }
        st
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty() && self.ips.is_empty() && self.domains.is_empty()
    }

    pub fn len(&self) -> usize {
        self.nets.len() + self.ips.len() + self.domains.len()
    }

    pub fn lookup_ip(&self, ip: &IpAddr) -> Option<&str> {
        let ip = match ip {
            IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(*ip),
            _ => *ip,
        };
        if let Some(s) = self.ips.get(&ip) {
            return Some(s);
        }
        self.nets.iter().find(|(n, _)| n.contains(&ip)).map(|(_, s)| s.as_str())
    }

    /// ドメインはサフィックス一致（`bad.example` を入れると `x.bad.example` も一致）
    pub fn lookup_domain(&self, host: &str) -> Option<&str> {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        let mut cur = h.as_str();
        loop {
            if let Some(s) = self.domains.get(cur) {
                return Some(s);
            }
            cur = &cur[cur.find('.')? + 1..];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_formats() {
        let mut i = Intel::default();
        let st = i.load_text(
            "# Feodo\n203.0.113.10\n198.51.100.0/24 ; SBL1\n{\"cidr\":\"192.0.2.0/24\",\"sblid\":\"x\"}\n\
             bad.example\n*.evil.test\n2001:db8::/32\nnot a thing!!\n",
            "test",
        );
        assert_eq!(st, LoadStats { ips: 1, nets: 3, domains: 2, skipped: 1 });
        let p = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(i.lookup_ip(&p("203.0.113.10")).is_some());
        assert!(i.lookup_ip(&p("198.51.100.77")).is_some());
        assert!(i.lookup_ip(&p("::ffff:192.0.2.5")).is_some());
        assert!(i.lookup_ip(&p("2001:db8::1")).is_some());
        assert!(i.lookup_ip(&p("8.8.8.8")).is_none());
        assert!(i.lookup_domain("x.Bad.Example.").is_some());
        assert!(i.lookup_domain("a.evil.test").is_some());
        assert!(i.lookup_domain("notbad.example").is_none());
    }
}
