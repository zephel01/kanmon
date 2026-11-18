//! 許可/拒否ルール（設計書 §7・§18.1 のサブセット）。
//! 第1弾は遮断しないため、照合結果は `kanmon.verdict`（allow / would_deny）として記録・通知に使う。
//!
//! 評価順（§7.1）：脅威インテル一致は呼び出し側で先に処理。ここではユーザールールのみ。
//! 具体性：プロセス指定 +4、宛先指定 +2、ポート指定 +1。最も具体的なものを採用し、同点なら deny 優先。

use anyhow::{Context, Result};
use chrono::{DateTime, FixedOffset, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;
use std::path::Path;

use crate::event::get_path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcMatch {
    /// signature / package / hash / path / any
    #[serde(rename = "match")]
    pub kind: String,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub package: Option<String>,
    pub sha256: Option<String>,
    pub path: Option<String>,
    pub interpreter_script: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Remote {
    pub domains: Vec<String>,
    pub cidrs: Vec<String>,
    /// internet / lan / loopback / any
    pub scope: Option<String>,
    pub ports: Vec<u16>,
    /// tcp / udp / any
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Lifetime {
    /// always / until
    pub kind: String,
    pub until: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub action: Action,
    /// outbound / inbound / both
    #[serde(default = "both")]
    pub direction: String,
    #[serde(default)]
    pub process: ProcMatch,
    #[serde(default)]
    pub remote: Remote,
    #[serde(default)]
    pub local_port: Option<u16>,
    #[serde(default)]
    pub lifetime: Lifetime,
    #[serde(default)]
    pub note: String,
}

fn yes() -> bool {
    true
}
fn both() -> String {
    "both".into()
}

#[derive(Debug, Default)]
pub struct RuleSet {
    pub rules: Vec<(Rule, Vec<IpNet>)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub action: Action,
    pub rule_id: String,
}

fn s<'a>(ev: &'a Value, p: &str) -> Option<&'a str> {
    get_path(ev, p).and_then(|v| v.as_str())
}

fn domain_match(pat: &str, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let pat = pat.to_ascii_lowercase();
    match pat.strip_prefix("*.") {
        Some(base) => host == base || host.ends_with(&format!(".{base}")),
        None => host == pat,
    }
}

impl RuleSet {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Self::from_json(&text).with_context(|| format!("parse {}", path.display()))
    }

    pub fn from_json(text: &str) -> Result<Self> {
        let rules: Vec<Rule> = serde_json::from_str(text)?;
        let mut out = vec![];
        for r in rules {
            let nets = r
                .remote
                .cidrs
                .iter()
                .map(|c| c.parse::<IpNet>().with_context(|| format!("rule {}: cidr {c}", r.id)))
                .collect::<Result<Vec<_>>>()?;
            out.push((r, nets));
        }
        Ok(Self { rules: out })
    }

    fn proc_matches(m: &ProcMatch, ev: &Value) -> bool {
        let eq = |want: &Option<String>, path: &str| want.as_deref().is_none_or(|w| s(ev, path) == Some(w));
        let script_ok = eq(&m.interpreter_script, "process.script");
        script_ok
            && match m.kind.as_str() {
                "" | "any" => true,
                "signature" => {
                    (m.team_id.is_some() || m.signing_id.is_some())
                        && eq(&m.team_id, "process.code_signature.team_id")
                        && eq(&m.signing_id, "process.code_signature.signing_id")
                }
                "package" => m.package.is_some() && eq(&m.package, "process.code_signature.package"),
                "hash" => m.sha256.is_some() && eq(&m.sha256, "process.hash.sha256"),
                "path" => m.path.is_some() && eq(&m.path, "process.executable"),
                _ => false,
            }
    }

    fn rule_matches(r: &Rule, nets: &[IpNet], ev: &Value, now: DateTime<Utc>) -> bool {
        if !r.enabled {
            return false;
        }
        if r.lifetime.kind == "until" {
            let exp = r.lifetime.until.as_deref().and_then(|u| DateTime::<FixedOffset>::parse_from_rfc3339(u).ok());
            if exp.is_none_or(|e| e.with_timezone(&Utc) < now) {
                return false;
            }
        }
        let dir = s(ev, "network.direction").unwrap_or("");
        if r.direction != "both" && r.direction != dir {
            return false;
        }
        if !Self::proc_matches(&r.process, ev) {
            return false;
        }
        let rm = &r.remote;
        if let Some(p) = rm.protocol.as_deref() {
            if p != "any" && s(ev, "network.transport") != Some(p) {
                return false;
            }
        }
        if let Some(sc) = rm.scope.as_deref() {
            if sc != "any" && s(ev, "network.scope") != Some(sc) {
                return false;
            }
        }
        if !rm.ports.is_empty() {
            let port = get_path(ev, "destination.port").and_then(|v| v.as_u64());
            if !port.is_some_and(|p| rm.ports.iter().any(|x| *x as u64 == p)) {
                return false;
            }
        }
        if let Some(lp) = r.local_port {
            if get_path(ev, "source.port").and_then(|v| v.as_u64()) != Some(lp as u64) {
                return false;
            }
        }
        if !rm.domains.is_empty() || !nets.is_empty() {
            let dom_ok = s(ev, "destination.domain").is_some_and(|h| rm.domains.iter().any(|p| domain_match(p, h)));
            let ip_ok = s(ev, "destination.ip")
                .and_then(|i| i.parse::<IpAddr>().ok())
                .is_some_and(|ip| nets.iter().any(|n| n.contains(&ip)));
            if !dom_ok && !ip_ok {
                return false;
            }
        }
        true
    }

    fn specificity(r: &Rule, nets: &[IpNet]) -> u8 {
        let p = !matches!(r.process.kind.as_str(), "" | "any") as u8 * 4;
        let d = (!r.remote.domains.is_empty() || !nets.is_empty()) as u8 * 2;
        let po = (!r.remote.ports.is_empty() || r.local_port.is_some()) as u8;
        p + d + po
    }

    pub fn evaluate(&self, ev: &Value) -> Option<Verdict> {
        self.evaluate_at(ev, Utc::now())
    }

    pub fn evaluate_at(&self, ev: &Value, now: DateTime<Utc>) -> Option<Verdict> {
        self.rules
            .iter()
            .filter(|(r, n)| Self::rule_matches(r, n, ev, now))
            .max_by_key(|(r, n)| (Self::specificity(r, n), r.action == Action::Deny))
            .map(|(r, _)| Verdict { action: r.action, rule_id: r.id.clone() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const R: &str = r#"[
      {"id":"allow-vscode","action":"allow","direction":"outbound",
       "process":{"match":"signature","team_id":"UBF8T346G9","signing_id":"com.microsoft.VSCode"},
       "remote":{"domains":["*.githubusercontent.com","github.com"],"ports":[443],"protocol":"tcp"}},
      {"id":"deny-vscode-all","action":"deny","process":{"match":"signature","team_id":"UBF8T346G9"}},
      {"id":"allow-doc-net","action":"allow","remote":{"cidrs":["198.51.100.0/24"]}},
      {"id":"expired","action":"deny","remote":{"cidrs":["198.51.100.0/24"]},
       "lifetime":{"kind":"until","until":"2020-01-01T00:00:00+09:00"}}
    ]"#;

    fn ev(domain: &str, ip: &str, port: u16) -> Value {
        json!({
            "network": {"direction":"outbound","transport":"tcp","scope":"internet"},
            "process": {"code_signature": {"status":"developer_id","team_id":"UBF8T346G9","signing_id":"com.microsoft.VSCode"}},
            "destination": {"domain": domain, "ip": ip, "port": port}
        })
    }

    #[test]
    fn specificity_and_expiry() {
        let rs = RuleSet::from_json(R).unwrap();
        let v = rs.evaluate(&ev("raw.githubusercontent.com", "185.199.108.133", 443)).unwrap();
        assert_eq!(v.rule_id, "allow-vscode");
        let v = rs.evaluate(&ev("example.com", "93.184.215.14", 443)).unwrap();
        assert_eq!(v.rule_id, "deny-vscode-all");
        // プロセス指定(4) の deny が 宛先指定(2) の allow に勝つ
        let v = rs.evaluate(&ev("", "198.51.100.3", 443)).unwrap();
        assert_eq!(v.rule_id, "deny-vscode-all");
        let mut e = ev("", "198.51.100.3", 443);
        e["process"] = json!({});
        assert_eq!(rs.evaluate(&e).unwrap().rule_id, "allow-doc-net");
    }
}
