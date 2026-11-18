//! DNS の改ざん検知のうち、OS に触る部分：DNS サーバー設定の読み取りと、DoH での引き直し。
//! 判定そのものは kanmon-core の dnsguard（純関数）。

use anyhow::{bail, Result};
use kanmon_core::dnsguard;
use std::io::Read;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

const MAX_DOH_BYTES: u64 = 64 * 1024;

/// 今の DNS サーバー一覧。macOS は `scutil --dns`（引数で渡し、シェルを通さない）、Linux は resolv.conf 群
pub fn read_resolvers(resolv_conf: &[PathBuf]) -> Vec<IpAddr> {
    if cfg!(target_os = "macos") {
        return std::process::Command::new("/usr/sbin/scutil")
            .arg("--dns")
            .output()
            .map(|o| dnsguard::parse_scutil_dns(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default();
    }
    let mut v: Vec<IpAddr> = resolv_conf
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .flat_map(|t| dnsguard::parse_resolv_conf(&t))
        .collect();
    v.sort();
    v.dedup();
    v
}

fn doh_one(url: &str, name: &str, rtype: &str) -> Result<Vec<IpAddr>> {
    if !url.starts_with("https://") {
        bail!("DoH は https のみ: {url}");
    }
    // name は DNS パケットから読んだもので、英数字・ハイフン・下線・ドットに限ってある（wire::label_ok）
    let resp = ureq::get(url)
        .query("name", name)
        .query("type", rtype)
        .set("accept", "application/dns-json")
        .timeout(Duration::from_secs(5))
        .call()?;
    let mut buf = Vec::new();
    resp.into_reader().take(MAX_DOH_BYTES + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_DOH_BYTES {
        bail!("DoH の応答が大きすぎます");
    }
    let v: serde_json::Value = serde_json::from_slice(&buf)?;
    dnsguard::parse_doh_json(&v).ok_or_else(|| anyhow::anyhow!("DoH の応答を解釈できません"))
}

/// A と AAAA を引く（ブロッキング。別スレッドから呼ぶ）
pub fn doh_lookup(url: &str, name: &str) -> Result<Vec<IpAddr>> {
    let mut v = doh_one(url, name, "A")?;
    if let Ok(mut six) = doh_one(url, name, "AAAA") {
        v.append(&mut six);
    }
    v.sort();
    v.dedup();
    Ok(v)
}
