//! DNS の改ざん検知のうち、OS に触る部分：DNS サーバー設定の読み取りと、DoH での引き直し。
//! 判定そのものは kanmon-core の dnsguard（純関数）。

use anyhow::{bail, Result};
use kanmon_core::dnsguard;
use std::io::Read;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
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

/// 証明書の確認結果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsVerdict {
    /// そのドメインの正しい証明書が出た
    Valid,
    /// 証明書の検証に失敗した（名前が違う・信頼できない発行者・期限切れ等）
    Invalid(String),
    /// 接続できない等で判断できない
    Inconclusive(String),
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // OS に入っている証明書（社内の TLS 検査の証明書等）も信頼する。読めないものは無視
        for c in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(c);
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("TLS の既定の版")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(cfg)
    })
    .clone()
}

/// `ip:443` に `name` として TLS で接続し、証明書を検証する（ハンドシェイクだけ。HTTP は送らない）
pub fn verify_tls(ip: IpAddr, name: &str) -> TlsVerdict {
    verify_tls_with(tls_config(), std::net::SocketAddr::new(ip, 443), name)
}

fn verify_tls_with(cfg: Arc<rustls::ClientConfig>, addr: std::net::SocketAddr, name: &str) -> TlsVerdict {
    use std::net::TcpStream;
    let Ok(sn) = rustls::pki_types::ServerName::try_from(name.to_string()) else {
        return TlsVerdict::Inconclusive("名前が不正".into());
    };
    let mut sock = match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
        Ok(s) => s,
        Err(e) => return TlsVerdict::Inconclusive(format!("接続できない: {e}")),
    };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(4)));
    let _ = sock.set_write_timeout(Some(Duration::from_secs(4)));
    let mut conn = match rustls::ClientConnection::new(cfg, sn) {
        Ok(c) => c,
        Err(e) => return TlsVerdict::Inconclusive(format!("{e}")),
    };
    while conn.is_handshaking() {
        if let Err(e) = conn.complete_io(&mut sock) {
            let inner = e.get_ref().and_then(|x| x.downcast_ref::<rustls::Error>());
            return match inner {
                Some(rustls::Error::InvalidCertificate(c)) => TlsVerdict::Invalid(format!("{c:?}")),
                _ => TlsVerdict::Inconclusive(format!("{e}")),
            };
        }
    }
    conn.send_close_notify();
    let _ = conn.complete_io(&mut sock);
    TlsVerdict::Valid
}

/// N3 の確認：DoH で引き直し、食い違ったら答えの IP の証明書を確かめる（ブロッキング）
pub struct Crosscheck {
    pub doh: Vec<IpAddr>,
    /// DoH の答え（と履歴）と /24 でも重ならなかった
    pub mismatch: bool,
    /// 食い違ったときの、受け身で見た IP ごとの証明書の確認（最大 3 件）
    pub tls: Vec<(IpAddr, TlsVerdict)>,
}

impl Crosscheck {
    /// 証明書の検証に失敗した IP があり、正しい証明書を出した IP が 1 つも無い
    pub fn tampered(&self) -> bool {
        self.mismatch
            && self.tls.iter().any(|(_, v)| matches!(v, TlsVerdict::Invalid(_)))
            && !self.tls.iter().any(|(_, v)| *v == TlsVerdict::Valid)
    }
}

pub fn crosscheck(url: &str, name: &str, passive: &[IpAddr], history: &[IpAddr]) -> Result<Crosscheck> {
    let doh = doh_lookup(url, name)?;
    let mismatch = dnsguard::crosscheck_mismatch(passive, &doh, history);
    let tls = if mismatch { passive.iter().take(3).map(|ip| (*ip, verify_tls(*ip, name))).collect() } else { vec![] };
    Ok(Crosscheck { doh, mismatch, tls })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddr, TcpListener};

    /// 自己署名の証明書（名前 `kanmon-test.example`）で TLS を話すローカルのサーバー
    fn server() -> (SocketAddr, rustls::pki_types::CertificateDer<'static>) {
        let ck = rcgen::generate_simple_self_signed(vec!["kanmon-test.example".to_string()]).unwrap();
        let cert = ck.cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(ck.key_pair.serialize_der().into());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let scfg = Arc::new(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert.clone()], key)
                .unwrap(),
        );
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for s in l.incoming().take(3).flatten() {
                let mut s = s;
                let mut c = rustls::ServerConnection::new(scfg.clone()).unwrap();
                while c.is_handshaking() {
                    if c.complete_io(&mut s).is_err() {
                        break;
                    }
                }
            }
        });
        (addr, cert)
    }

    fn cfg_trusting(cert: &rustls::pki_types::CertificateDer<'static>) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Arc::new(
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    #[test]
    fn tls_verdicts() {
        let (addr, cert) = server();
        // 発行者を信頼していれば正しい
        assert_eq!(verify_tls_with(cfg_trusting(&cert), addr, "kanmon-test.example"), TlsVerdict::Valid);
        // 名前が違えば失敗
        assert!(matches!(verify_tls_with(cfg_trusting(&cert), addr, "other.example"), TlsVerdict::Invalid(_)));
        // 公開の認証局の一覧では、自己署名は信頼されない（偽サーバーの典型）
        assert!(matches!(verify_tls_with(tls_config(), addr, "kanmon-test.example"), TlsVerdict::Invalid(_)));
        // 接続できなければ判断しない
        let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        assert!(matches!(verify_tls_with(tls_config(), closed, "kanmon-test.example"), TlsVerdict::Inconclusive(_)));
    }

    #[test]
    fn tampered_needs_invalid_and_no_valid() {
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let bad = TlsVerdict::Invalid("x".into());
        let mk = |tls| Crosscheck { doh: vec![], mismatch: true, tls };
        assert!(mk(vec![(ip, bad.clone())]).tampered());
        assert!(!mk(vec![(ip, bad.clone()), (ip, TlsVerdict::Valid)]).tampered());
        assert!(!mk(vec![(ip, TlsVerdict::Inconclusive("t".into()))]).tampered());
        assert!(!Crosscheck { doh: vec![], mismatch: false, tls: vec![(ip, bad)] }.tampered());
    }
}
