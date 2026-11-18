//! レジストリ（PyPI・npm）から版の情報とアーカイブを取る。
//!
//! - https のみ。許可するホストは pypi.org・files.pythonhosted.org・registry.npmjs.org だけ。
//!   リダイレクトは自分で判定し、許可リストの外へは行かない
//! - TLS の検証は外さない。ダウンロードしたアーカイブはレジストリが示すハッシュと照合する
//! - パッケージ名・版は呼び出し前に `kanmon_core::inspect::parse_spec` で検証済みであること

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use kanmon_core::inspect::{valid_name, valid_version, Ecosystem, Meta};
use serde_json::Value;
use sha2::{Digest as _, Sha256, Sha512};
use std::io::Read;
use std::time::Duration;

pub const ALLOWED_HOSTS: &[&str] = &["pypi.org", "files.pythonhosted.org", "registry.npmjs.org"];

/// 取得口。テストではメモリ上の偽物に差し替える
pub trait Fetcher {
    fn get(&self, url: &str, max: u64) -> Result<Vec<u8>>;
}

/// URL が https で、許可したホスト（ポート指定・利用者情報なし）か
pub fn allowed_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else { return false };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    !host.contains('@') && !host.contains(':') && ALLOWED_HOSTS.contains(&host.to_ascii_lowercase().as_str())
}

/// TLS の設定：同梱のルート証明書に加え、OS に入っている証明書（社内の TLS 検査の証明書等。
/// `SSL_CERT_FILE` も効く）も信頼する。検証そのものは外さない
fn tls_config() -> std::sync::Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for c in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(c);
    }
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS の既定の版")
        .with_root_certificates(roots)
        .with_no_client_auth();
    std::sync::Arc::new(cfg)
}

pub struct HttpFetcher {
    agent: ureq::Agent,
}

impl HttpFetcher {
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .tls_config(tls_config())
            .redirects(0)
            .timeout_connect(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .user_agent(concat!("kanmonctl/", env!("CARGO_PKG_VERSION"), " (inspect)"))
            .build();
        Self { agent }
    }
}

impl Fetcher for HttpFetcher {
    fn get(&self, url: &str, max: u64) -> Result<Vec<u8>> {
        let mut cur = url.to_string();
        for _ in 0..5 {
            if !allowed_url(&cur) {
                bail!("許可していない取得先です: {cur}");
            }
            let resp = match self.agent.get(&cur).call() {
                Ok(r) => r,
                Err(ureq::Error::Status(code, r)) if (300..400).contains(&code) => r,
                Err(ureq::Error::Status(code, _)) => bail!("HTTP {code}: {cur}"),
                Err(e) => return Err(anyhow!("取得できません: {e}")),
            };
            if (300..400).contains(&resp.status()) {
                let loc = resp.header("location").ok_or_else(|| anyhow!("リダイレクト先がありません"))?;
                cur = if loc.starts_with('/') {
                    let host = cur.trim_start_matches("https://").split('/').next().unwrap_or("");
                    format!("https://{host}{loc}")
                } else {
                    loc.to_string()
                };
                continue;
            }
            let mut buf = vec![];
            resp.into_reader().take(max + 1).read_to_end(&mut buf)?;
            if buf.len() as u64 > max {
                bail!("応答が大きすぎます（上限 {max} バイト）");
            }
            return Ok(buf);
        }
        bail!("リダイレクトが多すぎます")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Digest {
    Sha256(String),
    /// npm の `dist.integrity`（`sha512-` の後ろの base64）
    Sha512B64(String),
}

#[derive(Debug, Clone)]
pub struct Artifact {
    pub url: String,
    pub digest: Digest,
    pub filename: String,
}

#[derive(Debug)]
pub struct Resolved {
    pub meta: Meta,
    pub target: Artifact,
    pub base: Option<Artifact>,
}

fn ts(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s).ok().map(|d| d.timestamp())
}

/// プレリリースらしい版か（比較相手の候補から外す）
fn prerelease(eco: Ecosystem, v: &str) -> bool {
    match eco {
        Ecosystem::Npm => v.contains('-'),
        Ecosystem::Pypi => {
            let l = v.to_ascii_lowercase();
            ["a", "b", "rc", "dev", "alpha", "beta", "pre"]
                .iter()
                .any(|t| l.split(|c: char| c.is_ascii_digit() || c == '.').any(|seg| seg == *t))
        }
    }
}

/// 版の数字の並び（`1.26.2` → [1, 26, 2]、`2.0.0b3` → [2, 0, 0, 3]）。比べるためだけに使う
fn ver_key(v: &str) -> Vec<u64> {
    v.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty()).take(6).filter_map(|s| s.parse().ok()).collect()
}

/// 比較相手：対象より前に公開され、版の番号が対象より小さいもののうち、番号が最も大きいもの。
/// 公開時刻だけで選ぶと、古い系列の保守版（8.3.8 に対する 6.4.6 等）を選んで差分が大きくなるため
fn pick_base(eco: Ecosystem, target: &str, times: &[(String, i64)]) -> Option<String> {
    let t = times.iter().find(|(v, _)| v == target)?.1;
    let tk = ver_key(target);
    let pre_ok = prerelease(eco, target);
    let cands: Vec<&(String, i64)> =
        times.iter().filter(|(v, at)| v != target && *at < t && (pre_ok || !prerelease(eco, v))).collect();
    cands
        .iter()
        .filter(|(v, _)| !tk.is_empty() && ver_key(v) < tk)
        .max_by(|a, b| ver_key(&a.0).cmp(&ver_key(&b.0)).then(a.1.cmp(&b.1)))
        .or_else(|| cands.iter().max_by_key(|(_, at)| *at))
        .map(|(v, _)| v.clone())
}

fn pypi_files(rel: &Value) -> Vec<&Value> {
    rel.as_array().map(|a| a.iter().filter(|f| !f["yanked"].as_bool().unwrap_or(false)).collect()).unwrap_or_default()
}

/// wheel（py3-none-any を優先）→ ほかの wheel → sdist の順に選ぶ。`like` があれば同じ形のファイル名を優先
fn pypi_choose<'a>(files: &[&'a Value], like: Option<&str>) -> Option<&'a Value> {
    let name = |f: &Value| f["filename"].as_str().unwrap_or("").to_string();
    if let Some(l) = like {
        if let Some(f) = files.iter().find(|f| tag_of(&name(f)) == tag_of(l)) {
            return Some(f);
        }
    }
    files
        .iter()
        .find(|f| name(f).ends_with("py3-none-any.whl"))
        .or_else(|| files.iter().find(|f| name(f).ends_with(".whl")))
        .or_else(|| files.iter().find(|f| name(f).ends_with(".tar.gz") || name(f).ends_with(".zip")))
        .copied()
}

/// wheel のタグ部分（`name-ver-` の後ろ）。sdist は拡張子
fn tag_of(filename: &str) -> String {
    if let Some(stem) = filename.strip_suffix(".whl") {
        stem.splitn(3, '-').nth(2).unwrap_or("").to_string()
    } else if filename.ends_with(".tar.gz") {
        "sdist.tar.gz".into()
    } else {
        "sdist.zip".into()
    }
}

fn pypi_artifact(f: &Value) -> Result<Artifact> {
    let url = f["url"].as_str().ok_or_else(|| anyhow!("ファイルの URL がありません"))?.to_string();
    let sha = f["digests"]["sha256"].as_str().ok_or_else(|| anyhow!("sha256 がありません"))?;
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("sha256 の形が正しくありません");
    }
    Ok(Artifact {
        url,
        digest: Digest::Sha256(sha.to_ascii_lowercase()),
        filename: f["filename"].as_str().unwrap_or("").to_string(),
    })
}

fn resolve_pypi(f: &dyn Fetcher, name: &str, ver: Option<&str>, base: Option<&str>) -> Result<Resolved> {
    let body = f.get(&format!("https://pypi.org/pypi/{name}/json"), 64 * 1024 * 1024)?;
    let v: Value = serde_json::from_slice(&body).context("PyPI の応答を JSON として読めません")?;
    let target = match ver {
        Some(x) => x.to_string(),
        None => v["info"]["version"].as_str().ok_or_else(|| anyhow!("最新版が分かりません"))?.to_string(),
    };
    if !valid_version(&target) {
        bail!("版の形が正しくありません");
    }
    let rels = v["releases"].as_object().ok_or_else(|| anyhow!("releases がありません"))?;
    let mut times: Vec<(String, i64)> = vec![];
    for (rv, files) in rels {
        let fs = pypi_files(files);
        if let Some(t) = fs.iter().filter_map(|f| f["upload_time_iso_8601"].as_str().and_then(ts)).min() {
            times.push((rv.clone(), t));
        }
    }
    let tfiles = pypi_files(rels.get(&target).ok_or_else(|| anyhow!("版 {target} がありません"))?);
    let tf = pypi_choose(&tfiles, None).ok_or_else(|| anyhow!("版 {target} に取れるファイルがありません"))?;
    let target_art = pypi_artifact(tf)?;
    let base_ver = match base {
        Some(b) => Some(b.to_string()),
        None => pick_base(Ecosystem::Pypi, &target, &times),
    };
    let base_art = match &base_ver {
        Some(b) => {
            if !valid_version(b) {
                bail!("比較する版の形が正しくありません");
            }
            let bf = pypi_files(rels.get(b).ok_or_else(|| anyhow!("比較する版 {b} がありません"))?);
            pypi_choose(&bf, Some(&target_art.filename)).map(pypi_artifact).transpose()?
        }
        None => None,
    };
    let when = |x: &str| times.iter().find(|(v, _)| v == x).map(|(_, t)| *t);
    let meta = Meta {
        name: name.to_string(),
        version: target.clone(),
        published: when(&target),
        base_published: base_ver.as_deref().and_then(when),
        base_version: base_ver,
        ..Default::default()
    };
    Ok(Resolved { meta, target: target_art, base: base_art })
}

fn npm_artifact(v: &Value, ver: &str) -> Result<Artifact> {
    let d = &v["versions"][ver]["dist"];
    let url = d["tarball"].as_str().ok_or_else(|| anyhow!("tarball がありません"))?.to_string();
    let integ = d["integrity"].as_str().ok_or_else(|| anyhow!("整合性の情報（integrity）がありません"))?;
    let b64 = integ.strip_prefix("sha512-").ok_or_else(|| anyhow!("sha512 の integrity ではありません"))?;
    Ok(Artifact { url, digest: Digest::Sha512B64(b64.to_string()), filename: format!("{ver}.tgz") })
}

fn resolve_npm(f: &dyn Fetcher, name: &str, ver: Option<&str>, base: Option<&str>) -> Result<Resolved> {
    let path = name.replacen('/', "%2f", 1);
    let body = f.get(&format!("https://registry.npmjs.org/{path}"), 128 * 1024 * 1024)?;
    let v: Value = serde_json::from_slice(&body).context("npm の応答を JSON として読めません")?;
    let target = match ver {
        Some(x) => x.to_string(),
        None => v["dist-tags"]["latest"].as_str().ok_or_else(|| anyhow!("最新版が分かりません"))?.to_string(),
    };
    if !valid_version(&target) {
        bail!("版の形が正しくありません");
    }
    if v["versions"].get(&target).is_none() {
        bail!("版 {target} がありません");
    }
    // 削除済みの版は time にだけ残るので、versions にあるものだけを候補にする
    let times: Vec<(String, i64)> = v["time"]
        .as_object()
        .map(|o| {
            o.iter()
                .filter(|(k, _)| v["versions"].get(k.as_str()).is_some())
                .filter_map(|(k, t)| t.as_str().and_then(ts).map(|t| (k.clone(), t)))
                .collect()
        })
        .unwrap_or_default();
    let base_ver = match base {
        Some(b) => Some(b.to_string()),
        None => pick_base(Ecosystem::Npm, &target, &times),
    };
    if let Some(b) = &base_ver {
        if !valid_version(b) || v["versions"].get(b).is_none() {
            bail!("比較する版 {b} がありません");
        }
    }
    let when = |x: &str| times.iter().find(|(k, _)| k == x).map(|(_, t)| *t);
    let user = |x: &str| v["versions"][x]["_npmUser"]["name"].as_str().map(str::to_string);
    let attested = |x: &str| Some(v["versions"][x]["dist"].get("attestations").is_some());
    let meta = Meta {
        name: name.to_string(),
        version: target.clone(),
        published: when(&target),
        base_published: base_ver.as_deref().and_then(when),
        publisher: user(&target),
        base_publisher: base_ver.as_deref().and_then(user),
        attested: attested(&target),
        base_attested: base_ver.as_deref().and_then(attested),
        base_version: base_ver.clone(),
    };
    Ok(Resolved {
        target: npm_artifact(&v, &target)?,
        base: base_ver.as_deref().map(|b| npm_artifact(&v, b)).transpose()?,
        meta,
    })
}

/// 版の情報を取り、対象と比較相手のアーカイブの場所を決める
pub fn resolve(f: &dyn Fetcher, eco: Ecosystem, name: &str, ver: Option<&str>, base: Option<&str>) -> Result<Resolved> {
    if !valid_name(eco, name) {
        bail!("パッケージ名の形が正しくありません");
    }
    match eco {
        Ecosystem::Pypi => resolve_pypi(f, name, ver, base),
        Ecosystem::Npm => resolve_npm(f, name, ver, base),
    }
}

/// 依存のパッケージが初めて公開された時刻（UNIX 秒）。レジストリに無ければ None
pub fn first_published(f: &dyn Fetcher, eco: Ecosystem, name: &str) -> Result<Option<i64>> {
    if !valid_name(eco, name) {
        bail!("パッケージ名の形が正しくありません");
    }
    let url = match eco {
        Ecosystem::Pypi => format!("https://pypi.org/pypi/{name}/json"),
        Ecosystem::Npm => format!("https://registry.npmjs.org/{}", name.replacen('/', "%2f", 1)),
    };
    let body = match f.get(&url, 128 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) if e.to_string().contains("HTTP 404") => return Ok(None),
        Err(e) => return Err(e),
    };
    let v: Value = serde_json::from_slice(&body).context("レジストリの応答を JSON として読めません")?;
    let t = match eco {
        Ecosystem::Npm => v["time"]["created"].as_str().and_then(ts),
        Ecosystem::Pypi => v["releases"]
            .as_object()
            .into_iter()
            .flatten()
            .flat_map(|(_, fs)| fs.as_array().into_iter().flatten())
            .filter_map(|x| x["upload_time_iso_8601"].as_str().and_then(ts))
            .min(),
    };
    Ok(t)
}

/// 取得してハッシュを照合する
pub fn download(f: &dyn Fetcher, a: &Artifact, max: u64) -> Result<Vec<u8>> {
    if !allowed_url(&a.url) {
        bail!("許可していない取得先です: {}", a.url);
    }
    let data = f.get(&a.url, max)?;
    let ok = match &a.digest {
        Digest::Sha256(h) => {
            let d = Sha256::digest(&data);
            d.iter().map(|b| format!("{b:02x}")).collect::<String>() == *h
        }
        Digest::Sha512B64(b) => base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&data)) == *b,
    };
    if !ok {
        bail!("ハッシュが合いません（取得したファイルがレジストリの記録と違う）: {}", a.url);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Fake(HashMap<String, Vec<u8>>);
    impl Fetcher for Fake {
        fn get(&self, url: &str, max: u64) -> Result<Vec<u8>> {
            let d = self.0.get(url).cloned().ok_or_else(|| anyhow!("404 {url}"))?;
            if d.len() as u64 > max {
                bail!("大きすぎる");
            }
            Ok(d)
        }
    }

    fn sha256hex(d: &[u8]) -> String {
        Sha256::digest(d).iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn hosts() {
        assert!(allowed_url("https://pypi.org/pypi/x/json"));
        assert!(allowed_url("https://files.pythonhosted.org/packages/a/b.whl"));
        assert!(!allowed_url("http://pypi.org/x"));
        assert!(!allowed_url("https://pypi.org.evil.example/x"));
        assert!(!allowed_url("https://user@pypi.org/x"));
        assert!(!allowed_url("https://pypi.org:8443/x"));
        assert!(!allowed_url("https://203.0.113.9/x"));
    }

    #[test]
    fn pypi_resolve_and_download() {
        let w_new = b"new wheel".to_vec();
        let w_old = b"old wheel".to_vec();
        let j = serde_json::json!({
            "info": {"version": "1.26.2"},
            "releases": {
                "1.26.0": [{"filename": "af-1.26.0-py3-none-any.whl", "url": "https://files.pythonhosted.org/af-1.26.0.whl",
                            "digests": {"sha256": sha256hex(&w_old)}, "upload_time_iso_8601": "2026-11-10T00:00:00Z", "yanked": false}],
                "1.26.1": [{"filename": "af-1.26.1-py3-none-any.whl", "url": "https://files.pythonhosted.org/af-1.26.1.whl",
                            "digests": {"sha256": "00"}, "upload_time_iso_8601": "2026-11-17T10:00:00Z", "yanked": true}],
                "1.26.2": [{"filename": "af-1.26.2.tar.gz", "url": "https://files.pythonhosted.org/af-1.26.2.tar.gz",
                            "digests": {"sha256": sha256hex(b"sdist")}, "upload_time_iso_8601": "2026-11-17T10:40:00Z", "yanked": false},
                           {"filename": "af-1.26.2-py3-none-any.whl", "url": "https://files.pythonhosted.org/af-1.26.2.whl",
                            "digests": {"sha256": sha256hex(&w_new)}, "upload_time_iso_8601": "2026-11-17T10:33:00Z", "yanked": false}],
                "1.27.0rc1": [{"filename": "af-1.27.0rc1-py3-none-any.whl", "url": "https://files.pythonhosted.org/rc.whl",
                            "digests": {"sha256": sha256hex(b"rc")}, "upload_time_iso_8601": "2026-11-16T00:00:00Z", "yanked": false}]
            }
        });
        let mut m = HashMap::new();
        m.insert("https://pypi.org/pypi/af/json".to_string(), serde_json::to_vec(&j).unwrap());
        m.insert("https://files.pythonhosted.org/af-1.26.2.whl".to_string(), w_new.clone());
        m.insert("https://files.pythonhosted.org/af-1.26.0.whl".to_string(), w_old.clone());
        let f = Fake(m);
        let r = resolve(&f, Ecosystem::Pypi, "af", None, None).unwrap();
        assert_eq!(r.meta.version, "1.26.2");
        // 取り下げ（yanked）とプレリリースは比較相手にしない
        assert_eq!(r.meta.base_version.as_deref(), Some("1.26.0"));
        assert!(r.target.filename.ends_with("py3-none-any.whl"));
        assert_eq!(download(&f, &r.target, 1 << 20).unwrap(), w_new);
        assert_eq!(download(&f, r.base.as_ref().unwrap(), 1 << 20).unwrap(), w_old);
        // ハッシュ不一致
        let mut bad = r.target.clone();
        bad.url = "https://files.pythonhosted.org/af-1.26.0.whl".into();
        assert!(download(&f, &bad, 1 << 20).is_err());
        // 大きすぎる
        assert!(download(&f, &r.target, 3).is_err());
        assert!(resolve(&f, Ecosystem::Pypi, "af", Some("9.9.9"), None).is_err());
    }

    #[test]
    fn npm_resolve() {
        let t_new = b"tgz new".to_vec();
        let integ =
            |d: &[u8]| format!("sha512-{}", base64::engine::general_purpose::STANDARD.encode(Sha512::digest(d)));
        let j = serde_json::json!({
            "dist-tags": {"latest": "6.0.0"},
            "versions": {
                "5.3.2": {"_npmUser": {"name": "maint"}, "dist": {"tarball": "https://registry.npmjs.org/keyv/-/keyv-5.3.2.tgz", "integrity": integ(b"old"), "attestations": {}}},
                "6.0.0": {"_npmUser": {"name": "other"}, "dist": {"tarball": "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz", "integrity": integ(&t_new)}},
                "6.0.0-beta.1": {"_npmUser": {"name": "maint"}, "dist": {"tarball": "https://registry.npmjs.org/keyv/-/b.tgz", "integrity": integ(b"b")}}
            },
            "time": {"created": "2020-01-01T00:00:00Z", "5.3.2": "2026-07-01T00:00:00Z", "5.9.9": "2026-08-01T00:00:00Z",
                     "6.0.0-beta.1": "2026-08-02T00:00:00Z", "6.0.0": "2026-08-04T00:00:00Z"}
        });
        let mut m = HashMap::new();
        m.insert("https://registry.npmjs.org/keyv".to_string(), serde_json::to_vec(&j).unwrap());
        m.insert("https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz".to_string(), t_new.clone());
        let f = Fake(m);
        let r = resolve(&f, Ecosystem::Npm, "keyv", Some("6.0.0"), None).unwrap();
        // 削除済み（versions に無い 5.9.9）とプレリリースは除く
        assert_eq!(r.meta.base_version.as_deref(), Some("5.3.2"));
        assert_eq!(r.meta.publisher.as_deref(), Some("other"));
        assert_eq!(r.meta.base_publisher.as_deref(), Some("maint"));
        assert_eq!((r.meta.attested, r.meta.base_attested), (Some(false), Some(true)));
        assert_eq!(download(&f, &r.target, 1 << 20).unwrap(), t_new);
        // スコープ付きの名前は %2f
        let mut m2 = HashMap::new();
        m2.insert("https://registry.npmjs.org/@s%2fp".to_string(), serde_json::to_vec(&j).unwrap());
        assert!(resolve(&Fake(m2), Ecosystem::Npm, "@s/p", Some("6.0.0"), None).is_ok());
        // 許可外ホストの tarball
        let mut a = r.target.clone();
        a.url = "https://203.0.113.9/x.tgz".into();
        assert!(download(&f, &a, 1 << 20).is_err());
    }

    #[test]
    fn base_prefers_same_line() {
        let t = |v: &str, at: i64| (v.to_string(), at);
        // 8.3.8 の直前に古い系列の 6.4.6 が出ていても、8.3.7 を選ぶ
        let times = vec![t("8.3.7", 10), t("6.4.6", 20), t("8.3.8", 30), t("9.0.0", 40)];
        assert_eq!(pick_base(Ecosystem::Npm, "8.3.8", &times).as_deref(), Some("8.3.7"));
        // 古い系列の保守版を調べるときは、その系列の前の版
        let times = vec![t("6.4.5", 5), t("8.3.7", 10), t("6.4.6", 20)];
        assert_eq!(pick_base(Ecosystem::Npm, "6.4.6", &times).as_deref(), Some("6.4.5"));
    }

    #[test]
    fn first_published_lookup() {
        struct F404;
        impl Fetcher for F404 {
            fn get(&self, _: &str, _: u64) -> Result<Vec<u8>> {
                bail!("HTTP 404: x")
            }
        }
        assert_eq!(first_published(&F404, Ecosystem::Npm, "easy-day-js").unwrap(), None);
        let mut m = HashMap::new();
        m.insert(
            "https://registry.npmjs.org/@s%2fp".to_string(),
            serde_json::to_vec(&serde_json::json!({"time": {"created": "2026-11-01T00:00:00Z"}})).unwrap(),
        );
        m.insert(
            "https://pypi.org/pypi/evil-pkg/json".to_string(),
            serde_json::to_vec(
                &serde_json::json!({"releases": {"0.1": [{"upload_time_iso_8601": "2026-11-10T00:00:00Z"}],
                "0.2": [{"upload_time_iso_8601": "2026-11-12T00:00:00Z"}]}}),
            )
            .unwrap(),
        );
        let f = Fake(m);
        assert_eq!(first_published(&f, Ecosystem::Npm, "@s/p").unwrap(), ts("2026-11-01T00:00:00Z"));
        assert_eq!(first_published(&f, Ecosystem::Pypi, "evil-pkg").unwrap(), ts("2026-11-10T00:00:00Z"));
        assert!(first_published(&f, Ecosystem::Npm, "../x").is_err());
    }

    #[test]
    fn prerelease_rules() {
        assert!(prerelease(Ecosystem::Pypi, "1.27.0rc1"));
        assert!(prerelease(Ecosystem::Pypi, "2.0.0b3"));
        assert!(prerelease(Ecosystem::Pypi, "1.0.dev4"));
        assert!(!prerelease(Ecosystem::Pypi, "1.26.2"));
        assert!(!prerelease(Ecosystem::Pypi, "1.0.post1"));
        assert!(prerelease(Ecosystem::Npm, "6.0.0-beta.1"));
    }
}
