//! 宛先の AS のデータ（KASN1）の取得と読み込み。
//!
//! 取得元は kanmon-data の Release（既定）。iptoasn.com には直接行かない（運営者の負荷を増やさないため）。
//! 取得経路も攻撃面なので、フィードと同じく：https のみ・TLS 検証は無効にしない・サイズ上限・
//! SHA-256 の照合・形式の検査に通らないものは採用しない（前回分を使い続ける）・一時ファイル→rename。
//! 先に小さな `.sha256` だけを取り、手元と同じなら本体は取らない。

use crate::config::Config;
use anyhow::{bail, Context, Result};
use kanmon_core::asn::AsnDb;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// 圧縮した本体の上限（実データは約 3MB）
const MAX_GZ: u64 = 32 * 1024 * 1024;
/// 展開後の上限（実データは約 9MB）
const MAX_RAW: u64 = 96 * 1024 * 1024;

fn dir(cfg: &Config) -> PathBuf {
    cfg.data_dir.join("asn")
}

fn data_path(cfg: &Config) -> PathBuf {
    dir(cfg).join("asn.kasn.gz")
}

/// 端末ごとのずらし（0〜1 日）。全員が同じ時刻に取りに行かないように
fn jitter_s(cfg: &Config) -> u64 {
    let h = Sha256::digest(cfg.data_dir.to_string_lossy().as_bytes());
    u64::from_le_bytes(h[..8].try_into().unwrap_or_default()) % 86_400
}

fn due(cfg: &Config) -> bool {
    let p = data_path(cfg);
    match std::fs::metadata(&p).and_then(|m| m.modified()) {
        Ok(t) => {
            let age = SystemTime::now().duration_since(t).unwrap_or_default();
            age > Duration::from_secs(cfg.asn.refresh_days.max(1) as u64 * 86_400 + jitter_s(cfg))
        }
        Err(_) => true,
    }
}

fn get(url: &str, max: u64) -> Result<Vec<u8>> {
    if !url.starts_with("https://") {
        bail!("https 以外からは取りません: {url}");
    }
    let resp = ureq::get(url).timeout(Duration::from_secs(60)).call()?;
    // リダイレクトの先も https であること（ureq は既定で追う）
    if !resp.get_url().starts_with("https://") {
        bail!("リダイレクトの先が https ではありません");
    }
    let mut buf = Vec::new();
    resp.into_reader().take(max + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        bail!("サイズ上限超過");
    }
    Ok(buf)
}

/// `.sha256` の中身（先頭の 64 桁の 16 進）を取り出す
pub fn parse_sha(text: &str) -> Option<String> {
    let w = text.split_whitespace().next()?.to_ascii_lowercase();
    (w.len() == 64 && w.chars().all(|c| c.is_ascii_hexdigit())).then_some(w)
}

/// gzip なら展開して KASN1 として読む
pub fn decode(bytes: &[u8]) -> Result<AsnDb> {
    let raw = if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(bytes).take(MAX_RAW + 1).read_to_end(&mut out).context("gzip の展開")?;
        if out.len() as u64 > MAX_RAW {
            bail!("展開後のサイズが上限を超えています");
        }
        out
    } else {
        bytes.to_vec()
    };
    AsnDb::from_bytes(&raw)
}

fn fetch(cfg: &Config) -> Result<Option<usize>> {
    let d = dir(cfg);
    std::fs::create_dir_all(&d)?;
    let dest = data_path(cfg);
    let sha_file = d.join("asn.sha256");
    let want = parse_sha(&String::from_utf8_lossy(&get(&format!("{}.sha256", cfg.asn.url), 1024)?))
        .context(".sha256 の形式が違います")?;
    let have = std::fs::read_to_string(&sha_file).ok().and_then(|t| parse_sha(&t));
    if have.as_deref() == Some(want.as_str()) && dest.exists() {
        // 変わっていない。次の確認まで待つために更新時刻だけ進める
        std::fs::File::options().append(true).open(&dest)?.set_modified(SystemTime::now())?;
        return Ok(None);
    }
    let body = get(&cfg.asn.url, MAX_GZ)?;
    let got = hex::encode(Sha256::digest(&body));
    if got != want {
        bail!("SHA-256 が一致しません");
    }
    let db = decode(&body)?;
    let tmp = dest.with_extension("tmp");
    std::fs::write(&tmp, &body)?;
    std::fs::rename(&tmp, &dest)?;
    std::fs::write(&sha_file, format!("{want}\n"))?;
    let (a, b, _) = db.counts();
    Ok(Some(a + b))
}

/// 期限が来ていれば取り直す（ブロッキング。別スレッドから呼ぶ）。取り直したら true
pub fn refresh(cfg: &Config) -> bool {
    if !cfg.asn.enabled || cfg.asn.file.is_some() || !due(cfg) {
        return false;
    }
    match fetch(cfg) {
        Ok(Some(n)) => {
            logln!("AS のデータを更新（範囲 {n} 件）");
            true
        }
        Ok(None) => false,
        Err(e) => {
            logln!("AS のデータの取得に失敗（前回分を継続）: {e:#}");
            false
        }
    }
}

/// 手元のデータを読む。無い・壊れているときは None（AS は付かない）
pub fn load(cfg: &Config) -> Option<AsnDb> {
    if !cfg.asn.enabled {
        return None;
    }
    let p: &Path = &cfg.asn.file.clone().unwrap_or_else(|| data_path(cfg));
    let bytes = std::fs::read(p).ok()?;
    match decode(&bytes) {
        Ok(db) => Some(db),
        Err(e) => {
            logln!("AS のデータを読めません（{}）: {e:#}", p.display());
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha_parse() {
        let h = "a".repeat(64);
        assert_eq!(parse_sha(&format!("{h}  asn.kasn.gz\n")), Some(h.clone()));
        assert_eq!(parse_sha(&h.to_uppercase()), Some(h));
        assert_eq!(parse_sha("deadbeef"), None);
        assert_eq!(parse_sha(""), None);
    }

    /// tools/asn-data/build_asn.py が作ったファイルを Rust 側で読めること（形式の食い違いを防ぐ）
    #[test]
    fn reads_python_built_fixture() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/asn-doc.kasn.gz");
        let db = decode(&std::fs::read(p).unwrap()).unwrap();
        assert_eq!(db.counts(), (2, 1, 3));
        let a = db.lookup("203.0.113.205".parse().unwrap()).unwrap();
        assert_eq!((a.number, a.country.as_deref()), (4713, Some("JP")));
        // 名前は一覧にある AS（4713）だけ
        assert!(a.name.starts_with("OCN"));
        assert_eq!(db.lookup("198.51.100.5".parse().unwrap()).unwrap().name, "");
        assert_eq!(db.lookup("2001:db8::1".parse().unwrap()).unwrap().number, 64501);
    }

    /// 実データでの読み込み時間とメモリの目安（手元に置いたときだけ。`KANMON_ASN_REAL=path cargo test -- --ignored`）
    #[test]
    #[ignore]
    fn real_data() {
        let Ok(p) = std::env::var("KANMON_ASN_REAL") else { return };
        let t = std::time::Instant::now();
        let db = decode(&std::fs::read(p).unwrap()).unwrap();
        let (a, b, c) = db.counts();
        eprintln!(
            "読み込み {:?}、v4 {a}・v6 {b}・AS {c}、範囲の配列 約 {} MB",
            t.elapsed(),
            (a * 12 + b * 36) / 1_000_000
        );
        assert_eq!(db.lookup("8.8.8.8".parse().unwrap()).unwrap().number, 15169);
        assert_eq!(db.lookup("1.1.1.1".parse().unwrap()).unwrap().number, 13335);
        let t = std::time::Instant::now();
        for i in 0..1_000_000u32 {
            let _ = db.lookup(std::net::IpAddr::V4(std::net::Ipv4Addr::from(i.wrapping_mul(2_654_435_761))));
        }
        eprintln!("100 万回の照合 {:?}", t.elapsed());
    }

    #[test]
    fn decode_gzip_and_raw() {
        let tsv = "203.0.113.0\t203.0.113.255\t64500\tJP\tDOC\n";
        let (db, _) = AsnDb::from_tsv(tsv).unwrap();
        let raw = db.to_bytes();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, &raw).unwrap();
        let gz = gz.finish().unwrap();
        assert_eq!(decode(&gz).unwrap().lookup("203.0.113.1".parse().unwrap()).unwrap().number, 64500);
        assert_eq!(decode(&raw).unwrap().counts(), db.counts());
        assert!(decode(&gz[..gz.len() / 2]).is_err());
    }
}
