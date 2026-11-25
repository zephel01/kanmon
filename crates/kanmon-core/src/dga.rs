//! DGA（ドメイン生成アルゴリズム）らしさ（設計書 §9.3）。
//! 登録ドメイン（eTLD+1）のラベル部分を評価し 0〜1 を返す。誤検知前提の弱いシグナル。

use std::collections::HashSet;
use std::sync::OnceLock;

/// 英語の頻出 bigram ＋ 日本語ローマ字に多い bigram
const COMMON_BIGRAMS: &str = "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr no ct us ac ot il tr ly nc et ut ss so rs un lo wa ge ie wh ee wi em ad ol rt po we na ul ni ts mo ow pa im mi ai sh ir su id os iv ia am fi ci vi pl ig tu ev ld ry mp fe bl ab gh ty op wo sa ay ex ke fr oo av ag if ap gr od bo sp rd do uc bu ei ov by rm ep tt oc fa ef cu rn sc gi da yo cr cl du ga qu ue ff ba ey ls va um pp ua up lu go ht ru ug ds lt pi rc rr eg au ck ew mu br bi pt ak pu ui rg ib tl ny ki rk ys ob mm fu ph og ms ye ud mb ip ub oi rl gu dr hr cc tw ft wn nu ka ku ko sh ji tsu fu mu yu ya yo ri ra re ro wa ga gi gu go za zu ze zo da de do ba bi bu be bo pa po kyo ryo sho cho nya";

fn bigrams() -> &'static HashSet<[u8; 2]> {
    static B: OnceLock<HashSet<[u8; 2]>> = OnceLock::new();
    B.get_or_init(|| {
        let mut s = HashSet::new();
        for w in COMMON_BIGRAMS.split_whitespace() {
            let b = w.as_bytes();
            for p in b.windows(2) {
                s.insert([p[0], p[1]]);
            }
        }
        s
    })
}

/// 登録ドメイン（例：`a.b.example.co.jp` → `example.co.jp`）
pub fn registered_domain(host: &str) -> Option<String> {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    psl::domain_str(&h).map(|s| s.to_string())
}

/// 公開サフィックスの一覧に載っている名前か（`.warp-svc`・`.internal` のような私的な名前は偽）
pub fn is_public_name(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    psl::suffix(h.as_bytes()).is_some_and(|s| s.is_known())
}

/// 登録ドメインから公開サフィックスを除いたラベル（例：`example.co.jp` → `example`）
fn label_of(host: &str) -> Option<String> {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let rd = psl::domain_str(&h)?;
    let sfx = psl::suffix_str(&h)?;
    let label = rd.strip_suffix(sfx)?.trim_end_matches('.');
    Some(label.to_string())
}

fn entropy(s: &[u8]) -> f64 {
    let mut c = [0usize; 256];
    for b in s {
        c[*b as usize] += 1;
    }
    let n = s.len() as f64;
    c.iter()
        .filter(|x| **x > 0)
        .map(|x| {
            let p = *x as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn max_consonant_run(s: &[u8]) -> usize {
    let (mut best, mut cur) = (0, 0);
    for b in s {
        if b.is_ascii_alphabetic() && !b"aeiouy".contains(b) {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

#[derive(Debug, Clone, PartialEq)]
pub struct DgaFeatures {
    pub label: String,
    pub len: usize,
    pub entropy: f64,
    pub consonant_run: usize,
    pub digit_ratio: f64,
    pub common_bigram_ratio: f64,
}

/// UUID の形（8-4-4-4-12 の 16 進）。クラウドの実行環境・CDN が名前に使う。DGA は登録できるドメインを
/// 作るもので、この形にはならない
pub fn is_uuid(label: &str) -> bool {
    let parts: Vec<&str> = label.split('-').collect();
    parts.len() == 5
        && parts.iter().zip([8, 4, 4, 4, 12]).all(|(p, n)| p.len() == n && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

pub fn features(host: &str) -> Option<DgaFeatures> {
    let label = label_of(host)?;
    if is_uuid(&label) {
        return None;
    }
    // ハイフンで区切られた語は普通の命名が多いので除いて評価。数字だけの区切り（Cloud Run の
    // 「語-語-数字」のプロジェクト番号等）は外す。数字だけのラベルは従来どおり評価する
    let tokens: Vec<&str> = label.split('-').filter(|t| !t.is_empty()).collect();
    let words: Vec<&str> = tokens.iter().copied().filter(|t| !t.bytes().all(|b| b.is_ascii_digit())).collect();
    let kept = if words.is_empty() { tokens } else { words };
    let core: Vec<u8> = kept.concat().into_bytes();
    if core.is_empty() {
        return None;
    }
    let digits = core.iter().filter(|b| b.is_ascii_digit()).count();
    let pairs: Vec<[u8; 2]> = core.windows(2).map(|p| [p[0], p[1]]).collect();
    let common = pairs.iter().filter(|p| bigrams().contains(*p)).count();
    Some(DgaFeatures {
        len: core.len(),
        entropy: entropy(&core),
        consonant_run: max_consonant_run(&core),
        digit_ratio: digits as f64 / core.len() as f64,
        common_bigram_ratio: if pairs.is_empty() { 1.0 } else { common as f64 / pairs.len() as f64 },
        label,
    })
}

/// 0〜1。7 文字未満のラベルは判定しない（0）。
pub fn score(host: &str) -> f64 {
    let Some(f) = features(host) else { return 0.0 };
    if f.len < 7 {
        return 0.0;
    }
    let len_term = ((f.len as f64 - 8.0) / 8.0).clamp(0.0, 1.5);
    let z = -4.0
        + 1.1 * (f.entropy - 2.5).max(0.0) * 2.0
        + 0.55 * (f.consonant_run as f64 - 2.0).max(0.0)
        + 3.0 * f.digit_ratio
        + 5.0 * (0.6 - f.common_bigram_ratio).max(0.0) * 2.0
        + 0.8 * len_term;
    let s = 1.0 / (1.0 + (-z).exp());
    (s * 1000.0).round() / 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered() {
        assert_eq!(registered_domain("a.b.example.co.jp").as_deref(), Some("example.co.jp"));
        assert_eq!(registered_domain("WWW.Google.com.").as_deref(), Some("google.com"));
    }

    #[test]
    fn cloud_names_low() {
        // 実機の誤検知：Cloud Run の名前とプロジェクト番号、UUID のサブドメイン
        for d in [
            "antigravity-cli-auto-updater-974169037036.us-central1.run.app",
            "df8392c1-ca63-44c2-bc08-242de938102d.frame.claudeusercontent.com",
        ] {
            assert!(score(d) < 0.7, "{d}: {}", score(d));
        }
        assert!(is_uuid("df8392c1-ca63-44c2-bc08-242de938102d"));
        assert!(!is_uuid("df8392c1-ca63-44c2-bc08"));
        // 数字を混ぜたでたらめな名前は引き続き高い
        assert!(score("xkq9zt7vbw3p.com") >= 0.7, "{}", score("xkq9zt7vbw3p.com"));
    }

    #[test]
    fn benign_low() {
        for d in [
            "google.com",
            "www.wikipedia.org",
            "githubusercontent.com",
            "rakuten.co.jp",
            "yahoo.co.jp",
            "microsoftonline.com",
            "cloudflare-dns.com",
            "amazonaws.com",
            "nikkei.com",
            "objective-see.org",
            "mercari.com",
            "shinkansen-info.jp",
            "stackoverflow.com",
        ] {
            let s = score(d);
            assert!(s < 0.5, "{d} => {s} {:?}", features(d));
        }
    }

    #[test]
    fn dga_like_high() {
        for d in ["xjw3kq9zpvb2.com", "qwkzhtpxlmnr.net", "a8f3k2l9x7q1.info", "zzkqprtvbnmwxs.org"] {
            let s = score(d);
            assert!(s >= 0.7, "{d} => {s} {:?}", features(d));
        }
    }
}
