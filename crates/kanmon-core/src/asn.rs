//! IP → AS（自律システム）の手元での照合（v0.5.1）。
//!
//! 元データは iptoasn.com の `ip2asn-combined.tsv`（PDDL）。利用者が各自そこから取ると
//! 運営者に負荷がかかるので、kanmon-data リポジトリの CI が週 1 回だけ取得し、
//! この形式（KASN1）に変換して Release に置く。kanmond はそれを取って読む。
//!
//! 形式（リトルエンディアン。配布時は gzip で圧縮）：
//! ```text
//! "KASN1\0\0\0"  u32 v4 の件数  u32 v6 の件数  u32 AS の件数
//! v4：start u32, end u32, asn u32（start 昇順、重なりなし）
//! v6：start u128, end u128, asn u32（同上）
//! AS：asn u32, 国 [u8; 2], 名前の長さ u16, 名前（UTF-8）
//! ```
//! 外から来るデータなので、件数・長さ・並び順を確かめ、合わなければ全体を捨てる。

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::net::IpAddr;

const MAGIC: &[u8; 8] = b"KASN1\0\0\0";
/// 件数の上限（実データは v4 約 41 万・v6 約 9 万・AS 約 9 万。余裕を見て 4 倍程度）
const MAX_V4: usize = 2_000_000;
const MAX_V6: usize = 1_000_000;
const MAX_AS: usize = 400_000;
const MAX_NAME: usize = 256;

#[derive(Debug, Clone, PartialEq)]
pub struct AsnInfo {
    pub number: u32,
    pub name: String,
    /// AS の登録国（ISO 3166-1 alpha-2）。不明なら None
    pub country: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct AsnDb {
    v4: Vec<(u32, u32, u32)>,
    v6: Vec<(u128, u128, u32)>,
    names: HashMap<u32, ([u8; 2], String)>,
}

impl AsnDb {
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        (self.v4.len(), self.v6.len(), self.names.len())
    }

    /// iptoasn.com の TSV（`開始 終了 AS番号 国 説明`）から作る。AS 0（経路なし）は捨て、
    /// 隣り合う同じ AS の範囲はまとめる。読めない行は数えて飛ばす。
    pub fn from_tsv(text: &str) -> Result<(Self, usize)> {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        let mut names: HashMap<u32, ([u8; 2], String)> = HashMap::new();
        let mut bad = 0usize;
        for line in text.lines() {
            let mut it = line.split('\t');
            let (Some(a), Some(b), Some(asn), cc, desc) = (it.next(), it.next(), it.next(), it.next(), it.next())
            else {
                bad += 1;
                continue;
            };
            let Ok(asn) = asn.trim().parse::<u32>() else {
                bad += 1;
                continue;
            };
            if asn == 0 {
                continue;
            }
            match (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
                (Ok(IpAddr::V4(s)), Ok(IpAddr::V4(e))) if u32::from(s) <= u32::from(e) => {
                    v4.push((u32::from(s), u32::from(e), asn))
                }
                (Ok(IpAddr::V6(s)), Ok(IpAddr::V6(e))) if u128::from(s) <= u128::from(e) => {
                    v6.push((u128::from(s), u128::from(e), asn))
                }
                _ => {
                    bad += 1;
                    continue;
                }
            }
            names.entry(asn).or_insert_with(|| {
                let cc = cc.unwrap_or("").trim().as_bytes();
                let cc =
                    if cc.len() == 2 && cc.iter().all(|c| c.is_ascii_uppercase()) { [cc[0], cc[1]] } else { [0, 0] };
                let mut d: String = desc.unwrap_or("").trim().chars().filter(|c| !c.is_control()).collect();
                while d.len() > MAX_NAME {
                    d.pop();
                }
                (cc, d)
            });
        }
        let db = AsnDb { v4: merge(v4), v6: merge(v6), names };
        if db.is_empty() {
            bail!("有効な行がありません（形式変更の可能性）");
        }
        Ok((db, bad))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(20 + self.v4.len() * 12 + self.v6.len() * 36 + self.names.len() * 40);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.v4.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.v6.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.names.len() as u32).to_le_bytes());
        for (s, e, a) in &self.v4 {
            out.extend_from_slice(&s.to_le_bytes());
            out.extend_from_slice(&e.to_le_bytes());
            out.extend_from_slice(&a.to_le_bytes());
        }
        for (s, e, a) in &self.v6 {
            out.extend_from_slice(&s.to_le_bytes());
            out.extend_from_slice(&e.to_le_bytes());
            out.extend_from_slice(&a.to_le_bytes());
        }
        let mut asns: Vec<_> = self.names.keys().copied().collect();
        asns.sort_unstable();
        for a in asns {
            let (cc, name) = &self.names[&a];
            out.extend_from_slice(&a.to_le_bytes());
            out.extend_from_slice(cc);
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(name.as_bytes());
        }
        out
    }

    /// KASN1 を読む（展開済みのバイト列）。おかしなところがあれば全体を捨てる。
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut r = Reader { b, i: 0 };
        if r.take(8)? != MAGIC {
            bail!("KASN1 の形式ではありません");
        }
        let (n4, n6, na) = (r.u32()? as usize, r.u32()? as usize, r.u32()? as usize);
        if n4 > MAX_V4 || n6 > MAX_V6 || na > MAX_AS {
            bail!("件数が上限を超えています（v4 {n4}・v6 {n6}・AS {na}）");
        }
        if b.len() < 20 + n4 * 12 + n6 * 36 {
            bail!("長さが足りません");
        }
        let mut v4 = Vec::with_capacity(n4);
        for _ in 0..n4 {
            v4.push((r.u32()?, r.u32()?, r.u32()?));
        }
        let mut v6 = Vec::with_capacity(n6);
        for _ in 0..n6 {
            v6.push((r.u128()?, r.u128()?, r.u32()?));
        }
        check_sorted(&v4).context("v4")?;
        check_sorted(&v6).context("v6")?;
        let mut names = HashMap::with_capacity(na);
        for _ in 0..na {
            let a = r.u32()?;
            let cc = r.take(2)?;
            let cc = [cc[0], cc[1]];
            let len = r.u16()? as usize;
            if len > MAX_NAME {
                bail!("AS の名前が長すぎます");
            }
            let name = std::str::from_utf8(r.take(len)?).context("AS の名前が UTF-8 ではありません")?;
            names.insert(a, (cc, name.to_string()));
        }
        if r.i != b.len() {
            bail!("末尾に余分なデータがあります");
        }
        let db = AsnDb { v4, v6, names };
        if db.is_empty() {
            bail!("範囲が 1 件もありません");
        }
        Ok(db)
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<AsnInfo> {
        let asn = match ip {
            IpAddr::V4(v) => find(&self.v4, u32::from(v)),
            IpAddr::V6(v) => match v.to_ipv4_mapped() {
                Some(v4) => find(&self.v4, u32::from(v4)),
                None => find(&self.v6, u128::from(v)),
            },
        }?;
        let (cc, name) = self.names.get(&asn).cloned().unwrap_or(([0, 0], String::new()));
        let country = (cc != [0, 0]).then(|| String::from_utf8_lossy(&cc).into_owned());
        Some(AsnInfo { number: asn, name, country })
    }
}

/// 回線の種類（`kanmon.net_type`）。一覧は検知ルールの lists（AS 番号の文字列）から渡す。
/// どれにも無ければ "unknown"。一覧は網羅できないので、"unknown" には点を付けない。
pub fn net_type(asn: u32, cloud: &[String], cdn: &[String], residential: &[String]) -> &'static str {
    let s = asn.to_string();
    let has = |l: &[String]| l.iter().any(|x| x.trim() == s);
    if has(cdn) {
        "cdn"
    } else if has(cloud) {
        "cloud"
    } else if has(residential) {
        "residential"
    } else {
        "unknown"
    }
}

fn merge<T: Copy + PartialEq + Ord + std::ops::Add<Output = T> + From<u8>>(
    mut r: Vec<(T, T, u32)>,
) -> Vec<(T, T, u32)> {
    r.sort_unstable();
    let mut out: Vec<(T, T, u32)> = Vec::with_capacity(r.len());
    for (s, e, a) in r {
        if let Some(last) = out.last_mut() {
            // 重なりは後の範囲を捨てる（元データでは起きない想定）
            if s <= last.1 {
                continue;
            }
            if last.2 == a && last.1 + T::from(1) == s {
                last.1 = e;
                continue;
            }
        }
        out.push((s, e, a));
    }
    out
}

fn check_sorted<T: Ord + Copy>(r: &[(T, T, u32)]) -> Result<()> {
    for w in r.windows(2) {
        if w[0].1 >= w[1].0 {
            bail!("範囲が昇順でないか、重なっています");
        }
    }
    if r.iter().any(|x| x.0 > x.1) {
        bail!("範囲の始まりが終わりより後です");
    }
    Ok(())
}

fn find<T: Ord + Copy>(r: &[(T, T, u32)], ip: T) -> Option<u32> {
    let i = r.partition_point(|x| x.0 <= ip);
    let x = r.get(i.checked_sub(1)?)?;
    (ip <= x.1).then_some(x.2)
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.i.checked_add(n).filter(|&e| e <= self.b.len()).context("データが途中で切れています")?;
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
    }
    fn u128(&mut self) -> Result<u128> {
        Ok(u128::from_le_bytes(self.take(16)?.try_into()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 文書用の AS（RFC 5398）と文書用の IP（RFC 5737・RFC 3849）だけで作る
    const TSV: &str = "198.51.100.0\t198.51.100.127\t64496\tUS\tDOC-CLOUD\n\
198.51.100.128\t198.51.100.255\t64496\tUS\tDOC-CLOUD\n\
203.0.113.0\t203.0.113.255\t64500\tJP\tDOC-HOME-ISP\n\
192.0.2.0\t192.0.2.255\t0\tNone\tNot routed\n\
2001:db8::\t2001:db8:0:ffff:ffff:ffff:ffff:ffff\t64501\tJP\tDOC-V6\n\
garbage line\n";

    #[test]
    fn tsv_merge_lookup_roundtrip() {
        let (db, bad) = AsnDb::from_tsv(TSV).unwrap();
        assert_eq!(bad, 1);
        // 隣り合う同じ AS はまとまる。AS 0 は捨てる
        assert_eq!(db.counts(), (2, 1, 3));
        let a = db.lookup("203.0.113.9".parse().unwrap()).unwrap();
        assert_eq!((a.number, a.name.as_str(), a.country.as_deref()), (64500, "DOC-HOME-ISP", Some("JP")));
        assert_eq!(db.lookup("198.51.100.200".parse().unwrap()).unwrap().number, 64496);
        assert_eq!(db.lookup("2001:db8::1".parse().unwrap()).unwrap().number, 64501);
        assert_eq!(db.lookup("::ffff:203.0.113.1".parse().unwrap()).unwrap().number, 64500);
        assert!(db.lookup("192.0.2.1".parse().unwrap()).is_none());
        assert!(db.lookup("8.8.8.8".parse().unwrap()).is_none());

        let b = db.to_bytes();
        let db2 = AsnDb::from_bytes(&b).unwrap();
        assert_eq!(db2.counts(), db.counts());
        assert_eq!(db2.lookup("203.0.113.9".parse().unwrap()), Some(a));
    }

    #[test]
    fn rejects_broken() {
        let (db, _) = AsnDb::from_tsv(TSV).unwrap();
        let b = db.to_bytes();
        assert!(AsnDb::from_bytes(&b[..b.len() - 1]).is_err());
        let mut extra = b.clone();
        extra.push(0);
        assert!(AsnDb::from_bytes(&extra).is_err());
        let mut magic = b.clone();
        magic[0] = b'X';
        assert!(AsnDb::from_bytes(&magic).is_err());
        // 件数を大きく書き換える
        let mut big = b.clone();
        big[8..12].copy_from_slice(&(MAX_V4 as u32 + 1).to_le_bytes());
        assert!(AsnDb::from_bytes(&big).is_err());
        // 並び順を壊す（v4 の 1 件目と 2 件目を入れ替える）
        let mut uns = b.clone();
        let (x, y) = (uns[20..32].to_vec(), uns[32..44].to_vec());
        uns[20..32].copy_from_slice(&y);
        uns[32..44].copy_from_slice(&x);
        assert!(AsnDb::from_bytes(&uns).is_err());
        assert!(AsnDb::from_tsv("a\tb\n").is_err());
    }

    #[test]
    fn classify() {
        let l = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let (cloud, cdn, res) = (l(&["64496"]), l(&["64497"]), l(&["64500"]));
        assert_eq!(net_type(64496, &cloud, &cdn, &res), "cloud");
        assert_eq!(net_type(64497, &cloud, &cdn, &res), "cdn");
        assert_eq!(net_type(64500, &cloud, &cdn, &res), "residential");
        assert_eq!(net_type(64511, &cloud, &cdn, &res), "unknown");
    }
}
