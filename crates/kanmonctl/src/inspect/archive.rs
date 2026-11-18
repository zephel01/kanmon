//! アーカイブ（tar.gz・zip/whl）をメモリ上で読む。ディスクには書かない。
//!
//! 攻撃者が作ったアーカイブを開くので：
//! - 展開先のパスを作らない（`unpack` 系は呼ばない）。不正なパス・リンク等は中身を読まず所見にする
//! - 件数・合計・1 ファイル・圧縮比に上限を設け、超えたらそこで読むのをやめて所見にする（エラーで終えない）
//! - 入れ子のアーカイブは開かない

use anyhow::{bail, Result};
use kanmon_core::inspect::{Entry, Finding, Limits};
use std::io::{Cursor, Read};

pub struct ReadResult {
    pub entries: Vec<Entry>,
    pub findings: Vec<Finding>,
}

/// 展開後の読み出し量に上限を掛ける Reader（超えたらエラーを返す）
struct LimitReader<R> {
    inner: R,
    left: u64,
    pub hit: bool,
}

impl<R: Read> Read for LimitReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.left == 0 {
            self.hit = true;
            return Err(std::io::Error::other("展開後の大きさが上限を超えた"));
        }
        let n = buf.len().min(self.left.min(usize::MAX as u64) as usize);
        let r = self.inner.read(&mut buf[..n])?;
        self.left -= r as u64;
        Ok(r)
    }
}

/// パスが不正か（`..`・絶対パス・`\`・NUL・ドライブ名）
pub fn bad_path(p: &str) -> bool {
    p.starts_with('/')
        || p.contains('\\')
        || p.contains('\0')
        || p.split('/').any(|c| c == "..")
        || (p.len() >= 2 && p.as_bytes()[1] == b':' && p.as_bytes()[0].is_ascii_alphabetic())
}

/// 先頭のバイトで形式を判定して読む（gzip: 1f 8b、zip: 50 4b 03 04）
pub fn read_archive(bytes: &[u8], lim: &Limits) -> Result<ReadResult> {
    if bytes.len() as u64 > lim.max_compressed {
        return Ok(ReadResult {
            entries: vec![],
            findings: vec![Finding::new(
                "archive_limit",
                "(archive)",
                None,
                &format!("圧縮された大きさ {} バイトが上限を超えた", bytes.len()),
            )],
        });
    }
    if bytes.starts_with(&[0x1f, 0x8b]) {
        read_targz(bytes, lim)
    } else if bytes.starts_with(b"PK\x03\x04") {
        read_zip(bytes, lim)
    } else {
        bail!("tar.gz でも zip でもない（先頭のバイトが合わない）")
    }
}

struct Acc<'a> {
    lim: &'a Limits,
    compressed: u64,
    total: u64,
    out: ReadResult,
}

impl Acc<'_> {
    fn limit(&mut self, why: &str) {
        self.out.findings.push(Finding::new("archive_limit", "(archive)", None, why));
    }
    /// 1 エントリを読む。戻り値 false なら打ち切り
    fn take(&mut self, path: String, special: bool, r: &mut dyn Read) -> bool {
        if self.out.entries.len() >= self.lim.max_entries {
            self.limit(&format!("ファイル数が上限 {} を超えた", self.lim.max_entries));
            return false;
        }
        if bad_path(&path) {
            self.out.findings.push(Finding::new("archive_anomaly", &path, None, "不正なパス（.. ・絶対パス等）"));
            return true;
        }
        if special {
            self.out.findings.push(Finding::new("archive_anomaly", &path, None, "通常ファイル以外（リンク等）"));
            self.out.entries.push(Entry { path, data: vec![], special: true });
            return true;
        }
        // 残りの予算（合計の上限と圧縮比の上限の小さい方）を超えては読まない
        let by_ratio = self.compressed.max(1).saturating_mul(self.lim.max_ratio);
        let budget = self.lim.max_total.min(by_ratio).saturating_sub(self.total);
        let mut data = vec![];
        let res = r.take(self.lim.max_file.min(budget) + 1).read_to_end(&mut data);
        if res.is_err() {
            self.limit("展開中に読めなくなった（上限超え・壊れたデータ）");
            return false;
        }
        let n = data.len() as u64;
        if n > budget {
            let why = if by_ratio < self.lim.max_total {
                format!("圧縮比が上限 {} 倍を超えた", self.lim.max_ratio)
            } else {
                format!("展開後の合計が上限 {} バイトを超えた", self.lim.max_total)
            };
            self.limit(&why);
            return false;
        }
        self.total += n;
        if n > self.lim.max_file {
            // テキスト（コード）が大きすぎるときだけ所見にする。共有ライブラリ等のバイナリは普通に大きい
            if kanmon_core::inspect::features::is_scanned(&path) {
                self.out.findings.push(Finding::new("oversize_file", &path, None, "大きすぎるので中身は見ていない"));
            }
            data.clear();
        }
        self.out.entries.push(Entry { path, data, special: false });
        true
    }
}

fn read_targz(bytes: &[u8], lim: &Limits) -> Result<ReadResult> {
    let gz = flate2::read::GzDecoder::new(Cursor::new(bytes));
    // 比率の上限と合計の上限の小さい方まで（tar のヘッダの分を少し足す）
    let cap = lim.max_total.min(bytes.len() as u64 * lim.max_ratio) + 1024 * 1024;
    let lr = LimitReader { inner: gz, left: cap, hit: false };
    let mut ar = tar::Archive::new(lr);
    let mut acc =
        Acc { lim, compressed: bytes.len() as u64, total: 0, out: ReadResult { entries: vec![], findings: vec![] } };
    let entries = match ar.entries() {
        Ok(e) => e,
        Err(e) => bail!("tar を読めない: {e}"),
    };
    for (n, ent) in entries.enumerate() {
        let mut ent = match ent {
            Ok(x) => x,
            Err(_) => {
                if n == 0 {
                    bail!("tar.gz が壊れている");
                }
                acc.limit("展開中に読めなくなった（上限超え・壊れたデータ）");
                break;
            }
        };
        let path = String::from_utf8_lossy(&ent.path_bytes()).into_owned();
        let ty = ent.header().entry_type();
        if ty.is_dir() {
            continue;
        }
        if ty.is_pax_global_extensions() || ty.is_pax_local_extensions() || ty.is_gnu_longname() || ty.is_gnu_longlink()
        {
            continue;
        }
        let special = !(ty.is_file() || ty.is_contiguous());
        if !acc.take(path, special, &mut ent) {
            break;
        }
    }
    Ok(acc.out)
}

fn read_zip(bytes: &[u8], lim: &Limits) -> Result<ReadResult> {
    let mut z = match zip::ZipArchive::new(Cursor::new(bytes)) {
        Ok(z) => z,
        Err(e) => bail!("zip を読めない: {e}"),
    };
    let mut acc =
        Acc { lim, compressed: bytes.len() as u64, total: 0, out: ReadResult { entries: vec![], findings: vec![] } };
    for i in 0..z.len() {
        let mut f = match z.by_index(i) {
            Ok(f) => f,
            Err(e) => {
                acc.out.findings.push(Finding::new(
                    "archive_anomaly",
                    "(zip)",
                    None,
                    &format!("読めないエントリ: {e}"),
                ));
                continue;
            }
        };
        let path = String::from_utf8_lossy(f.name_raw()).into_owned();
        if f.is_dir() {
            continue;
        }
        let special = f.is_symlink();
        if !acc.take(path, special, &mut f) {
            break;
        }
    }
    Ok(acc.out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn targz(files: &[(&str, &[u8])], link: Option<&str>) -> Vec<u8> {
        let gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
        let mut b = tar::Builder::new(gz);
        for (p, d) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(d.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            // set_path は `..` を拒むので、名前のフィールドに直接書く（不正なアーカイブを作るため）
            let name = p.as_bytes();
            h.as_old_mut().name[..name.len()].copy_from_slice(name);
            h.set_cksum();
            b.append(&h, *d).unwrap();
        }
        if let Some(l) = link {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            b.append_link(&mut h, l, "/etc/passwd").unwrap();
        }
        b.into_inner().unwrap().finish().unwrap()
    }

    fn zipf(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(vec![]));
        let o: zip::write::SimpleFileOptions =
            zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (p, d) in files {
            w.start_file(*p, o).unwrap();
            w.write_all(d).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn feats(r: &ReadResult) -> Vec<&str> {
        r.findings.iter().map(|f| f.feature.as_str()).collect()
    }

    #[test]
    fn reads_targz_and_flags_bad_paths() {
        let t =
            targz(&[("package/a.js", b"x"), ("../evil", b"y"), ("/etc/x", b"z"), ("a\\b", b"w")], Some("package/ln"));
        let r = read_archive(&t, &Limits::default()).unwrap();
        let paths: Vec<&str> = r.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["package/a.js", "package/ln"]);
        assert!(r.entries[1].special && r.entries[1].data.is_empty());
        assert_eq!(feats(&r).iter().filter(|f| **f == "archive_anomaly").count(), 4, "{:?}", feats(&r));
    }

    #[test]
    fn reads_wheel() {
        let z = zipf(&[("pkg/__init__.py", b"x = 1\n"), ("pkg-1.0.dist-info/RECORD", b"r"), ("../up", b"u")]);
        let r = read_archive(&z, &Limits::default()).unwrap();
        assert_eq!(r.entries.len(), 2);
        assert_eq!(feats(&r), vec!["archive_anomaly"]);
    }

    #[test]
    fn limits() {
        let small = Limits { max_entries: 2, ..Limits::default() };
        let r = read_archive(&targz(&[("a", b"1"), ("b", b"2"), ("c", b"3")], None), &small).unwrap();
        assert_eq!(r.entries.len(), 2);
        assert!(feats(&r).contains(&"archive_limit"));

        let f = Limits { max_file: 4, ..Limits::default() };
        let r = read_archive(&zipf(&[("big.py", b"0123456789"), ("lib.so", b"0123456789"), ("ok", b"1")]), &f).unwrap();
        assert_eq!(feats(&r), vec!["oversize_file"]);
        assert!(r.entries.iter().find(|e| e.path == "big.py").unwrap().data.is_empty());

        // ゼロ埋め 30 MiB（圧縮すると非常に小さい）：比率の上限で止まる
        let zeros = vec![0u8; 30 * 1024 * 1024];
        let bomb = targz(&[("z", &zeros)], None);
        let r = read_archive(&bomb, &Limits::default()).unwrap();
        assert!(feats(&r).contains(&"archive_limit"), "{:?}", feats(&r));
        let r = read_archive(&zipf(&[("z", &zeros)]), &Limits::default()).unwrap();
        assert!(feats(&r).contains(&"archive_limit"), "{:?}", feats(&r));

        let tot = Limits { max_total: 3, max_ratio: 1_000_000, ..Limits::default() };
        let r = read_archive(&zipf(&[("a", b"12"), ("b", b"34"), ("c", b"5")]), &tot).unwrap();
        assert!(feats(&r).contains(&"archive_limit"));
    }

    #[test]
    fn broken_inputs() {
        assert!(read_archive(b"\x1f\x8bnot gzip at all", &Limits::default()).is_err());
        assert!(read_archive(b"PK\x03\x04broken", &Limits::default()).is_err());
        assert!(read_archive(b"hello", &Limits::default()).is_err());
        let big = Limits { max_compressed: 3, ..Limits::default() };
        assert_eq!(feats(&read_archive(b"hello", &big).unwrap()), vec!["archive_limit"]);
    }

    #[test]
    fn bad_paths() {
        for p in ["../a", "a/../b", "/abs", "a\\b", "C:x", "a\0b"] {
            assert!(bad_path(p), "{p}");
        }
        for p in ["a/b", "a..b/c", "..a", ".hidden"] {
            assert!(!bad_path(p), "{p}");
        }
    }
}
