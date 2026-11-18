//! 正規化と差分：共通の先頭ディレクトリを外し、パスで突き合わせて中身（SHA-256）で比べる。

use super::{Change, Entry, FileDiff};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};

/// npm の `package/`、sdist の `name-ver/` のような共通の先頭ディレクトリを外す。
/// 全エントリが同じ先頭ディレクトリを持つときだけ外す
pub fn strip_common_root(entries: &mut [Entry]) {
    let first = |p: &str| p.split_once('/').map(|(a, _)| a.to_string());
    let Some(root) = entries.first().and_then(|e| first(&e.path)) else { return };
    if root.is_empty() || !entries.iter().all(|e| first(&e.path).as_deref() == Some(root.as_str())) {
        return;
    }
    let prefix = format!("{root}/");
    for e in entries.iter_mut() {
        if let Some(rest) = e.path.strip_prefix(&prefix) {
            e.path = rest.to_string();
        }
    }
}

fn sha(d: &[u8]) -> [u8; 32] {
    Sha256::digest(d).into()
}

/// パスで突き合わせ、中身で比較する。特殊ファイル（リンク等）は比べない。
/// `old` が None（初めての公開・比較相手なし）なら全ファイルを Added とする
pub fn diff(new: &[Entry], old: Option<&[Entry]>) -> Vec<FileDiff> {
    let map = |es: &[Entry]| -> BTreeMap<String, Vec<u8>> {
        es.iter().filter(|e| !e.special).map(|e| (e.path.clone(), e.data.clone())).collect()
    };
    let n = map(new);
    let o = old.map(map).unwrap_or_default();
    let mut out = vec![];
    for (p, d) in &n {
        match o.get(p) {
            None => out.push(FileDiff { path: p.clone(), change: Change::Added, old: None, new: Some(d.clone()) }),
            Some(od) if sha(od) != sha(d) => out.push(FileDiff {
                path: p.clone(),
                change: Change::Changed,
                old: Some(od.clone()),
                new: Some(d.clone()),
            }),
            _ => {}
        }
    }
    for (p, d) in &o {
        if !n.contains_key(p) {
            out.push(FileDiff { path: p.clone(), change: Change::Removed, old: Some(d.clone()), new: None });
        }
    }
    out
}

/// テキストとして読めるか：先頭 8 KiB に NUL が無い
pub fn is_text(d: &[u8]) -> bool {
    !d[..d.len().min(8192)].contains(&0)
}

/// 1 行の最大の長さ（これを超える部分は見ない。正規表現・走査の時間を抑える）
pub const MAX_LINE: usize = 100_000;

fn clip_line(l: &str) -> String {
    if l.len() <= MAX_LINE {
        return l.to_string();
    }
    let mut end = MAX_LINE;
    while !l.is_char_boundary(end) {
        end -= 1;
    }
    l[..end].to_string()
}

/// 増えた行（1 始まりの行番号つき）。Added は全行、Changed は古い側に同じ行が無いもの。
/// バイナリ・Removed は空
pub fn added_lines(d: &FileDiff) -> Vec<(usize, String)> {
    let Some(new) = &d.new else { return vec![] };
    if !is_text(new) {
        return vec![];
    }
    let text = String::from_utf8_lossy(new);
    let old_text = d.old.as_ref().map(|o| String::from_utf8_lossy(o).into_owned()).unwrap_or_default();
    let old_set: HashSet<&str> = old_text.lines().collect();
    text.lines()
        .enumerate()
        .filter(|(_, l)| d.change == Change::Added || !old_set.contains(l))
        .map(|(i, l)| (i + 1, clip_line(l)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(p: &str, d: &str) -> Entry {
        Entry { path: p.into(), data: d.as_bytes().to_vec(), special: false }
    }

    #[test]
    fn strip_root() {
        let mut a = vec![e("package/a.js", ""), e("package/lib/b.js", "")];
        strip_common_root(&mut a);
        assert_eq!(a[0].path, "a.js");
        assert_eq!(a[1].path, "lib/b.js");
        let mut b = vec![e("pkg/a.py", ""), e("pkg-1.0.dist-info/RECORD", "")];
        strip_common_root(&mut b);
        assert_eq!(b[0].path, "pkg/a.py");
        let mut c = vec![e("top.py", ""), e("pkg/a.py", "")];
        strip_common_root(&mut c);
        assert_eq!(c[0].path, "top.py");
    }

    #[test]
    fn diffs() {
        let old = vec![e("a", "1\n2\n"), e("b", "x"), e("gone", "y")];
        let mut link = e("ln", "");
        link.special = true;
        let new = vec![e("a", "1\n2\n3\n"), e("b", "x"), e("c", "new\nfile"), link];
        let d = diff(&new, Some(&old));
        let get = |p: &str| d.iter().find(|x| x.path == p);
        assert_eq!(get("a").unwrap().change, Change::Changed);
        assert!(get("b").is_none());
        assert_eq!(get("c").unwrap().change, Change::Added);
        assert_eq!(get("gone").unwrap().change, Change::Removed);
        assert!(get("ln").is_none());
        assert_eq!(added_lines(get("a").unwrap()), vec![(3, "3".to_string())]);
        assert_eq!(added_lines(get("c").unwrap()), vec![(1, "new".to_string()), (2, "file".to_string())]);
        assert!(added_lines(get("gone").unwrap()).is_empty());
        // 比較相手なし：全部 Added
        assert!(diff(&new, None).iter().all(|x| x.change == Change::Added));
    }

    #[test]
    fn binary_and_long_line() {
        let bin = FileDiff { path: "x.so".into(), change: Change::Added, old: None, new: Some(vec![0, 1, 2]) };
        assert!(added_lines(&bin).is_empty());
        let long = "あ".repeat(60_000);
        let f = FileDiff { path: "x.js".into(), change: Change::Added, old: None, new: Some(long.into_bytes()) };
        let l = added_lines(&f);
        assert!(l[0].1.len() <= MAX_LINE);
    }
}
