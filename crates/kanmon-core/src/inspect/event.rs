//! 所見をまとめて、検知エンジンに渡すイベント（`network.kind = inspect`）にする。

use super::diff::{added_lines, diff, strip_common_root};
use super::features::{scan_lines, Lists};
use super::{eco, Ecosystem, Entry, Finding, Meta};
use serde_json::{json, Value};

/// 1 回の検査：正規化 → 差分 → 特徴の抽出。`old` が None なら比較相手なし（全ファイルを見る）。
/// `pre` はアーカイブの読み出しで出た所見（不正なパス・上限超え等）
pub fn analyze(
    eco: Ecosystem,
    mut new: Vec<Entry>,
    old: Option<Vec<Entry>>,
    meta: &Meta,
    now: i64,
    lists: &Lists,
    pre: Vec<Finding>,
) -> Vec<Finding> {
    strip_common_root(&mut new);
    let old = old.map(|mut o| {
        strip_common_root(&mut o);
        o
    });
    let diffs = diff(&new, old.as_deref());
    let mut out = pre;
    out.extend(match eco {
        Ecosystem::Npm => eco::scan_npm(&diffs),
        Ecosystem::Pypi => {
            let base: Option<Vec<String>> = old.as_ref().map(|o| o.iter().map(|e| e.path.clone()).collect());
            eco::scan_pypi(&diffs, base.as_deref())
        }
    });
    for n in eco::new_dependencies(eco, &diffs) {
        out.push(Finding::new("new_dependency", "依存", None, &n));
    }
    for d in &diffs {
        let lines = added_lines(d);
        out.extend(scan_lines(&d.path, &lines, lists));
    }
    out.extend(eco::scan_meta(meta, now));
    out
}

/// 所見をまとめて 1 件のイベントにする。所見の詳細はイベントに入れず（表示側で使う）、特徴の一覧だけを入れる
pub fn to_event(eco: Ecosystem, m: &Meta, findings: &[Finding]) -> Value {
    let mut feats: Vec<&str> = findings.iter().map(|f| f.feature.as_str()).collect();
    feats.sort();
    feats.dedup();
    let mut ins = json!({ "features": feats, "count": findings.len() });
    if let Some(b) = &m.base_version {
        ins["base_version"] = json!(b);
    }
    json!({
        "event": { "kind": "alert", "action": "inspect" },
        "network": { "kind": "inspect", "direction": "none", "transport": "file" },
        "package": { "name": m.name, "version": m.version, "type": eco.as_str() },
        "kanmon": { "mode": "observe", "inspect": ins },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(p: &str, d: &str) -> Entry {
        Entry { path: p.into(), data: d.as_bytes().to_vec(), special: false }
    }

    #[test]
    fn analyze_wheel_and_event() {
        let ex = vec!["webhook.site".to_string()];
        let empty: Vec<String> = vec![];
        let lists = Lists { exfil: &ex, chain_rpc: &empty, chain_rpc_suffixes: &empty };
        let old = vec![e("af/__init__.py", "x = 1\n"), e("af-1.0.dist-info/RECORD", "a")];
        let new = vec![
            e("af/__init__.py", "x = 1\n"),
            e("af-1.1.dist-info/RECORD", "b"),
            e("af_meta.pth", "import af_meta\n"),
            e("af_meta/__init__.py", "u = 'https://webhook.site/x'\n"),
        ];
        let m =
            Meta { name: "af".into(), version: "1.1".into(), base_version: Some("1.0".into()), ..Default::default() };
        let f = analyze(Ecosystem::Pypi, new, Some(old), &m, 0, &lists, vec![]);
        let v = to_event(Ecosystem::Pypi, &m, &f);
        let feats: Vec<&str> =
            v["kanmon"]["inspect"]["features"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
        assert_eq!(feats, vec!["exfil_host", "new_top_level", "pth_exec"], "{f:?}");
        assert_eq!(v["network"]["kind"], "inspect");
        assert_eq!(v["package"]["type"], "pypi");
        assert_eq!(v["kanmon"]["inspect"]["base_version"], "1.0");
    }
}
