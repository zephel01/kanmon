//! エコシステム固有の特徴：npm の package.json、PyPI の wheel・sdist の構成、公開の付帯情報。

use super::diff::added_lines;
use super::{Change, FileDiff, Finding, Meta};
use std::collections::HashSet;

/// 導入時に動く npm の scripts
const NPM_INSTALL_SCRIPTS: &[&str] = &["preinstall", "install", "postinstall", "prepare"];

fn json_of(d: Option<&Vec<u8>>) -> Option<serde_json::Value> {
    d.and_then(|b| serde_json::from_slice(b).ok())
}

fn str_at<'a>(v: &'a serde_json::Value, k: &str) -> Option<&'a serde_json::Value> {
    v.get(k)
}

/// npm：package.json の scripts / main / exports / bin、ルート直下の新しいスクリプト
pub fn scan_npm(diffs: &[FileDiff]) -> Vec<Finding> {
    let mut out = vec![];
    let Some(pj) = diffs.iter().find(|d| d.path == "package.json" && d.change != Change::Removed) else {
        return scan_new_root_scripts(diffs, None, &mut out);
    };
    let new = json_of(pj.new.as_ref());
    let old = json_of(pj.old.as_ref());
    let Some(new) = new else {
        out.push(Finding::new("archive_anomaly", "package.json", None, "package.json を JSON として読めない"));
        return out;
    };
    let old = old.unwrap_or(serde_json::Value::Null);
    let scripts = |v: &serde_json::Value, k: &str| {
        v.get("scripts").and_then(|s| s.get(k)).and_then(|x| x.as_str()).map(str::to_string)
    };
    for k in NPM_INSTALL_SCRIPTS {
        let (n, o) = (scripts(&new, k), scripts(&old, k));
        if let Some(cmd) = &n {
            if n != o {
                out.push(Finding::new("install_script", "package.json", None, &format!("{k}: {cmd}")));
            }
        }
    }
    // 依存に、レジストリ以外（GitHub のコミット・URL・ファイル）から取るものが増えた。
    // 2026 年の npm の乗っ取り（TanStack 等）は optionalDependencies に github:…#<コミット> を足し、本体をそこに置いた
    for sect in ["dependencies", "optionalDependencies", "peerDependencies", "bundleDependencies"] {
        let deps = |v: &serde_json::Value| v.get(sect).and_then(|x| x.as_object()).cloned().unwrap_or_default();
        let (nd, od) = (deps(&new), deps(&old));
        for (name, spec) in &nd {
            let sp = spec.as_str().unwrap_or("");
            if od.get(name) == Some(spec) {
                continue;
            }
            let l = sp.to_ascii_lowercase();
            if ["github:", "git+", "git://", "http://", "https://", "file:", "gitlab:", "bitbucket:"]
                .iter()
                .any(|p| l.starts_with(p))
                || (sp.contains('/') && !sp.starts_with('@') && !sp.starts_with("npm:") && sp.contains('#'))
            {
                out.push(Finding::new("dep_from_url", "package.json", None, &format!("{sect}.{name}: {sp}")));
            }
        }
    }
    for k in ["main", "exports", "bin", "module"] {
        let (n, o) = (str_at(&new, k), str_at(&old, k));
        if n.is_some() && n != o && pj.change == Change::Changed {
            let s = n.map(|x| x.to_string()).unwrap_or_default();
            out.push(Finding::new("entry_changed", "package.json", None, &format!("{k}: {s}")));
        }
    }
    scan_new_root_scripts(diffs, Some(&new), &mut out)
}

/// binding.gyp のコマンド展開（`<!(…)`）は、npm install の node-gyp で実行される（scripts が無くても動く）
fn gyp_exec(diffs: &[FileDiff], out: &mut Vec<Finding>) {
    for d in diffs.iter().filter(|d| d.change != Change::Removed && d.path.ends_with("binding.gyp")) {
        for (n, l) in added_lines(d) {
            if l.contains("<!(") || l.contains("<!@(") {
                out.push(Finding::new("install_script", &d.path, Some(n), &l));
            }
        }
    }
}

/// ルート直下の新しい .js / .mjs / .cjs が scripts か main から参照されている
fn scan_new_root_scripts(diffs: &[FileDiff], pj: Option<&serde_json::Value>, out: &mut Vec<Finding>) -> Vec<Finding> {
    gyp_exec(diffs, out);
    let refs: String = pj
        .map(|v| {
            let mut s = String::new();
            if let Some(o) = v.get("scripts").and_then(|x| x.as_object()) {
                for x in o.values() {
                    s.push_str(x.as_str().unwrap_or(""));
                    s.push(' ');
                }
            }
            for k in ["main", "bin", "exports", "module"] {
                if let Some(x) = v.get(k) {
                    s.push_str(&x.to_string());
                }
            }
            s
        })
        .unwrap_or_default();
    for d in diffs.iter().filter(|d| d.change == Change::Added) {
        let p = d.path.as_str();
        let root_js = !p.contains('/') && [".js", ".mjs", ".cjs"].iter().any(|e| p.ends_with(e));
        if root_js && refs.contains(p) {
            out.push(Finding::new(
                "new_top_level",
                p,
                None,
                "ルート直下に増えたスクリプトが package.json から呼ばれる",
            ));
        }
    }
    std::mem::take(out)
}

/// wheel・sdist のトップレベルの名前（`pkg/…` → `pkg`、`mod.py` → `mod`）。メタデータ類は除く
fn top_level(path: &str) -> Option<String> {
    let first = path.split('/').next()?;
    if first.ends_with(".dist-info") || first.ends_with(".data") || first.ends_with(".egg-info") {
        return None;
    }
    if path.contains('/') {
        return Some(first.to_string());
    }
    first.strip_suffix(".py").map(str::to_string)
}

/// PyPI：.pth、新しいトップレベル、setup.py、__init__.py の新しい import、ワークフロー。
/// `base_paths` は前の版の全ファイルのパス（比較相手が無ければ None）
pub fn scan_pypi(diffs: &[FileDiff], base_paths: Option<&[String]>) -> Vec<Finding> {
    let mut out = vec![];
    let existing: HashSet<String> = base_paths.unwrap_or_default().iter().filter_map(|p| top_level(p)).collect();
    let had_base = base_paths.is_some();
    let mut reported: HashSet<String> = HashSet::new();
    for d in diffs {
        let p = d.path.as_str();
        let name = p.rsplit('/').next().unwrap_or(p);
        if d.change == Change::Removed {
            continue;
        }
        if name.ends_with(".pth") && d.change == Change::Added {
            let text = String::from_utf8_lossy(d.new.as_deref().unwrap_or_default()).into_owned();
            for l in crate::persist::pth_exec_lines(&text) {
                out.push(Finding::new("pth_exec", p, None, &l));
                // .pth の 1 行にコードを詰めて、起動のたびに実行する（exec・eval・__import__）
                let c: String = l.to_ascii_lowercase().chars().filter(|c| !c.is_whitespace()).collect();
                if ["exec(", "eval(", "__import__(", "subprocess", "urllib"].iter().any(|k| c.contains(k)) {
                    out.push(Finding::new("import_time_exec", p, None, &l));
                }
            }
        }
        if name == "setup.py" && !p.contains('/') {
            out.push(Finding::new(
                "install_script",
                p,
                None,
                "setup.py が追加・変更された（sdist の導入時に実行される）",
            ));
        }
        if (p.starts_with(".github/workflows/") || p.contains("/.github/workflows/")) && d.change == Change::Added {
            out.push(Finding::new("ci_secrets", p, None, "パッケージにワークフローが増えた"));
        }
        if had_base && d.change == Change::Added {
            if let Some(t) = top_level(p) {
                if !existing.contains(&t) && reported.insert(t.clone()) {
                    out.push(Finding::new("new_top_level", p, None, &format!("前の版に無いトップレベル `{t}`")));
                }
            }
        }
        // トップレベルの __init__.py に増えた import
        if d.change == Change::Changed && p.matches('/').count() == 1 && name == "__init__.py" {
            for (n, l) in added_lines(d) {
                let t = l.trim_start();
                if t.starts_with("import ") || t.starts_with("from ") {
                    out.push(Finding::new("entry_changed", p, Some(n), &l));
                }
            }
        }
    }
    out
}

/// 公開の付帯情報：公開から日が浅い、前の版との間隔が短い、公開者が変わった、証明が消えた
pub fn scan_meta(m: &Meta, now: i64) -> Vec<Finding> {
    let mut out = vec![];
    let label = format!("{} {}", m.name, m.version);
    if let Some(p) = m.published {
        if now - p < 7 * 86_400 {
            let h = (now - p).max(0) / 3600;
            out.push(Finding::new("fresh_release", &label, None, &format!("公開から {h} 時間")));
        }
        if let Some(b) = m.base_published {
            if p >= b && p - b < 2 * 3600 {
                out.push(Finding::new("burst_release", &label, None, &format!("前の版から {} 分", (p - b) / 60)));
            }
        }
    }
    if let (Some(a), Some(b)) = (&m.publisher, &m.base_publisher) {
        if a != b {
            out.push(Finding::new("publisher_changed", &label, None, &format!("{b} → {a}")));
        }
    }
    if m.base_attested == Some(true) && m.attested == Some(false) {
        out.push(Finding::new("attestation_dropped", &label, None, "前の版にあった証明（attestation）が無い"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fd(p: &str, c: Change, old: Option<&str>, new: Option<&str>) -> FileDiff {
        FileDiff {
            path: p.into(),
            change: c,
            old: old.map(|s| s.as_bytes().to_vec()),
            new: new.map(|s| s.as_bytes().to_vec()),
        }
    }
    fn feats(v: &[Finding]) -> Vec<&str> {
        v.iter().map(|f| f.feature.as_str()).collect()
    }

    #[test]
    fn npm_scripts() {
        let old = r#"{"name":"k","main":"dist/index.js","scripts":{"test":"jest"}}"#;
        let new = r#"{"name":"k","main":"dist/index.js","scripts":{"test":"jest","preinstall":"node setup.mjs"}}"#;
        let d = vec![
            fd("package.json", Change::Changed, Some(old), Some(new)),
            fd("setup.mjs", Change::Added, None, Some("x")),
            fd("other.js", Change::Added, None, Some("x")),
        ];
        let f = scan_npm(&d);
        assert_eq!(feats(&f), vec!["install_script", "new_top_level"], "{f:?}");
        assert_eq!(f[1].path, "setup.mjs");
        // 変化なし
        assert!(scan_npm(&[fd("package.json", Change::Changed, Some(new), Some(new))]).is_empty());
        // main の変更
        let m = new.replace("dist/index.js", "lib/x.js");
        assert_eq!(
            feats(&scan_npm(&[fd("package.json", Change::Changed, Some(new), Some(&m))])),
            vec!["entry_changed"]
        );
        // GitHub のコミットから取る依存が増えた
        let g = new.replace(
            r#""scripts""#,
            r#""optionalDependencies":{"@x/setup":"github:x/y#79ac49eedf774dd4b0cfa308722bc463cfe5885c"},"scripts""#,
        );
        assert_eq!(feats(&scan_npm(&[fd("package.json", Change::Changed, Some(new), Some(&g))])), vec!["dep_from_url"]);
        let ok = new.replace(r#""scripts""#, r#""dependencies":{"left-pad":"^1.3.0","@s/x":"npm:@s/y@1"},"scripts""#);
        assert!(scan_npm(&[fd("package.json", Change::Changed, Some(new), Some(&ok))]).is_empty());
        // binding.gyp のコマンド展開
        let gyp =
            r#"{"targets":[{"target_name":"S","sources":["<!(node index.js > /dev/null 2>&1 && echo stub.c)"]}]}"#;
        assert_eq!(feats(&scan_npm(&[fd("binding.gyp", Change::Added, None, Some(gyp))])), vec!["install_script"]);
        // 読めない package.json
        assert_eq!(
            feats(&scan_npm(&[fd("package.json", Change::Changed, Some(new), Some("{"))])),
            vec!["archive_anomaly"]
        );
    }

    #[test]
    fn pypi_wheel() {
        let d = vec![
            fd("agent_framework/core.py", Change::Changed, Some("a"), Some("b")),
            fd("x_meta.pth", Change::Added, None, Some("import x_meta\n")),
            fd("x_meta/__init__.py", Change::Added, None, Some("from . import _t\n")),
            fd("agent_framework-1.0.dist-info/RECORD", Change::Changed, Some("a"), Some("b")),
            fd("agent_framework/__init__.py", Change::Changed, Some("x = 1\n"), Some("x = 1\nimport x_meta\n")),
        ];
        let base: Vec<String> =
            ["agent_framework/core.py", "agent_framework/__init__.py", "agent_framework-1.0.dist-info/RECORD"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        let f = scan_pypi(&d, Some(&base));
        let fs = feats(&f);
        assert!(fs.contains(&"pth_exec"), "{f:?}");
        assert!(!fs.contains(&"import_time_exec"), "import だけの .pth は import_time_exec にしない");
        assert_eq!(f.iter().filter(|x| x.feature == "new_top_level").count(), 1, "{f:?}");
        assert!(f.iter().any(|x| x.feature == "entry_changed" && x.line == Some(2)));
        // 1 行にコードを詰めた .pth
        let p2 = vec![fd(
            "x-setup.pth",
            Change::Added,
            None,
            Some("import os as _O;_O.path.exists(g) or exec('import subprocess')\n"),
        )];
        assert!(feats(&scan_pypi(&p2, None)).contains(&"import_time_exec"));
        // sdist の setup.py
        assert_eq!(
            feats(&scan_pypi(
                &[fd("setup.py", Change::Changed, Some("a"), Some("b"))],
                Some(&["setup.py".to_string()])
            )),
            vec!["install_script"]
        );
        // 初めての公開（比較相手なし）では new_top_level を出さない
        assert!(!feats(&scan_pypi(&[fd("pkg/a.py", Change::Added, None, Some("x"))], None)).contains(&"new_top_level"));
    }

    #[test]
    fn meta() {
        let now = 1_000_000_000;
        let m = Meta {
            name: "k".into(),
            version: "2".into(),
            published: Some(now - 7 * 86_400),
            base_published: Some(now - 7 * 86_400 - 2 * 3600),
            publisher: Some("a".into()),
            base_publisher: Some("a".into()),
            attested: Some(true),
            base_attested: Some(true),
            ..Default::default()
        };
        assert!(scan_meta(&m, now).is_empty(), "境界ちょうどは出さない");
        let m2 = Meta {
            published: Some(now - 3600),
            base_published: Some(now - 3600 - 33 * 60),
            publisher: Some("b".into()),
            attested: Some(false),
            ..m
        };
        assert_eq!(
            feats(&scan_meta(&m2, now)),
            vec!["fresh_release", "burst_release", "publisher_changed", "attestation_dropped"]
        );
    }
}
