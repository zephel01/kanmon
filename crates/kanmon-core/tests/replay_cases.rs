//! 回帰テスト：同梱の検知ルール（detections/）を tests/fixtures/replay-cases.jsonl に当て、
//! 各ケースの `_expect` / `_expect_not` / `_expect_extra` / `_level` を確認する。
//! ルールを変えたら、このテストで点数の変化を CI で検出できる（設計書 §21「回帰」）。

use kanmon_core::detect::DetectionSet;
use kanmon_core::rules::RuleSet;
use kanmon_core::scoring::{apply, Thresholds};
use serde_json::Value;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn strs(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

#[test]
fn bundled_detections_match_fixtures() {
    let base = DetectionSet::load_dir(&root().join("detections"), false).expect("detections/");
    let extra = DetectionSet::load_paths(
        &[root().join("detections"), root().join("examples/detections/60-supply-chain.yaml")],
        false,
    )
    .expect("extra");
    let rules = RuleSet::default();
    let th = Thresholds::default();
    let text = std::fs::read_to_string(root().join("tests/fixtures/replay-cases.jsonl")).unwrap();
    let mut failures = vec![];
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let case: Value = serde_json::from_str(line).unwrap();
        let name = case["_case"].as_str().unwrap_or("?").to_string();
        for (set, key) in [(&base, "_expect"), (&extra, "_expect_extra")] {
            let mut v = case.clone();
            let out = apply(&mut v, set, &rules, &th);
            let got: Vec<&str> = out.signals.iter().map(|h| h.id.as_str()).collect();
            for want in strs(&case, key) {
                if !got.contains(&want.as_str()) {
                    failures.push(format!("[{name}] {want} が出ない（got {got:?}）"));
                }
            }
            if key == "_expect" {
                for no in strs(&case, "_expect_not") {
                    if got.contains(&no.as_str()) {
                        failures.push(format!("[{name}] {no} が出てはいけない（got {got:?}）"));
                    }
                }
                if let Some(l) = case.get("_level").and_then(|x| x.as_str()) {
                    if out.level.as_str() != l {
                        failures.push(format!(
                            "[{name}] level {l} のはずが {}（score {}）",
                            out.level.as_str(),
                            out.score
                        ));
                    }
                }
            }
        }
        // 基本セットでは追加ルール X1 は出ない
        let mut v = case.clone();
        let out = apply(&mut v, &base, &rules, &th);
        if out.signals.iter().any(|h| h.id == "X1") {
            failures.push(format!("[{name}] 基本セットで X1 が出た"));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
