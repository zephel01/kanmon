//! スコアから動作レベルへ（設計書 §9.6）。第1弾は「通知の強さ」を決める。

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::detect::{DetectionSet, SignalHit};
use crate::event::set_path;
use crate::rules::{Action, RuleSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// 0–29：記録のみ
    Info,
    /// 30–59：注意（低優先度通知）
    Notice,
    /// 60–99：警告（設計では「既定拒否」に当たる）
    Warn,
    /// ≥100：即遮断相当
    Critical,
}

impl Level {
    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Notice => "notice",
            Level::Warn => "warn",
            Level::Critical => "critical",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "info" => Level::Info,
            "notice" => Level::Notice,
            "warn" => Level::Warn,
            "critical" => Level::Critical,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(default)]
pub struct Thresholds {
    pub notice: i32,
    pub warn: i32,
    pub critical: i32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self { notice: 30, warn: 60, critical: 100 }
    }
}

impl Thresholds {
    pub fn level(&self, score: i32) -> Level {
        if score >= self.critical {
            Level::Critical
        } else if score >= self.warn {
            Level::Warn
        } else if score >= self.notice {
            Level::Notice
        } else {
            Level::Info
        }
    }
}

#[derive(Debug, Clone)]
pub struct Outcome {
    pub score: i32,
    pub level: Level,
    pub signals: Vec<SignalHit>,
    pub verdict: Option<String>,
    pub rule_id: Option<String>,
}

/// イベントを評価して `kanmon.score / level / signals / verdict / rule_id` を書き込む。
///
/// - 検知ルールの点数を合算（下限 0）。
/// - 脅威インテル一致（`kanmon.ti_match`）は許可ルールより優先（§7.1）。
/// - ユーザー許可ルールに一致し、かつインテル一致でなければ Info に抑える（ユーザーが許可済み）。
/// - ユーザー拒否ルールに一致すれば最低 Warn（`would_deny`。第1弾は遮断しない）。
pub fn apply(ev: &mut Value, dets: &DetectionSet, rules: &RuleSet, th: &Thresholds) -> Outcome {
    derive_domain_facts(ev);
    let signals = dets.evaluate(ev);
    let score = signals.iter().map(|s| s.points).sum::<i32>().max(0);
    let mut level = th.level(score);
    let ti = crate::event::get_path(ev, "kanmon.ti_match").and_then(|v| v.as_bool()).unwrap_or(false);
    let mut verdict = None;
    let mut rule_id = None;
    if ti {
        verdict = Some("would_deny".to_string());
        rule_id = Some("threat_intel".to_string());
        level = level.max(Level::Critical);
    } else if let Some(v) = rules.evaluate(ev) {
        rule_id = Some(v.rule_id);
        match v.action {
            Action::Allow => {
                verdict = Some("allow".to_string());
                level = Level::Info;
            }
            Action::Deny => {
                verdict = Some("would_deny".to_string());
                level = level.max(Level::Warn);
            }
        }
    }
    set_path(ev, "kanmon.score", Value::from(score));
    set_path(ev, "kanmon.level", Value::from(level.as_str()));
    set_path(ev, "kanmon.signals", serde_json::to_value(&signals).unwrap_or_default());
    set_path(ev, "kanmon.verdict", verdict.clone().map(Value::from).unwrap_or(Value::Null));
    set_path(ev, "kanmon.rule_id", rule_id.clone().map(Value::from).unwrap_or(Value::Null));
    Outcome { score, level, signals, verdict, rule_id }
}

/// イベントだけから決まる事実を補う（ライブ・replay 共通）：
/// `destination.domain` があれば `destination.registered_domain` と `kanmon.dga_score`。
pub fn derive_domain_facts(ev: &mut Value) {
    let Some(host) = crate::event::get_path(ev, "destination.domain").and_then(|v| v.as_str()).map(str::to_string)
    else {
        return;
    };
    if crate::event::get_path(ev, "destination.registered_domain").is_none() {
        if let Some(rd) = crate::dga::registered_domain(&host) {
            set_path(ev, "destination.registered_domain", Value::from(rd));
        }
    }
    if crate::event::get_path(ev, "kanmon.dga_score").is_none() {
        set_path(ev, "kanmon.dga_score", Value::from(crate::dga::score(&host)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn levels() {
        let t = Thresholds::default();
        assert_eq!(t.level(0), Level::Info);
        assert_eq!(t.level(30), Level::Notice);
        assert_eq!(t.level(70), Level::Warn);
        assert_eq!(t.level(100), Level::Critical);
    }

    #[test]
    fn allow_rule_suppresses_but_intel_wins() {
        let d = DetectionSet::from_yaml(
            "detections: [{id: X, name: x, points: 70, when: {field: process.name, op: eq, value: tool}}]",
        )
        .unwrap();
        let r = RuleSet::from_json(r#"[{"id":"ok","action":"allow","process":{"match":"path","path":"/opt/tool"}}]"#)
            .unwrap();
        let th = Thresholds::default();
        let mut ev = json!({"process":{"name":"tool","executable":"/opt/tool"},"network":{"direction":"outbound"}});
        let o = apply(&mut ev, &d, &r, &th);
        assert_eq!((o.score, o.level, o.verdict.as_deref()), (70, Level::Info, Some("allow")));
        ev["kanmon"]["ti_match"] = json!(true);
        let o = apply(&mut ev, &d, &r, &th);
        assert_eq!(o.level, Level::Critical);
        assert_eq!(o.rule_id.as_deref(), Some("threat_intel"));
    }
}
