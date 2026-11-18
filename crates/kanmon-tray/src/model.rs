//! トレイの判断（OS に依存しない。どの OS でもテストできる）。
//!
//! - kanmond の状態（`{"cmd":"status"}` の答え）を読む
//! - アイコンの状態：平常・注意（warn）・警告（critical）・停止（kanmond に届かない）
//! - トーストを出す警告：warn 以上で、まだ見ていないもの。起動直後にあった警告は出さない（一度に大量に出ないように）
//! - 通知の一時停止の間は出さない（見たことにはする）
//! - 表示する文字列は外部入力（プロセス名・ドメイン等）を含むので、制御文字を除いて長さを切る

use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Alert {
    pub id: String,
    #[serde(default)]
    pub ts: String,
    pub level: String,
    #[serde(default)]
    pub score: i32,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub body: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Status {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub learning: bool,
    /// 新しい順
    #[serde(default)]
    pub alerts: Vec<Alert>,
}

impl Status {
    pub fn parse(json: &str) -> Option<Self> {
        let v: serde_json::Value = serde_json::from_str(json.trim()).ok()?;
        if v.get("error").is_some() {
            return None;
        }
        serde_json::from_value(v).ok()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IconState {
    Normal,
    Warn,
    Critical,
    /// kanmond に届かない
    Down,
}

fn rank(level: &str) -> u8 {
    match level {
        "critical" => 3,
        "warn" => 2,
        "notice" => 1,
        _ => 0,
    }
}

#[derive(Debug, Default)]
pub struct Model {
    /// 見た（トーストを出した・出さないと決めた）警告の ID
    seen: HashSet<String>,
    /// 「確認済みにする」を押したときにあった警告の ID（アイコンの色を戻す）
    acked: HashSet<String>,
    initialized: bool,
}

impl Model {
    /// 新しい状態を受け取り、トーストを出す警告を返す（古い順）
    pub fn update(&mut self, st: &Status, paused: bool) -> Vec<Alert> {
        let mut out = vec![];
        for a in &st.alerts {
            if self.seen.insert(a.id.clone()) && self.initialized && !paused && rank(&a.level) >= 2 {
                out.push(a.clone());
            }
        }
        self.initialized = true;
        // 覚える数を抑える（kanmond の一覧は最大 50 件）
        if self.seen.len() > 2_000 {
            let keep: HashSet<String> = st.alerts.iter().map(|a| a.id.clone()).collect();
            self.seen.retain(|x| keep.contains(x));
            self.acked.retain(|x| keep.contains(x));
        }
        out.reverse();
        out
    }

    /// 今ある警告をすべて確認済みにする
    pub fn ack_all(&mut self, st: &Status) {
        self.acked.extend(st.alerts.iter().map(|a| a.id.clone()));
    }

    /// アイコンの状態：確認していない警告のうち一番重いもの
    pub fn icon(&self, st: Option<&Status>) -> IconState {
        let Some(st) = st else { return IconState::Down };
        let top = st.alerts.iter().filter(|a| !self.acked.contains(&a.id)).map(|a| rank(&a.level)).max().unwrap_or(0);
        match top {
            3 => IconState::Critical,
            2 => IconState::Warn,
            _ => IconState::Normal,
        }
    }

    /// 確認していない warn 以上の件数
    pub fn unacked(&self, st: &Status) -> usize {
        st.alerts.iter().filter(|a| rank(&a.level) >= 2 && !self.acked.contains(&a.id)).count()
    }
}

/// 表示用：制御文字を空白にし、連続する空白をまとめ、`max` 文字で切る（切ったら … を付ける）
pub fn clean(s: &str, max: usize) -> String {
    let t: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
    if t.chars().count() > max {
        format!("{}…", t.chars().take(max.saturating_sub(1)).collect::<String>())
    } else {
        t
    }
}

/// 複数行の本文：行ごとに clean し、`lines` 行まで
pub fn clean_body(s: &str, lines: usize, max: usize) -> String {
    s.lines().map(|l| clean(l, max)).filter(|l| !l.is_empty()).take(lines).collect::<Vec<_>>().join("\n")
}

/// XML の文字をエスケープする（トーストの XML に入れるため）
pub fn xml_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            _ => o.push(c),
        }
    }
    o
}

/// トーストの XML（ToastGeneric）。文字列はエスケープして入れる
pub fn toast_xml(title: &str, body: &str) -> String {
    format!(
        "<toast><visual><binding template=\"ToastGeneric\"><text>{}</text><text>{}</text></binding></visual></toast>",
        xml_escape(&clean(title, 120)),
        xml_escape(&clean_body(body, 4, 200))
    )
}

/// メニューの 1 行（直近の警告）
pub fn menu_label(a: &Alert) -> String {
    let lv = match a.level.as_str() {
        "critical" => "【重大】",
        "warn" => "【警告】",
        "notice" => "【注意】",
        _ => "",
    };
    // ts は "2026-11-19T03:14:00+09:00" → "11-19 03:14"
    let t = a.ts.get(5..16).map(|x| x.replace('T', " ")).unwrap_or_default();
    // & はメニューのアクセラレータになるので && にする
    clean(&format!("{t} {lv}{}", a.title), 70).replace('&', "&&")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(alerts: &[(&str, &str)]) -> Status {
        Status {
            alerts: alerts
                .iter()
                .map(|(id, lv)| Alert {
                    id: id.to_string(),
                    ts: "2026-11-19T03:14:00+09:00".into(),
                    level: lv.to_string(),
                    score: 60,
                    kind: "connect".into(),
                    title: format!("t{id}"),
                    body: "b".into(),
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn toasts_only_new_warn_and_above_after_start() {
        let mut m = Model::default();
        // 起動直後の警告は出さない
        assert!(m.update(&st(&[("a", "critical")]), false).is_empty());
        // 新しいものだけ。notice は出さない。古い順
        let t = m.update(&st(&[("d", "notice"), ("c", "warn"), ("b", "critical"), ("a", "critical")]), false);
        assert_eq!(t.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(), vec!["b", "c"]);
        // 一時停止中は出さないが、見たことにする
        assert!(m.update(&st(&[("e", "critical")]), true).is_empty());
        assert!(m.update(&st(&[("e", "critical")]), false).is_empty());
    }

    #[test]
    fn icon_and_ack() {
        let mut m = Model::default();
        assert_eq!(m.icon(None), IconState::Down);
        let s = st(&[("a", "warn"), ("b", "notice")]);
        assert_eq!(m.icon(Some(&s)), IconState::Warn);
        assert_eq!(m.unacked(&s), 1);
        m.ack_all(&s);
        assert_eq!(m.icon(Some(&s)), IconState::Normal);
        let s2 = st(&[("c", "critical"), ("a", "warn")]);
        assert_eq!(m.icon(Some(&s2)), IconState::Critical);
    }

    #[test]
    fn parse_status() {
        let j = r#"{"version":"0.4.0","host":"h","os":"windows","mode":"observe","learning":false,
            "alerts":[{"id":"e1","ts":"2026-11-19T03:14:00+09:00","level":"warn","score":60,"kind":"connect","title":"x","body":"y"}],
            "counts_24h":{"warn":1}}"#;
        let s = Status::parse(j).unwrap();
        assert_eq!((s.host.as_str(), s.alerts.len()), ("h", 1));
        assert!(Status::parse(r#"{"error":"forbidden"}"#).is_none());
        assert!(Status::parse("garbage").is_none());
    }

    #[test]
    fn text_is_cleaned_and_escaped() {
        let x = toast_xml("a<b>&\u{7}c", "line1\u{1b}[31m\n\nline2 <script>");
        assert_eq!(
            x,
            "<toast><visual><binding template=\"ToastGeneric\"><text>a&lt;b&gt;&amp; c</text>\
             <text>line1 [31m\nline2 &lt;script&gt;</text></binding></visual></toast>"
        );
        assert_eq!(clean(&"あ".repeat(10), 5), "ああああ…");
        let a = Alert {
            id: "1".into(),
            ts: "2026-11-19T03:14:00+09:00".into(),
            level: "critical".into(),
            score: 100,
            kind: String::new(),
            title: "R&D".into(),
            body: String::new(),
        };
        assert_eq!(menu_label(&a), "11-19 03:14 【重大】R&&D");
    }
}
