//! 通知・一覧表示用の文面（人が読む形）。ライブ通知と `kanmonctl alerts` で共通。

use crate::event::get_path;
use serde_json::Value;

fn s<'a>(v: &'a Value, p: &str) -> Option<&'a str> {
    get_path(v, p).and_then(|x| x.as_str()).filter(|x| !x.is_empty())
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

fn sig_label(status: &str) -> &str {
    match status {
        "apple" => "Apple 署名",
        "app_store" => "App Store",
        "developer_id" => "Developer ID 署名",
        "signed_other" => "その他の署名",
        "invalid" => "署名の検証に失敗",
        "adhoc" => "ad-hoc 署名（実質未署名）",
        "unsigned" => "未署名",
        "package" => "公式パッケージ",
        "unmanaged" => "パッケージ管理外",
        _ => "不明",
    }
}

fn kind_label(kind: &str) -> &str {
    match kind {
        "connect" => "外向き接続",
        "accept" => "着信",
        "listen" => "待受",
        "raw_socket" => "raw ソケット",
        "beacon_report" => "周期通信（ビーコン）",
        "dns_integrity" => "DNS の改ざん検知",
        _ => kind,
    }
}

fn finding_label(f: &str) -> &str {
    match f {
        "hosts_changed" => "hosts が書き換えられた",
        "resolver_changed" => "DNS サーバーの設定が変わった",
        "crosscheck_mismatch" => "暗号化 DNS で引き直した答えと合わない",
        "private_answer" => "公開ドメインがローカルの IP に解決された",
        "conflicting_answer" => "同じ問い合わせに違う応答が届いた",
        "unexpected_resolver" => "設定にない DNS サーバーから応答",
        _ => f,
    }
}

fn strs(v: &Value, p: &str) -> Vec<String> {
    get_path(v, p)
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// DNS の改ざん検知イベントの文面
fn dns_text(v: &Value, level: &str, score: i64) -> (String, String) {
    let f = s(v, "kanmon.dns.finding").unwrap_or("?");
    let subject = s(v, "dns.question.name").or_else(|| s(v, "file.path")).unwrap_or("");
    let title =
        format!("kanmon {} {}点: {} {}", level.to_uppercase(), score, finding_label(f), subject).trim_end().to_string();
    let mut lines = vec![format!("【理由】合計 {score} 点（{level}）")];
    if let Some(sigs) = get_path(v, "kanmon.signals").and_then(|x| x.as_array()) {
        for h in sigs {
            let desc = h["description"].as_str().filter(|d| !d.is_empty()).or(h["name"].as_str()).unwrap_or("?");
            lines.push(format!("・{desc}（{:+}）", h["points"].as_i64().unwrap_or(0)));
        }
    }
    lines.push(String::new());
    lines.push(format!("【内容】{}", finding_label(f)));
    if let Some(p) = s(v, "file.path") {
        lines.push(format!("  ファイル: {p}"));
    }
    if let Some(q) = s(v, "dns.question.name") {
        lines.push(format!("  名前: {q}"));
    }
    let ips = strs(v, "dns.resolved_ip");
    if !ips.is_empty() {
        lines.push(format!("  答え: {}", ips.join(", ")));
    }
    let other = strs(v, "kanmon.dns.other");
    if !other.is_empty() {
        let label = if f == "crosscheck_mismatch" { "暗号化 DNS の答え" } else { "もう一方の答え" };
        lines.push(format!("  {label}: {}", other.join(", ")));
    }
    if let Some(sv) = s(v, "kanmon.dns.server") {
        lines.push(format!("  DNS サーバー: {sv}"));
    }
    for (k, label) in [("kanmon.dns.added", "追加"), ("kanmon.dns.removed", "削除")] {
        let a = strs(v, k);
        for x in a.iter().take(10) {
            lines.push(format!("  {label}: {x}"));
        }
        if a.len() > 10 {
            lines.push(format!("  {label}: ほか {} 件", a.len() - 10));
        }
    }
    if let Some(ts) = s(v, "@timestamp") {
        lines.push(format!("【時刻】{ts}  id {}", s(v, "event.id").unwrap_or("?")));
    }
    (title, lines.join("\n"))
}

/// (タイトル, 本文) を返す。タイトルは 1 行、本文は複数行。
pub fn alert_text(v: &Value) -> (String, String) {
    if s(v, "network.kind") == Some("dns_integrity") {
        let level = s(v, "kanmon.level").unwrap_or("info");
        let score = get_path(v, "kanmon.score").and_then(|x| x.as_i64()).unwrap_or(0);
        return dns_text(v, level, score);
    }
    let level = s(v, "kanmon.level").unwrap_or("info");
    let score = get_path(v, "kanmon.score").and_then(|x| x.as_i64()).unwrap_or(0);
    let kind = s(v, "network.kind").unwrap_or("");
    let exe = s(v, "process.executable").or_else(|| s(v, "process.proc_key")).unwrap_or("不明なプロセス");
    let target = match kind {
        "beacon_report" => s(v, "destination.domain").or_else(|| s(v, "kanmon.dest_key")).unwrap_or("?").to_string(),
        "listen" | "raw_socket" => format!(
            "{}:{}",
            s(v, "source.ip").unwrap_or("?"),
            get_path(v, "source.port").map(|x| x.to_string()).unwrap_or_default()
        ),
        _ => {
            let host = s(v, "destination.domain").or_else(|| s(v, "destination.ip")).unwrap_or("?");
            let port = get_path(v, "destination.port").map(|x| x.to_string()).unwrap_or_default();
            let h = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
            format!("{h}:{port}")
        }
    };
    let arrow = if kind == "accept" { "←" } else { "→" };
    let title = format!("kanmon {} {}点: {} {} {}", level.to_uppercase(), score, basename(exe), arrow, target);

    let mut lines = vec![];
    lines.push(format!("【理由】合計 {score} 点（{level}）"));
    if let Some(sigs) = get_path(v, "kanmon.signals").and_then(|x| x.as_array()) {
        for h in sigs {
            let desc = h["description"].as_str().filter(|d| !d.is_empty()).or(h["name"].as_str()).unwrap_or("?");
            lines.push(format!("・{desc}（{:+}）", h["points"].as_i64().unwrap_or(0)));
        }
    }
    if let Some(src) = s(v, "kanmon.ti_source") {
        lines.push(format!("  一致したリスト: {src}"));
    }
    if let Some(b) = get_path(v, "kanmon.beacon") {
        lines.push(format!(
            "  {} 回、間隔の中央値 {:.0} 秒（ばらつき {:.1} 秒）、周期スコア {:.2}",
            b["n"].as_u64().unwrap_or(0),
            b["median_interval_s"].as_f64().unwrap_or(0.0),
            b["mad_s"].as_f64().unwrap_or(0.0),
            b["score"].as_f64().unwrap_or(0.0)
        ));
    }
    lines.push(String::new());
    lines.push(format!("【通信】{}  {} {}", kind_label(kind), arrow, target));
    if let Some(sc) = s(v, "network.scope") {
        lines.push(format!("  範囲: {sc}  / {}", s(v, "network.transport").unwrap_or("")));
    }
    lines.push(format!("【プロセス】{exe}"));
    let pid = get_path(v, "process.pid").map(|x| x.to_string());
    let user = s(v, "process.user");
    if pid.is_some() || user.is_some() {
        lines.push(format!("  pid {}  ユーザー {}", pid.unwrap_or_else(|| "?".into()), user.unwrap_or("?")));
    }
    if let Some(st) = s(v, "process.code_signature.status") {
        let mut l = format!("  署名: {}", sig_label(st));
        if let Some(t) = s(v, "process.code_signature.team_id") {
            l.push_str(&format!("  Team {t}"));
        }
        if let Some(p) = s(v, "process.code_signature.package") {
            l.push_str(&format!("  パッケージ {p}"));
        }
        lines.push(l);
    }
    if let Some(sc) = s(v, "process.script") {
        lines.push(format!("  スクリプト: {sc}"));
    }
    if let Some(chain) = get_path(v, "process.parent_chain").and_then(|x| x.as_array()) {
        let c: Vec<&str> = chain.iter().filter_map(|x| x.as_str()).collect();
        if !c.is_empty() {
            lines.push(format!("  親: {}", c.join(" ← ")));
        }
    }
    if let Some(h) = s(v, "process.hash.sha256") {
        lines.push(format!("  SHA-256: {h}"));
    }
    if let Some(vd) = s(v, "kanmon.verdict") {
        lines.push(format!("【判定】{vd}（{}）", s(v, "kanmon.rule_id").unwrap_or("-")));
    }
    if let Some(ts) = s(v, "@timestamp") {
        lines.push(format!("【時刻】{ts}  id {}", s(v, "event.id").unwrap_or("?")));
    }
    (title, lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn readable_text() {
        let v = json!({
            "@timestamp": "2026-11-18T10:19:07.841+09:00",
            "event": {"id": "e_1"},
            "network": {"kind": "connect", "scope": "internet", "transport": "tcp"},
            "process": {"executable": "/private/tmp/updater", "pid": 42, "user": "alice",
                        "code_signature": {"status": "adhoc"}, "parent_chain": ["zsh", "Terminal"],
                        "hash": {"sha256": "ab"}},
            "destination": {"ip": "198.51.100.7", "port": 443},
            "kanmon": {"level": "critical", "score": 160, "ti_source": "local:blocklist.txt",
                       "verdict": "would_deny", "rule_id": "threat_intel",
                       "signals": [{"id": "S1", "name": "threat_intel_match", "points": 100,
                                    "description": "脅威インテル（既知の悪性 IP・ドメイン）に一致"},
                                   {"id": "S4", "name": "temp_dir_exec", "points": 25}]}
        });
        let (t, b) = alert_text(&v);
        assert_eq!(t, "kanmon CRITICAL 160点: updater → 198.51.100.7:443");
        assert!(b.contains("・脅威インテル（既知の悪性 IP・ドメイン）に一致（+100）"), "{b}");
        assert!(b.contains("・temp_dir_exec（+25）"), "{b}");
        assert!(b.contains("一致したリスト: local:blocklist.txt"));
        assert!(b.contains("署名: ad-hoc 署名（実質未署名）"));
        assert!(b.contains("親: zsh ← Terminal"));
        assert!(b.contains("【判定】would_deny（threat_intel）"));
    }

    #[test]
    fn beacon_and_ipv6() {
        let v = json!({"network": {"kind": "beacon_report"}, "process": {"executable": "/x/sync"},
                       "kanmon": {"level": "warn", "score": 75, "dest_key": "203.0.113.0/24",
                                  "beacon": {"n": 11, "median_interval_s": 60.0, "mad_s": 1.0, "score": 0.86}}});
        let (t, b) = alert_text(&v);
        assert_eq!(t, "kanmon WARN 75点: sync → 203.0.113.0/24");
        assert!(b.contains("11 回、間隔の中央値 60 秒"));
        let v6 = json!({"network": {"kind": "connect"}, "destination": {"ip": "2001:db8::1", "port": 443},
                        "kanmon": {"level": "notice", "score": 30}});
        assert!(alert_text(&v6).0.ends_with("[2001:db8::1]:443"));
    }

    #[test]
    fn dns_integrity_text() {
        let v = json!({"network": {"kind": "dns_integrity"}, "file": {"path": "/etc/hosts"},
                       "kanmon": {"level": "critical", "score": 140,
                                  "dns": {"finding": "hosts_changed", "redirected": true,
                                          "added": ["203.0.113.66 registry.npmjs.org"]}}});
        let (t, b) = alert_text(&v);
        assert_eq!(t, "kanmon CRITICAL 140点: hosts が書き換えられた /etc/hosts");
        assert!(b.contains("追加: 203.0.113.66 registry.npmjs.org"), "{b}");
    }
}
