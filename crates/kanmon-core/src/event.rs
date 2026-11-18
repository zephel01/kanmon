//! 接続イベント（設計書 §18.2、ECS 寄せ）とフィールド参照。

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `a.b.c` 形式でネストした JSON を辿る。配列の途中は辿らない。
pub fn get_path<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    if cur.is_null() {
        None
    } else {
        Some(cur)
    }
}

/// `a.b.c` に値を書き込む（途中のオブジェクトは作る）。
pub fn set_path(v: &mut Value, path: &str, val: Value) {
    let segs: Vec<&str> = path.split('.').collect();
    let mut cur = v;
    for (i, seg) in segs.iter().enumerate() {
        if !cur.is_object() {
            *cur = Value::Object(Default::default());
        }
        let obj = cur.as_object_mut().expect("object");
        if i == segs.len() - 1 {
            obj.insert((*seg).to_string(), val);
            return;
        }
        cur = obj.entry((*seg).to_string()).or_insert_with(|| Value::Object(Default::default()));
    }
}

/// 旧名 netmon 時代のイベント（判定欄が `netmon.*`）を `kanmon.*` に読み替える。
/// replay / alerts / tail で古いログをそのまま扱えるようにするため。
pub fn migrate_legacy(v: &mut Value) {
    if let Some(obj) = v.as_object_mut() {
        if !obj.contains_key("kanmon") {
            if let Some(x) = obj.remove("netmon") {
                obj.insert("kanmon".to_string(), x);
            }
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Event {
    #[serde(rename = "@timestamp")]
    pub timestamp: String,
    pub event: EventMeta,
    pub host: Host,
    pub network: Network,
    pub process: Process,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Endpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<Destination>,
    /// DNS の問い合わせ・応答（ECS の `dns.*`）。DNS の改ざん検知イベントで使う
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<Dns>,
    /// 対象のファイル（ECS の `file.*`）。hosts の書き換え等
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<File>,
    pub kanmon: KanmonInfo,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Dns {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub question: Option<DnsQuestion>,
    /// 応答の A/AAAA
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_ip: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct File {
    pub path: String,
}

/// DNS の改ざん検知で分かった事実（`kanmon.dns.*`）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsFacts {
    /// hosts_changed / resolver_changed / crosscheck_mismatch / private_answer / conflicting_answer / unexpected_resolver
    pub finding: String,
    /// 監視リストのドメインが関わる
    #[serde(default)]
    pub watched: bool,
    /// hosts で監視リストのドメインが、ループバック以外の IP へ向けられている
    #[serde(default)]
    pub redirected: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<String>,
    /// 追加された DNS サーバーの最も外側の範囲（internet / lan / loopback）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub added_scope: Option<String>,
    /// インターネット上の、よく使われる公開 DNS でもないサーバーが追加された
    #[serde(default)]
    pub unknown_public: bool,
    /// 応答を返した DNS サーバー
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// 比較相手の答え（競合した前の応答、DoH の答え）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub other: Vec<String>,
    /// 答えの IP ごとの TLS 証明書の確認結果（N3）。例 `203.0.113.5: 証明書の検証に失敗（…）`
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tls: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventMeta {
    pub id: String,
    pub kind: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Host {
    pub name: String,
    pub os: String,
}

/// `kind`：connect（外向き）/ accept（内向き接続）/ listen（待受）/ raw_socket / beacon_report
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Network {
    pub kind: String,
    pub direction: String,
    pub transport: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Process {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_signature: Option<CodeSignature>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<Parent>,
    /// 親から上へ向かう実行ファイル名（basename）の列
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_chain: Vec<String>,
    #[serde(default)]
    pub exe_deleted: bool,
    #[serde(default)]
    pub memfd: bool,
    #[serde(default)]
    pub hidden: bool,
    /// インタプリタ（python/node/bash 等）なら true。script に argv のスクリプトパス
    #[serde(default)]
    pub interpreter: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    /// 安定識別キー（署名/パッケージ/ハッシュ由来）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proc_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    /// kanmon が初めてこの proc_key を見てからの秒数
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen_age_s: Option<i64>,
    /// 実行ファイルの mtime からの経過秒
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_age_s: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Hash {
    pub sha256: String,
}

/// status: apple / app_store / developer_id / signed_other / adhoc / unsigned /
///         package / unmanaged / unknown
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CodeSignature {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Parent {
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Endpoint {
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Destination {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registered_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_source: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KanmonInfo {
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub score: i32,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub signals: Vec<crate::detect::SignalHit>,
    // ---- 検知ルールが参照する事実（facts） ----
    #[serde(default)]
    pub ti_match: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ti_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dga_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub beacon: Option<crate::beacon::BeaconScore>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest_key: Option<String>,
    /// このプロセスが初めて行く宛先（ベースライン差分）
    #[serde(default)]
    pub dest_first_for_process: bool,
    /// このプロセスが初めて使うリモートポート
    #[serde(default)]
    pub port_first_for_process: bool,
    /// 待受がベースラインに無い
    #[serde(default)]
    pub listen_new: bool,
    /// 学習期間中か
    #[serde(default)]
    pub learning: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsFacts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<BytesFacts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persist: Option<PersistFacts>,
    /// 直近（既定 24 時間）に、起動のたびに動く仕掛けが追加・変更された種類（pth_exec・claude_hook 等）。
    /// 通信のイベントに付け、「仕込み → 外へ送る」の 2 段階を結び付けて評価する
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub persist_recent: Vec<String>,
}

/// 居座りの検知（`network.kind = persistence`）の事実（`kanmon.persist.*`）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistFacts {
    /// claude_hook / vscode_folderopen / pth_exec / workflow / git_hook / autostart / rc_pipe
    pub kind: String,
    /// added / changed / removed
    pub change: String,
    /// 中身の要約（フックのコマンド等）
    pub detail: String,
    /// network / pipe_shell / inline_code / base64 / tmp_path（workflow は secrets_dump / secrets_send / oidc_token）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub risky: Vec<String>,
    /// pth_exec のとき、最初に読み込むモジュールのトップレベル名
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
}

/// 送信量の報告（`network.kind = bytes_report`）の事実（`kanmon.bytes.*`）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BytesFacts {
    /// 窓の中で、この宛先へ送ったバイト数
    pub out: u64,
    /// 集計の窓（秒）
    pub window_s: u64,
    /// 開いている通常ファイルの合計容量
    #[serde(default)]
    pub open_size: u64,
    /// 送信量 ÷ 開いているファイルの合計（開いているファイルが無ければ無し）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_per_open: Option<f64>,
    /// 開いているファイルのパス（容量の大きい順、最大 128 件）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_paths: Vec<String>,
    /// 開いているファイルの拡張子（小文字）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_exts: Vec<String>,
    /// 表示用：大きい順に 5 件「パス (容量)」
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_top: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn path_roundtrip() {
        let mut v = json!({});
        set_path(&mut v, "a.b.c", json!(3));
        assert_eq!(get_path(&v, "a.b.c"), Some(&json!(3)));
        assert_eq!(get_path(&v, "a.x"), None);
    }

    #[test]
    fn legacy_namespace() {
        let mut v = json!({"netmon": {"score": 5}});
        migrate_legacy(&mut v);
        assert_eq!(get_path(&v, "kanmon.score"), Some(&json!(5)));
        assert!(v.get("netmon").is_none());
    }

    #[test]
    fn event_serializes_ecs_names() {
        let e = Event::default();
        let v = serde_json::to_value(&e).unwrap();
        assert!(v.get("@timestamp").is_some());
        assert!(get_path(&v, "kanmon.ti_match").is_some());
    }
}
