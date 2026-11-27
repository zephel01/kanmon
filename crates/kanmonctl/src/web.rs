//! `kanmonctl web`：脅威の履歴・プロセスのつながりをブラウザで見る（v0.5.7、読み取り専用）。
//!
//! - 自分のマシンの 127.0.0.1 だけで待ち受ける（ポートは既定で起動のたびに変わる）
//! - データは kanmond の状態ソケット（history / event / process / tree）から取る。DB は直接読まない
//! - 守り
//!   - 起動時に作ったトークンが合わない要求は断る（ページは `?t=`、API は `X-Kanmon-Token` ヘッダー）。
//!     ヘッダーが要るので、他のサイトのページから API は呼べない（CORS の許可は返さない）
//!   - Host ヘッダーが 127.0.0.1:ポート / localhost:ポート 以外なら断る（DNS リバインディング対策）
//!   - 画面は実行ファイルに埋め込んだ HTML・JS・CSS だけで、外部から何も読まない。CSP で外への通信と
//!     インラインのスクリプトを止める。外から来た文字列（プロセス名・ドメイン）は JS 側で textContent で出す
//!   - ソケットへ渡すのは、決めたキーと型だけ（文字列は長さを切り、制御文字を含むものは捨てる）

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const INDEX_HTML: &str = include_str!("web/index.html");
const APP_JS: &str = include_str!("web/app.js");
const APP_CSS: &str = include_str!("web/app.css");

/// ソケットの応答の上限
const MAX_RESPONSE: u64 = 64 * 1024 * 1024;

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; \
                   base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub struct Options {
    pub socket: PathBuf,
    pub port: u16,
    pub open: bool,
    /// この秒数のあいだ要求が無ければ終わる（0 は終わらない）
    pub idle_exit: u64,
}

/// 32 バイトの乱数を 16 進にする
fn new_token() -> Result<String> {
    let mut b = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// 時間が長さだけに比例する比較（トークンの照合）
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `%XX` と `+` を戻す（不正な並びはそのまま）
pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let h = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok());
                match h {
                    Some(v) => {
                        out.push(v);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// URL をパスとクエリ（キー → 値）に分ける
pub fn split_url(url: &str) -> (String, Vec<(String, String)>) {
    let (path, q) = url.split_once('?').unwrap_or((url, ""));
    let params = q
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect();
    (path.to_string(), params)
}

/// Host ヘッダーが自分（127.0.0.1 / localhost と待ち受けのポート）か
pub fn host_ok(host: Option<&str>, port: u16) -> bool {
    let Some(h) = host else { return false };
    h == format!("127.0.0.1:{port}") || h == format!("localhost:{port}")
}

/// API の要求を、ソケットへ渡す JSON にする。決めたキーと型だけを通す
pub fn api_request(cmd: &str, params: &[(String, String)]) -> Option<Value> {
    let (ints, strs): (&[&str], &[&str]) = match cmd {
        "history" => (&["hours", "limit"], &["level", "rule", "q", "before"]),
        "event" => (&[], &["id"]),
        "process" => (&["hours"], &["proc_key"]),
        "tree" => (&["hours"], &["min_level"]),
        _ => return None,
    };
    let mut m = Map::new();
    m.insert("cmd".into(), cmd.into());
    for (k, v) in params {
        if ints.contains(&k.as_str()) {
            if let Ok(n) = v.parse::<i64>() {
                m.insert(k.clone(), n.into());
            }
        } else if strs.contains(&k.as_str()) && !v.is_empty() && v.len() <= 200 && !v.chars().any(char::is_control) {
            m.insert(k.clone(), v.clone().into());
        }
    }
    Some(Value::Object(m))
}

/// 状態ソケットに 1 行の要求を送り、1 行の応答を受け取る
pub fn socket_call(socket: &Path, req: &Value) -> Result<String> {
    let mut s = UnixStream::connect(socket)
        .with_context(|| format!("{} に接続できません（kanmond が動いているか）", socket.display()))?;
    s.set_read_timeout(Some(Duration::from_secs(60)))?;
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    s.write_all(format!("{req}\n").as_bytes())?;
    let mut out = String::new();
    s.take(MAX_RESPONSE).read_to_string(&mut out)?;
    Ok(out.trim_end().to_string())
}

fn header(k: &str, v: &str) -> tiny_http::Header {
    tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()).expect("固定のヘッダー")
}

fn respond(req: tiny_http::Request, status: u16, ctype: &str, body: String) {
    let mut r = tiny_http::Response::from_string(body).with_status_code(status);
    for (k, v) in [
        ("Content-Type", ctype),
        ("Content-Security-Policy", CSP),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Cache-Control", "no-store"),
        ("Cross-Origin-Resource-Policy", "same-origin"),
    ] {
        r.add_header(header(k, v));
    }
    let _ = req.respond(r);
}

/// 1 件の要求の振り分け（応答の状態・種類・本文）。テストのため Request から切り離す
pub fn route(
    method: &str,
    url: &str,
    host: Option<&str>,
    token_header: Option<&str>,
    port: u16,
    token: &str,
    call: &dyn Fn(&Value) -> Result<String>,
) -> (u16, &'static str, String) {
    const JSON: &str = "application/json; charset=utf-8";
    const TEXT: &str = "text/plain; charset=utf-8";
    if !host_ok(host, port) {
        return (403, TEXT, "Host が違います".into());
    }
    if method != "GET" {
        return (405, TEXT, "GET だけ受け付けます".into());
    }
    let (path, params) = split_url(url);
    match path.as_str() {
        "/" => {
            let t = params.iter().find(|(k, _)| k == "t").map(|(_, v)| v.as_str()).unwrap_or("");
            if ct_eq(t, token) {
                (200, "text/html; charset=utf-8", INDEX_HTML.to_string())
            } else {
                (403, TEXT, "kanmonctl web が表示した URL（?t= 付き）を開いてください".into())
            }
        }
        "/app.js" => (200, "text/javascript; charset=utf-8", APP_JS.to_string()),
        "/app.css" => (200, "text/css; charset=utf-8", APP_CSS.to_string()),
        p if p.starts_with("/api/") => {
            if !token_header.is_some_and(|t| ct_eq(t, token)) {
                return (403, JSON, json!({"error": "トークンが違います"}).to_string());
            }
            let Some(req) = api_request(&p["/api/".len()..], &params) else {
                return (404, JSON, json!({"error": "ありません"}).to_string());
            };
            match call(&req) {
                Ok(body) => (200, JSON, body),
                Err(e) => (502, JSON, json!({"error": format!("{e:#}")}).to_string()),
            }
        }
        _ => (404, TEXT, "ありません".into()),
    }
}

pub fn run(o: Options) -> Result<()> {
    // 先にソケットへ届くかを確かめる（届かなくても画面は開ける）
    if let Err(e) = socket_call(&o.socket, &json!({"cmd": "ping"})) {
        eprintln!("注意: {e:#}");
    }
    let server =
        tiny_http::Server::http(("127.0.0.1", o.port)).map_err(|e| anyhow::anyhow!("待ち受けできません: {e}"))?;
    let port = server.server_addr().to_ip().map(|a| a.port()).context("ポートが分かりません")?;
    let token = new_token()?;
    let url = format!("http://127.0.0.1:{port}/?t={token}");
    println!("ブラウザで開いてください（このマシンからだけ見られます。Ctrl-C で終わります）\n{url}");
    let _ = std::io::stdout().flush();
    if o.open {
        let opener = if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
        // シェルを通さず、URL は引数として渡す
        if let Err(e) = std::process::Command::new(opener).arg(&url).spawn() {
            eprintln!("ブラウザを開けませんでした（{opener}: {e}）。上の URL を開いてください");
        }
    }
    let socket = o.socket.clone();
    let call = move |req: &Value| socket_call(&socket, req);
    let mut last = Instant::now();
    loop {
        let req = match server.recv_timeout(Duration::from_secs(5)) {
            Ok(Some(r)) => r,
            Ok(None) => {
                if o.idle_exit > 0 && last.elapsed() > Duration::from_secs(o.idle_exit) {
                    println!("{} 秒のあいだ要求が無かったので終わります", o.idle_exit);
                    return Ok(());
                }
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        last = Instant::now();
        let get = |name: &'static str| {
            req.headers().iter().find(|h| h.field.equiv(name)).map(|h| h.value.as_str().to_string())
        };
        let (host, tok) = (get("Host"), get("X-Kanmon-Token"));
        let method = req.method().as_str().to_string();
        let url = req.url().to_string();
        let (status, ctype, body) = route(&method, &url, host.as_deref(), tok.as_deref(), port, &token, &call);
        respond(req, status, ctype, body);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_and_split() {
        assert_eq!(percent_decode("a%20b+c%E3%81%82%zz%4"), "a b cあ%zz%4");
        let (p, q) = split_url("/api/history?q=50%25&level=notice&x");
        assert_eq!(p, "/api/history");
        assert_eq!(q, [("q".into(), "50%".into()), ("level".into(), "notice".into()), ("x".into(), String::new())]);
    }

    #[test]
    fn api_request_allows_only_known_keys() {
        let p = |v: &[(&str, &str)]| v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect::<Vec<_>>();
        let r = api_request(
            "history",
            &p(&[("hours", "24"), ("q", "curl"), ("cmd", "export"), ("limit", "x"), ("rule", "a\nb"), ("evil", "1")]),
        )
        .unwrap();
        assert_eq!(
            r,
            json!({"cmd": "history", "hours": 24, "q": "curl"}),
            "cmd の差し替え・知らないキー・制御文字は通さない"
        );
        assert!(api_request("export", &[]).is_none(), "書き出しはブラウザから呼べない");
        assert!(api_request("status", &[]).is_none());
        let long = "a".repeat(201);
        assert_eq!(api_request("event", &p(&[("id", &long)])).unwrap(), json!({"cmd": "event"}));
    }

    #[test]
    fn route_checks_host_token_and_method() {
        let tok = "t0k";
        let call = |req: &Value| Ok(json!({"echo": req}).to_string());
        let r = |m: &str, u: &str, h: Option<&str>, t: Option<&str>| route(m, u, h, t, 8080, tok, &call);
        assert_eq!(r("GET", "/?t=t0k", Some("127.0.0.1:8080"), None).0, 200);
        assert_eq!(r("GET", "/?t=t0k", Some("localhost:8080"), None).0, 200);
        assert_eq!(r("GET", "/?t=bad", Some("127.0.0.1:8080"), None).0, 403);
        assert_eq!(r("GET", "/", Some("127.0.0.1:8080"), None).0, 403);
        assert_eq!(r("GET", "/?t=t0k", Some("evil.example:8080"), None).0, 403, "DNS リバインディング");
        assert_eq!(r("GET", "/?t=t0k", None, None).0, 403);
        assert_eq!(r("POST", "/api/tree", Some("127.0.0.1:8080"), Some(tok)).0, 405);
        assert_eq!(r("GET", "/api/tree?hours=2", Some("127.0.0.1:8080"), None).0, 403);
        assert_eq!(r("GET", "/api/tree?hours=2", Some("127.0.0.1:8080"), Some("t0x")).0, 403);
        let (s, _, b) = r("GET", "/api/tree?hours=2", Some("127.0.0.1:8080"), Some(tok));
        assert_eq!(s, 200);
        assert_eq!(serde_json::from_str::<Value>(&b).unwrap()["echo"], json!({"cmd": "tree", "hours": 2}));
        assert_eq!(r("GET", "/api/export", Some("127.0.0.1:8080"), Some(tok)).0, 404);
        assert_eq!(r("GET", "/app.js", Some("127.0.0.1:8080"), None).0, 200);
        assert_eq!(r("GET", "/../etc/passwd", Some("127.0.0.1:8080"), None).0, 404);
    }

    #[test]
    fn assets_have_no_external_or_inline_code() {
        assert!(!INDEX_HTML.contains("<script>") && !INDEX_HTML.contains("onclick") && !INDEX_HTML.contains("style="));
        for a in [INDEX_HTML, APP_JS, APP_CSS] {
            assert!(!a.contains("http://") && !a.contains("https://"), "外部の URL を含まない");
        }
        assert!(!APP_JS.contains("innerHTML") && !APP_JS.contains("insertAdjacentHTML") && !APP_JS.contains("eval("));
    }
}
