//! プロセス識別（設計書 §6）：署名／パッケージ／SHA-256、安定キー（proc_key）。
//! 結果は (dev, inode, mtime, size) でキャッシュする。

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct Identity {
    /// apple / app_store / developer_id / signed_other / invalid / adhoc / unsigned / package / unmanaged / unknown
    /// （Windows は microsoft / signed_other / unsigned / invalid / unknown）
    pub status: String,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub package: Option<String>,
    pub sha256: Option<String>,
    pub file_age_s: Option<i64>,
}

const MAX_HASH_BYTES: u64 = 512 * 1024 * 1024;

pub fn sha256_file(path: &str) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    if f.metadata().ok()?.len() > MAX_HASH_BYTES {
        return None;
    }
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(hex::encode(h.finalize()))
}

/// `codesign -dvvv` の出力（stderr）を解析
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn parse_codesign(text: &str) -> Identity {
    let mut id = Identity::default();
    if text.contains("code object is not signed") {
        id.status = "unsigned".into();
        return id;
    }
    let mut authorities = vec![];
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("Identifier=") {
            id.signing_id = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("TeamIdentifier=") {
            let v = v.trim();
            if v != "not set" {
                id.team_id = Some(v.to_string());
            }
        } else if let Some(v) = line.strip_prefix("Authority=") {
            authorities.push(v.trim().to_string());
        }
    }
    let adhoc = text.lines().any(|l| l.trim() == "Signature=adhoc") || text.contains("flags=0x2(adhoc)");
    id.status = if adhoc {
        "adhoc"
    } else if authorities.iter().any(|a| a == "Software Signing") {
        "apple"
    } else if authorities.iter().any(|a| a.starts_with("Apple Mac OS Application Signing")) {
        "app_store"
    } else if authorities.iter().any(|a| a.starts_with("Developer ID Application")) {
        "developer_id"
    } else if !authorities.is_empty() {
        "signed_other"
    } else {
        "unknown"
    }
    .into();
    id
}

/// `dpkg-query -S` の出力 `pkg:arch: /path` → `pkg`
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_dpkg_s(text: &str) -> Option<String> {
    let line = text.lines().find(|l| !l.starts_with("diversion"))?;
    let (pkgs, _) = line.split_once(": ")?;
    Some(pkgs.split(',').next()?.trim().to_string())
}

#[cfg(target_os = "macos")]
fn platform_identity(path: &str) -> Identity {
    let out = Command::new("/usr/bin/codesign").args(["-dvvv", path]).output();
    let mut id = match out {
        Ok(o) => parse_codesign(&String::from_utf8_lossy(&o.stderr)),
        Err(_) => Identity { status: "unknown".into(), ..Default::default() },
    };
    // 署名済みなら改ざんの有無を検証（失敗＝invalid）。
    // OS が封印して検証している領域（SSV・Cryptex）は対象外：書き換えには SIP の無効化が必要で、
    // かつ Cryptex 内の Apple 純正バイナリは codesign --verify --strict が失敗することがある（誤検知）。
    if !matches!(id.status.as_str(), "unsigned" | "unknown") && !os_sealed_path(path) {
        let verify = |strict: bool| {
            let mut c = Command::new("/usr/bin/codesign");
            c.arg("--verify");
            if strict {
                c.arg("--strict");
            }
            c.arg(path).output().map(|o| o.status.success()).unwrap_or(false)
        };
        // --strict だけ失敗するもの（バンドル構造の細かい差）は改ざんとはみなさない
        if !verify(true) && !verify(false) {
            id.status = "invalid".into();
        }
    }
    id
}

/// macOS が封印・検証している読み取り専用の領域（Signed System Volume・Cryptex）
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn os_sealed_path(path: &str) -> bool {
    ["/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/lib/", "/bin/", "/sbin/"]
        .iter()
        .any(|p| path.starts_with(p))
}

#[cfg(target_os = "linux")]
fn platform_identity(path: &str) -> Identity {
    let mut candidates = vec![path.to_string()];
    // usr-merge：/usr/bin/x が /bin/x として登録されている場合がある
    if let Some(rest) = path.strip_prefix("/usr") {
        candidates.push(rest.to_string());
    } else {
        candidates.push(format!("/usr{path}"));
    }
    for c in candidates {
        if let Ok(o) = Command::new("dpkg-query").args(["-S", &c]).output() {
            if o.status.success() {
                if let Some(p) = parse_dpkg_s(&String::from_utf8_lossy(&o.stdout)) {
                    return Identity { status: "package".into(), package: Some(p), ..Default::default() };
                }
            }
        }
        if let Ok(o) = Command::new("rpm").args(["-qf", "--qf", "%{NAME}", &c]).output() {
            if o.status.success() {
                let p = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if !p.is_empty() {
                    return Identity { status: "package".into(), package: Some(p), ..Default::default() };
                }
            }
        }
    }
    Identity { status: "unmanaged".into(), ..Default::default() }
}

/// Windows：`Get-AuthenticodeSignature` の結果（JSON）を解釈する。
/// - Valid で署名者が Microsoft → microsoft（OS の部品は「カタログ署名」なので、ファイルに署名が無くてもここで Valid になる）
/// - Valid でその他 → signed_other
/// - NotSigned → unsigned、NotTrusted（信頼されない発行元・自己署名）→ unsigned
/// - HashMismatch（署名後に書き換えられた）→ invalid
/// - それ以外・読めない → unknown
#[cfg_attr(not(windows), allow(dead_code))]
pub fn parse_authenticode(json: &str) -> Identity {
    let unknown = || Identity { status: "unknown".into(), ..Default::default() };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json.trim()) else { return unknown() };
    let st = v.get("status").and_then(|x| x.as_str()).unwrap_or("");
    let subject = v.get("subject").and_then(|x| x.as_str()).unwrap_or("");
    // 署名者の名前（CN=…）を team_id に入れる（表示用）。Windows の署名者は発行元（会社）単位なので、
    // macOS の signing_id（アプリ単位）とは違う。proc_key は SHA-256 で作る（同じ発行元の別アプリを混ぜない）
    let cn = subject
        .split(',')
        .map(str::trim)
        .find_map(|p| p.strip_prefix("CN="))
        .map(|x| x.trim_matches('"').chars().take(200).collect::<String>());
    let status = match st {
        "Valid" if subject.contains("O=Microsoft Corporation") => "microsoft",
        "Valid" => "signed_other",
        "NotSigned" | "NotTrusted" => "unsigned",
        "HashMismatch" => "invalid",
        _ => return unknown(),
    };
    Identity { status: status.into(), team_id: if status == "unsigned" { None } else { cn }, ..Default::default() }
}

#[cfg(windows)]
fn platform_identity(path: &str) -> Identity {
    // パスは環境変数で渡す（コマンドの文字列に埋め込まない。シェルも経由しない）
    const SCRIPT: &str = "$s = Get-AuthenticodeSignature -LiteralPath $env:KANMON_SIG_PATH; \
        [pscustomobject]@{ status = [string]$s.Status; type = [string]$s.SignatureType; \
        subject = $(if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' }) } | ConvertTo-Json -Compress";
    let ps = std::env::var("SystemRoot")
        .map(|r| format!("{r}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"))
        .unwrap_or_else(|_| "powershell.exe".into());
    let out = Command::new(ps)
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", SCRIPT])
        .env("KANMON_SIG_PATH", path)
        .output();
    match out {
        Ok(o) if o.status.success() => parse_authenticode(&String::from_utf8_lossy(&o.stdout)),
        _ => Identity { status: "unknown".into(), ..Default::default() },
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn platform_identity(_path: &str) -> Identity {
    Identity { status: "unknown".into(), ..Default::default() }
}

/// キャッシュの鍵：(デバイス, inode, 更新時刻, 大きさ)。Windows は inode が無いので、パスのハッシュで代える
#[cfg(unix)]
fn file_key(md: &std::fs::Metadata, _path: &str) -> ((u64, u64, i64, u64), i64) {
    use std::os::unix::fs::MetadataExt;
    ((md.dev(), md.ino(), md.mtime(), md.size()), md.mtime())
}

#[cfg(not(unix))]
fn file_key(md: &std::fs::Metadata, path: &str) -> ((u64, u64, i64, u64), i64) {
    use std::hash::{Hash, Hasher};
    let mtime = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut h = std::collections::hash_map::DefaultHasher::new();
    path.to_lowercase().hash(&mut h);
    ((0, h.finish(), mtime, md.len()), mtime)
}

#[derive(Default)]
pub struct IdCache {
    map: HashMap<(u64, u64, i64, u64), Identity>,
}

impl IdCache {
    /// `read_path`：ハッシュ計算に使うパス（Linux は /proc/<pid>/exe で削除済みでも読める）
    /// `display_path`：署名・パッケージ照会に使う実パス
    pub fn identify(&mut self, read_path: &str, display_path: &str, deleted: bool) -> Identity {
        let Ok(md) = std::fs::metadata(read_path) else {
            return Identity { status: "unknown".into(), ..Default::default() };
        };
        let (key, mtime) = file_key(&md, read_path);
        let now = chrono::Utc::now().timestamp();
        if let Some(id) = self.map.get(&key) {
            let mut id = id.clone();
            id.file_age_s = Some(now - mtime);
            return id;
        }
        let mut id = if deleted {
            Identity { status: "unmanaged".into(), ..Default::default() }
        } else {
            platform_identity(display_path)
        };
        id.sha256 = sha256_file(read_path);
        id.file_age_s = Some(now - mtime);
        if self.map.len() > 20_000 {
            self.map.clear();
        }
        self.map.insert(key, id.clone());
        id
    }
}

/// インタプリタ判定。`names` は設定の interpreters。戻り値はスクリプト（無ければ None）
pub fn interpreter_script(exe_name: &str, args: &[String], names: &[String]) -> Option<Option<String>> {
    // Windows の「python.exe」等は拡張子を外して比べる
    let exe_name = exe_name.strip_suffix(".exe").unwrap_or(exe_name);
    let base = exe_name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    let is_interp = names.iter().any(|n| n == exe_name || n == base);
    if !is_interp {
        return None;
    }
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        if a == "-c" || a == "-e" || a == "--eval" || a == "-m" {
            return Some(Some(match a.as_str() {
                "-m" => format!("module:{}", it.next().cloned().unwrap_or_default()),
                _ => "<inline>".to_string(),
            }));
        }
        if a == "-" {
            return Some(Some("<stdin>".to_string()));
        }
        if a.starts_with('-') {
            continue;
        }
        return Some(Some(a.clone()));
    }
    Some(None)
}

/// 安定識別キー
pub fn proc_key(id: &Identity, exe: Option<&str>, script: Option<&str>) -> String {
    let base = match (id.status.as_str(), &id.signing_id, &id.package, &id.sha256) {
        ("apple" | "app_store" | "developer_id" | "signed_other", Some(sid), _, _) => {
            format!("sig:{}:{}", id.team_id.as_deref().unwrap_or("apple"), sid)
        }
        ("package", _, Some(p), _) => format!("pkg:{}:{}", p, exe.unwrap_or("?")),
        (_, _, _, Some(h)) => format!("sha256:{h}"),
        _ => format!("path:{}", exe.unwrap_or("?")),
    };
    match script {
        Some(s) => format!("{base}|script:{s}"),
        None => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticode_variants() {
        let ms = r#"{"status":"Valid","type":"Catalog","subject":"CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"}"#;
        let i = parse_authenticode(ms);
        assert_eq!((i.status.as_str(), i.team_id.as_deref()), ("microsoft", Some("Microsoft Windows")));
        let other =
            r#"{"status":"Valid","type":"Authenticode","subject":"CN=\"Example, Inc.\", O=\"Example, Inc.\", C=US"}"#;
        assert_eq!(parse_authenticode(other).status, "signed_other");
        // O=Microsoft Corporation を名乗っても Valid でなければ microsoft にしない
        let fake = r#"{"status":"NotTrusted","subject":"CN=x, O=Microsoft Corporation"}"#;
        assert_eq!(parse_authenticode(fake).status, "unsigned");
        assert_eq!(parse_authenticode(r#"{"status":"NotSigned","subject":""}"#).status, "unsigned");
        assert_eq!(parse_authenticode(r#"{"status":"HashMismatch","subject":"CN=a"}"#).status, "invalid");
        assert_eq!(parse_authenticode("garbage").status, "unknown");
        // proc_key は発行元ではなくハッシュで作る
        let mut i = parse_authenticode(ms);
        i.sha256 = Some("ab".into());
        assert_eq!(proc_key(&i, Some(r"C:\Windows\System32\svchost.exe"), None), "sha256:ab");
    }

    #[test]
    fn codesign_variants() {
        let apple = "Executable=/usr/bin/curl\nIdentifier=com.apple.curl\nFormat=Mach-O universal\nCodeDirectory v=20400 size=1 flags=0x0(none)\nAuthority=Software Signing\nAuthority=Apple Code Signing Certification Authority\nAuthority=Apple Root CA\nTeamIdentifier=not set\n";
        let i = parse_codesign(apple);
        assert_eq!((i.status.as_str(), i.signing_id.as_deref(), i.team_id), ("apple", Some("com.apple.curl"), None));
        let dev = "Identifier=com.microsoft.VSCode\nAuthority=Developer ID Application: Microsoft Corporation (UBF8T346G9)\nAuthority=Developer ID Certification Authority\nTeamIdentifier=UBF8T346G9\n";
        let i = parse_codesign(dev);
        assert_eq!((i.status.as_str(), i.team_id.as_deref()), ("developer_id", Some("UBF8T346G9")));
        let adhoc = "Identifier=updater\nCodeDirectory v=20400 size=200 flags=0x20002(adhoc,linker-signed)\nSignature=adhoc\nTeamIdentifier=not set\n";
        assert_eq!(parse_codesign(adhoc).status, "adhoc");
        assert_eq!(parse_codesign("/tmp/x: code object is not signed at all\n").status, "unsigned");
    }

    #[test]
    fn sealed_paths() {
        assert!(os_sealed_path("/System/Volumes/Preboot/Cryptexes/OS/System/Library/Frameworks/WebKit.framework/x"));
        assert!(os_sealed_path("/usr/libexec/nsurlsessiond"));
        assert!(!os_sealed_path("/usr/local/bin/x"));
        assert!(!os_sealed_path("/Applications/Foo.app/Contents/MacOS/Foo"));
        assert!(!os_sealed_path("/private/tmp/x"));
    }

    #[test]
    fn dpkg() {
        assert_eq!(parse_dpkg_s("curl: /usr/bin/curl\n").as_deref(), Some("curl"));
        assert_eq!(parse_dpkg_s("libc6:arm64: /usr/lib/x\n").as_deref(), Some("libc6:arm64"));
    }

    #[test]
    fn interpreters() {
        let names: Vec<String> = ["python", "node", "bash"].iter().map(|s| s.to_string()).collect();
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            interpreter_script("python3.12", &a(&["python3", "-u", "/tmp/x.py"]), &names),
            Some(Some("/tmp/x.py".into()))
        );
        assert_eq!(interpreter_script("bash", &a(&["bash", "-c", "curl x"]), &names), Some(Some("<inline>".into())));
        assert_eq!(
            interpreter_script("python3", &a(&["python3", "-m", "http.server"]), &names),
            Some(Some("module:http.server".into()))
        );
        assert_eq!(interpreter_script("curl", &a(&["curl"]), &names), None);
        assert_eq!(
            interpreter_script("python3", &a(&["python3", "-", "/tmp/out"]), &names),
            Some(Some("<stdin>".into()))
        );
    }

    #[test]
    fn keys() {
        let i = Identity { status: "unmanaged".into(), sha256: Some("ab".into()), ..Default::default() };
        assert_eq!(proc_key(&i, Some("/tmp/x"), None), "sha256:ab");
        let p = Identity { status: "package".into(), package: Some("curl".into()), ..Default::default() };
        assert_eq!(proc_key(&p, Some("/usr/bin/curl"), Some("s")), "pkg:curl:/usr/bin/curl|script:s");
    }
}
