//! Windows：レジストリにある自動起動（居座り）を読む。読むだけで、書き換えない。
#![cfg_attr(not(windows), allow(dead_code))]
//!
//! | 場所 | 中身 |
//! |---|---|
//! | `HKLM`・各ユーザー（`HKU\<SID>`）の `…\CurrentVersion\Run`・`RunOnce`・`Policies\Explorer\Run` | ログオン時に起動 |
//! | `HKLM\…\WOW6432Node\…\Run`・`RunOnce` | 32 ビットのアプリの分 |
//! | `HKLM\…\Winlogon` の `Shell`・`Userinit` | ログオンの仕組みそのものの差し替え |
//! | `HKLM\…\Image File Execution Options\<名前>\Debugger` | 実行ファイルの横取り |
//! | `HKLM\SYSTEM\CurrentControlSet\Services\<名前>` の `ImagePath`（自動起動のもの） | サービス・ドライバ |
//!
//! 結果は kanmon-core の `persist::Item`（kind = `autostart`）にして、ファイルの走査の結果に足す。
//! kanmon 自身の登録（`Program Files\kanmon` の実行ファイルを指すもの）は除く。

use kanmon_core::persist::{risky_flags, Item};
use sha2::{Digest, Sha256};

/// 1 件を Item にする（純関数。どの OS でもテストできる）
pub fn make_item(key: &str, name: &str, data: &str) -> Item {
    let shown = if name.is_empty() { "(既定)" } else { name };
    let data_c: String = data.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(300).collect();
    Item {
        kind: "autostart".into(),
        path: format!("{key}\\{shown}"),
        detail: format!("{shown} → {data_c}"),
        hash: hex::encode(Sha256::digest(data.as_bytes())),
        risky: risky_flags(data),
    }
}

/// kanmon 自身の登録か：値・サービスの中身が `<Program Files>\kanmon\` の実行ファイルを指す
/// （そのフォルダは管理者しか書けない。名前だけでは判断しない）
pub fn own_entry(data: &str, program_files: &str) -> bool {
    let d = data.trim().trim_start_matches('"').to_ascii_lowercase();
    let base = format!("{}\\kanmon\\", program_files.trim_end_matches('\\').to_ascii_lowercase());
    d.starts_with(&base) && (d.contains("kanmond.exe") || d.contains("kanmon-tray.exe"))
}

#[cfg(windows)]
pub fn registry_items() -> Vec<Item> {
    imp::registry_items()
}

#[cfg(windows)]
mod imp {
    use super::*;
    use winreg::enums::{HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ};
    use winreg::RegKey;

    const RUN_KEYS: &[&str] = &[
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    ];
    const RUN_KEYS_WOW: &[&str] = &[
        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ];

    fn values(root: &RegKey, root_name: &str, sub: &str, pf: &str, out: &mut Vec<Item>) {
        let Ok(k) = root.open_subkey_with_flags(sub, KEY_READ) else { return };
        for (name, _) in k.enum_values().flatten() {
            let Ok(data) = k.get_value::<String, _>(&name) else { continue };
            if own_entry(&data, pf) {
                continue;
            }
            out.push(make_item(&format!("{root_name}\\{sub}"), &name, &data));
        }
    }

    pub fn registry_items() -> Vec<Item> {
        let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
        let mut out = vec![];
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        for k in RUN_KEYS.iter().chain(RUN_KEYS_WOW) {
            values(&hklm, "HKLM", k, &pf, &mut out);
        }
        // 読み込まれている各ユーザー（S-1-5-21-…。_Classes は除く）
        let hku = RegKey::predef(HKEY_USERS);
        for sid in hku.enum_keys().flatten() {
            if !sid.starts_with("S-1-5-21-") || sid.ends_with("_Classes") {
                continue;
            }
            let Ok(user) = hku.open_subkey_with_flags(&sid, KEY_READ) else { continue };
            for k in RUN_KEYS {
                values(&user, &format!("HKU\\{sid}"), k, &pf, &mut out);
            }
        }
        // Winlogon の Shell・Userinit
        let wl = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
        if let Ok(k) = hklm.open_subkey_with_flags(wl, KEY_READ) {
            for name in ["Shell", "Userinit"] {
                if let Ok(data) = k.get_value::<String, _>(name) {
                    out.push(make_item(&format!("HKLM\\{wl}"), name, &data));
                }
            }
        }
        // Image File Execution Options の Debugger（実行ファイルの横取り）
        let ifeo = r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        if let Ok(k) = hklm.open_subkey_with_flags(ifeo, KEY_READ) {
            for exe in k.enum_keys().flatten() {
                if let Ok(sk) = k.open_subkey_with_flags(&exe, KEY_READ) {
                    if let Ok(data) = sk.get_value::<String, _>("Debugger") {
                        out.push(make_item(&format!("HKLM\\{ifeo}\\{exe}"), "Debugger", &data));
                    }
                }
            }
        }
        // 自動起動のサービス・ドライバ（Start：0 boot・1 system・2 automatic）
        let svc = r"SYSTEM\CurrentControlSet\Services";
        if let Ok(k) = hklm.open_subkey_with_flags(svc, KEY_READ) {
            for name in k.enum_keys().flatten() {
                let Ok(sk) = k.open_subkey_with_flags(&name, KEY_READ) else { continue };
                let start: u32 = sk.get_value("Start").unwrap_or(4);
                if start > 2 {
                    continue;
                }
                let Ok(path) = sk.get_value::<String, _>("ImagePath") else { continue };
                if own_entry(&path, &pf) {
                    continue;
                }
                out.push(make_item(&format!("HKLM\\{svc}\\{name}"), "ImagePath", &path));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items_and_own_entries() {
        let pf = r"C:\Program Files";
        assert!(own_entry(r#""C:\Program Files\kanmon\kanmon-tray.exe""#, pf));
        assert!(own_entry(r#""C:\PROGRAM FILES\kanmon\kanmond.exe" --service"#, pf));
        // 名前が同じでも別の場所なら除かない
        assert!(!own_entry(r"C:\Users\u\AppData\Local\Temp\kanmon\kanmon-tray.exe", pf));
        assert!(!own_entry(r"C:\Program Files\kanmon\other.exe", pf));

        let i = make_item(
            r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run",
            "Updater",
            "powershell -w hidden -enc SQBFAFgA",
        );
        assert_eq!(i.kind, "autostart");
        assert!(i.path.ends_with(r"\Run\Updater"));
        assert!(i.risky.contains(&"base64".to_string()), "{:?}", i.risky);
        assert_eq!(make_item("HKLM\\x", "", "a").detail, "(既定) → a");
    }
}
