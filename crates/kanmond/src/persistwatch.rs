//! 居座りの走査（kanmon-core の persist）の OS 依存部分：走査するユーザーのホームを決める。
//! kanmond は root で動くので、`~` は「ログイン中のユーザーのホーム」に読み替える。
//! - macOS：`/dev/console` の所有者（画面にログインしている人）
//! - Linux：`/run/user/<uid>` があるユーザー（uid 1000 以上）

use std::path::PathBuf;

fn home_of(uid: u32) -> Option<PathBuf> {
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() || (*pw).pw_dir.is_null() {
            return None;
        }
        let s = std::ffi::CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned();
        (!s.is_empty() && s != "/").then(|| PathBuf::from(s))
    }
}

/// 走査するユーザーのホーム。root で動いていないときは自分のホーム
pub fn user_homes() -> Vec<PathBuf> {
    if unsafe { libc::geteuid() } != 0 {
        return std::env::var_os("HOME").map(PathBuf::from).into_iter().collect();
    }
    let mut uids: Vec<u32> = vec![];
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(md) = std::fs::metadata("/dev/console") {
            if md.uid() != 0 {
                uids.push(md.uid());
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(rd) = std::fs::read_dir("/run/user") {
            for e in rd.flatten() {
                if let Some(u) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) {
                    if u >= 1000 {
                        uids.push(u);
                    }
                }
            }
        }
    }
    uids.sort();
    uids.dedup();
    uids.into_iter().filter_map(home_of).collect()
}

/// 設定の roots（`~/kanmon-work` 等）を、各ユーザーのホームで展開する
pub fn expand_roots(roots: &[String], homes: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = vec![];
    for r in roots {
        if let Some(rest) = r.strip_prefix("~/") {
            out.extend(homes.iter().map(|h| h.join(rest)));
        } else if r == "~" {
            out.extend(homes.iter().cloned());
        } else {
            out.push(PathBuf::from(r));
        }
    }
    out.retain(|p| p.is_dir());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_tilde() {
        let t = std::env::temp_dir().join(format!("kanmon-pw-{}", std::process::id()));
        std::fs::create_dir_all(t.join("kanmon-work")).unwrap();
        let r = expand_roots(&["~/kanmon-work".into(), "~/missing".into()], std::slice::from_ref(&t));
        assert_eq!(r, vec![t.join("kanmon-work")]);
        std::fs::remove_dir_all(&t).ok();
    }
}
