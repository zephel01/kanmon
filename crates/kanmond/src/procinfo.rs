//! プロセス情報（実行ファイル・親・引数・ユーザー）。
//! Linux は /proc、macOS は libproc（proc_pidpath / proc_pidinfo）と sysctl(KERN_PROCARGS2)。

use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub uid: Option<u32>,
    pub exe: Option<String>,
    pub args: Vec<String>,
    pub exe_deleted: bool,
    pub memfd: bool,
    /// プロセス開始時刻（pid 再利用の判別用）
    pub start: u64,
}

pub fn basename(p: &str) -> String {
    p.rsplit('/').next().unwrap_or(p).to_string()
}

pub fn user_name(uid: u32) -> Option<String> {
    // getpwuid はスレッド安全ではないが、呼び出しは監視スレッドのみ
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() || (*pw).pw_name.is_null() {
            return None;
        }
        Some(std::ffi::CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned())
    }
}

#[cfg(target_os = "linux")]
pub fn read(pid: u32) -> Option<ProcInfo> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm に空白や ')' が入り得るので最後の ')' 以降を使う
    let rest = &stat[stat.rfind(')')? + 2..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    let ppid = f.get(1)?.parse().ok()?;
    let start = f.get(19).and_then(|x| x.parse().ok()).unwrap_or(0);
    let link = std::fs::read_link(format!("/proc/{pid}/exe")).ok().map(|p| p.to_string_lossy().into_owned());
    let (exe, deleted) = match link {
        Some(l) => match l.strip_suffix(" (deleted)") {
            Some(x) => (Some(x.to_string()), true),
            None => (Some(l), false),
        },
        None => (None, false),
    };
    let memfd = exe.as_deref().is_some_and(|e| e.starts_with("/memfd:"));
    let args = std::fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .map(|b| {
            b.split(|c| *c == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect()
        })
        .unwrap_or_default();
    let uid = std::fs::read_to_string(format!("/proc/{pid}/status")).ok().and_then(|s| {
        s.lines().find(|l| l.starts_with("Uid:")).and_then(|l| l.split_whitespace().nth(1)).and_then(|x| x.parse().ok())
    });
    Some(ProcInfo { pid, ppid, uid, exe, args, exe_deleted: deleted, memfd, start })
}

#[cfg(target_os = "macos")]
pub fn read(pid: u32) -> Option<ProcInfo> {
    use std::mem::{size_of, MaybeUninit};
    unsafe {
        let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
        let n = libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr() as *mut libc::c_void,
            size_of::<libc::proc_bsdinfo>() as i32,
        );
        if n as usize != size_of::<libc::proc_bsdinfo>() {
            return None;
        }
        let info = info.assume_init();
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let len = libc::proc_pidpath(pid as i32, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32);
        let exe = if len > 0 { Some(String::from_utf8_lossy(&buf[..len as usize]).into_owned()) } else { None };
        let deleted = exe.as_deref().is_some_and(|e| !std::path::Path::new(e).exists());
        Some(ProcInfo {
            pid,
            ppid: info.pbi_ppid,
            uid: Some(info.pbi_uid),
            exe,
            args: procargs(pid).unwrap_or_default(),
            exe_deleted: deleted,
            memfd: false,
            start: info.pbi_start_tvsec,
        })
    }
}

/// KERN_PROCARGS2：先頭 4 バイトが argc、続いて実行パス\0、パディング\0…、argv[0..argc]
#[cfg(target_os = "macos")]
fn procargs(pid: u32) -> Option<Vec<String>> {
    unsafe {
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as i32];
        let mut size: libc::size_t = 0;
        if libc::sysctl(mib.as_mut_ptr(), 3, std::ptr::null_mut(), &mut size, std::ptr::null_mut(), 0) != 0 {
            return None;
        }
        let mut buf = vec![0u8; size];
        if libc::sysctl(mib.as_mut_ptr(), 3, buf.as_mut_ptr() as *mut libc::c_void, &mut size, std::ptr::null_mut(), 0)
            != 0
        {
            return None;
        }
        buf.truncate(size);
        parse_procargs2(&buf)
    }
}

#[allow(dead_code)]
pub fn parse_procargs2(buf: &[u8]) -> Option<Vec<String>> {
    if buf.len() < 4 {
        return None;
    }
    let argc = i32::from_ne_bytes(buf[0..4].try_into().ok()?) as usize;
    let mut i = 4;
    while i < buf.len() && buf[i] != 0 {
        i += 1; // 実行パス
    }
    while i < buf.len() && buf[i] == 0 {
        i += 1; // パディング
    }
    let mut out = vec![];
    while out.len() < argc && i < buf.len() {
        let start = i;
        while i < buf.len() && buf[i] != 0 {
            i += 1;
        }
        out.push(String::from_utf8_lossy(&buf[start..i]).into_owned());
        i += 1;
    }
    Some(out)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn read(_pid: u32) -> Option<ProcInfo> {
    None
}

/// pid → ProcInfo のキャッシュ（開始時刻が変われば読み直す）
#[derive(Default)]
pub struct ProcCache {
    map: HashMap<u32, ProcInfo>,
}

impl ProcCache {
    pub fn get(&mut self, pid: u32) -> Option<ProcInfo> {
        let fresh = read(pid)?;
        match self.map.get(&pid) {
            Some(old) if old.start == fresh.start && old.exe == fresh.exe => Some(old.clone()),
            _ => {
                self.map.insert(pid, fresh.clone());
                Some(fresh)
            }
        }
    }

    /// 親を最大 depth 段たどり、実行ファイル名（basename）を返す
    pub fn parent_chain(&mut self, ppid: u32, depth: usize) -> Vec<(u32, Option<String>, Vec<String>)> {
        let mut out = vec![];
        let mut cur = ppid;
        for _ in 0..depth {
            if cur == 0 {
                break;
            }
            let Some(p) = self.get(cur) else { break };
            out.push((cur, p.exe.clone(), p.args.clone()));
            if p.ppid == cur || cur == 1 {
                break;
            }
            cur = p.ppid;
        }
        out
    }

    pub fn retain_alive(&mut self, alive: &std::collections::HashSet<u32>) {
        self.map.retain(|k, _| alive.contains(k));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn procargs2() {
        let mut b = 2i32.to_ne_bytes().to_vec();
        b.extend(b"/usr/bin/python3\0\0\0\0python3\0/tmp/x.py\0USER=a\0");
        assert_eq!(parse_procargs2(&b).unwrap(), vec!["python3", "/tmp/x.py"]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_self() {
        let p = read(std::process::id()).unwrap();
        assert!(p.exe.is_some());
        assert!(!p.args.is_empty());
    }
}
