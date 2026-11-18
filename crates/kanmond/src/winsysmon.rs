//! Windows：Sysmon の記録（`Microsoft-Windows-Sysmon/Operational`）を購読する。
//!
//! - 起動時に、直近のプロセスの起動（ID 1）を新しい順に読み戻してプロセス表を埋める
//!   （kanmond より前から動いているプロセスの親・コマンドラインを知るため）
//! - 以降は `EvtSubscribe`（シグナルを待って `EvtNext` で取り出す形）で新しい記録を読む
//! - 解析は kanmon-core の純関数（`kanmon_core::sysmon`）。ここは取得とスレッドと表だけ
//! - XML は外部入力として扱う：大きすぎるものは捨てる（core 側でも長さを見る）

use crate::capture::Obs;
use crate::sockets::{Proto, Sock, State};
use kanmon_core::sysmon::{self, SysmonEvent};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_INSUFFICIENT_BUFFER, WAIT_OBJECT_0};
use windows_sys::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender, EvtRenderEventXml,
    EvtSubscribe, EvtSubscribeToFutureEvents, EVT_HANDLE,
};
use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject};

/// プロセス表の 1 件（Sysmon の ID 1 から）
#[derive(Debug, Clone)]
pub struct Entry {
    pub image: String,
    pub command_line: String,
    pub user: Option<String>,
    pub parent_pid: Option<u32>,
    #[allow(dead_code)]
    pub sha256: Option<String>,
    /// 終わった時刻（ID 5）。少しの間は残す（終わった直後の短い接続にも親を付けるため）
    pub ended: Option<Instant>,
}

/// 表の大きさの上限（超えたら終わったものから捨てる）
const MAX_PROCS: usize = 50_000;
/// 終わったプロセスを残す時間
const KEEP_ENDED: Duration = Duration::from_secs(120);
/// 起動時に読み戻すプロセスの起動の件数
const PRELOAD: usize = 20_000;

fn table() -> &'static Mutex<HashMap<u32, Entry>> {
    static T: OnceLock<Mutex<HashMap<u32, Entry>>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(HashMap::new()))
}

static PERSIST_NUDGE: AtomicBool = AtomicBool::new(false);

/// 自動起動の場所に変化があったか（読んだら下ろす）
pub fn take_persist_nudge() -> bool {
    PERSIST_NUDGE.swap(false, Ordering::Relaxed)
}

/// pid のプロセス表の内容
pub fn lookup(pid: u32) -> Option<Entry> {
    table().lock().ok()?.get(&pid).cloned()
}

fn insert(pid: u32, e: Entry, overwrite: bool) {
    let Ok(mut t) = table().lock() else { return };
    if t.len() >= MAX_PROCS {
        let now = Instant::now();
        t.retain(|_, v| v.ended.is_none_or(|x| now.duration_since(x) < KEEP_ENDED));
        if t.len() >= MAX_PROCS {
            t.clear();
        }
    }
    if overwrite || !t.contains_key(&pid) {
        t.insert(pid, e);
    }
}

fn mark_ended(pid: u32) {
    let Ok(mut t) = table().lock() else { return };
    if let Some(e) = t.get_mut(&pid) {
        e.ended = Some(Instant::now());
    }
    let now = Instant::now();
    t.retain(|_, v| v.ended.is_none_or(|x| now.duration_since(x) < KEEP_ENDED));
}

/// 自動起動に関わる場所か（Sysmon の設定で絞ってあるが、念のためここでも見る）
fn persist_related(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    [
        "\\currentversion\\run",
        "\\winlogon\\",
        "\\image file execution options\\",
        "\\imagepath",
        "\\start menu\\programs\\startup\\",
        "\\system32\\tasks\\",
        ".pth",
        "\\.claude\\",
        "\\.vscode\\",
        "\\.github\\workflows\\",
        "\\.git\\hooks\\",
        "profile.ps1",
    ]
    .iter()
    .any(|x| p.contains(x))
}

/// 1 件を処理する。`live` が偽（起動時の読み戻し）なら表を埋めるだけ
fn dispatch(ev: SysmonEvent, tx: &SyncSender<Obs>, live: bool) {
    match ev {
        SysmonEvent::ProcessCreate(p) => insert(
            p.pid,
            Entry {
                image: p.image,
                command_line: p.command_line,
                user: p.user,
                parent_pid: p.parent_pid,
                sha256: p.sha256,
                ended: None,
            },
            live,
        ),
        _ if !live => {}
        SysmonEvent::ProcessTerminate { pid, .. } => mark_ended(pid),
        SysmonEvent::NetworkConnect(c) => {
            let (local, remote) = if c.initiated {
                (SocketAddr::new(c.src_ip, c.src_port), SocketAddr::new(c.dst_ip, c.dst_port))
            } else {
                (SocketAddr::new(c.dst_ip, c.dst_port), SocketAddr::new(c.src_ip, c.src_port))
            };
            let proto = if c.protocol == "udp" { Proto::Udp } else { Proto::Tcp };
            let sock = Sock {
                proto,
                local,
                remote: Some(remote),
                state: State::Established,
                pid: Some(c.pid),
                uid: None,
                inode: 0,
            };
            // 監視ループが詰まっているときは捨てる（Sysmon 側に記録は残る）
            let _ = tx.try_send(Obs::Connect(sock));
        }
        SysmonEvent::DnsQuery(d) => {
            if d.status == 0 && !d.ips.is_empty() {
                let _ = tx.try_send(Obs::Resolved { name: d.name, ips: d.ips });
            }
        }
        SysmonEvent::FileCreate { target, .. } | SysmonEvent::Registry { target, .. } => {
            if persist_related(&target) {
                PERSIST_NUDGE.store(true, Ordering::Relaxed);
            }
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 1 件の記録を XML にする
fn render(h: EVT_HANDLE, buf: &mut Vec<u16>) -> Option<String> {
    unsafe {
        let mut used = 0u32;
        let mut props = 0u32;
        let bytes = (buf.len() * 2) as u32;
        if EvtRender(0, h, EvtRenderEventXml, bytes, buf.as_mut_ptr() as *mut _, &mut used, &mut props) == 0 {
            if GetLastError() != ERROR_INSUFFICIENT_BUFFER || used as usize > sysmon::MAX_XML * 2 {
                return None;
            }
            buf.resize((used as usize).div_ceil(2), 0);
            let bytes = (buf.len() * 2) as u32;
            if EvtRender(0, h, EvtRenderEventXml, bytes, buf.as_mut_ptr() as *mut _, &mut used, &mut props) == 0 {
                return None;
            }
        }
        let n = (used as usize / 2).min(buf.len());
        let end = buf[..n].iter().position(|&c| c == 0).unwrap_or(n);
        Some(String::from_utf16_lossy(&buf[..end]))
    }
}

/// 結果の集合から最大 `limit` 件を取り出して処理する。取り出した件数を返す
fn drain(results: EVT_HANDLE, tx: &SyncSender<Obs>, live: bool, limit: usize, buf: &mut Vec<u16>) -> usize {
    let mut total = 0;
    let mut handles = [0isize; 64];
    while total < limit {
        let mut got = 0u32;
        let ok = unsafe { EvtNext(results, handles.len() as u32, handles.as_mut_ptr(), 0, 0, &mut got) };
        if ok == 0 || got == 0 {
            break;
        }
        for &h in &handles[..got as usize] {
            if let Some(ev) = render(h, buf).and_then(|x| sysmon::parse_event(&x)) {
                dispatch(ev, tx, live);
            }
            unsafe { EvtClose(h) };
        }
        total += got as usize;
    }
    total
}

/// 起動時：直近のプロセスの起動（ID 1）を新しい順に読み、表を埋める
fn preload(tx: &SyncSender<Obs>, buf: &mut Vec<u16>) -> usize {
    let path = wide(sysmon::CHANNEL);
    let q = wide("*[System[(EventID=1)]]");
    let h = unsafe { EvtQuery(0, path.as_ptr(), q.as_ptr(), EvtQueryChannelPath | EvtQueryReverseDirection) };
    if h == 0 {
        return 0;
    }
    let n = drain(h, tx, false, PRELOAD, buf);
    unsafe { EvtClose(h) };
    n
}

/// 購読を始める（スレッドを起動して戻る）。チャネルが無ければエラー
pub fn start(tx: SyncSender<Obs>) -> anyhow::Result<()> {
    let path = wide(sysmon::CHANNEL);
    let query = wide(sysmon::QUERY);
    let signal = unsafe { CreateEventW(std::ptr::null(), 1, 1, std::ptr::null()) };
    if signal.is_null() {
        anyhow::bail!("CreateEventW に失敗（{}）", unsafe { GetLastError() });
    }
    let sub = unsafe {
        EvtSubscribe(0, signal, path.as_ptr(), query.as_ptr(), 0, std::ptr::null(), None, EvtSubscribeToFutureEvents)
    };
    if sub == 0 {
        let e = unsafe { GetLastError() };
        unsafe { CloseHandle(signal) };
        anyhow::bail!("EvtSubscribe に失敗（{e}）。Sysmon が入っていないか、管理者で動いていない");
    }
    // HANDLE（ポインタ）はスレッドをまたいで送れないので数値で渡す
    let signal_n = signal as usize;
    std::thread::Builder::new().name("kanmon-sysmon".into()).spawn(move || {
        let signal = signal_n as windows_sys::Win32::Foundation::HANDLE;
        let mut buf = vec![0u16; 8192];
        let n = preload(&tx, &mut buf);
        crate::logln!("Sysmon：プロセスの起動を {n} 件読み戻した");
        loop {
            let w = unsafe { WaitForSingleObject(signal, 1000) };
            if w == WAIT_OBJECT_0 {
                // 取り切ってからシグナルを戻す（取り切る前に戻すと取りこぼす）
                while drain(sub, &tx, true, 10_000, &mut buf) > 0 {}
                unsafe { ResetEvent(signal) };
                while drain(sub, &tx, true, 10_000, &mut buf) > 0 {}
            }
        }
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persist_paths() {
        assert!(persist_related(r"HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\x"));
        assert!(persist_related(r"C:\Users\u\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\a.lnk"));
        assert!(!persist_related(r"C:\Users\u\Documents\a.txt"));
    }
}
