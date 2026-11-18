//! ソケット一覧の取得（ポーリング）。
//!
//! - Linux：`/proc/net/{tcp,tcp6,udp,udp6,raw,raw6,packet}` を読み、`/proc/<pid>/fd` の
//!   `socket:[inode]` でプロセスに帰属させる（netns はデーモン自身のもののみ）。
//! - macOS：`lsof -nP -iTCP -iUDP -F` の出力を解析する（root で動かさないと他ユーザー分は見えない）。
//! - Windows：`GetExtendedTcpTable`・`GetExtendedUdpTable`（pid 付き）。一覧に出る前に終わる短い接続は
//!   Sysmon の ID 3 で補う（monitor が合わせる）。
//!
//! 解析関数は OS に依存しない純関数にしてあり、どの OS でもテストできる。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
// raw / packet は Linux の /proc/net からのみ生成される
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub enum Proto {
    Tcp,
    Udp,
    Raw,
    Packet,
}

impl Proto {
    pub fn as_str(&self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Raw => "raw",
            Proto::Packet => "packet",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    Listen,
    Established,
    SynSent,
    /// UDP の未接続（bind のみ）
    Unconnected,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sock {
    pub proto: Proto,
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    pub state: State,
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    /// Linux の inode（macOS は 0）
    pub inode: u64,
}

impl Sock {
    /// 差分検出用のキー
    pub fn key(&self) -> (Proto, SocketAddr, Option<SocketAddr>, Option<u32>) {
        (self.proto, self.local, self.remote, self.pid)
    }
}

// ---------------------------------------------------------------- Linux /proc/net

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_hex_addr(s: &str) -> Option<SocketAddr> {
    let (a, p) = s.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    let ip = match a.len() {
        8 => {
            let w = u32::from_str_radix(a, 16).ok()?;
            IpAddr::V4(Ipv4Addr::from(w.to_le_bytes()))
        }
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                let w = u32::from_str_radix(&a[i * 8..i * 8 + 8], 16).ok()?;
                b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(b))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// `/proc/net/tcp*`・`udp*`・`raw*` の 1 ファイル分を解析（pid は未設定）。
/// カーネルは 32bit 語をホストのバイト順で出すため、リトルエンディアン前提で変換する。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_proc_net(text: &str, proto: Proto) -> Vec<Sock> {
    let mut out = vec![];
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let (Some(local), Some(rem)) = (parse_hex_addr(f[1]), parse_hex_addr(f[2])) else { continue };
        let st = u8::from_str_radix(f[3], 16).unwrap_or(0);
        let uid = f[7].parse().ok();
        let inode = f[9].parse().unwrap_or(0);
        let remote_set = !rem.ip().is_unspecified() || rem.port() != 0;
        let state = match (proto, st) {
            (Proto::Tcp, 0x0A) => State::Listen,
            (Proto::Tcp, 0x01) => State::Established,
            (Proto::Tcp, 0x02) => State::SynSent,
            (Proto::Udp, 0x01) => State::Established,
            (Proto::Udp, _) if !remote_set => State::Unconnected,
            (Proto::Raw, _) => State::Other,
            _ => State::Other,
        };
        out.push(Sock {
            proto,
            local,
            remote: if remote_set { Some(rem) } else { None },
            state,
            pid: None,
            uid,
            inode,
        });
    }
    out
}

/// `/proc/net/packet`（AF_PACKET）。列：sk RefCnt Type Proto Iface R Rmem User Inode
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_proc_packet(text: &str) -> Vec<Sock> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 9 {
                return None;
            }
            Some(Sock {
                proto: Proto::Packet,
                local: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                remote: None,
                state: State::Other,
                pid: None,
                uid: f[7].parse().ok(),
                inode: f[8].parse().unwrap_or(0),
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
pub struct LinuxCollector {
    inode_pid: HashMap<u64, u32>,
}

#[cfg(target_os = "linux")]
impl LinuxCollector {
    pub fn new() -> Self {
        Self { inode_pid: HashMap::new() }
    }

    fn rescan_fds(&mut self) {
        self.inode_pid.clear();
        let Ok(rd) = std::fs::read_dir("/proc") else { return };
        for e in rd.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
            let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
            for fd in fds.flatten() {
                if let Ok(t) = std::fs::read_link(fd.path()) {
                    let t = t.to_string_lossy();
                    if let Some(n) = t.strip_prefix("socket:[").and_then(|x| x.strip_suffix(']')) {
                        if let Ok(ino) = n.parse::<u64>() {
                            // 複数プロセスで共有される場合は最初（小さい pid＝親側が多い）を採用
                            self.inode_pid.entry(ino).or_insert(pid);
                        }
                    }
                }
            }
        }
    }

    pub fn snapshot(&mut self) -> anyhow::Result<Vec<Sock>> {
        let mut all = vec![];
        for (f, p) in [
            ("/proc/net/tcp", Proto::Tcp),
            ("/proc/net/tcp6", Proto::Tcp),
            ("/proc/net/udp", Proto::Udp),
            ("/proc/net/udp6", Proto::Udp),
            ("/proc/net/raw", Proto::Raw),
            ("/proc/net/raw6", Proto::Raw),
        ] {
            if let Ok(t) = std::fs::read_to_string(f) {
                all.extend(parse_proc_net(&t, p));
            }
        }
        if let Ok(t) = std::fs::read_to_string("/proc/net/packet") {
            all.extend(parse_proc_packet(&t));
        }
        // TIME_WAIT 等は inode 0。帰属不能なので除外
        all.retain(|s| s.inode != 0);
        if all.iter().any(|s| !self.inode_pid.contains_key(&s.inode)) {
            self.rescan_fds();
        }
        for s in &mut all {
            s.pid = self.inode_pid.get(&s.inode).copied();
        }
        Ok(all)
    }
}

// ---------------------------------------------------------------- macOS lsof

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_lsof_endpoint(s: &str, v6: bool) -> Option<SocketAddr> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once("]:")?;
        (h, p)
    } else {
        s.rsplit_once(':')?
    };
    let host = host.split('%').next().unwrap_or(host);
    let ip: IpAddr = if host == "*" {
        if v6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        }
    } else {
        host.parse().ok()?
    };
    let port = if port == "*" { 0 } else { port.parse().ok()? };
    Some(SocketAddr::new(ip, port))
}

/// `lsof -nP -iTCP -iUDP -FpcuftPnT` の出力を解析
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn parse_lsof(text: &str) -> Vec<Sock> {
    #[derive(Default)]
    struct Cur {
        v6: bool,
        proto: Option<Proto>,
        name: Option<String>,
        st: Option<String>,
    }
    let mut out = vec![];
    let mut pid: Option<u32> = None;
    let mut uid: Option<u32> = None;
    let mut cur: Option<Cur> = None;

    let flush = |cur: &mut Option<Cur>, pid: Option<u32>, uid: Option<u32>, out: &mut Vec<Sock>| {
        let Some(c) = cur.take() else { return };
        let (Some(proto), Some(name)) = (c.proto, c.name) else { return };
        let (l, r) = match name.split_once("->") {
            Some((a, b)) => (a.to_string(), Some(b.to_string())),
            None => (name.clone(), None),
        };
        let Some(local) = parse_lsof_endpoint(&l, c.v6) else { return };
        let remote = r.and_then(|x| parse_lsof_endpoint(&x, c.v6));
        let state = match (proto, c.st.as_deref()) {
            (Proto::Tcp, Some("LISTEN")) => State::Listen,
            (Proto::Tcp, Some("ESTABLISHED")) => State::Established,
            (Proto::Tcp, Some("SYN_SENT")) => State::SynSent,
            (Proto::Udp, _) if remote.is_none() => State::Unconnected,
            (Proto::Udp, _) => State::Established,
            _ => State::Other,
        };
        out.push(Sock { proto, local, remote, state, pid, uid, inode: 0 });
    };

    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let (tag, val) = line.split_at(1);
        match tag {
            "p" => {
                flush(&mut cur, pid, uid, &mut out);
                pid = val.parse().ok();
                uid = None;
            }
            "u" => uid = val.parse().ok(),
            "f" => {
                flush(&mut cur, pid, uid, &mut out);
                cur = Some(Cur::default());
            }
            "t" => {
                if let Some(c) = cur.as_mut() {
                    c.v6 = val == "IPv6";
                }
            }
            "P" => {
                if let Some(c) = cur.as_mut() {
                    c.proto = match val {
                        "TCP" => Some(Proto::Tcp),
                        "UDP" => Some(Proto::Udp),
                        _ => None,
                    };
                }
            }
            "n" => {
                if let Some(c) = cur.as_mut() {
                    c.name = Some(val.to_string());
                }
            }
            "T" => {
                if let (Some(c), Some(st)) = (cur.as_mut(), val.strip_prefix("ST=")) {
                    c.st = Some(st.to_string());
                }
            }
            _ => {}
        }
    }
    flush(&mut cur, pid, uid, &mut out);
    out
}

#[cfg(target_os = "macos")]
pub struct MacCollector;

#[cfg(target_os = "macos")]
impl MacCollector {
    pub fn new() -> Self {
        Self
    }
    pub fn snapshot(&mut self) -> anyhow::Result<Vec<Sock>> {
        let out =
            std::process::Command::new("/usr/sbin/lsof").args(["-nP", "-iTCP", "-iUDP", "-FpcuftPnT"]).output()?;
        // lsof は一部失敗でも終了コード 1 を返すことがあるので、出力があれば使う
        Ok(parse_lsof(&String::from_utf8_lossy(&out.stdout)))
    }
}

// ---------------------------------------------------------------- Windows

/// Windows の TCP の状態（MIB_TCP_STATE）を変える
#[cfg_attr(not(windows), allow(dead_code))]
pub fn win_tcp_state(st: u32) -> State {
    match st {
        2 => State::Listen,
        3 => State::SynSent,
        5 => State::Established,
        _ => State::Other,
    }
}

/// Windows の表の 1 行（IPv4。アドレスとポートはメモリ上でネットワークの順。`to_ne_bytes` でそのまま並べる）
#[cfg_attr(not(windows), allow(dead_code))]
pub fn win_v4(addr: u32, port: u32) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr.to_ne_bytes())), u16::from_be(port as u16))
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn win_v6(addr: [u8; 16], port: u32) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), u16::from_be(port as u16))
}

/// TCP の 1 行を Sock にする。TIME_WAIT・CLOSED（pid 0）は除く
#[cfg_attr(not(windows), allow(dead_code))]
pub fn win_tcp_sock(local: SocketAddr, remote: SocketAddr, state: u32, pid: u32) -> Option<Sock> {
    if matches!(state, 1 | 11) || pid == 0 {
        return None;
    }
    let st = win_tcp_state(state);
    let remote_set = !remote.ip().is_unspecified() || remote.port() != 0;
    Some(Sock {
        proto: Proto::Tcp,
        local,
        remote: (remote_set && st != State::Listen).then_some(remote),
        state: st,
        pid: Some(pid),
        uid: None,
        inode: 0,
    })
}

#[cfg(windows)]
pub struct WinCollector;

#[cfg(windows)]
impl WinCollector {
    pub fn new() -> Self {
        Self
    }

    /// 表を取る。必要な大きさを聞いてから取り直す（間に増えたら数回まで繰り返す）
    fn table(tcp: bool, af: u32) -> Vec<u8> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
        };
        let mut size = 0u32;
        let mut buf: Vec<u8> = vec![];
        for _ in 0..4 {
            let r = unsafe {
                let p = if buf.is_empty() { std::ptr::null_mut() } else { buf.as_mut_ptr() as *mut _ };
                if tcp {
                    GetExtendedTcpTable(p, &mut size, 0, af, TCP_TABLE_OWNER_PID_ALL, 0)
                } else {
                    GetExtendedUdpTable(p, &mut size, 0, af, UDP_TABLE_OWNER_PID, 0)
                }
            };
            if r == 0 && !buf.is_empty() {
                buf.truncate(size as usize);
                return buf;
            }
            // 122 = ERROR_INSUFFICIENT_BUFFER
            if r != 122 && r != 0 {
                return vec![];
            }
            buf = vec![0u8; size as usize + 4096];
            size = buf.len() as u32;
        }
        vec![]
    }

    /// 表の行を読む（先頭 4 バイトが件数、続いて行）
    fn rows<T: Copy>(buf: &[u8]) -> Vec<T> {
        if buf.len() < 4 {
            return vec![];
        }
        let n = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let sz = std::mem::size_of::<T>();
        let max = (buf.len() - 4) / sz;
        (0..n.min(max)).map(|i| unsafe { std::ptr::read_unaligned(buf.as_ptr().add(4 + i * sz) as *const T) }).collect()
    }

    pub fn snapshot(&mut self) -> anyhow::Result<Vec<Sock>> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID,
        };
        const AF_INET: u32 = 2;
        const AF_INET6: u32 = 23;
        let mut out = vec![];
        for r in Self::rows::<MIB_TCPROW_OWNER_PID>(&Self::table(true, AF_INET)) {
            let l = win_v4(r.dwLocalAddr, r.dwLocalPort);
            let rm = win_v4(r.dwRemoteAddr, r.dwRemotePort);
            out.extend(win_tcp_sock(l, rm, r.dwState, r.dwOwningPid));
        }
        for r in Self::rows::<MIB_TCP6ROW_OWNER_PID>(&Self::table(true, AF_INET6)) {
            let l = win_v6(r.ucLocalAddr, r.dwLocalPort);
            let rm = win_v6(r.ucRemoteAddr, r.dwRemotePort);
            out.extend(win_tcp_sock(l, rm, r.dwState, r.dwOwningPid));
        }
        let udp = |local: SocketAddr, pid: u32| Sock {
            proto: Proto::Udp,
            local,
            remote: None,
            state: State::Unconnected,
            pid: Some(pid),
            uid: None,
            inode: 0,
        };
        for r in Self::rows::<MIB_UDPROW_OWNER_PID>(&Self::table(false, AF_INET)) {
            out.push(udp(win_v4(r.dwLocalAddr, r.dwLocalPort), r.dwOwningPid));
        }
        for r in Self::rows::<MIB_UDP6ROW_OWNER_PID>(&Self::table(false, AF_INET6)) {
            out.push(udp(win_v6(r.ucLocalAddr, r.dwLocalPort), r.dwOwningPid));
        }
        Ok(out)
    }
}

pub enum Collector {
    #[cfg(target_os = "linux")]
    Linux(LinuxCollector),
    #[cfg(target_os = "macos")]
    Mac(MacCollector),
    #[cfg(windows)]
    Win(WinCollector),
}

impl Collector {
    pub fn new() -> anyhow::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            return Ok(Collector::Linux(LinuxCollector::new()));
        }
        #[cfg(target_os = "macos")]
        {
            return Ok(Collector::Mac(MacCollector::new()));
        }
        #[cfg(windows)]
        {
            return Ok(Collector::Win(WinCollector::new()));
        }
        #[allow(unreachable_code)]
        Err(anyhow::anyhow!("未対応の OS です"))
    }

    pub fn snapshot(&mut self) -> anyhow::Result<Vec<Sock>> {
        match self {
            #[cfg(target_os = "linux")]
            Collector::Linux(c) => c.snapshot(),
            #[cfg(target_os = "macos")]
            Collector::Mac(c) => c.snapshot(),
            #[cfg(windows)]
            Collector::Win(c) => c.snapshot(),
        }
    }
}

/// 待受ポート集合（プロトコル, ポート）
pub fn listen_ports(socks: &[Sock]) -> HashMap<(Proto, u16), ()> {
    socks
        .iter()
        .filter(|s| s.state == State::Listen || (s.proto == Proto::Udp && s.state == State::Unconnected))
        .map(|s| ((s.proto, s.local.port()), ()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:B3A8 0A7100CB:20FB 01 00000000:00000000 02:000A7D3D 00000000  1000        0 23456 2 0000000000000000 20 4 30 10 -1
   2: 0100007F:B3A9 0A7100CB:20FB 06 00000000:00000000 03:00000F35 00000000     0        0 0 3 0000000000000000
";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 999 1 0000000000000000 100 0 0 10 0
";
    const UDP: &str = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  100: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   107        0 777 2 0000000000000000 0
  101: 0F02000A:A1B2 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 778 2 0000000000000000 0
";

    #[test]
    fn proc_net_tcp() {
        let v = parse_proc_net(TCP, Proto::Tcp);
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].state, State::Listen);
        assert_eq!(v[0].local.to_string(), "0.0.0.0:8000");
        assert_eq!(v[1].state, State::Established);
        assert_eq!(v[1].local.to_string(), "127.0.0.1:45992");
        assert_eq!(v[1].remote.unwrap().to_string(), "203.0.113.10:8443");
        assert_eq!(v[1].uid, Some(1000));
        assert_eq!(v[1].inode, 23456);
        let v6 = parse_proc_net(TCP6, Proto::Tcp);
        assert_eq!(v6[0].local.to_string(), "[::1]:22");
    }

    #[test]
    fn proc_net_udp() {
        let v = parse_proc_net(UDP, Proto::Udp);
        assert_eq!(v[0].state, State::Unconnected);
        assert_eq!(v[0].local.port(), 5353);
        assert_eq!(v[1].state, State::Established);
        assert_eq!(v[1].remote.unwrap().to_string(), "8.8.8.8:53");
        assert_eq!(v[1].local.ip().to_string(), "10.0.2.15");
    }

    #[test]
    fn packet() {
        let t = "sk       RefCnt Type Proto  Iface R Rmem   User   Inode\n\
                 ffff8880 3      3    0003   2     1 0      0      4242\n";
        let v = parse_proc_packet(t);
        assert_eq!((v[0].proto, v[0].inode, v[0].uid), (Proto::Packet, 4242, Some(0)));
    }

    #[test]
    fn windows_rows() {
        // メモリ上の並びはネットワークの順：203.0.113.10 → [203, 0, 113, 10]、ポート 443 → [0x01, 0xBB]
        let addr = u32::from_ne_bytes([203, 0, 113, 10]);
        let port = u16::from_ne_bytes([0x01, 0xBB]) as u32;
        assert_eq!(win_v4(addr, port).to_string(), "203.0.113.10:443");
        let local = win_v4(u32::from_ne_bytes([127, 0, 0, 1]), u16::from_ne_bytes([0xC6, 0x41]) as u32);
        assert_eq!(local.port(), 50753);
        let s = win_tcp_sock(local, win_v4(addr, port), 5, 4242).unwrap();
        assert_eq!((s.state, s.pid, s.remote.unwrap().port()), (State::Established, Some(4242), 443));
        // TIME_WAIT と pid 0 は除く
        assert!(win_tcp_sock(local, win_v4(addr, port), 11, 4242).is_none());
        assert!(win_tcp_sock(local, win_v4(addr, port), 5, 0).is_none());
        // 待受は相手なし
        let l = win_tcp_sock(local, win_v4(0, 0), 2, 9).unwrap();
        assert_eq!((l.state, l.remote), (State::Listen, None));
        let mut v6 = [0u8; 16];
        v6[15] = 1;
        assert_eq!(win_v6(v6, port).to_string(), "[::1]:443");
    }

    #[test]
    fn lsof() {
        let t = "p501\ncrapportd\nu501\nf12\ntIPv4\nPTCP\nn192.168.1.20:52000->17.57.144.10:443\nTST=ESTABLISHED\nTQR=0\nTQS=0\n\
                 f13\ntIPv6\nPTCP\nn*:8000\nTST=LISTEN\n\
                 p88\ncmDNSResponder\nu65\nf5\ntIPv4\nPUDP\nn*:5353\n\
                 f6\ntIPv6\nPUDP\nn[fe80::1%lo0]:5353->[ff02::fb]:5353\n\
                 f7\ntIPv4\nPTCP\nn10.0.0.2:61000->10.0.0.9:22\nTST=SYN_SENT\n";
        let v = parse_lsof(t);
        assert_eq!(v.len(), 5, "{v:?}");
        assert_eq!(v[0].pid, Some(501));
        assert_eq!(v[0].remote.unwrap().to_string(), "17.57.144.10:443");
        assert_eq!(v[0].state, State::Established);
        assert_eq!(v[1].state, State::Listen);
        assert_eq!(v[1].local.to_string(), "[::]:8000");
        assert_eq!((v[2].pid, v[2].uid, v[2].state), (Some(88), Some(65), State::Unconnected));
        assert_eq!(v[3].local.to_string(), "[fe80::1]:5353");
        assert_eq!(v[4].state, State::SynSent);
    }
}
