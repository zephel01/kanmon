//! 接続ごとの累積送信量と、プロセスが開いているファイルの取得（OS 依存部分）。
//!
//! - Linux：netlink の sock_diag（INET_DIAG_INFO）で TCP の `tcpi_bytes_acked`（相手が受け取りを
//!   確認したバイト数）を読む。プロセスへの帰属は、ソケット一覧と同じ inode で行う。
//! - macOS：`nettop -L 1 -n -x -m tcp -J bytes_out` の CSV を読む（引数で渡し、シェルを通さない）
//!   【要検証：出力形式は版で変わり得る】。
//! - 開いているファイル：Linux は `/proc/<pid>/fd`、macOS は `lsof -nP -p <pid> -Ftsn`。
//! - UDP（QUIC 等）の送信量は取れない（v0.2.2 時点）。
//!
//! 解析は純関数にしてあり、どの OS でもテストできる。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use kanmon_core::volume::FlowBytes;

// ---------------------------------------------------------------- Linux sock_diag

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const INET_DIAG_INFO: u16 = 2;
const TCP_LISTEN: u32 = 10;
/// struct tcp_info の tcpi_bytes_acked の位置（Linux 4.1 以降）
const TCPI_BYTES_ACKED: usize = 120;

/// 1 ソケット分（inode, ローカル, リモート, 累積送信バイト数）
pub type DiagRow = (u64, SocketAddr, SocketAddr, u64);

/// SOCK_DIAG_BY_FAMILY の要求（TCP、待受以外の全状態、tcp_info 付き）
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn diag_request(family: u8, seq: u32) -> Vec<u8> {
    let len: u32 = 16 + 56;
    let mut v = Vec::with_capacity(len as usize);
    v.extend_from_slice(&len.to_ne_bytes());
    v.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    v.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    v.extend_from_slice(&seq.to_ne_bytes());
    v.extend_from_slice(&0u32.to_ne_bytes());
    // inet_diag_req_v2
    v.push(family);
    v.push(6); // IPPROTO_TCP
    v.push(1 << (INET_DIAG_INFO - 1)); // idiag_ext
    v.push(0);
    let states: u32 = ((1u32 << 12) - 1) & !(1 << TCP_LISTEN) & !1;
    v.extend_from_slice(&states.to_ne_bytes());
    v.extend_from_slice(&[0u8; 48]); // inet_diag_sockid（全件）
    v
}

fn ne16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(i..i + 2)?.try_into().ok()?))
}
fn ne32(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(i..i + 4)?.try_into().ok()?))
}
fn ne64(b: &[u8], i: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(b.get(i..i + 8)?.try_into().ok()?))
}
fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(i..i + 2)?.try_into().ok()?))
}

fn diag_addr(family: u8, b: &[u8]) -> Option<IpAddr> {
    match family {
        2 => Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))),
        10 => {
            let a: [u8; 16] = b.get(..16)?.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(a)))
        }
        _ => None,
    }
}

/// netlink の応答を読む。戻り値は（行, 終わりか）
pub fn parse_diag(buf: &[u8]) -> (Vec<DiagRow>, bool) {
    let mut out = vec![];
    let mut off = 0;
    while off + 16 <= buf.len() {
        let Some(len) = ne32(buf, off).map(|x| x as usize) else { break };
        let Some(ty) = ne16(buf, off + 4) else { break };
        if len < 16 || off + len > buf.len() {
            break;
        }
        if ty == NLMSG_DONE || ty == NLMSG_ERROR {
            return (out, true);
        }
        let p = &buf[off + 16..off + len];
        if p.len() >= 72 {
            let family = p[0];
            let row = (|| {
                let sport = be16(p, 4)?;
                let dport = be16(p, 6)?;
                let src = diag_addr(family, &p[8..24])?;
                let dst = diag_addr(family, &p[24..40])?;
                let inode = ne32(p, 68)? as u64;
                // 属性（rtattr）から tcp_info を探す
                let mut a = 72;
                let mut acked = None;
                while a + 4 <= p.len() {
                    let alen = ne16(p, a)? as usize;
                    let aty = ne16(p, a + 2)?;
                    if alen < 4 || a + alen > p.len() {
                        break;
                    }
                    if aty == INET_DIAG_INFO {
                        acked = ne64(&p[a + 4..a + alen], TCPI_BYTES_ACKED);
                    }
                    a += (alen + 3) & !3;
                }
                Some((inode, SocketAddr::new(src, sport), SocketAddr::new(dst, dport), acked?))
            })();
            if let Some(r) = row {
                if r.0 != 0 {
                    out.push(r);
                }
            }
        }
        off += (len + 3) & !3;
    }
    (out, false)
}

#[cfg(target_os = "linux")]
fn diag_dump(family: u8) -> std::io::Result<Vec<DiagRow>> {
    use std::io::Error;
    struct Fd(i32);
    impl Drop for Fd {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }
    unsafe {
        let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, libc::NETLINK_SOCK_DIAG);
        if fd < 0 {
            return Err(Error::last_os_error());
        }
        let fd = Fd(fd);
        let tv = libc::timeval { tv_sec: 2, tv_usec: 0 };
        libc::setsockopt(
            fd.0,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as u32,
        );
        let req = diag_request(family, 1);
        let mut sa: libc::sockaddr_nl = std::mem::zeroed();
        sa.nl_family = libc::AF_NETLINK as u16;
        let n = libc::sendto(
            fd.0,
            req.as_ptr() as *const libc::c_void,
            req.len(),
            0,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        );
        if n < 0 {
            return Err(Error::last_os_error());
        }
        let mut buf = vec![0u8; 64 * 1024];
        let mut out = vec![];
        for _ in 0..10_000 {
            let n = libc::recv(fd.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
            if n < 0 {
                return Err(Error::last_os_error());
            }
            if n == 0 {
                break;
            }
            let (rows, done) = parse_diag(&buf[..n as usize]);
            out.extend(rows);
            if done {
                break;
            }
        }
        Ok(out)
    }
}

/// Linux：TCP の接続ごとの累積送信量。`inode_pid` はソケット一覧から作った inode → pid
#[cfg(target_os = "linux")]
pub fn collect(inode_pid: &HashMap<u64, u32>) -> Vec<FlowBytes> {
    let mut rows = vec![];
    for fam in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
        match diag_dump(fam) {
            Ok(r) => rows.extend(r),
            Err(e) => {
                crate::logln!("送信量を読めません（sock_diag）: {e}");
                return vec![];
            }
        }
    }
    rows.into_iter()
        .filter_map(|(ino, local, remote, b)| {
            Some(FlowBytes { pid: *inode_pid.get(&ino)?, local, remote, bytes_out: b })
        })
        .collect()
}

// ---------------------------------------------------------------- macOS nettop

/// nettop の端点。IPv4 は `a.b.c.d:port`、IPv6 は `addr.port`（`%if` 付きのことがある）、
/// 角括弧つき `[addr]:port` にも対応する【要検証】
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn parse_nettop_endpoint(s: &str) -> Option<SocketAddr> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        let (a, p) = rest.split_once("]:")?;
        let ip: Ipv6Addr = a.split('%').next()?.parse().ok()?;
        return Some(SocketAddr::new(IpAddr::V6(ip), p.parse().ok()?));
    }
    if let Some((a, p)) = s.rsplit_once(':') {
        if let (Ok(ip), Ok(port)) = (a.parse::<Ipv4Addr>(), p.parse::<u16>()) {
            return Some(SocketAddr::new(IpAddr::V4(ip), port));
        }
    }
    let (a, p) = s.rsplit_once('.')?;
    let ip: Ipv6Addr = a.split('%').next()?.parse().ok()?;
    Some(SocketAddr::new(IpAddr::V6(ip), p.parse().ok()?))
}

/// `nettop -L 1 -n -x -m tcp -J bytes_out` の CSV。プロセスの行（`名前.pid`）の後に、
/// その接続の行（`tcp4 ローカル<->リモート`）が続く。macOS 15 系の実機では見出しが `,bytes_out,`
/// （名前の列が先頭・見出しは空）だった。`time,,bytes_out` の形（時刻の列あり）にも対応する
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn parse_nettop(text: &str) -> Vec<FlowBytes> {
    let mut lines = text.lines();
    let Some(header) = lines.next() else { return vec![] };
    let cols: Vec<&str> = header.split(',').map(str::trim).collect();
    let Some(bi) = cols.iter().position(|c| *c == "bytes_out") else { return vec![] };
    // 名前（プロセス・接続）の列は、見出しが空の最初の列
    let Some(ni) = cols.iter().position(|c| c.is_empty()) else { return vec![] };
    let mut out = vec![];
    let mut pid: Option<u32> = None;
    for l in lines {
        let f: Vec<&str> = l.split(',').collect();
        let Some(ent) = f.get(ni).map(|x| x.trim()) else { continue };
        if let Some(rest) = ent.strip_prefix("tcp4 ").or_else(|| ent.strip_prefix("tcp6 ")) {
            let (Some(p), Some((a, b))) = (pid, rest.split_once("<->")) else { continue };
            let (Some(local), Some(remote)) = (parse_nettop_endpoint(a), parse_nettop_endpoint(b)) else {
                continue;
            };
            let Some(bytes) = f.get(bi).and_then(|x| x.trim().parse::<u64>().ok()) else { continue };
            out.push(FlowBytes { pid: p, local, remote, bytes_out: bytes });
        } else {
            // プロセスの行：名前に「.」を含み得るので最後の「.」の後ろを pid とみなす
            pid = ent.rsplit_once('.').and_then(|(_, p)| p.parse().ok());
        }
    }
    out
}

#[cfg(target_os = "macos")]
pub fn collect(_inode_pid: &HashMap<u64, u32>) -> Vec<FlowBytes> {
    match std::process::Command::new("/usr/bin/nettop")
        .args(["-L", "1", "-n", "-x", "-m", "tcp", "-J", "bytes_out"])
        .output()
    {
        Ok(o) => parse_nettop(&String::from_utf8_lossy(&o.stdout)),
        Err(e) => {
            crate::logln!("送信量を読めません（nettop）: {e}");
            vec![]
        }
    }
}

// ---------------------------------------------------------------- 開いているファイル

/// `lsof -nP -p <pid> -Ftsn` の出力から通常ファイル（パス, 容量）を取り出す
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn parse_lsof_files(text: &str) -> Vec<(String, u64)> {
    let mut out = vec![];
    let (mut ty, mut size): (Option<String>, Option<u64>) = (None, None);
    for l in text.lines() {
        let (k, v) = l.split_at(l.len().min(1));
        match k {
            "f" => {
                ty = None;
                size = None;
            }
            "t" => ty = Some(v.to_string()),
            "s" => size = v.parse().ok(),
            "n" if ty.as_deref() == Some("REG") => out.push((v.to_string(), size.unwrap_or(0))),
            _ => {}
        }
    }
    out
}

/// プロセスが開いている通常ファイル（パス, 容量）。最大 1024 件
pub fn open_files(pid: u32) -> Vec<(String, u64)> {
    #[cfg(target_os = "linux")]
    {
        let Ok(rd) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { return vec![] };
        let mut out = vec![];
        for e in rd.flatten().take(4096) {
            let Ok(t) = std::fs::read_link(e.path()) else { continue };
            let s = t.to_string_lossy();
            if !s.starts_with('/') || s.starts_with("/dev/") || s.starts_with("/proc/") {
                continue;
            }
            let path = s.strip_suffix(" (deleted)").unwrap_or(&s).to_string();
            // fd 経由で容量を見る（削除済みでも読める）
            if let Ok(md) = std::fs::metadata(e.path()) {
                if md.is_file() {
                    out.push((path, md.len()));
                }
            }
            if out.len() >= 1024 {
                break;
            }
        }
        out
    }
    #[cfg(target_os = "macos")]
    {
        let pid_s = pid.to_string();
        match std::process::Command::new("/usr/sbin/lsof").args(["-nP", "-p", &pid_s, "-Ftsn"]).output() {
            Ok(o) => {
                let mut v = parse_lsof_files(&String::from_utf8_lossy(&o.stdout));
                v.truncate(1024);
                v
            }
            Err(_) => vec![],
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// テスト用に sock_diag の応答 1 件を組み立てる（ホストのバイト順）
    fn diag_msg(family: u8, src: &[u8], sport: u16, dst: &[u8], dport: u16, inode: u32, acked: u64) -> Vec<u8> {
        let mut p = vec![family, 1, 0, 0];
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        let mut a = [0u8; 16];
        a[..src.len()].copy_from_slice(src);
        p.extend_from_slice(&a);
        let mut b = [0u8; 16];
        b[..dst.len()].copy_from_slice(dst);
        p.extend_from_slice(&b);
        p.extend_from_slice(&[0u8; 12]); // if, cookie
        p.extend_from_slice(&[0u8; 16]); // expires, rqueue, wqueue, uid
        p.extend_from_slice(&inode.to_ne_bytes());
        // rtattr INET_DIAG_INFO（tcp_info 232 バイト）
        let mut info = vec![0u8; 232];
        info[TCPI_BYTES_ACKED..TCPI_BYTES_ACKED + 8].copy_from_slice(&acked.to_ne_bytes());
        p.extend_from_slice(&((4 + info.len()) as u16).to_ne_bytes());
        p.extend_from_slice(&INET_DIAG_INFO.to_ne_bytes());
        p.extend_from_slice(&info);
        let mut m = ((16 + p.len()) as u32).to_ne_bytes().to_vec();
        m.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        m.extend_from_slice(&[0u8; 10]);
        m.extend_from_slice(&p);
        m
    }

    #[test]
    fn diag_parse() {
        let mut buf = diag_msg(2, &[192, 0, 2, 10], 50000, &[203, 0, 113, 70], 443, 1234, 5_000_000);
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        buf.extend(diag_msg(10, &v6.octets(), 50001, &v6.octets(), 443, 99, 7));
        let mut done = 16u32.to_ne_bytes().to_vec();
        done.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
        done.extend_from_slice(&[0u8; 10]);
        buf.extend(done);
        let (rows, fin) = parse_diag(&buf);
        assert!(fin);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0],
            (1234, "192.0.2.10:50000".parse().unwrap(), "203.0.113.70:443".parse().unwrap(), 5_000_000)
        );
        assert_eq!(rows[1].2, SocketAddr::new(IpAddr::V6(v6), 443));
        for n in 0..buf.len() {
            let _ = parse_diag(&buf[..n]);
        }
        assert_eq!(diag_request(2, 1).len(), 72);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn diag_live_sees_own_connection() {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = vec![0u8; 300_000];
            let mut got = 0;
            while got < 300_000 {
                let n = s.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                got += n;
            }
            got
        });
        let mut c = std::net::TcpStream::connect(addr).unwrap();
        c.write_all(&vec![7u8; 300_000]).unwrap();
        assert_eq!(h.join().unwrap(), 300_000);
        let local = c.local_addr().unwrap();
        let rows = diag_dump(libc::AF_INET as u8).unwrap();
        let mine = rows.iter().find(|r| r.1 == local && r.2 == addr).expect("自分の接続が見えない");
        assert!(mine.3 >= 300_000, "bytes_acked={}", mine.3);
    }

    /// 利用者の Mac（2026-11-18）の実出力を元にした例（アドレスは文書用に置き換え）
    #[test]
    fn nettop_parse_real_layout() {
        let text = ",bytes_out,\n\
                    launchd.1,0,\n\
                    tcp6 ::1.8021<->*.*,,\n\
                    tcp4 127.0.0.1:8021<->*:*,,\n\
                    apsd.381,868359,\n\
                    tcp4 192.0.2.28:51391<->203.0.113.27:5223,868359,\n\
                    WarpLike.535,0,\n\
                    tcp4 127.0.2.2:53<->*:*,,\n\
                    some.agent.542,154071456,\n\
                    tcp6 2001:db8:1::cd32.55156<->2001:db8:2::406.443,154071456,\n\
                    rapportd.711,1775288,\n\
                    tcp4 *:54960<->*:*,,\n\
                    tcp6 fe80::c83:fed5:f838:6fbd%en0.54960<->fe80::1463:2656:e957:4acd%en0.64052,1775288,\n";
        let v = parse_nettop(text);
        assert_eq!(v.len(), 3, "{v:?}");
        assert_eq!((v[0].pid, v[0].bytes_out), (381, 868359));
        assert_eq!(v[0].remote, "203.0.113.27:5223".parse().unwrap());
        assert_eq!((v[1].pid, v[1].bytes_out), (542, 154071456));
        assert_eq!(v[1].remote, "[2001:db8:2::406]:443".parse().unwrap());
        assert_eq!(v[2].pid, 711);
        assert_eq!(v[2].local.port(), 54960);
    }

    #[test]
    fn nettop_parse() {
        let text = "time,,bytes_out,\n\
                    16:40:01.000000,Google Chrome H.812,123456,\n\
                    16:40:01.000000,tcp4 192.0.2.10:50000<->203.0.113.70:443,100000,\n\
                    16:40:01.000000,tcp6 2001:db8::10.50001<->2001:db8::70.443,23456,\n\
                    16:40:01.000000,node.4242,9,\n\
                    16:40:01.000000,tcp4 192.0.2.10:50002<->203.0.113.71:443,9,\n";
        let v = parse_nettop(text);
        assert_eq!(v.len(), 3);
        assert_eq!((v[0].pid, v[0].bytes_out), (812, 100000));
        assert_eq!(v[1].remote, "[2001:db8::70]:443".parse().unwrap());
        assert_eq!(v[2].pid, 4242);
        assert!(parse_nettop("garbage").is_empty());
        assert_eq!(parse_nettop_endpoint("[fe80::1%en0]:443"), Some("[fe80::1]:443".parse().unwrap()));
    }

    #[test]
    fn lsof_files() {
        let t = "p42\nfcwd\ntDIR\ns4096\nn/Users/a\nf3\ntREG\ns4900000000\nn/Users/a/m.gguf\nf4\ntIPv4\nn192.0.2.1:1->203.0.113.1:443\nf5\ntREG\ns300\nn/Users/a/w/.env\n";
        assert_eq!(
            parse_lsof_files(t),
            vec![("/Users/a/m.gguf".to_string(), 4_900_000_000), ("/Users/a/w/.env".to_string(), 300)]
        );
    }
}
