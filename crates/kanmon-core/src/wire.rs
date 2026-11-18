//! 受け身で読んだパケットの解析（純関数）：リンク層 → IPv4/IPv6 → UDP/TCP、
//! DNS メッセージ、TLS ClientHello の SNI。
//!
//! 入力は外部から来る信用できないバイト列なので、すべて境界を確かめて読み、
//! 解釈できないものは `None` を返す（パニックしない）。圧縮ポインタの循環、
//! 長さの食い違い、途中で切れたパケットもここで弾く。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ---------------- リンク層〜トランスポート層 ----------------

/// pcap の DLT（データリンク種別）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    /// DLT_EN10MB（1）
    Ethernet,
    /// DLT_NULL（0）・DLT_LOOP（108）：4 バイトのアドレスファミリーの後に IP
    Null,
    /// DLT_RAW（12・14）・LINKTYPE_RAW（101）：先頭から IP
    Raw,
    /// DLT_LINUX_SLL（113）
    LinuxSll,
    /// DLT_LINUX_SLL2（276）
    LinuxSll2,
}

impl Link {
    pub fn from_dlt(dlt: i32) -> Option<Self> {
        Some(match dlt {
            1 => Link::Ethernet,
            0 | 108 => Link::Null,
            12 | 14 | 101 => Link::Raw,
            113 => Link::LinuxSll,
            276 => Link::LinuxSll2,
            _ => return None,
        })
    }
}

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub payload: &'a [u8],
}

fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn be32(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes([*b.get(i)?, *b.get(i + 1)?, *b.get(i + 2)?, *b.get(i + 3)?]))
}

/// リンク層から UDP/TCP のペイロードまで読む。断片化した IP・UDP/TCP 以外は `None`。
pub fn parse_frame(link: Link, data: &[u8]) -> Option<Segment<'_>> {
    let ip = match link {
        Link::Ethernet => {
            let mut et = be16(data, 12)?;
            let mut off = 14;
            // VLAN タグ（802.1Q / 802.1ad）を 2 段まで外す
            for _ in 0..2 {
                if et == 0x8100 || et == 0x88a8 {
                    et = be16(data, off + 2)?;
                    off += 4;
                }
            }
            if et != 0x0800 && et != 0x86dd {
                return None;
            }
            data.get(off..)?
        }
        Link::Null => data.get(4..)?,
        Link::Raw => data,
        Link::LinuxSll => {
            let et = be16(data, 14)?;
            if et != 0x0800 && et != 0x86dd {
                return None;
            }
            data.get(16..)?
        }
        Link::LinuxSll2 => {
            let et = be16(data, 0)?;
            if et != 0x0800 && et != 0x86dd {
                return None;
            }
            data.get(20..)?
        }
    };
    parse_ip(ip)
}

/// IP ヘッダから読む（版はバイト先頭の 4 ビットで判定）。
pub fn parse_ip(b: &[u8]) -> Option<Segment<'_>> {
    match b.first()? >> 4 {
        4 => {
            let ihl = ((b[0] & 0x0f) as usize) * 4;
            if ihl < 20 || b.len() < ihl {
                return None;
            }
            let total = be16(b, 2)? as usize;
            let frag = be16(b, 6)?;
            // MF ビットか断片オフセットがあれば扱わない
            if frag & 0x3fff != 0 {
                return None;
            }
            let proto = *b.get(9)?;
            let src = IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15]));
            let dst = IpAddr::V4(Ipv4Addr::new(b[16], b[17], b[18], b[19]));
            let end = total.min(b.len());
            if end < ihl {
                return None;
            }
            parse_l4(src, dst, proto, &b[ihl..end])
        }
        6 => {
            if b.len() < 40 {
                return None;
            }
            let plen = be16(b, 4)? as usize;
            let mut next = b[6];
            let mut a = [0u8; 16];
            a.copy_from_slice(&b[8..24]);
            let src = IpAddr::V6(Ipv6Addr::from(a));
            a.copy_from_slice(&b[24..40]);
            let dst = IpAddr::V6(Ipv6Addr::from(a));
            let end = (40 + plen).min(b.len());
            let mut off = 40;
            // 拡張ヘッダ（hop-by-hop・routing・destination options）を最大 4 つ外す。断片（44）は扱わない
            for _ in 0..4 {
                match next {
                    0 | 43 | 60 => {
                        let nh = *b.get(off)?;
                        let len = (*b.get(off + 1)? as usize + 1) * 8;
                        next = nh;
                        off += len;
                    }
                    _ => break,
                }
            }
            if off > end {
                return None;
            }
            parse_l4(src, dst, next, &b[off..end])
        }
        _ => None,
    }
}

fn parse_l4(src: IpAddr, dst: IpAddr, proto: u8, b: &[u8]) -> Option<Segment<'_>> {
    match proto {
        PROTO_UDP => {
            let len = be16(b, 4)? as usize;
            if len < 8 {
                return None;
            }
            let end = len.min(b.len());
            Some(Segment { src, dst, proto, sport: be16(b, 0)?, dport: be16(b, 2)?, payload: b.get(8..end)? })
        }
        PROTO_TCP => {
            let doff = ((*b.get(12)? >> 4) as usize) * 4;
            if doff < 20 {
                return None;
            }
            Some(Segment { src, dst, proto, sport: be16(b, 0)?, dport: be16(b, 2)?, payload: b.get(doff..)? })
        }
        _ => None,
    }
}

// ---------------- DNS ----------------

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Other(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub name: String,
    pub ttl: u32,
    pub data: RData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub response: bool,
    pub rcode: u8,
    pub qname: Option<String>,
    pub qtype: u16,
    pub answers: Vec<Answer>,
}

impl DnsMessage {
    /// 応答に含まれる A/AAAA のアドレス（重複なし、昇順）
    pub fn addresses(&self) -> Vec<IpAddr> {
        let mut v: Vec<IpAddr> = self
            .answers
            .iter()
            .filter_map(|a| match a.data {
                RData::A(x) => Some(IpAddr::V4(x)),
                RData::Aaaa(x) => Some(IpAddr::V6(x)),
                _ => None,
            })
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// A/AAAA の TTL の最小値
    pub fn min_ttl(&self) -> Option<u32> {
        self.answers.iter().filter(|a| matches!(a.data, RData::A(_) | RData::Aaaa(_))).map(|a| a.ttl).min()
    }
}

const MAX_ANSWERS: usize = 64;
const MAX_NAME: usize = 253;

/// ドメイン名として受け付ける文字か（英小文字・数字・ハイフン・下線）
fn label_ok(l: &[u8]) -> bool {
    !l.is_empty() && l.len() <= 63 && l.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
}

/// 圧縮ポインタを辿って名前を読む。戻り値は（名前, 名前の直後のオフセット）。
fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut pos = start;
    let mut after: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(pos)? as usize;
        match len & 0xc0 {
            0x00 => {
                if len == 0 {
                    pos += 1;
                    break;
                }
                let l = msg.get(pos + 1..pos + 1 + len)?;
                if !label_ok(l) {
                    return None;
                }
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(&String::from_utf8_lossy(l).to_ascii_lowercase());
                if out.len() > MAX_NAME {
                    return None;
                }
                pos += 1 + len;
            }
            0xc0 => {
                let ptr = ((len & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
                if after.is_none() {
                    after = Some(pos + 2);
                }
                jumps += 1;
                // 前方を指すポインタ・循環は不正
                if jumps > 16 || ptr >= pos {
                    return None;
                }
                pos = ptr;
            }
            _ => return None,
        }
    }
    Some((out, after.unwrap_or(pos)))
}

/// DNS メッセージ（UDP のペイロード、または TCP の 2 バイト長を外したもの）を読む。
pub fn parse_dns(msg: &[u8]) -> Option<DnsMessage> {
    let id = be16(msg, 0)?;
    let flags = be16(msg, 2)?;
    let qd = be16(msg, 4)? as usize;
    let an = be16(msg, 6)? as usize;
    let response = flags & 0x8000 != 0;
    let opcode = (flags >> 11) & 0x0f;
    if opcode != 0 || qd > 4 {
        return None;
    }
    let mut pos = 12;
    let mut qname = None;
    let mut qtype = 0;
    for i in 0..qd {
        let (n, p) = read_name(msg, pos)?;
        let t = be16(msg, p)?;
        be16(msg, p + 2)?;
        if i == 0 {
            qname = Some(n);
            qtype = t;
        }
        pos = p + 4;
    }
    let mut answers = vec![];
    for _ in 0..an.min(MAX_ANSWERS) {
        let (name, p) = read_name(msg, pos)?;
        let rtype = be16(msg, p)?;
        let class = be16(msg, p + 2)?;
        let ttl = be32(msg, p + 4)?;
        let rdlen = be16(msg, p + 8)? as usize;
        let rd = p + 10;
        let body = msg.get(rd..rd + rdlen)?;
        let data = match (rtype, class) {
            (TYPE_A, 1) if rdlen == 4 => RData::A(Ipv4Addr::new(body[0], body[1], body[2], body[3])),
            (TYPE_AAAA, 1) if rdlen == 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(body);
                RData::Aaaa(Ipv6Addr::from(a))
            }
            (TYPE_CNAME, 1) => match read_name(msg, rd) {
                Some((c, _)) => RData::Cname(c),
                None => RData::Other(rtype),
            },
            _ => RData::Other(rtype),
        };
        answers.push(Answer { name, ttl, data });
        pos = rd + rdlen;
    }
    Some(DnsMessage { id, response, rcode: (flags & 0x0f) as u8, qname, qtype, answers })
}

/// TCP 上の DNS（先頭 2 バイトがメッセージ長）。1 セグメントに収まっているものだけ読む。
pub fn parse_dns_tcp(payload: &[u8]) -> Option<DnsMessage> {
    let len = be16(payload, 0)? as usize;
    parse_dns(payload.get(2..2 + len)?)
}

// ---------------- TLS ClientHello の SNI ----------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// server_name 拡張の名前（無ければ None）
    pub sni: Option<String>,
    /// ECH（encrypted_client_hello, 0xfe0d）拡張がある。このとき SNI は外側の公開名
    pub ech: bool,
}

/// TLS レコードの先頭（TCP ペイロード）から ClientHello を読む。
/// 途中で切れていて SNI まで届かない場合は `None`。
pub fn parse_client_hello(b: &[u8]) -> Option<ClientHello> {
    // レコード：type(1)=22 handshake, version(2), length(2)
    if *b.first()? != 0x16 || *b.get(1)? != 0x03 {
        return None;
    }
    let rec_len = be16(b, 3)? as usize;
    let rec = b.get(5..)?;
    let rec = &rec[..rec_len.min(rec.len())];
    // ハンドシェイク：type(1)=1 ClientHello, length(3)
    if *rec.first()? != 0x01 {
        return None;
    }
    let mut p = 4 + 2 + 32; // 種別・長さ・client_version・random
    let sid = *rec.get(p)? as usize;
    p += 1 + sid;
    let cs = be16(rec, p)? as usize;
    p += 2 + cs;
    let cm = *rec.get(p)? as usize;
    p += 1 + cm;
    let ext_total = be16(rec, p)? as usize;
    p += 2;
    let ext_end = (p + ext_total).min(rec.len());
    let mut sni = None;
    let mut ech = false;
    while p + 4 <= ext_end {
        let t = be16(rec, p)?;
        let l = be16(rec, p + 2)? as usize;
        let body_start = p + 4;
        match t {
            0x0000 => {
                // server_name_list(2) → name_type(1)=0 host_name, length(2), name
                let body = rec.get(body_start..body_start + l)?;
                if *body.get(2)? == 0 {
                    let nl = be16(body, 3)? as usize;
                    let name = body.get(5..5 + nl)?;
                    let ok = !name.is_empty() && name.len() <= MAX_NAME && name.split(|c| *c == b'.').all(label_ok);
                    if ok {
                        sni = Some(String::from_utf8_lossy(name).to_ascii_lowercase());
                    }
                }
            }
            0xfe0d => ech = true,
            _ => {}
        }
        p = body_start + l;
    }
    if sni.is_none() && p < ext_total {
        // 拡張の途中で切れている
        return None;
    }
    Some(ClientHello { sni, ech })
}

#[cfg(test)]
pub(crate) mod testdata {
    //! テスト用に DNS 応答・ClientHello を組み立てる（ドメインは example / test、IP は RFC 5737）
    use std::net::IpAddr;

    pub fn name(n: &str) -> Vec<u8> {
        let mut v = vec![];
        for l in n.split('.') {
            v.push(l.len() as u8);
            v.extend_from_slice(l.as_bytes());
        }
        v.push(0);
        v
    }

    /// qname への応答。CNAME を挟む場合は cname を指定
    pub fn dns_response(id: u16, qname: &str, cname: Option<&str>, ips: &[IpAddr], ttl: u32) -> Vec<u8> {
        let an = ips.len() + usize::from(cname.is_some());
        let mut m = vec![];
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&0x8180u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&(an as u16).to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        m.extend_from_slice(&name(qname));
        m.extend_from_slice(&[0, 1, 0, 1]);
        let mut owner = vec![0xc0, 12]; // 質問の名前を指すポインタ
        if let Some(c) = cname {
            let cn = name(c);
            m.extend_from_slice(&owner);
            m.extend_from_slice(&[0, 5, 0, 1]);
            m.extend_from_slice(&ttl.to_be_bytes());
            m.extend_from_slice(&(cn.len() as u16).to_be_bytes());
            let cpos = m.len();
            m.extend_from_slice(&cn);
            owner = vec![0xc0 | ((cpos >> 8) as u8), (cpos & 0xff) as u8];
        }
        for ip in ips {
            m.extend_from_slice(&owner);
            match ip {
                IpAddr::V4(a) => {
                    m.extend_from_slice(&[0, 1, 0, 1]);
                    m.extend_from_slice(&ttl.to_be_bytes());
                    m.extend_from_slice(&4u16.to_be_bytes());
                    m.extend_from_slice(&a.octets());
                }
                IpAddr::V6(a) => {
                    m.extend_from_slice(&[0, 28, 0, 1]);
                    m.extend_from_slice(&ttl.to_be_bytes());
                    m.extend_from_slice(&16u16.to_be_bytes());
                    m.extend_from_slice(&a.octets());
                }
            }
        }
        m
    }

    pub fn client_hello(sni: Option<&str>, ech: bool) -> Vec<u8> {
        let mut ext = vec![];
        if let Some(s) = sni {
            let n = s.as_bytes();
            let mut body = vec![];
            body.extend_from_slice(&((n.len() + 3) as u16).to_be_bytes());
            body.push(0);
            body.extend_from_slice(&(n.len() as u16).to_be_bytes());
            body.extend_from_slice(n);
            ext.extend_from_slice(&[0, 0]);
            ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
            ext.extend_from_slice(&body);
        }
        if ech {
            ext.extend_from_slice(&[0xfe, 0x0d, 0, 2, 0, 0]);
        }
        let mut hs = vec![0x03, 0x03];
        hs.extend_from_slice(&[0x11; 32]);
        hs.push(0); // session id
        hs.extend_from_slice(&[0, 2, 0x13, 0x01]); // cipher suites
        hs.extend_from_slice(&[1, 0]); // compression
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);
        let mut h = vec![1];
        h.extend_from_slice(&(hs.len() as u32).to_be_bytes()[1..]);
        h.extend_from_slice(&hs);
        let mut r = vec![0x16, 0x03, 0x01];
        r.extend_from_slice(&(h.len() as u16).to_be_bytes());
        r.extend_from_slice(&h);
        r
    }

    /// IPv4 + UDP/TCP のパケット（チェックサムは 0）
    pub fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let l4 = if proto == 17 {
            let mut u = vec![];
            u.extend_from_slice(&sport.to_be_bytes());
            u.extend_from_slice(&dport.to_be_bytes());
            u.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
            u.extend_from_slice(&[0, 0]);
            u.extend_from_slice(payload);
            u
        } else {
            let mut t = vec![];
            t.extend_from_slice(&sport.to_be_bytes());
            t.extend_from_slice(&dport.to_be_bytes());
            t.extend_from_slice(&[0; 8]);
            t.push(5 << 4);
            t.push(0x18);
            t.extend_from_slice(&[0; 6]);
            t.extend_from_slice(payload);
            t
        };
        let mut ip = vec![0x45, 0];
        ip.extend_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0x40, 0, 64, proto, 0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&l4);
        ip
    }
}

#[cfg(test)]
mod tests {
    use super::testdata::*;
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn dns_answer_with_cname() {
        let m = dns_response(
            0x1234,
            "www.example.com",
            Some("edge.example.net"),
            &[ip("203.0.113.10"), ip("2001:db8::1")],
            300,
        );
        let d = parse_dns(&m).unwrap();
        assert!(d.response);
        assert_eq!(d.id, 0x1234);
        assert_eq!(d.qname.as_deref(), Some("www.example.com"));
        assert_eq!(d.answers.len(), 3);
        assert_eq!(d.answers[0].data, RData::Cname("edge.example.net".into()));
        assert_eq!(d.answers[1].name, "edge.example.net");
        assert_eq!(d.addresses(), vec![ip("203.0.113.10"), ip("2001:db8::1")]);
        assert_eq!(d.min_ttl(), Some(300));
    }

    #[test]
    fn dns_rejects_loops_and_garbage() {
        // 自分自身を指す圧縮ポインタ
        let mut m = vec![0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1];
        assert!(parse_dns(&m).is_none());
        // 制御文字を含むラベル
        m = vec![0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'a', 0, b'b', 0, 0, 1, 0, 1];
        assert!(parse_dns(&m).is_none());
        // 途中で切れた応答（パニックしないこと）
        let full = dns_response(1, "a.example.com", None, &[ip("203.0.113.1")], 60);
        for n in 0..full.len() {
            let _ = parse_dns(&full[..n]);
        }
        // 総当たりの小さなファズ
        let mut x: u32 = 12345;
        for _ in 0..20_000 {
            let mut buf = full.clone();
            for _ in 0..3 {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                let i = (x as usize >> 8) % buf.len();
                buf[i] = (x >> 16) as u8;
            }
            let _ = parse_dns(&buf);
            let _ = parse_client_hello(&buf);
        }
    }

    #[test]
    fn sni_and_ech() {
        let ch = parse_client_hello(&client_hello(Some("API.Example.com"), false)).unwrap();
        assert_eq!(ch.sni.as_deref(), Some("api.example.com"));
        assert!(!ch.ech);
        let ch = parse_client_hello(&client_hello(Some("public.example.net"), true)).unwrap();
        assert!(ch.ech);
        assert_eq!(parse_client_hello(&client_hello(None, false)).unwrap().sni, None);
        let full = client_hello(Some("a.example.com"), false);
        for n in 0..full.len() {
            let _ = parse_client_hello(&full[..n]);
        }
        assert!(parse_client_hello(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn frames() {
        let dns = dns_response(7, "x.example.com", None, &[ip("203.0.113.7")], 60);
        let pkt = ipv4(17, [198, 51, 100, 53], [192, 0, 2, 10], 53, 40000, &dns);
        // Raw
        let s = parse_frame(Link::Raw, &pkt).unwrap();
        assert_eq!((s.sport, s.dport, s.proto), (53, 40000, PROTO_UDP));
        assert_eq!(s.src, ip("198.51.100.53"));
        assert_eq!(parse_dns(s.payload).unwrap().qname.as_deref(), Some("x.example.com"));
        // Ethernet + VLAN
        let mut eth = vec![0; 12];
        eth.extend_from_slice(&[0x81, 0x00, 0, 5, 0x08, 0x00]);
        eth.extend_from_slice(&pkt);
        assert_eq!(parse_frame(Link::Ethernet, &eth).unwrap().sport, 53);
        // NULL（macOS の lo0・utun）
        let mut null = vec![2, 0, 0, 0];
        null.extend_from_slice(&pkt);
        assert_eq!(parse_frame(Link::Null, &null).unwrap().dport, 40000);
        // SLL2（Linux の any）
        let mut sll2 = vec![0x08, 0x00];
        sll2.extend_from_slice(&[0; 18]);
        sll2.extend_from_slice(&pkt);
        assert_eq!(parse_frame(Link::LinuxSll2, &sll2).unwrap().sport, 53);
        // TCP + ClientHello
        let ch = client_hello(Some("sni.example.com"), false);
        let t = ipv4(6, [192, 0, 2, 10], [203, 0, 113, 9], 50000, 443, &ch);
        let s = parse_frame(Link::Raw, &t).unwrap();
        assert_eq!(s.dport, 443);
        assert_eq!(parse_client_hello(s.payload).unwrap().sni.as_deref(), Some("sni.example.com"));
        // 断片化パケットは扱わない
        let mut frag = pkt.clone();
        frag[6] = 0x20;
        assert!(parse_frame(Link::Raw, &frag).is_none());
        for n in 0..pkt.len() {
            let _ = parse_frame(Link::Raw, &pkt[..n]);
        }
    }

    #[test]
    fn dns_over_tcp() {
        let dns = dns_response(9, "t.example.com", None, &[ip("203.0.113.9")], 60);
        let mut p = (dns.len() as u16).to_be_bytes().to_vec();
        p.extend_from_slice(&dns);
        assert_eq!(parse_dns_tcp(&p).unwrap().addresses(), vec![ip("203.0.113.9")]);
        assert!(parse_dns_tcp(&p[..p.len() - 1]).is_none());
    }
}
