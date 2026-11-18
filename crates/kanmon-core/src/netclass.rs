//! 宛先の範囲（loopback / lan / internet）と、ビーコン集計用の宛先キー。

use std::net::IpAddr;

pub fn scope(ip: &IpAddr) -> &'static str {
    if ip.is_loopback() || ip.is_unspecified() {
        return "loopback";
    }
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            let cgnat = o[0] == 100 && (o[1] & 0xC0) == 64; // 100.64.0.0/10（Tailscale 等）
            if v.is_private() || v.is_link_local() || v.is_multicast() || v.is_broadcast() || cgnat {
                "lan"
            } else {
                "internet"
            }
        }
        IpAddr::V6(v) => {
            if let Some(m) = v.to_ipv4_mapped() {
                return scope(&IpAddr::V4(m));
            }
            let s0 = v.segments()[0];
            let ula = (s0 & 0xfe00) == 0xfc00;
            let link = (s0 & 0xffc0) == 0xfe80;
            if ula || link || v.is_multicast() {
                "lan"
            } else {
                "internet"
            }
        }
    }
}

/// 登録ドメインがあればそれ、無ければ IPv4 は /24、IPv6 は /48。
pub fn dest_key(registered_domain: Option<&str>, ip: Option<&IpAddr>) -> Option<String> {
    if let Some(d) = registered_domain {
        return Some(d.to_string());
    }
    match ip? {
        IpAddr::V4(v) => {
            let o = v.octets();
            Some(format!("{}.{}.{}.0/24", o[0], o[1], o[2]))
        }
        IpAddr::V6(v) => {
            if let Some(m) = v.to_ipv4_mapped() {
                return dest_key(None, Some(&IpAddr::V4(m)));
            }
            let s = v.segments();
            Some(format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes() {
        let p = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(scope(&p("127.0.0.1")), "loopback");
        assert_eq!(scope(&p("::1")), "loopback");
        assert_eq!(scope(&p("192.168.1.5")), "lan");
        assert_eq!(scope(&p("100.101.1.1")), "lan");
        assert_eq!(scope(&p("fe80::1")), "lan");
        assert_eq!(scope(&p("::ffff:10.0.0.1")), "lan");
        assert_eq!(scope(&p("8.8.8.8")), "internet");
        assert_eq!(scope(&p("2606:4700::1111")), "internet");
        assert_eq!(dest_key(None, Some(&p("203.0.113.9"))).unwrap(), "203.0.113.0/24");
        assert_eq!(dest_key(Some("example.com"), Some(&p("1.1.1.1"))).unwrap(), "example.com");
    }
}
