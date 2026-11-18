//! Sysmon（Windows）のイベント XML を kanmon の内部の形に直す（純関数。どの OS でもテストできる）。
//!
//! kanmond（Windows）は `Microsoft-Windows-Sysmon/Operational` を購読し、`EvtRender` で得た XML を
//! ここに渡す。XML は外部入力として扱う：長さを制限し、知らない形は捨てる。
//!
//! | Event ID | 使い道 |
//! |---|---|
//! | 1 ProcessCreate | プロセス表（親・コマンドライン・ユーザー・ハッシュ） |
//! | 3 NetworkConnect | 短命な接続を取りこぼさない（定期的な一覧の取得の補い） |
//! | 5 ProcessTerminate | プロセス表から外す |
//! | 11 FileCreate | 居座りの場所にファイルができたら走査を早める |
//! | 12〜14 Registry | 自動起動のキーが変わったら走査を早める |
//! | 22 DnsQuery | 宛先の IP に名前を付ける |
//!
//! 実機（Windows 11 26H2 の組み込み Sysmon）で確かめたこと：つながらなかった接続は ID 3 に出ない。

use std::net::IpAddr;

/// Sysmon のログのチャネル（組み込み版・Sysinternals 版とも同じ。実機で確認）
pub const CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";
/// kanmond が購読する Event ID（XPath）
pub const QUERY: &str =
    "*[System[(EventID=1 or EventID=3 or EventID=5 or EventID=11 or EventID=12 or EventID=13 or EventID=14 or EventID=22)]]";

/// これより長い XML は捨てる（Sysmon の 1 件は通常数 KB）
pub const MAX_XML: usize = 64 * 1024;
/// コマンドラインなどの文字列はこの長さで切る
const MAX_FIELD: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct ProcessCreate {
    pub guid: String,
    pub pid: u32,
    pub image: String,
    pub command_line: String,
    pub user: Option<String>,
    pub parent_guid: Option<String>,
    pub parent_pid: Option<u32>,
    pub sha256: Option<String>,
    /// Sysmon の UtcTime（"2026-11-19 03:14:00.123"）を UNIX 秒にしたもの
    pub utc: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NetworkConnect {
    pub guid: Option<String>,
    pub pid: u32,
    pub image: String,
    /// "tcp" / "udp"
    pub protocol: String,
    /// 自分から始めた接続か（false は受けた側）
    pub initiated: bool,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub utc: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnsQuery {
    pub pid: u32,
    pub image: String,
    pub name: String,
    /// 0 なら成功
    pub status: u32,
    pub ips: Vec<IpAddr>,
    pub cnames: Vec<String>,
    pub utc: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SysmonEvent {
    ProcessCreate(ProcessCreate),
    ProcessTerminate {
        guid: Option<String>,
        pid: u32,
    },
    NetworkConnect(NetworkConnect),
    DnsQuery(DnsQuery),
    /// ID 11
    FileCreate {
        pid: u32,
        image: String,
        target: String,
    },
    /// ID 12〜14
    Registry {
        pid: u32,
        image: String,
        event_type: String,
        target: String,
    },
}

/// XML の文字参照を戻す（&lt; &gt; &amp; &quot; &apos; &#NN; &#xHH;）。知らない参照はそのまま残す
pub fn xml_unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let Some(end) = tail[..tail.len().min(12)].find(';') else {
            out.push('&');
            rest = &tail[1..];
            continue;
        };
        let ent = &tail[1..end];
        let ch = match ent {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => {
                let n = if let Some(h) = ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X")) {
                    u32::from_str_radix(h, 16).ok()
                } else if let Some(d) = ent.strip_prefix('#') {
                    d.parse().ok()
                } else {
                    None
                };
                n.and_then(char::from_u32)
            }
        };
        match ch {
            Some(c) => {
                out.push(c);
                rest = &tail[end + 1..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn clip(mut s: String) -> String {
    if s.len() > MAX_FIELD {
        let mut n = MAX_FIELD;
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        s.truncate(n);
    }
    s
}

/// `<EventID>` の値と、`<Data Name='X'>値</Data>` の組を取り出す
pub fn parse_fields(xml: &str) -> Option<(u32, Vec<(String, String)>)> {
    if xml.len() > MAX_XML {
        return None;
    }
    let i = xml.find("<EventID")?;
    let after = &xml[i..];
    let gt = after.find('>')?;
    let end = after.find("</EventID>")?;
    let id: u32 = after.get(gt + 1..end)?.trim().parse().ok()?;
    let mut fields = vec![];
    let mut rest = xml;
    while let Some(p) = rest.find("<Data") {
        rest = &rest[p + 5..];
        // <DataX> のような別の要素は除く
        if !rest.starts_with([' ', '\t', '\n', '\r', '/', '>']) {
            continue;
        }
        let Some(tag_end) = rest.find('>') else { break };
        let tag = &rest[..tag_end];
        let name = attr(tag, "Name").unwrap_or_default();
        if tag.ends_with('/') {
            fields.push((name, String::new()));
            rest = &rest[tag_end + 1..];
            continue;
        }
        let body = &rest[tag_end + 1..];
        let Some(close) = body.find("</Data>") else { break };
        fields.push((name, clip(xml_unescape(&body[..close]))));
        rest = &body[close + 7..];
    }
    Some((id, fields))
}

/// `Name='X'` または `Name="X"` の値
fn attr(tag: &str, name: &str) -> Option<String> {
    let i = tag.find(&format!("{name}="))?;
    let v = &tag[i + name.len() + 1..];
    let q = v.chars().next()?;
    if q != '\'' && q != '"' {
        return None;
    }
    let end = v[1..].find(q)?;
    Some(xml_unescape(&v[1..1 + end]))
}

fn get<'a>(f: &'a [(String, String)], k: &str) -> Option<&'a str> {
    f.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty() && *v != "-")
}

/// Sysmon の UtcTime（"2026-11-19 03:14:00.123"）→ UNIX 秒
pub fn parse_utc(s: &str) -> Option<i64> {
    let t = s.split('.').next()?;
    chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S").ok().map(|d| d.and_utc().timestamp())
}

/// "SHA1=..,MD5=..,SHA256=..,IMPHASH=.." から SHA256 を取る
pub fn sha256_of(hashes: &str) -> Option<String> {
    hashes.split(',').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k.trim().eq_ignore_ascii_case("SHA256") && v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| v.to_ascii_lowercase())
    })
}

/// ID 22 の QueryResults（"type:  5 a.example.net;::ffff:203.0.113.10;2001:db8::1;"）を IP と CNAME に分ける
pub fn parse_query_results(s: &str) -> (Vec<IpAddr>, Vec<String>) {
    let mut ips = vec![];
    let mut cnames = vec![];
    for part in s.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        if let Some(rest) = part.strip_prefix("type:") {
            // "type:  5 name" → 5 は CNAME
            let mut it = rest.split_whitespace();
            if it.next() == Some("5") {
                if let Some(n) = it.next() {
                    cnames.push(n.trim_end_matches('.').to_ascii_lowercase());
                }
            }
            continue;
        }
        if let Ok(ip) = part.parse::<IpAddr>() {
            // ::ffff:a.b.c.d は IPv4 に戻す
            let ip = match ip {
                IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
                v4 => v4,
            };
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    (ips, cnames)
}

/// 1 件の XML を解釈する。対象外の ID・壊れた XML は None
pub fn parse_event(xml: &str) -> Option<SysmonEvent> {
    let (id, f) = parse_fields(xml)?;
    let pid = || get(&f, "ProcessId").and_then(|x| x.parse::<u32>().ok());
    let s = |k: &str| get(&f, k).map(str::to_string);
    let utc = get(&f, "UtcTime").and_then(parse_utc);
    Some(match id {
        1 => SysmonEvent::ProcessCreate(ProcessCreate {
            guid: s("ProcessGuid")?,
            pid: pid()?,
            image: s("Image")?,
            command_line: s("CommandLine").unwrap_or_default(),
            user: s("User"),
            parent_guid: s("ParentProcessGuid"),
            parent_pid: get(&f, "ParentProcessId").and_then(|x| x.parse().ok()),
            sha256: get(&f, "Hashes").and_then(sha256_of),
            utc,
        }),
        5 => SysmonEvent::ProcessTerminate { guid: s("ProcessGuid"), pid: pid()? },
        3 => {
            let port = |k: &str| get(&f, k).and_then(|x| x.parse::<u16>().ok());
            let ip = |k: &str| get(&f, k).and_then(|x| x.parse::<IpAddr>().ok());
            SysmonEvent::NetworkConnect(NetworkConnect {
                guid: s("ProcessGuid"),
                pid: pid()?,
                image: s("Image").unwrap_or_default(),
                protocol: s("Protocol").unwrap_or_else(|| "tcp".into()).to_ascii_lowercase(),
                initiated: get(&f, "Initiated").is_some_and(|x| x.eq_ignore_ascii_case("true")),
                src_ip: ip("SourceIp")?,
                src_port: port("SourcePort")?,
                dst_ip: ip("DestinationIp")?,
                dst_port: port("DestinationPort")?,
                utc,
            })
        }
        22 => {
            let (ips, cnames) = parse_query_results(get(&f, "QueryResults").unwrap_or(""));
            SysmonEvent::DnsQuery(DnsQuery {
                pid: pid()?,
                image: s("Image").unwrap_or_default(),
                name: s("QueryName")?.trim_end_matches('.').to_ascii_lowercase(),
                status: get(&f, "QueryStatus").and_then(|x| x.parse().ok()).unwrap_or(0),
                ips,
                cnames,
                utc,
            })
        }
        11 => SysmonEvent::FileCreate {
            pid: pid().unwrap_or(0),
            image: s("Image").unwrap_or_default(),
            target: s("TargetFilename")?,
        },
        12..=14 => SysmonEvent::Registry {
            pid: pid().unwrap_or(0),
            image: s("Image").unwrap_or_default(),
            event_type: s("EventType").unwrap_or_default(),
            target: s("TargetObject")?,
        },
        _ => return None,
    })
}

/// Windows のコマンドラインを引数に分ける（CommandLineToArgvW と同じ規則）。
/// - 空白で区切る。`"` で囲んだ中の空白は区切らない
/// - `\` が 2n 個続いて `"` → `\` n 個と、引用の切り替え
/// - `\` が 2n+1 個続いて `"` → `\` n 個と `"` そのもの
/// - 最初の引数（プログラム名）は `"` で囲むだけで、`\` は特別扱いしない
pub fn split_command_line(cmd: &str) -> Vec<String> {
    let chars: Vec<char> = cmd.chars().collect();
    let mut out = vec![];
    let mut i = 0;
    while i < chars.len() && chars[i].is_whitespace() {
        i += 1;
    }
    if i >= chars.len() {
        return out;
    }
    // プログラム名
    let mut prog = String::new();
    if chars[i] == '"' {
        i += 1;
        while i < chars.len() && chars[i] != '"' {
            prog.push(chars[i]);
            i += 1;
        }
        i += 1;
    } else {
        while i < chars.len() && !chars[i].is_whitespace() {
            prog.push(chars[i]);
            i += 1;
        }
    }
    out.push(prog);
    loop {
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        let mut arg = String::new();
        let mut quoted = false;
        while i < chars.len() {
            let c = chars[i];
            if c == '\\' {
                let mut n = 0;
                while i < chars.len() && chars[i] == '\\' {
                    n += 1;
                    i += 1;
                }
                if i < chars.len() && chars[i] == '"' {
                    arg.extend(std::iter::repeat_n('\\', n / 2));
                    if n % 2 == 1 {
                        arg.push('"');
                        i += 1;
                    }
                } else {
                    arg.extend(std::iter::repeat_n('\\', n));
                }
                continue;
            }
            if c == '"' {
                // 引用の中の "" は " 1 つ
                if quoted && i + 1 < chars.len() && chars[i + 1] == '"' {
                    arg.push('"');
                    i += 2;
                    continue;
                }
                quoted = !quoted;
                i += 1;
                continue;
            }
            if c.is_whitespace() && !quoted {
                break;
            }
            arg.push(c);
            i += 1;
        }
        out.push(arg);
    }
    out
}

/// Windows のパスの最後の部品（`\` と `/` の両方で区切る）
pub fn win_basename(p: &str) -> &str {
    p.rsplit(['\\', '/']).next().unwrap_or(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(id: u32, data: &[(&str, &str)]) -> String {
        let mut s = format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
             <Provider Name='Microsoft-Windows-Sysmon' Guid='{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}'/>\
             <EventID>{id}</EventID><Version>5</Version><Computer>TESTHOST</Computer></System><EventData>"
        );
        for (k, v) in data {
            if v.is_empty() {
                s.push_str(&format!("<Data Name='{k}'/>"));
            } else {
                s.push_str(&format!("<Data Name='{k}'>{v}</Data>"));
            }
        }
        s.push_str("</EventData></Event>");
        s
    }

    #[test]
    fn process_create() {
        let x = ev(
            1,
            &[
                ("RuleName", "-"),
                ("UtcTime", "2026-11-19 03:14:00.123"),
                ("ProcessGuid", "{a1b2c3d4-0000-1111-2222-333344445555}"),
                ("ProcessId", "4242"),
                ("Image", r"C:\Users\u\AppData\Local\Temp\x.exe"),
                ("CommandLine", r#""C:\Users\u\AppData\Local\Temp\x.exe" -k &quot;a b&quot; &amp;"#),
                ("User", r"PC\u"),
                (
                    "Hashes",
                    "SHA1=AA,MD5=BB,SHA256=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF,IMPHASH=CC",
                ),
                ("ParentProcessGuid", "{p}"),
                ("ParentProcessId", "100"),
                ("ParentImage", r"C:\Windows\explorer.exe"),
            ],
        );
        let SysmonEvent::ProcessCreate(p) = parse_event(&x).unwrap() else { panic!() };
        assert_eq!(p.pid, 4242);
        assert_eq!(p.parent_pid, Some(100));
        assert_eq!(p.image, r"C:\Users\u\AppData\Local\Temp\x.exe");
        assert_eq!(p.command_line, r#""C:\Users\u\AppData\Local\Temp\x.exe" -k "a b" &"#);
        assert_eq!(p.user.as_deref(), Some(r"PC\u"));
        assert_eq!(p.sha256.as_deref(), Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
        assert_eq!(p.utc, Some(chrono::DateTime::parse_from_rfc3339("2026-11-19T03:14:00Z").unwrap().timestamp()));
    }

    #[test]
    fn network_connect() {
        let x = ev(
            3,
            &[
                ("ProcessId", "4242"),
                ("Image", r"C:\x.exe"),
                ("Protocol", "tcp"),
                ("Initiated", "true"),
                ("SourceIsIpv6", "false"),
                ("SourceIp", "127.0.0.1"),
                ("SourcePort", "50753"),
                ("DestinationIp", "203.0.113.10"),
                ("DestinationHostname", "-"),
                ("DestinationPort", "443"),
            ],
        );
        let SysmonEvent::NetworkConnect(c) = parse_event(&x).unwrap() else { panic!() };
        assert!(c.initiated);
        assert_eq!(c.dst_ip.to_string(), "203.0.113.10");
        assert_eq!((c.src_port, c.dst_port), (50753, 443));
        // 宛先が壊れていれば捨てる
        let bad = ev(
            3,
            &[
                ("ProcessId", "1"),
                ("SourceIp", "x"),
                ("SourcePort", "1"),
                ("DestinationIp", "y"),
                ("DestinationPort", "2"),
            ],
        );
        assert_eq!(parse_event(&bad), None);
    }

    #[test]
    fn dns_query() {
        let x = ev(
            22,
            &[
                ("ProcessId", "77"),
                ("QueryName", "Example.COM."),
                ("QueryStatus", "0"),
                ("QueryResults", "type:  5 edge.example.net;::ffff:203.0.113.10;2001:db8::1;::ffff:203.0.113.10;"),
                ("Image", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            ],
        );
        let SysmonEvent::DnsQuery(d) = parse_event(&x).unwrap() else { panic!() };
        assert_eq!(d.name, "example.com");
        assert_eq!(d.ips.iter().map(|i| i.to_string()).collect::<Vec<_>>(), vec!["203.0.113.10", "2001:db8::1"]);
        assert_eq!(d.cnames, vec!["edge.example.net"]);
    }

    #[test]
    fn other_ids_and_garbage() {
        assert!(matches!(
            parse_event(&ev(5, &[("ProcessId", "9")])),
            Some(SysmonEvent::ProcessTerminate { pid: 9, .. })
        ));
        let r = parse_event(&ev(
            13,
            &[("EventType", "SetValue"), ("TargetObject", r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run\x")],
        ));
        assert!(matches!(r, Some(SysmonEvent::Registry { .. })));
        assert_eq!(parse_event(&ev(7, &[("ProcessId", "1")])), None);
        assert_eq!(parse_event("<Event><EventID>x</EventID></Event>"), None);
        assert_eq!(parse_event("not xml"), None);
        assert_eq!(parse_event(&"a".repeat(MAX_XML + 1)), None);
        // 空の Data 要素
        let (_, f) = parse_fields(&ev(1, &[("RuleName", ""), ("User", "u")])).unwrap();
        assert_eq!(f[0], ("RuleName".into(), String::new()));
    }

    #[test]
    fn unescape() {
        assert_eq!(xml_unescape("a &lt;b&gt; &amp;&amp; &#65;&#x42; &bogus; &"), "a <b> && AB &bogus; &");
    }

    #[test]
    fn command_line_split() {
        let v = split_command_line(r#""C:\Program Files\App\a.exe" -c "x y" z\\"q" "a\"b" C:\dir\ """#);
        assert_eq!(v, vec![r"C:\Program Files\App\a.exe", "-c", "x y", r#"z\q"#, r#"a"b"#, r"C:\dir\", ""]);
        assert_eq!(split_command_line(r"powershell.exe -enc AAAA"), vec!["powershell.exe", "-enc", "AAAA"]);
        assert!(split_command_line("   ").is_empty());
    }

    #[test]
    fn basename() {
        assert_eq!(win_basename(r"C:\Windows\System32\cmd.exe"), "cmd.exe");
        assert_eq!(win_basename("cmd.exe"), "cmd.exe");
    }
}
