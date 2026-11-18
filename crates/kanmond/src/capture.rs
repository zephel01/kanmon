//! DNS 応答と TLS ClientHello（SNI）を受け身で読む（libpcap）。
//!
//! - 読むだけ。パケットの送信・改変はしない。プロミスキャスモードにもしない。
//! - フィルタで「53 番からの応答」と「443 番宛ての TLS ハンドシェイク」だけに絞る。
//!   大きなアップロードの本体（GGUF 等）はフィルタで落ちるので、ユーザー空間には上がらない。
//! - Linux は `any`（全インターフェース）。macOS には `any` が無いので、稼働中のインターフェース
//!   （lo0・en*・utun* 等）を 1 つずつ開き、60 秒ごとに増えたものを足す。
//!   WARP などが 127.0.2.2 等で DNS を受けている場合、アプリ↔ローカルの DNS は lo0 で見える【要検証】。
//! - 解析は kanmon-core の純関数（wire）。ここは取得とスレッドだけ。

use kanmon_core::wire::{self, ClientHello, DnsMessage, Link};
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::SyncSender;

/// キャプチャスレッドから監視ループへ渡す観測
#[derive(Debug, Clone)]
pub enum Obs {
    Dns { server: IpAddr, client: IpAddr, client_port: u16, msg: DnsMessage },
    Sni { local: SocketAddr, remote: SocketAddr, hello: ClientHello },
}

/// BPF フィルタ。IPv4 は TCP ペイロード先頭が 0x16（TLS ハンドシェイク）のものだけ、
/// IPv6 は拡張ヘッダの無い TCP に限って同じ判定をする。
pub const FILTER: &str = "(udp src port 53) or (tcp src port 53) or \
(tcp dst port 443 and ((ip and tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16) or \
(ip6 and ip6[6] = 6 and ip6[(40 + ((ip6[52:1] & 0xf0) >> 2)):1] = 0x16)))";

/// 1 パケットを観測に変える（純粋な変換。テスト可能）
pub fn to_obs(link: Link, data: &[u8]) -> Option<Obs> {
    let seg = wire::parse_frame(link, data)?;
    if seg.sport == 53 {
        let msg = if seg.proto == wire::PROTO_UDP {
            wire::parse_dns(seg.payload)?
        } else {
            wire::parse_dns_tcp(seg.payload)?
        };
        if !msg.response {
            return None;
        }
        return Some(Obs::Dns { server: seg.src, client: seg.dst, client_port: seg.dport, msg });
    }
    if seg.proto == wire::PROTO_TCP && seg.dport == 443 {
        let hello = wire::parse_client_hello(seg.payload)?;
        hello.sni.as_ref()?;
        return Some(Obs::Sni {
            local: SocketAddr::new(seg.src, seg.sport),
            remote: SocketAddr::new(seg.dst, seg.dport),
            hello,
        });
    }
    None
}

#[cfg(feature = "capture")]
mod imp {
    use super::*;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    fn run_one(dev: String, tx: SyncSender<Obs>, active: Arc<Mutex<HashSet<String>>>) {
        let res = (|| -> Result<(), pcap::Error> {
            let mut cap = pcap::Capture::from_device(dev.as_str())?
                .promisc(false)
                .snaplen(4096)
                .timeout(1000)
                .immediate_mode(true)
                .open()?;
            cap.filter(FILTER, true)?;
            let Some(link) = Link::from_dlt(cap.get_datalink().0) else {
                eprintln!("kanmond: {dev} のリンク種別 {:?} は未対応", cap.get_datalink());
                return Ok(());
            };
            loop {
                match cap.next_packet() {
                    Ok(p) => {
                        if let Some(o) = to_obs(link, p.data) {
                            // 監視ループが詰まっているときは捨てる（取得側で溜め込まない）
                            if let Err(std::sync::mpsc::TrySendError::Disconnected(_)) = tx.try_send(o) {
                                return Ok(());
                            }
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => continue,
                    Err(e) => return Err(e),
                }
            }
        })();
        if let Err(e) = res {
            eprintln!("kanmond: {dev} のパケット取得を終了: {e}");
        }
        active.lock().map(|mut a| a.remove(&dev)).ok();
    }

    fn wanted_devices(cfg_ifaces: &[String]) -> Vec<String> {
        if !cfg_ifaces.is_empty() {
            return cfg_ifaces.to_vec();
        }
        if cfg!(target_os = "linux") {
            return vec!["any".into()];
        }
        pcap::Device::list()
            .map(|l| {
                l.into_iter()
                    .filter(|d| d.flags.is_up() && !d.addresses.is_empty())
                    .map(|d| d.name)
                    // 仮想ブリッジ・AirDrop 用などは対象外
                    .filter(|n| !n.starts_with("awdl") && !n.starts_with("llw") && !n.starts_with("ap"))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 取得スレッドを起動する。開けたインターフェース名を返す
    pub fn start(cfg_ifaces: Vec<String>, tx: SyncSender<Obs>) -> Vec<String> {
        // フィルタが通るか先に確かめる（libpcap の版による差を早めに出す）
        if let Ok(dead) = pcap::Capture::dead(pcap::Linktype::ETHERNET) {
            if let Err(e) = dead.compile(FILTER, true) {
                eprintln!("kanmond: BPF フィルタを解釈できません（名前付けを無効化）: {e}");
                return vec![];
            }
        }
        let active: Arc<Mutex<HashSet<String>>> = Arc::default();
        let spawn_new = {
            let active = active.clone();
            let tx = tx.clone();
            let ifaces = cfg_ifaces.clone();
            move || -> Vec<String> {
                let mut started = vec![];
                for dev in wanted_devices(&ifaces) {
                    let is_new = active.lock().map(|mut a| a.insert(dev.clone())).unwrap_or(false);
                    if !is_new {
                        continue;
                    }
                    let (tx, act, d) = (tx.clone(), active.clone(), dev.clone());
                    if std::thread::Builder::new()
                        .name(format!("kanmon-cap-{dev}"))
                        .spawn(move || run_one(d, tx, act))
                        .is_ok()
                    {
                        started.push(dev);
                    }
                }
                started
            }
        };
        let first = spawn_new();
        // macOS は VPN（utun）などが後から増えるので、定期的に足す
        if cfg!(target_os = "macos") && cfg_ifaces.is_empty() {
            let _ = std::thread::Builder::new().name("kanmon-cap-rescan".into()).spawn(move || loop {
                std::thread::sleep(Duration::from_secs(60));
                let s = spawn_new();
                if !s.is_empty() {
                    eprintln!("kanmond: パケット取得を追加: {}", s.join(", "));
                }
            });
        }
        first
    }
}

#[cfg(feature = "capture")]
pub use imp::start;

#[cfg(not(feature = "capture"))]
pub fn start(_cfg_ifaces: Vec<String>, _tx: SyncSender<Obs>) -> Vec<String> {
    eprintln!("kanmond: capture 機能なしでビルドされています（宛先の名前付けは無効）");
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "capture")]
    #[test]
    fn filter_compiles_for_all_link_types() {
        for lt in [
            pcap::Linktype::ETHERNET,
            pcap::Linktype::NULL,
            pcap::Linktype(276),
            pcap::Linktype(113),
            pcap::Linktype(12),
        ] {
            let dead = pcap::Capture::dead(lt).unwrap();
            assert!(dead.compile(FILTER, true).is_ok(), "{lt:?}");
        }
    }

    #[test]
    fn obs_from_packets() {
        // テスト用の組み立ては core 側の関数と同じ形を手で作る
        let dns = {
            // 1 件の A 応答：sni-test.example → 203.0.113.10
            let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
            for l in ["sni-test", "example"] {
                m.push(l.len() as u8);
                m.extend_from_slice(l.as_bytes());
            }
            m.extend_from_slice(&[0, 0, 1, 0, 1, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 10]);
            m
        };
        let mut pkt = vec![0x45, 0];
        pkt.extend_from_slice(&((28 + dns.len()) as u16).to_be_bytes());
        pkt.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0, 198, 51, 100, 53, 192, 0, 2, 10]);
        pkt.extend_from_slice(&53u16.to_be_bytes());
        pkt.extend_from_slice(&40000u16.to_be_bytes());
        pkt.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
        pkt.extend_from_slice(&[0, 0]);
        pkt.extend_from_slice(&dns);
        match to_obs(Link::Raw, &pkt) {
            Some(Obs::Dns { server, client_port, msg, .. }) => {
                assert_eq!(server.to_string(), "198.51.100.53");
                assert_eq!(client_port, 40000);
                assert_eq!(msg.qname.as_deref(), Some("sni-test.example"));
            }
            other => panic!("{other:?}"),
        }
        assert!(to_obs(Link::Raw, &pkt[..10]).is_none());
    }
}
