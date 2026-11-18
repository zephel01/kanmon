//! プロセスごと・宛先ごとの送信量の集計（純関数・時刻は呼び出し側が渡す）。
//!
//! OS から取れるのは「接続ごとの累積送信バイト数」なので、前回との差分を取り、
//! （pid, 宛先 IP）ごとに一定時間の窓で合計する。量だけで判断せず、どのファイルを開いていたか・
//! 宛先・親プロセスと組み合わせる判定は検知ルール（`detections/55-volume.yaml`）で行う。

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};

/// 1 本の接続の累積送信量
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowBytes {
    pub pid: u32,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    /// 接続開始からの累積（Linux は相手が受け取りを確認したバイト数＝tcpi_bytes_acked）
    pub bytes_out: u64,
}

type FlowKey = (u32, SocketAddr, SocketAddr);
type PairKey = (u32, IpAddr);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Due {
    pub pid: u32,
    pub remote: IpAddr,
    /// 窓の中の送信量
    pub bytes: u64,
}

#[derive(Debug, Default)]
pub struct VolumeTracker {
    last: HashMap<FlowKey, u64>,
    samples: HashMap<PairKey, VecDeque<(i64, u64)>>,
    reported: HashMap<PairKey, i64>,
    initialized: bool,
}

impl VolumeTracker {
    /// 今回の累積値を取り込み、差分を窓に足す。
    /// 初回は「起動前からの累積」を数えないよう、基準にするだけ。
    pub fn update(&mut self, flows: &[FlowBytes], now: i64, window_s: i64) {
        let mut seen: HashSet<FlowKey> = HashSet::with_capacity(flows.len());
        for f in flows {
            let k = (f.pid, f.local, f.remote);
            seen.insert(k);
            let delta = match self.last.get(&k) {
                Some(prev) if f.bytes_out >= *prev => f.bytes_out - prev,
                // 減っていたら別の接続（ポートの再利用）とみなす
                Some(_) => f.bytes_out,
                None if self.initialized => f.bytes_out,
                None => 0,
            };
            self.last.insert(k, f.bytes_out);
            if delta > 0 {
                self.samples.entry((f.pid, f.remote.ip())).or_default().push_back((now, delta));
            }
        }
        self.last.retain(|k, _| seen.contains(k));
        self.initialized = true;
        for q in self.samples.values_mut() {
            while q.front().is_some_and(|(t, _)| now - t > window_s) {
                q.pop_front();
            }
        }
        self.samples.retain(|_, q| !q.is_empty());
        self.reported.retain(|_, t| now - *t < 86_400);
    }

    /// 窓の中の合計が `min_bytes` 以上で、前回の報告から `every_s` 以上たったもの
    pub fn due(&mut self, now: i64, min_bytes: u64, every_s: i64) -> Vec<Due> {
        let mut out = vec![];
        for (k, q) in &self.samples {
            let total: u64 = q.iter().map(|(_, b)| *b).sum();
            if total < min_bytes || self.reported.get(k).is_some_and(|t| now - *t < every_s) {
                continue;
            }
            out.push(Due { pid: k.0, remote: k.1, bytes: total });
        }
        for d in &out {
            self.reported.insert((d.pid, d.remote), now);
        }
        out.sort_by_key(|d| std::cmp::Reverse(d.bytes));
        out
    }
}

/// 開いているファイル（パス・容量）から、ルールが使う事実を作る
#[derive(Debug, Clone, Default, PartialEq)]
pub struct OpenSummary {
    /// 容量の大きい順（最大 128 件）
    pub paths: Vec<String>,
    /// 拡張子（小文字、重複なし）
    pub exts: Vec<String>,
    /// 通常ファイルの合計容量
    pub total_size: u64,
    /// 表示用（大きい順に 5 件、「パス (容量)」）
    pub top: Vec<String>,
}

pub fn human_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

pub fn summarize_open(files: &[(String, u64)]) -> OpenSummary {
    let mut v: Vec<&(String, u64)> = files.iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.dedup_by(|a, b| a.0 == b.0);
    let mut exts: Vec<String> = v
        .iter()
        .filter_map(|(p, _)| {
            let name = p.rsplit('/').next()?;
            let (stem, ext) = name.rsplit_once('.')?;
            (!stem.is_empty() && ext.len() <= 16).then(|| ext.to_ascii_lowercase())
        })
        .collect();
    exts.sort();
    exts.dedup();
    OpenSummary {
        paths: v.iter().take(128).map(|(p, _)| p.clone()).collect(),
        exts,
        total_size: v.iter().map(|(_, s)| *s).sum(),
        top: v.iter().take(5).map(|(p, s)| format!("{p} ({})", human_bytes(*s))).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(pid: u32, lport: u16, b: u64) -> FlowBytes {
        FlowBytes {
            pid,
            local: format!("192.0.2.10:{lport}").parse().unwrap(),
            remote: "203.0.113.70:443".parse().unwrap(),
            bytes_out: b,
        }
    }

    #[test]
    fn deltas_windows_and_reporting() {
        let mut t = VolumeTracker::default();
        // 起動時に既にある接続の累積は数えない
        t.update(&[f(1, 5000, 10_000_000)], 0, 600);
        assert!(t.due(0, 1, 60).is_empty());
        // 増えた分と、新しい接続の分を数える
        t.update(&[f(1, 5000, 13_000_000), f(1, 5001, 2_000_000)], 10, 600);
        let d = t.due(10, 4_000_000, 60);
        assert_eq!(d, vec![Due { pid: 1, remote: "203.0.113.70".parse().unwrap(), bytes: 5_000_000 }]);
        // 報告の間隔内は出さない
        t.update(&[f(1, 5000, 20_000_000), f(1, 5001, 2_000_000)], 20, 600);
        assert!(t.due(20, 1, 60).is_empty());
        assert_eq!(t.due(80, 1, 60)[0].bytes, 12_000_000);
        // 窓を過ぎた分は消える
        t.update(&[], 700, 600);
        assert!(t.due(10_000, 1, 60).is_empty());
    }

    #[test]
    fn counter_reset_counts_as_new() {
        let mut t = VolumeTracker::default();
        t.update(&[f(1, 5000, 0)], 0, 600);
        t.update(&[f(1, 5000, 9_000)], 1, 600);
        t.update(&[f(1, 5000, 100)], 2, 600);
        assert_eq!(t.due(2, 1, 60)[0].bytes, 9_100);
    }

    #[test]
    fn open_files_summary() {
        let s = summarize_open(&[
            ("/Users/a/models/llama-8b.Q4_K_M.gguf".into(), 4_900_000_000),
            ("/Users/a/work/.env".into(), 300),
            ("/Users/a/work/.git/objects/pack/pack-1.pack".into(), 52_000_000),
            ("/Users/a/models/llama-8b.Q4_K_M.gguf".into(), 4_900_000_000),
        ]);
        assert_eq!(s.paths.len(), 3);
        assert_eq!(s.paths[0], "/Users/a/models/llama-8b.Q4_K_M.gguf");
        assert_eq!(s.exts, vec!["gguf", "pack"]);
        assert_eq!(s.total_size, 4_952_000_300);
        assert!(s.top[0].ends_with("(4.6 GB)"), "{:?}", s.top);
        assert_eq!(human_bytes(512), "512 B");
    }
}
