//! ビーコン周期性スコア（設計書 §9.2、RITA の考え方を簡略化）。
//!
//! beacon = 0.35·s_ts + 0.15·s_skew + 0.25·s_ds + 0.25·s_cov
//! 送信バイト数が取れない場合（第1弾のポーリング収集）は s_ds を除いて重みを按分する。

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BeaconScore {
    pub n: usize,
    pub median_interval_s: f64,
    pub mad_s: f64,
    pub bowley: f64,
    pub s_ts: f64,
    pub s_skew: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s_ds: Option<f64>,
    pub s_cov: f64,
    pub score: f64,
}

pub const MIN_POINTS: usize = 6;

fn median(sorted: &[f64]) -> f64 {
    let n = sorted.len();
    if n == 0 {
        return 0.0;
    }
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    }
}

/// 線形補間の分位点（sorted 前提）
fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let pos = q * (sorted.len() - 1) as f64;
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo as f64)
}

fn sort(v: &mut [f64]) {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
}

/// 規則性 1 − min(1, MAD/median)
fn regularity(values: &[f64]) -> (f64, f64, f64) {
    let mut s = values.to_vec();
    sort(&mut s);
    let med = median(&s);
    let mut dev: Vec<f64> = s.iter().map(|x| (x - med).abs()).collect();
    sort(&mut dev);
    let mad = median(&dev);
    let score = if med <= 0.0 { 0.0 } else { 1.0 - (mad / med).min(1.0) };
    (score, med, mad)
}

fn bowley(values: &[f64]) -> f64 {
    let mut s = values.to_vec();
    sort(&mut s);
    let (q1, q2, q3) = (quantile(&s, 0.25), quantile(&s, 0.5), quantile(&s, 0.75));
    if (q3 - q1).abs() < f64::EPSILON {
        0.0
    } else {
        ((q3 + q1 - 2.0 * q2) / (q3 - q1)).clamp(-1.0, 1.0)
    }
}

/// `starts`：接続開始時刻（UNIX 秒）。`bytes`：各接続の送信バイト（不明なら None）。
/// `window_s`：観測窓の長さ（通常 24h。監視開始から 24h 未満ならその経過時間）。
pub fn score(starts: &[f64], bytes: Option<&[f64]>, window_s: f64) -> Option<BeaconScore> {
    if starts.len() < MIN_POINTS {
        return None;
    }
    let mut t = starts.to_vec();
    sort(&mut t);
    let deltas: Vec<f64> = t.windows(2).map(|w| w[1] - w[0]).filter(|d| *d > 0.0).collect();
    if deltas.len() < MIN_POINTS - 1 {
        return None;
    }
    let (s_ts, med, mad) = regularity(&deltas);
    let b = bowley(&deltas);
    let s_skew = 1.0 - b.abs();

    let s_ds = bytes.filter(|b| b.len() >= MIN_POINTS).map(|b| regularity(b).0);

    // 継続性：観測窓を 1 時間単位に切り、接続があった時間帯の割合
    let hours = (window_s / 3600.0).ceil().max(1.0) as usize;
    let end = t[t.len() - 1] + 1e-6;
    let start = end - hours as f64 * 3600.0;
    let mut seen = vec![false; hours];
    for x in &t {
        if *x >= start {
            let idx = (((x - start) / 3600.0) as usize).min(hours - 1);
            seen[idx] = true;
        }
    }
    let s_cov = seen.iter().filter(|x| **x).count() as f64 / hours as f64;

    let score = match s_ds {
        Some(ds) => 0.35 * s_ts + 0.15 * s_skew + 0.25 * ds + 0.25 * s_cov,
        None => (0.35 * s_ts + 0.15 * s_skew + 0.25 * s_cov) / 0.75,
    };
    Some(BeaconScore {
        n: t.len(),
        median_interval_s: med,
        mad_s: mad,
        bowley: b,
        s_ts,
        s_skew,
        s_ds,
        s_cov,
        score: (score * 1000.0).round() / 1000.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 決定的な疑似乱数（テスト用）
    fn lcg(seed: &mut u64) -> f64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((*seed >> 33) as f64) / ((1u64 << 31) as f64)
    }

    #[test]
    fn fixed_interval_is_high() {
        // 60 秒ごと 3 時間、窓 3 時間
        let t: Vec<f64> = (0..180).map(|i| 1_000_000.0 + i as f64 * 60.0).collect();
        let s = score(&t, None, 3.0 * 3600.0).unwrap();
        assert!(s.score >= 0.95, "{s:?}");
    }

    #[test]
    fn jittered_beacon_is_medium_or_high() {
        // 設計書 §21 のジッタ版：sleep 45〜75 秒
        let mut seed = 42;
        let mut x = 1_000_000.0;
        let mut t = vec![];
        for _ in 0..200 {
            t.push(x);
            x += 45.0 + 30.0 * lcg(&mut seed);
        }
        let s = score(&t, None, 3.0 * 3600.0).unwrap();
        assert!(s.score >= 0.6, "{s:?}");
    }

    #[test]
    fn human_browsing_is_low() {
        // 人間らしい不規則（指数分布に近い間隔、ところどころ長い空白）
        let mut seed = 7;
        let mut x = 1_000_000.0;
        let mut t = vec![];
        for i in 0..60 {
            t.push(x);
            let u = lcg(&mut seed).max(1e-6);
            x += -300.0 * u.ln() + if i % 9 == 0 { 3600.0 } else { 0.0 };
        }
        let s = score(&t, None, 24.0 * 3600.0).unwrap();
        assert!(s.score < 0.6, "{s:?}");
    }

    #[test]
    fn too_few_points() {
        assert!(score(&[1.0, 2.0, 3.0], None, 3600.0).is_none());
    }
}
