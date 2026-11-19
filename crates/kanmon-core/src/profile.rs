//! プロセスごとの「いつもの形」（設計書 §9.6）。いつもと違う動きに点数を付けるための判定（純関数）。
//!
//! - 「初めて」だけでは誤検知が多い（更新のたびに宛先が変わるアプリ、毎日新しいサイトへ行くブラウザ）。
//!   そこで、**形が安定しているプロセス**で違いが出たときだけを「いつもと違う」とする
//! - 安定：観測を始めてから `min_age` 以上たち、知っている項目が `max_items` 以下で、
//!   最後に新しい項目が増えてから `quiet` 以上たっている
//! - 見る形：宛先（登録ドメイン）、動く時間帯、親 → 子（どの親がどの子を起動して通信したか）、送信量
//! - 宛先の国・ネットワーク（ASN）は、地理情報のデータを持たないので見ない【要検討】
//! - 違いだけでは通知に届かない点数にし（10〜25 点）、他の怪しい特徴と重なったときに届くようにする

/// ある種類の項目（宛先・時間帯・子）の集計
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Stats {
    /// 知っている項目の数
    pub known: i64,
    /// 一番古い項目を初めて見た時刻（UNIX 秒）
    pub oldest: Option<i64>,
    /// 一番新しい項目を初めて見た時刻（UNIX 秒）
    pub newest: Option<i64>,
}

/// 形が安定しているか。`age_s` はプロセス（または親）を観測してからの秒数
pub fn stable(age_s: i64, st: &Stats, now: i64, min_age_s: i64, quiet_s: i64, max_items: i64) -> bool {
    age_s >= min_age_s && st.known > 0 && st.known <= max_items && st.newest.is_some_and(|n| now - n >= quiet_s)
}

/// 送信量の倍率：今回の送信量 ÷ これまでの最大（無ければ報告の下限）
pub fn volume_ratio(out: u64, prev_max: Option<u64>, floor: u64) -> f64 {
    let base = prev_max.unwrap_or(0).max(floor).max(1);
    ((out as f64 / base as f64) * 100.0).round() / 100.0
}

/// 何日たったか（小数 1 桁）
pub fn days(s: i64) -> f64 {
    ((s.max(0) as f64 / 86_400.0) * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;
    const D: i64 = 86_400;

    #[test]
    fn stability() {
        let now = 100 * D;
        let st = Stats { known: 3, oldest: Some(now - 10 * D), newest: Some(now - 5 * D) };
        // 10 日見ていて、5 日間新しい宛先が無く、3 つだけ → 安定
        assert!(stable(10 * D, &st, now, 3 * D, 2 * D, 30));
        // 観測が短い
        assert!(!stable(2 * D, &st, now, 3 * D, 2 * D, 30));
        // 最近も新しい宛先が増えている（ブラウザ等）
        let busy = Stats { newest: Some(now - 3600), ..st };
        assert!(!stable(10 * D, &busy, now, 3 * D, 2 * D, 30));
        // 宛先が多すぎる
        let many = Stats { known: 200, ..st };
        assert!(!stable(10 * D, &many, now, 3 * D, 2 * D, 30));
        // 何も知らない
        assert!(!stable(10 * D, &Stats::default(), now, 3 * D, 2 * D, 30));
    }

    #[test]
    fn volume() {
        assert_eq!(volume_ratio(50 << 20, Some(2 << 20), 1 << 20), 25.0);
        // これまでの記録が無ければ、報告の下限（1MB）と比べる
        assert_eq!(volume_ratio(20 << 20, None, 1 << 20), 20.0);
        assert_eq!(volume_ratio(1, Some(0), 0), 1.0);
        assert_eq!(days(36 * 3600), 1.5);
    }
}
