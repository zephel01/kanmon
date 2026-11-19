//! kanmond — kanmon 監視デーモン（第1弾：ポーリング収集・遮断なし）
//!
//! 使い方：
//!   sudo kanmond --config /etc/kanmon/kanmon.toml
//!   kanmond --config ./dev.toml --print          # イベントを標準出力にも出す
//!   kanmond --config ./dev.toml --once --print   # 1 回だけ収集して終了（動作確認用）

/// kanmond のログ 1 行（先頭に時刻を付ける）
#[macro_export]
macro_rules! logln {
    ($($a:tt)*) => {
        $crate::logfile::write_line(&format!(
            "{} kanmond: {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            format_args!($($a)*)
        ))
    };
}

mod asndata;
mod capture;
mod config;
mod dnswatch;
mod feeds;
mod identity;
mod logfile;
mod monitor;
mod notify;
mod persistwatch;
mod procinfo;
mod sockets;
mod status;
mod volume;

use clap::Parser;

#[derive(Parser)]
#[command(version, about = "kanmon 監視デーモン（第1弾：監視のみ）")]
struct Args {
    /// 設定ファイル（TOML）。省略時は既定値
    #[arg(long, short)]
    config: Option<std::path::PathBuf>,
    /// 1 回だけ収集して終了
    #[arg(long)]
    once: bool,
    /// イベント JSON を標準出力にも出す
    #[arg(long)]
    print: bool,
    /// --once のとき、終了前にビーコン集計も実行
    #[arg(long)]
    beacon_now: bool,
    /// --once のとき、収集前に待つミリ秒（DNS・SNI の観測を取り込むため）
    #[arg(long, default_value_t = 0)]
    wait_ms: u64,
}

fn main() -> anyhow::Result<()> {
    let a = Args::parse();
    let cfg = config::Config::load(a.config.as_deref())?;
    if !cfg.log.path.as_os_str().is_empty() {
        if let Err(e) = logfile::init(&cfg.log.path, cfg.log.keep_days) {
            eprintln!("kanmond: ログファイル {} を開けません（標準エラーに出します）: {e}", cfg.log.path.display());
        }
    }
    if unsafe { libc::geteuid() } != 0 {
        logln!("root 以外で実行中です。他ユーザーのプロセスは帰属・識別できません");
    }
    let mut m = monitor::Monitor::new(cfg)?;
    m.print = a.print;
    if a.once {
        // DNS・SNI の観測を少し待ってから 1 回だけ収集する（--once のとき）
        std::thread::sleep(std::time::Duration::from_millis(a.wait_ms));
        let n = m.tick()?;
        logln!("{n} 件を記録");
        if a.beacon_now {
            let b = m.beacon_batch()?;
            logln!("ビーコン報告 {b} 件");
        }
        // 通知スレッドが送り終えるのを少し待つ
        std::thread::sleep(std::time::Duration::from_millis(300));
        return Ok(());
    }
    m.run()
}
