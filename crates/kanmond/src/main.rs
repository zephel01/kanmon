//! kanmond — kanmon 監視デーモン（第1弾：ポーリング収集・遮断なし）
//!
//! 使い方：
//!   sudo kanmond --config /etc/kanmon/kanmon.toml
//!   kanmond --config ./dev.toml --print          # イベントを標準出力にも出す
//!   kanmond --config ./dev.toml --once --print   # 1 回だけ収集して終了（動作確認用）
//!   kanmond --service --config C:\ProgramData\kanmon\kanmon.toml   # Windows のサービスとして（SCM から起動）

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

#[cfg_attr(windows, allow(dead_code))]
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
mod sys;
mod volume;
#[cfg(any(windows, test))]
mod winpersist;
#[cfg(windows)]
mod winsvc;
#[cfg(windows)]
mod winsysmon;

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
    /// Windows のサービスとして動く（サービス コントロール マネージャーから起動されたとき）
    #[arg(long)]
    service: bool,
}

/// 設定を読み、ログを開き、監視を用意する（コンソール・サービス共通）
pub(crate) fn start_monitor(config: Option<&std::path::Path>) -> anyhow::Result<monitor::Monitor> {
    let cfg = config::Config::load(config)?;
    if !cfg.log.path.as_os_str().is_empty() {
        if let Err(e) = logfile::init(&cfg.log.path, cfg.log.keep_days) {
            eprintln!("kanmond: ログファイル {} を開けません（標準エラーに出します）: {e}", cfg.log.path.display());
        }
    }
    if !sys::is_root() {
        logln!("管理者以外で実行中です。他ユーザーのプロセスは帰属・識別できません");
    }
    monitor::Monitor::new(cfg)
}

fn main() -> anyhow::Result<()> {
    let a = Args::parse();
    if a.service {
        #[cfg(windows)]
        return winsvc::run(a.config);
        #[cfg(not(windows))]
        anyhow::bail!("--service は Windows だけで使えます");
    }
    let mut m = start_monitor(a.config.as_deref())?;
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
