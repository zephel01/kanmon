//! kanmond — kanmon 監視デーモン（第1弾：ポーリング収集・遮断なし）
//!
//! 使い方：
//!   sudo kanmond --config /etc/kanmon/kanmon.toml
//!   kanmond --config ./dev.toml --print          # イベントを標準出力にも出す
//!   kanmond --config ./dev.toml --once --print   # 1 回だけ収集して終了（動作確認用）

mod config;
mod feeds;
mod identity;
mod monitor;
mod notify;
mod procinfo;
mod sockets;

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
}

fn main() -> anyhow::Result<()> {
    let a = Args::parse();
    let cfg = config::Config::load(a.config.as_deref())?;
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("kanmond: root 以外で実行中です。他ユーザーのプロセスは帰属・識別できません");
    }
    let mut m = monitor::Monitor::new(cfg)?;
    m.print = a.print;
    if a.once {
        let n = m.tick()?;
        eprintln!("kanmond: {n} 件を記録");
        if a.beacon_now {
            let b = m.beacon_batch()?;
            eprintln!("kanmond: ビーコン報告 {b} 件");
        }
        // 通知スレッドが送り終えるのを少し待つ
        std::thread::sleep(std::time::Duration::from_millis(300));
        return Ok(());
    }
    m.run()
}
