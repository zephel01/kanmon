//! kanmond の動作ログ（`logln!`）の出し先。設定 `[log] path` があればそのファイルに書き、
//! 日付が変わったら `kanmond.YYYY-MM-DD.log` に切り替える（`keep_days` 日を過ぎたら消す）。
//! 無ければ標準エラー（Linux の systemd では journald に入る）。

use kanmon_core::rotate::DailyFile;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

static LOG: OnceLock<Mutex<DailyFile>> = OnceLock::new();

/// ログファイルを開く（1 回だけ）。1 ファイルの上限は 50MB（超えたら同じ日の番号付きに切り替え）
pub fn init(path: &Path, keep_days: u32) -> std::io::Result<()> {
    let today = chrono::Local::now().date_naive();
    let f = DailyFile::open(path, keep_days, 50 * 1024 * 1024, today)?;
    let _ = LOG.set(Mutex::new(f));
    Ok(())
}

/// 1 行書く。ファイルに書けなければ標準エラーへ
pub fn write_line(line: &str) {
    if let Some(m) = LOG.get() {
        if let Ok(mut f) = m.lock() {
            let mut s = line.to_string();
            s.push('\n');
            if f.write_at(s.as_bytes(), chrono::Local::now().date_naive()).is_ok() {
                return;
            }
        }
    }
    eprintln!("{line}");
}
