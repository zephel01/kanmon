//! 日付ごとのファイルの切り替え（`kanmond.log` と `events.jsonl` の daily）。
//!
//! 書いている最中のファイルは常に元の名前（例 `kanmond.log`）。日付が変わったら
//! `kanmond.2026-11-18.log` のように日付を入れた名前に変え、新しいファイルを開く。
//! 同じ日にサイズの上限を超えた場合は `events.2026-11-18.1.jsonl`・`.2` と番号を足す。
//! 残す日数を過ぎたものは消す。

use chrono::NaiveDate;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// `dir/stem.ext` → `dir/stem.YYYY-MM-DD[.n].ext`
pub fn dated_path(path: &Path, date: NaiveDate, n: usize) -> PathBuf {
    let dir = path.parent().unwrap_or(Path::new("."));
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("log");
    let ext = path.extension().and_then(|s| s.to_str());
    let mut name = format!("{stem}.{}", date.format("%Y-%m-%d"));
    if n > 0 {
        name.push_str(&format!(".{n}"));
    }
    if let Some(e) = ext {
        name.push('.');
        name.push_str(e);
    }
    dir.join(name)
}

/// 同じディレクトリにある `stem.YYYY-MM-DD[.n].ext` の日付（それ以外は None）
pub fn date_of(path: &Path, base: &Path) -> Option<NaiveDate> {
    let stem = base.file_stem()?.to_str()?;
    let ext = base.extension().and_then(|s| s.to_str());
    let name = path.file_name()?.to_str()?;
    let rest = name.strip_prefix(stem)?.strip_prefix('.')?;
    let rest = match ext {
        Some(e) => rest.strip_suffix(e)?.strip_suffix('.')?,
        None => rest,
    };
    let date = rest.split('.').next()?;
    let tail = &rest[date.len()..];
    if !(tail.is_empty() || tail.strip_prefix('.').is_some_and(|n| n.chars().all(|c| c.is_ascii_digit()))) {
        return None;
    }
    NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()
}

/// 日付を入れた名前のうち、`keep_days` 日より前のものを消す。消した数を返す
pub fn cleanup(base: &Path, today: NaiveDate, keep_days: u32) -> usize {
    let dir = base.parent().unwrap_or(Path::new("."));
    let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
    let limit = today - chrono::Duration::days(keep_days.max(1) as i64);
    let mut n = 0;
    for e in rd.flatten() {
        let p = e.path();
        if date_of(&p, base).is_some_and(|d| d <= limit) && std::fs::remove_file(&p).is_ok() {
            n += 1;
        }
    }
    n
}

/// 空いている番号の付いた名前（同じ日に 2 回以上切り替えたとき）
pub fn free_dated_path(path: &Path, date: NaiveDate) -> PathBuf {
    (0..10_000).map(|n| dated_path(path, date, n)).find(|p| !p.exists()).unwrap_or_else(|| dated_path(path, date, 0))
}

fn open_append(path: &Path) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o640);
    }
    o.open(path)
}

/// 日付が変わったら切り替えるファイル。`max_bytes` を超えたときも同じ日の番号付きに切り替える
pub struct DailyFile {
    path: PathBuf,
    keep_days: u32,
    max_bytes: u64,
    file: File,
    date: NaiveDate,
    size: u64,
}

impl DailyFile {
    /// `today` は呼び出し側が渡す（テストのため）。既存のファイルが前の日のものなら、先に切り替える
    pub fn open(path: &Path, keep_days: u32, max_bytes: u64, today: NaiveDate) -> std::io::Result<Self> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        if let Ok(md) = std::fs::metadata(path) {
            let mdate =
                md.modified().ok().map(|t| chrono::DateTime::<chrono::Local>::from(t).date_naive()).unwrap_or(today);
            if mdate < today && md.len() > 0 {
                std::fs::rename(path, free_dated_path(path, mdate))?;
            }
        }
        let file = open_append(path)?;
        let size = file.metadata()?.len();
        cleanup(path, today, keep_days);
        Ok(Self { path: path.to_path_buf(), keep_days, max_bytes, file, date: today, size })
    }

    pub fn write_at(&mut self, data: &[u8], today: NaiveDate) -> std::io::Result<()> {
        if today != self.date {
            self.rotate(self.date)?;
            self.date = today;
            cleanup(&self.path, today, self.keep_days);
        } else if self.max_bytes > 0 && self.size > 0 && self.size + data.len() as u64 > self.max_bytes {
            self.rotate(today)?;
        }
        self.file.write_all(data)?;
        self.size += data.len() as u64;
        Ok(())
    }

    fn rotate(&mut self, date: NaiveDate) -> std::io::Result<()> {
        self.file.flush()?;
        std::fs::rename(&self.path, free_dated_path(&self.path, date))?;
        self.file = open_append(&self.path)?;
        self.size = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn names() {
        let p = Path::new("/var/log/kanmon/kanmond.log");
        assert_eq!(dated_path(p, d("2026-11-18"), 0), Path::new("/var/log/kanmon/kanmond.2026-11-18.log"));
        assert_eq!(dated_path(p, d("2026-11-18"), 2), Path::new("/var/log/kanmon/kanmond.2026-11-18.2.log"));
        assert_eq!(date_of(Path::new("/var/log/kanmon/kanmond.2026-11-18.2.log"), p), Some(d("2026-11-18")));
        assert_eq!(date_of(Path::new("/var/log/kanmon/kanmond.log"), p), None);
        assert_eq!(date_of(Path::new("/var/log/kanmon/other.2026-11-18.log"), p), None);
        assert_eq!(date_of(Path::new("/var/log/kanmon/kanmond.2026-11-18.x.log"), p), None);
        let j = Path::new("/l/events.jsonl");
        assert_eq!(date_of(Path::new("/l/events.2026-11-01.jsonl"), j), Some(d("2026-11-01")));
        assert_eq!(date_of(Path::new("/l/events.jsonl.1"), j), None);
    }

    #[test]
    fn rotates_by_day_and_size_and_cleans_up() {
        let dir = std::env::temp_dir().join(format!("kanmon-rotate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("kanmond.log");
        // 古い日付のファイル（残す日数を過ぎたもの・過ぎていないもの）
        std::fs::write(dated_path(&p, d("2026-10-01"), 0), "old").unwrap();
        std::fs::write(dated_path(&p, d("2026-11-10"), 0), "keep").unwrap();
        let mut f = DailyFile::open(&p, 14, 30, d("2026-11-17")).unwrap();
        assert!(!dated_path(&p, d("2026-10-01"), 0).exists(), "14 日より前は消える");
        assert!(dated_path(&p, d("2026-11-10"), 0).exists());
        f.write_at(b"0123456789\n", d("2026-11-17")).unwrap();
        f.write_at(b"0123456789\n", d("2026-11-17")).unwrap();
        // 30 バイトを超えるので同じ日の番号付きへ
        f.write_at(b"0123456789\n", d("2026-11-17")).unwrap();
        assert!(dated_path(&p, d("2026-11-17"), 0).exists());
        // 日付が変わった
        f.write_at(b"next day\n", d("2026-11-18")).unwrap();
        assert!(dated_path(&p, d("2026-11-17"), 1).exists());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "next day\n");
        std::fs::remove_dir_all(&dir).ok();
    }
}
