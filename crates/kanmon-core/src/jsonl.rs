//! JSONL 追記。切り替えは 2 通り：
//! - サイズごと（既定）：events.jsonl → events.jsonl.1 → … → .N
//! - 日付ごと（`daily`）：日付が変わったら events.YYYY-MM-DD.jsonl に名前を変え、残す日数を過ぎたら消す。
//!   同じ日にサイズの上限を超えたら events.YYYY-MM-DD.1.jsonl …

use anyhow::Result;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct JsonlWriter {
    daily: Option<crate::rotate::DailyFile>,
    path: PathBuf,
    max_bytes: u64,
    keep: usize,
    file: File,
    size: u64,
}

fn open(path: &Path) -> Result<File> {
    let mut o = OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o640);
    }
    Ok(o.open(path)?)
}

impl JsonlWriter {
    pub fn open(path: &Path, max_bytes: u64, keep: usize) -> Result<Self> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let file = open(path)?;
        let size = file.metadata()?.len();
        Ok(Self { daily: None, path: path.to_path_buf(), max_bytes, keep: keep.max(1), file, size })
    }

    /// 日付ごとに切り替える。`keep_days` 日より前のものは消す
    pub fn open_daily(path: &Path, max_bytes: u64, keep_days: u32) -> Result<Self> {
        let today = chrono::Local::now().date_naive();
        let daily = crate::rotate::DailyFile::open(path, keep_days, max_bytes, today)?;
        let file = open(path)?;
        Ok(Self { daily: Some(daily), path: path.to_path_buf(), max_bytes, keep: 1, file, size: 0 })
    }

    pub fn write(&mut self, v: &serde_json::Value) -> Result<()> {
        let mut line = serde_json::to_string(v)?;
        line.push('\n');
        if let Some(d) = self.daily.as_mut() {
            d.write_at(line.as_bytes(), chrono::Local::now().date_naive())?;
            return Ok(());
        }
        if self.size + line.len() as u64 > self.max_bytes && self.size > 0 {
            self.rotate()?;
        }
        self.file.write_all(line.as_bytes())?;
        self.size += line.len() as u64;
        Ok(())
    }

    fn rotate(&mut self) -> Result<()> {
        self.file.flush()?;
        for i in (1..self.keep).rev() {
            let from = self.path.with_extension(format!("jsonl.{i}"));
            if from.exists() {
                std::fs::rename(&from, self.path.with_extension(format!("jsonl.{}", i + 1)))?;
            }
        }
        std::fs::rename(&self.path, self.path.with_extension("jsonl.1"))?;
        self.file = open(&self.path)?;
        self.size = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates() {
        let d = std::env::temp_dir().join(format!("kanmon-jsonl-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("events.jsonl");
        let mut w = JsonlWriter::open(&p, 100, 3).unwrap();
        for i in 0..20 {
            w.write(&serde_json::json!({"i": i, "pad": "xxxxxxxxxxxxxxxxxxxx"})).unwrap();
        }
        assert!(p.exists());
        assert!(d.join("events.jsonl.1").exists());
        assert!(d.join("events.jsonl.3").exists());
        assert!(!d.join("events.jsonl.4").exists());
        std::fs::remove_dir_all(&d).ok();
    }
}
