//! JSONL 追記（サイズでローテーション：events.jsonl → events.jsonl.1 → … → .N）。

use anyhow::Result;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct JsonlWriter {
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
        Ok(Self { path: path.to_path_buf(), max_bytes, keep: keep.max(1), file, size })
    }

    pub fn write(&mut self, v: &serde_json::Value) -> Result<()> {
        let mut line = serde_json::to_string(v)?;
        line.push('\n');
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
