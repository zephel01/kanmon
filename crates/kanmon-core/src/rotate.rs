//! 日付ごとのファイルの切り替え（`kanmond.log` と `events.jsonl` の daily）。
//!
//! 書いている最中のファイルは常に元の名前（例 `kanmond.log`）。日付が変わったら
//! `kanmond.2026-11-18.log` のように日付を入れた名前に変え、新しいファイルを開く。
//! 同じ日にサイズの上限を超えた場合は `events.2026-11-18.1.jsonl`・`.2` と番号を足す。
//! 残す日数を過ぎたものは消す。
//!
//! 圧縮（`compress`）を有効にすると、切り替えた前の日のファイルを裏のスレッドで
//! `events.2026-11-18.jsonl.gz` のように gzip にする。`.gz.tmp` に書き終えてから名前を変え、
//! その後で元のファイルを消すので、途中で止まっても元のファイルか完成した `.gz` のどちらかが残る。
//! 起動時には、圧縮されずに残った日付付きのファイル（途中で止まった分・設定を切り替えた分）も圧縮する。

use chrono::NaiveDate;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// 圧縮を 1 つずつ行うためのロック（同じファイルを 2 つのスレッドで圧縮しない）
static GZIP_LOCK: Mutex<()> = Mutex::new(());

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

/// 同じディレクトリにある `stem.YYYY-MM-DD[.n].ext[.gz]` の日付（それ以外は None）
pub fn date_of(path: &Path, base: &Path) -> Option<NaiveDate> {
    dated_parts(path, base).map(|(d, _)| d)
}

/// `stem.YYYY-MM-DD[.n].ext[.gz]` の日付と番号（番号なしは 0）
fn dated_parts(path: &Path, base: &Path) -> Option<(NaiveDate, usize)> {
    let stem = base.file_stem()?.to_str()?;
    let ext = base.extension().and_then(|s| s.to_str());
    let name = path.file_name()?.to_str()?;
    let name = name.strip_suffix(".gz").unwrap_or(name);
    let rest = name.strip_prefix(stem)?.strip_prefix('.')?;
    let rest = match ext {
        Some(e) => rest.strip_suffix(e)?.strip_suffix('.')?,
        None => rest,
    };
    let date = rest.split('.').next()?;
    let tail = &rest[date.len()..];
    let n = if tail.is_empty() {
        0
    } else {
        let d = tail.strip_prefix('.')?;
        if d.is_empty() || !d.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        d.parse().ok()?
    };
    Some((NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()?, n))
}

/// `x.jsonl` → `x.jsonl.gz`
fn gz_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".gz");
    PathBuf::from(s)
}

/// ファイルを gzip にして元を消す。`.gz` のパスを返す。元が無ければ何もしない（Ok(None)）。
/// `.gz.tmp` に書いて同期し、名前を変えてから元を消す（途中で止まっても中身は失われない）
pub fn gzip_file(src: &Path) -> std::io::Result<Option<PathBuf>> {
    let _g = GZIP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !src.exists() {
        return Ok(None);
    }
    let dst = gz_path(src);
    if dst.exists() {
        // 名前を変えた後、元を消す前に止まった：.gz は完成している
        std::fs::remove_file(src)?;
        return Ok(Some(dst));
    }
    let mut tmp = dst.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut input = File::open(src)?;
        let out = open_trunc(&tmp)?;
        let mut gz = flate2::write::GzEncoder::new(out, flate2::Compression::default());
        std::io::copy(&mut input, &mut gz)?;
        let out = gz.finish()?;
        out.sync_all()?;
    }
    std::fs::rename(&tmp, &dst)?;
    std::fs::remove_file(src)?;
    Ok(Some(dst))
}

/// 同じディレクトリの、圧縮されていない日付付きのファイルを圧縮する。途中で止まった `.gz.tmp` は消す。
/// 圧縮した数を返す
pub fn compress_pending(base: &Path) -> usize {
    let dir = base.parent().unwrap_or(Path::new("."));
    let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
    let mut todo = vec![];
    for e in rd.flatten() {
        let p = e.path();
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else { continue };
        if let Some(orig) = name.strip_suffix(".gz.tmp") {
            if date_of(&dir.join(orig), base).is_some() {
                let _ = std::fs::remove_file(&p);
            }
            continue;
        }
        if !name.ends_with(".gz") && date_of(&p, base).is_some() {
            todo.push(p);
        }
    }
    todo.sort();
    todo.iter().filter(|p| gzip_file(p).ok().flatten().is_some()).count()
}

fn spawn_compress_pending(base: &Path) {
    let base = base.to_path_buf();
    let _ = std::thread::Builder::new().name("kanmon-gzip".into()).spawn(move || {
        compress_pending(&base);
    });
}

/// 読み込み用に開く。名前が `.gz` で終わるものは展開しながら読む
pub fn open_reader(path: &Path) -> std::io::Result<Box<dyn BufRead>> {
    let f = File::open(path)?;
    if path.extension().is_some_and(|e| e == "gz") {
        Ok(Box::new(BufReader::new(flate2::read::MultiGzDecoder::new(f))))
    } else {
        Ok(Box::new(BufReader::new(f)))
    }
}

/// `since` 以降のログのファイルを古い順に並べる：日付付き（`.gz` を含む）→ サイズごとの `.N`（大きい番号から）→ 書いている最中のファイル
pub fn files_since(base: &Path, since: NaiveDate) -> Vec<PathBuf> {
    let dir = base.parent().unwrap_or(Path::new("."));
    let mut dated = vec![];
    let mut numbered = vec![];
    if let Ok(rd) = std::fs::read_dir(dir) {
        let base_name = base.file_name().and_then(|n| n.to_str()).unwrap_or("");
        for e in rd.flatten() {
            let p = e.path();
            let Some(name) = p.file_name().and_then(|n| n.to_str()) else { continue };
            if name.ends_with(".tmp") {
                continue;
            }
            if let Some((d, n)) = dated_parts(&p, base) {
                // 圧縮が名前を変え終えて元を消す直前：同じ中身の .gz があるので元は読まない
                if !name.ends_with(".gz") && gz_path(&p).exists() {
                    continue;
                }
                if d >= since {
                    dated.push((d, n, p));
                }
            } else if let Some(n) = name.strip_prefix(base_name).and_then(|r| r.strip_prefix('.')) {
                if let Ok(n) = n.parse::<usize>() {
                    numbered.push((n, p));
                }
            }
        }
    }
    dated.sort();
    numbered.sort_by_key(|x| std::cmp::Reverse(x.0));
    let mut out: Vec<PathBuf> = dated.into_iter().map(|x| x.2).collect();
    out.extend(numbered.into_iter().map(|x| x.1));
    if base.exists() {
        out.push(base.to_path_buf());
    }
    out
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

/// 空いている番号の付いた名前（同じ日に 2 回以上切り替えたとき）。圧縮済みの `.gz` があればその番号も使用済み
pub fn free_dated_path(path: &Path, date: NaiveDate) -> PathBuf {
    (0..10_000)
        .map(|n| dated_path(path, date, n))
        .find(|p| !p.exists() && !gz_path(p).exists())
        .unwrap_or_else(|| dated_path(path, date, 0))
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

fn open_trunc(path: &Path) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.create(true).write(true).truncate(true);
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
    compress: bool,
    file: File,
    date: NaiveDate,
    size: u64,
}

impl DailyFile {
    /// `today` は呼び出し側が渡す（テストのため）。既存のファイルが前の日のものなら、先に切り替える。
    /// `compress` なら切り替えたファイルを裏で gzip にする（起動時に残っていた分も）
    pub fn open(
        path: &Path,
        keep_days: u32,
        max_bytes: u64,
        compress: bool,
        today: NaiveDate,
    ) -> std::io::Result<Self> {
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
        if compress {
            spawn_compress_pending(path);
        }
        Ok(Self { path: path.to_path_buf(), keep_days, max_bytes, compress, file, date: today, size })
    }

    pub fn write_at(&mut self, data: &[u8], today: NaiveDate) -> std::io::Result<()> {
        if today != self.date {
            self.rotate(self.date)?;
            self.date = today;
            cleanup(&self.path, today, self.keep_days);
            if self.compress {
                spawn_compress_pending(&self.path);
            }
        } else if self.max_bytes > 0 && self.size > 0 && self.size + data.len() as u64 > self.max_bytes {
            self.rotate(today)?;
            if self.compress {
                spawn_compress_pending(&self.path);
            }
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
    use std::io::Read;

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
        let mut f = DailyFile::open(&p, 14, 30, false, d("2026-11-17")).unwrap();
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

    #[test]
    fn gz_names_and_listing() {
        let j = Path::new("/l/events.jsonl");
        assert_eq!(date_of(Path::new("/l/events.2026-11-01.jsonl.gz"), j), Some(d("2026-11-01")));
        assert_eq!(date_of(Path::new("/l/events.2026-11-01.3.jsonl.gz"), j), Some(d("2026-11-01")));
        assert_eq!(date_of(Path::new("/l/events.2026-11-01.jsonl.gz.tmp"), j), None);
        assert_eq!(date_of(Path::new("/l/events.2026-11-01..jsonl"), j), None);

        let dir = std::env::temp_dir().join(format!("kanmon-rotate-ls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("events.jsonl");
        for n in [
            "events.2026-11-10.jsonl.gz",
            "events.2026-11-11.1.jsonl.gz",
            "events.2026-11-11.jsonl.gz",
            "events.2026-11-12.jsonl",
            "events.2026-11-09.jsonl.gz",
            "events.jsonl.2",
            "events.jsonl.1",
            "events.jsonl",
            "events.2026-11-12.jsonl.gz.tmp",
            "other.2026-11-12.jsonl",
        ] {
            std::fs::write(dir.join(n), "x").unwrap();
        }
        let got: Vec<String> = files_since(&p, d("2026-11-10"))
            .iter()
            .map(|x| x.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert_eq!(
            got,
            [
                "events.2026-11-10.jsonl.gz",
                "events.2026-11-11.jsonl.gz",
                "events.2026-11-11.1.jsonl.gz",
                "events.2026-11-12.jsonl",
                "events.jsonl.2",
                "events.jsonl.1",
                "events.jsonl"
            ]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn gzip_roundtrip_recovery_and_cleanup() {
        let dir = std::env::temp_dir().join(format!("kanmon-rotate-gz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("events.jsonl");
        let body = "{\"a\":1}\n".repeat(1000);
        // 未圧縮の日付付き・途中で止まった .gz.tmp・名前変更後に元が残ったもの
        std::fs::write(dated_path(&p, d("2026-11-15"), 0), &body).unwrap();
        std::fs::write(gz_path(&dated_path(&p, d("2026-11-15"), 1)).with_extension("gz.tmp"), "broken").unwrap();
        let done = dated_path(&p, d("2026-11-14"), 0);
        std::fs::write(&done, &body).unwrap();
        gzip_file(&done).unwrap();
        std::fs::write(&done, "leftover").unwrap();
        assert_eq!(compress_pending(&p), 2);
        let gz = gz_path(&dated_path(&p, d("2026-11-15"), 0));
        assert!(gz.exists() && !dated_path(&p, d("2026-11-15"), 0).exists());
        assert!(!done.exists(), "完成した .gz があれば元は消すだけ");
        assert!(!gz_path(&dated_path(&p, d("2026-11-15"), 1)).with_extension("gz.tmp").exists());
        let mut text = String::new();
        open_reader(&gz).unwrap().read_to_string(&mut text).unwrap();
        assert_eq!(text, body);
        assert!(std::fs::metadata(&gz).unwrap().len() < body.len() as u64 / 5);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&gz).unwrap().permissions().mode() & 0o777, 0o640);
        }
        // 番号付きの名前は .gz があれば使用済み
        assert_eq!(free_dated_path(&p, d("2026-11-15")), dated_path(&p, d("2026-11-15"), 1));
        // 残す日数を過ぎた .gz も消える
        assert_eq!(cleanup(&p, d("2026-11-29"), 14), 2);
        assert!(!gz.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn daily_file_compresses_previous_day() {
        let dir = std::env::temp_dir().join(format!("kanmon-rotate-dz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("events.jsonl");
        let mut f = DailyFile::open(&p, 14, 0, true, d("2026-11-17")).unwrap();
        f.write_at(b"day1\n", d("2026-11-17")).unwrap();
        f.write_at(b"day2\n", d("2026-11-18")).unwrap();
        let gz = gz_path(&dated_path(&p, d("2026-11-17"), 0));
        for _ in 0..200 {
            if gz.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let mut text = String::new();
        open_reader(&gz).unwrap().read_to_string(&mut text).unwrap();
        assert_eq!(text, "day1\n");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "day2\n");
        std::fs::remove_dir_all(&dir).ok();
    }
}
