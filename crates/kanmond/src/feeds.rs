//! 脅威インテルフィードの取得と読み込み。
//! 取得経路も攻撃面なので：TLS 検証は rustls 既定（無効化しない）、サイズ上限、
//! 1 件も解析できない応答は採用しない（前回分を使い続ける）、一時ファイル→rename で差し替え。

use crate::config::Config;
use anyhow::{bail, Result};
use kanmon_core::intel::Intel;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const MAX_FEED_BYTES: u64 = 20 * 1024 * 1024;

pub fn feed_dir(cfg: &Config) -> PathBuf {
    cfg.data_dir.join("feeds")
}

fn needs_refresh(p: &Path, hours: u32) -> bool {
    match std::fs::metadata(p).and_then(|m| m.modified()) {
        Ok(t) => SystemTime::now().duration_since(t).unwrap_or_default() > Duration::from_secs(hours as u64 * 3600),
        Err(_) => true,
    }
}

fn fetch_one(url: &str, dest: &Path) -> Result<usize> {
    if !url.starts_with("https://") {
        bail!("https 以外のフィードは使いません: {url}");
    }
    let resp = ureq::get(url).timeout(Duration::from_secs(30)).call()?;
    let mut buf = Vec::new();
    resp.into_reader().take(MAX_FEED_BYTES + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_FEED_BYTES {
        bail!("サイズ上限超過");
    }
    let text = String::from_utf8_lossy(&buf);
    let mut probe = Intel::default();
    let st = probe.load_text(&text, "probe");
    if st.total() == 0 {
        bail!("有効な行がありません（形式変更の可能性）");
    }
    let tmp = dest.with_extension("tmp");
    std::fs::write(&tmp, &buf)?;
    std::fs::rename(&tmp, dest)?;
    Ok(st.total())
}

/// 期限切れのフィードを取得（ブロッキング。別スレッドから呼ぶ）
pub fn refresh(cfg: &Config) {
    let dir = feed_dir(cfg);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("kanmond: feeds dir: {e}");
        return;
    }
    for f in cfg.feeds.iter().filter(|f| f.enabled) {
        let dest = dir.join(format!("{}.txt", f.name));
        if !needs_refresh(&dest, cfg.feeds_refresh_hours) {
            continue;
        }
        match fetch_one(&f.url, &dest) {
            Ok(n) => eprintln!("kanmond: feed {} 更新 ({n} 件)", f.name),
            Err(e) => eprintln!("kanmond: feed {} 取得失敗（前回分を継続）: {e}", f.name),
        }
    }
}

/// 保存済みフィードとローカル拒否リストを読み込む
pub fn load(cfg: &Config) -> Intel {
    let mut intel = Intel::default();
    for f in cfg.feeds.iter().filter(|f| f.enabled) {
        let p = feed_dir(cfg).join(format!("{}.txt", f.name));
        if let Ok(t) = std::fs::read_to_string(&p) {
            intel.load_text(&t, &f.name);
        }
    }
    for p in &cfg.local_blocklists {
        if cfg.strict_owner && unsafe { libc::geteuid() } == 0 {
            if let Err(e) = kanmon_core::detect::check_owner(p) {
                if p.exists() {
                    eprintln!("kanmond: 拒否リストを読みません: {e}");
                }
                continue;
            }
        }
        if let Ok(t) = std::fs::read_to_string(p) {
            let name = format!("local:{}", p.file_name().and_then(|s| s.to_str()).unwrap_or("list"));
            intel.load_text(&t, &name);
        }
    }
    intel
}
