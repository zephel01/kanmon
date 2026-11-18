//! SQLite 保存（設計書 §12・§18.3）。WAL。

use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::path::Path;

/// (ts, executable, score, signals, "ip:port")
pub type TopEvent = (i64, String, i64, String, String);

pub struct Store {
    conn: Connection,
}

pub struct ProcRow<'a> {
    pub proc_key: &'a str,
    pub executable: Option<&'a str>,
    pub sha256: Option<&'a str>,
    pub sig_status: Option<&'a str>,
    pub team_id: Option<&'a str>,
    pub signing_id: Option<&'a str>,
    pub package: Option<&'a str>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    pub fn open_readonly(path: &Path) -> Result<Self> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        Ok(Self { conn })
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
            CREATE TABLE IF NOT EXISTS processes (
              proc_key TEXT PRIMARY KEY, executable TEXT, sha256 TEXT, sig_status TEXT,
              team_id TEXT, signing_id TEXT, package TEXT, first_seen INTEGER, last_seen INTEGER
            );
            CREATE TABLE IF NOT EXISTS events (
              id TEXT PRIMARY KEY, ts INTEGER, kind TEXT, direction TEXT, proto TEXT,
              proc_key TEXT, pid INTEGER, executable TEXT, rip TEXT, rport INTEGER, lport INTEGER,
              domain TEXT, score INTEGER, level TEXT, signals TEXT, verdict TEXT, json TEXT
            );
            CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
            CREATE INDEX IF NOT EXISTS events_proc_ts ON events(proc_key, ts);
            CREATE TABLE IF NOT EXISTS baselines (
              proc_key TEXT, item TEXT, kind TEXT, first_seen INTEGER, last_seen INTEGER, count INTEGER,
              PRIMARY KEY (proc_key, item, kind)
            );
            CREATE TABLE IF NOT EXISTS conn_starts (
              proc_key TEXT, dest_key TEXT, ts REAL, bytes INTEGER
            );
            CREATE INDEX IF NOT EXISTS conn_starts_ts ON conn_starts(ts);
            "#,
        )?;
        Ok(Self { conn })
    }

    pub fn meta_get(&self, k: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT v FROM meta WHERE k=?1", [k], |r| r.get(0)).optional()?)
    }

    pub fn meta_set(&self, k: &str, v: &str) -> Result<()> {
        self.conn.execute("INSERT INTO meta(k,v) VALUES(?1,?2) ON CONFLICT(k) DO UPDATE SET v=excluded.v", [k, v])?;
        Ok(())
    }

    /// プロセスを登録し first_seen（UNIX 秒）を返す。
    pub fn upsert_process(&self, p: &ProcRow, now: i64) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO processes(proc_key,executable,sha256,sig_status,team_id,signing_id,package,first_seen,last_seen)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?8)
             ON CONFLICT(proc_key) DO UPDATE SET last_seen=excluded.last_seen, executable=excluded.executable",
            params![p.proc_key, p.executable, p.sha256, p.sig_status, p.team_id, p.signing_id, p.package, now],
        )?;
        Ok(self.conn.query_row("SELECT first_seen FROM processes WHERE proc_key=?1", [p.proc_key], |r| r.get(0))?)
    }

    /// ベースラインに記録し、初出なら true。kind: dest / port / listen
    pub fn baseline_touch(&self, proc_key: &str, item: &str, kind: &str, now: i64) -> Result<bool> {
        let n = self.conn.execute(
            "INSERT INTO baselines(proc_key,item,kind,first_seen,last_seen,count) VALUES(?1,?2,?3,?4,?4,1)
             ON CONFLICT(proc_key,item,kind) DO NOTHING",
            params![proc_key, item, kind, now],
        )?;
        if n == 0 {
            self.conn.execute(
                "UPDATE baselines SET last_seen=?4, count=count+1 WHERE proc_key=?1 AND item=?2 AND kind=?3",
                params![proc_key, item, kind, now],
            )?;
        }
        Ok(n == 1)
    }

    pub fn conn_start(&self, proc_key: &str, dest_key: &str, ts: f64, bytes: Option<i64>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO conn_starts(proc_key,dest_key,ts,bytes) VALUES(?1,?2,?3,?4)",
            params![proc_key, dest_key, ts, bytes],
        )?;
        Ok(())
    }

    /// since 以降の接続開始時刻を (proc_key, dest_key) ごとに返す
    pub fn conn_series(&self, since: f64) -> Result<HashMap<(String, String), Vec<f64>>> {
        let mut st = self.conn.prepare("SELECT proc_key,dest_key,ts FROM conn_starts WHERE ts>=?1 ORDER BY ts")?;
        let mut out: HashMap<(String, String), Vec<f64>> = HashMap::new();
        let rows =
            st.query_map([since], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, f64>(2)?)))?;
        for row in rows {
            let (p, d, t) = row?;
            out.entry((p, d)).or_default().push(t);
        }
        Ok(out)
    }

    /// プロセスの代表情報（beacon 報告で使う）
    pub fn process_info(&self, proc_key: &str) -> Result<Option<(Option<String>, Option<String>)>> {
        Ok(self
            .conn
            .query_row("SELECT executable, sig_status FROM processes WHERE proc_key=?1", [proc_key], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?)
    }

    pub fn insert_event(&self, ev: &serde_json::Value, ts: i64) -> Result<()> {
        use crate::event::get_path;
        let s = |p: &str| get_path(ev, p).and_then(|v| v.as_str()).map(str::to_string);
        let n = |p: &str| get_path(ev, p).and_then(|v| v.as_i64());
        let sig_ids: Vec<String> = get_path(ev, "kanmon.signals")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.get("id").and_then(|i| i.as_str()).map(str::to_string)).collect())
            .unwrap_or_default();
        self.conn.execute(
            "INSERT OR REPLACE INTO events(id,ts,kind,direction,proto,proc_key,pid,executable,rip,rport,lport,domain,score,level,signals,verdict,json)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            params![
                s("event.id"),
                ts,
                s("network.kind"),
                s("network.direction"),
                s("network.transport"),
                s("process.proc_key"),
                n("process.pid"),
                s("process.executable"),
                s("destination.ip"),
                n("destination.port"),
                n("source.port"),
                s("destination.domain"),
                n("kanmon.score"),
                s("kanmon.level"),
                sig_ids.join(","),
                s("kanmon.verdict"),
                serde_json::to_string(ev)?
            ],
        )?;
        Ok(())
    }

    /// 保持期間を過ぎたものを削除
    pub fn prune(&self, events_before: i64, conn_before: f64) -> Result<(usize, usize)> {
        let a = self.conn.execute("DELETE FROM events WHERE ts < ?1", [events_before])?;
        let b = self.conn.execute("DELETE FROM conn_starts WHERE ts < ?1", [conn_before])?;
        Ok((a, b))
    }

    /// level ごとの件数（since 以降）
    pub fn level_counts(&self, since: i64) -> Result<Vec<(String, i64)>> {
        let mut st =
            self.conn.prepare("SELECT level, COUNT(*) FROM events WHERE ts>=?1 GROUP BY level ORDER BY level")?;
        let rows = st.query_map([since], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// 指定レベル以上の直近イベント（新しい順）。JSON をそのまま返す
    pub fn recent_events(&self, since: i64, levels: &[&str], limit: i64) -> Result<Vec<serde_json::Value>> {
        let placeholders = levels.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT json FROM events WHERE ts>=? AND level IN ({placeholders}) ORDER BY ts DESC, id DESC LIMIT ?"
        );
        let mut st = self.conn.prepare(&sql)?;
        let mut params: Vec<rusqlite::types::Value> = vec![since.into()];
        params.extend(levels.iter().map(|l| rusqlite::types::Value::from(l.to_string())));
        params.push(limit.into());
        let rows = st.query_map(rusqlite::params_from_iter(params), |r| r.get::<_, String>(0))?;
        let mut out = vec![];
        for r in rows {
            if let Ok(v) = serde_json::from_str(&r?) {
                out.push(v);
            }
        }
        Ok(out)
    }

    /// スコア上位のイベント（since 以降）
    pub fn top_events(&self, since: i64, limit: i64) -> Result<Vec<TopEvent>> {
        let mut st = self.conn.prepare(
            "SELECT ts, COALESCE(executable,''), score, COALESCE(signals,''), COALESCE(rip,'')||':'||COALESCE(rport,'')
             FROM events WHERE ts>=?1 ORDER BY score DESC, ts DESC LIMIT ?2",
        )?;
        let rows =
            st.query_map(params![since, limit], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_and_series() {
        let s = Store::open_in_memory().unwrap();
        assert!(s.baseline_touch("p", "example.com", "dest", 1).unwrap());
        assert!(!s.baseline_touch("p", "example.com", "dest", 2).unwrap());
        assert!(s.baseline_touch("p", "example.com", "port", 2).unwrap());
        let row = ProcRow {
            proc_key: "p",
            executable: Some("/x"),
            sha256: None,
            sig_status: Some("unsigned"),
            team_id: None,
            signing_id: None,
            package: None,
        };
        assert_eq!(s.upsert_process(&row, 10).unwrap(), 10);
        assert_eq!(s.upsert_process(&row, 20).unwrap(), 10);
        for i in 0..8 {
            s.conn_start("p", "d", 100.0 + i as f64 * 60.0, None).unwrap();
        }
        let m = s.conn_series(0.0).unwrap();
        assert_eq!(m[&("p".to_string(), "d".to_string())].len(), 8);
        s.meta_set("k", "v").unwrap();
        for (i, lv) in ["info", "notice", "warn", "critical"].iter().enumerate() {
            let ev = serde_json::json!({"event": {"id": format!("e{i}")}, "kanmon": {"level": lv}});
            s.insert_event(&ev, 100 + i as i64).unwrap();
        }
        let r = s.recent_events(0, &["notice", "warn", "critical"], 10).unwrap();
        let ids: Vec<&str> = r.iter().map(|v| v["event"]["id"].as_str().unwrap()).collect();
        assert_eq!(ids, vec!["e3", "e2", "e1"], "新しい順・info は除く");
        assert_eq!(s.meta_get("k").unwrap().as_deref(), Some("v"));
    }
}
