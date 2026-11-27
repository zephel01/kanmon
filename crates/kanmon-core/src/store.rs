//! SQLite 保存（設計書 §12・§18.3）。WAL。

use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::path::Path;

/// (ts, executable, score, signals, "ip:port")
pub type TopEvent = (i64, String, i64, String, String);

/// プロセスの通信を相手ごとにまとめたもの（ブラウザのプロセス画面）
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct DestSummary {
    pub kind: String,
    pub target: String,
    pub ip: Option<String>,
    pub port: Option<i64>,
    pub count: i64,
    pub first: i64,
    pub last: i64,
    pub max_score: i64,
    pub level: String,
    pub as_number: Option<i64>,
    pub as_org: Option<String>,
    pub country: Option<String>,
    pub net_type: Option<String>,
}

/// processes 表の 1 行
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct ProcessSummary {
    pub proc_key: String,
    pub executable: Option<String>,
    pub sha256: Option<String>,
    pub sig_status: Option<String>,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub package: Option<String>,
    pub first_seen: Option<i64>,
    pub last_seen: Option<i64>,
}

/// LIKE の特殊文字（% _ \）をエスケープする（ESCAPE '\' と組で使う）
fn like_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '%' | '_' | '\\') {
            o.push('\\');
        }
        o.push(c);
    }
    o
}

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
            CREATE TABLE IF NOT EXISTS profile_volume (
              proc_key TEXT PRIMARY KEY, max_out INTEGER, reports INTEGER, first_seen INTEGER, last_seen INTEGER
            );
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

    /// ある種類のベースラインの集計（知っている数、一番古い・新しい first_seen）
    pub fn baseline_stats(&self, proc_key: &str, kind: &str) -> Result<crate::profile::Stats> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*), MIN(first_seen), MAX(first_seen) FROM baselines WHERE proc_key=?1 AND kind=?2",
            params![proc_key, kind],
            |r| Ok(crate::profile::Stats { known: r.get(0)?, oldest: r.get(1)?, newest: r.get(2)? }),
        )?)
    }

    /// 送信量のこれまで（最大、報告の回数）
    pub fn volume_profile(&self, proc_key: &str) -> Result<Option<(u64, i64)>> {
        Ok(self
            .conn
            .query_row("SELECT max_out, reports FROM profile_volume WHERE proc_key=?1", [proc_key], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get(1)?))
            })
            .optional()?)
    }

    /// 送信量を記録する（最大を更新）
    pub fn volume_record(&self, proc_key: &str, out: u64, now: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO profile_volume(proc_key,max_out,reports,first_seen,last_seen) VALUES(?1,?2,1,?3,?3)
             ON CONFLICT(proc_key) DO UPDATE SET max_out=MAX(max_out, excluded.max_out), reports=reports+1,
             last_seen=excluded.last_seen",
            params![proc_key, out as i64, now],
        )?;
        Ok(())
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

    /// 同じ (proc_key, dest_key) の beacon_report が since 以降に記録済みか（再起動をまたいだ重複防止）
    pub fn beacon_reported_since(&self, proc_key: &str, dest_key: &str, since: i64) -> Result<bool> {
        let pat = format!("%\"dest_key\":{}%", serde_json::to_string(dest_key)?);
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE kind='beacon_report' AND proc_key=?1 AND ts>=?2 AND json LIKE ?3",
            params![proc_key, since, pat],
            |r| r.get(0),
        )?;
        Ok(n > 0)
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

    /// 「つながり」の木を組むためのイベント（since 以上 until 未満、古い順、最大 limit 件）。
    /// JSON 全体は読まず、要る所だけ json_extract で取る。limit を超えたら .1 が true
    pub fn tree_rows(&self, since: i64, until: i64, limit: i64) -> Result<(Vec<crate::history::Row>, bool)> {
        use crate::history::{Anc, Row};
        let mut st = self.conn.prepare(
            "SELECT ts, id, COALESCE(kind,''), COALESCE(level,''), COALESCE(score,0), pid, executable, proc_key,
                    rip, rport, lport, domain, COALESCE(signals,''), proto,
                    json_extract(json,'$.process.name'), json_extract(json,'$.process.start'),
                    json_extract(json,'$.process.code_signature.status'), json_extract(json,'$.kanmon.net_type'),
                    json_extract(json,'$.process.ancestors'), json_extract(json,'$.process.parent.pid'),
                    json_extract(json,'$.process.parent.name'), json_extract(json,'$.process.parent.start'),
                    json_extract(json,'$.process.parent_chain')
             FROM events WHERE ts>=?1 AND ts<?2 AND pid IS NOT NULL ORDER BY ts, id LIMIT ?3",
        )?;
        let mut out = vec![];
        let mut rows = st.query(params![since, until, limit + 1])?;
        while let Some(r) = rows.next()? {
            if out.len() as i64 >= limit {
                return Ok((out, true));
            }
            let signals: String = r.get(12)?;
            let ancestors_json: Option<String> = r.get(18)?;
            let mut ancestors: Vec<Anc> = ancestors_json
                .as_deref()
                .and_then(|j| serde_json::from_str::<Vec<crate::event::Ancestor>>(j).ok())
                .unwrap_or_default()
                .into_iter()
                .map(|a| Anc { pid: Some(a.pid), name: a.name, start: a.start })
                .collect();
            if ancestors.is_empty() {
                // v0.5.6 までのイベント：pid は親だけ、その上は parent_chain の名前だけ
                let ppid: Option<i64> = r.get(19)?;
                if let Some(ppid) = ppid {
                    ancestors.push(Anc { pid: Some(ppid as u32), name: r.get(20)?, start: r.get(21)? });
                    let chain: Option<String> = r.get(22)?;
                    let chain: Vec<String> =
                        chain.as_deref().and_then(|j| serde_json::from_str(j).ok()).unwrap_or_default();
                    ancestors.extend(chain.into_iter().skip(1).map(|n| Anc { pid: None, name: Some(n), start: None }));
                }
            }
            let pid: Option<i64> = r.get(5)?;
            out.push(Row {
                ts: r.get(0)?,
                id: r.get(1)?,
                kind: r.get(2)?,
                level: r.get(3)?,
                score: r.get(4)?,
                pid: pid.map(|p| p as u32),
                executable: r.get(6)?,
                proc_key: r.get(7)?,
                rip: r.get(8)?,
                rport: r.get(9)?,
                lport: r.get(10)?,
                domain: r.get(11)?,
                rules: signals.split(',').filter(|x| !x.is_empty()).map(str::to_string).collect(),
                transport: r.get(13)?,
                name: r.get(14)?,
                start: r.get(15)?,
                sig: r.get(16)?,
                net_type: r.get(17)?,
                ancestors,
            });
        }
        Ok((out, false))
    }

    /// 履歴の一覧：指定レベル以上（levels）、ルール ID・文字列（実行ファイル・プロセス名・ドメイン・IP）で絞る。
    /// before（(ts, id) より前。並びは ts・id の降順）でページを送る。新しい順
    #[allow(clippy::too_many_arguments)] // 絞り込みの条件をそのまま並べる（どれも省略可）
    pub fn history(
        &self,
        since: i64,
        before: Option<(i64, &str)>,
        levels: &[&str],
        rule: Option<&str>,
        q: Option<&str>,
        proc_key: Option<&str>,
        limit: i64,
    ) -> Result<Vec<(i64, serde_json::Value)>> {
        let ph = levels.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let mut sql = format!("SELECT json FROM events WHERE ts>=? AND level IN ({ph})");
        let mut ps: Vec<rusqlite::types::Value> = vec![since.into()];
        ps.extend(levels.iter().map(|l| rusqlite::types::Value::from(l.to_string())));
        if let Some((bts, bid)) = before {
            sql.push_str(" AND (ts<? OR (ts=? AND id<?))");
            ps.push(bts.into());
            ps.push(bts.into());
            ps.push(bid.to_string().into());
        }
        if let Some(k) = proc_key {
            sql.push_str(" AND proc_key=?");
            ps.push(k.to_string().into());
        }
        if let Some(rule) = rule {
            // signals は "R1,S2" の形。LIKE の特殊文字を含む ID は来ない前提だが、念のため完全一致で見る
            sql.push_str(" AND (','||COALESCE(signals,'')||',') LIKE ? ESCAPE '\\'");
            ps.push(format!("%,{},%", like_escape(rule)).into());
        }
        if let Some(q) = q {
            sql.push_str(
                " AND (COALESCE(executable,'') LIKE ?1q ESCAPE '\\' OR COALESCE(domain,'') LIKE ?1q ESCAPE '\\'
                   OR COALESCE(rip,'') LIKE ?1q ESCAPE '\\' OR COALESCE(json_extract(json,'$.process.name'),'') LIKE ?1q ESCAPE '\\')",
            );
            let pat = format!("%{}%", like_escape(q));
            sql = sql.replace("?1q", "?");
            for _ in 0..4 {
                ps.push(pat.clone().into());
            }
        }
        sql.push_str(" ORDER BY ts DESC, id DESC LIMIT ?");
        ps.push(limit.into());
        let sql = sql.replacen("SELECT json FROM", "SELECT ts, json FROM", 1);
        let mut st = self.conn.prepare(&sql)?;
        let rows =
            st.query_map(rusqlite::params_from_iter(ps), |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = vec![];
        for r in rows {
            let (ts, j) = r?;
            if let Ok(v) = serde_json::from_str(&j) {
                out.push((ts, v));
            }
        }
        Ok(out)
    }

    /// 日ごと（ローカル時刻）・レベルごとの件数（since 以降、info を除く）
    pub fn daily_counts(&self, since: i64) -> Result<Vec<(String, String, i64)>> {
        let mut st = self.conn.prepare(
            "SELECT date(ts,'unixepoch','localtime') AS d, level, COUNT(*) FROM events
             WHERE ts>=?1 AND level IN ('notice','warn','critical') GROUP BY d, level ORDER BY d, level",
        )?;
        let rows = st.query_map([since], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// イベント 1 件（id で）
    pub fn event_by_id(&self, id: &str) -> Result<Option<serde_json::Value>> {
        let j: Option<String> =
            self.conn.query_row("SELECT json FROM events WHERE id=?1", [id], |r| r.get(0)).optional()?;
        Ok(j.and_then(|j| serde_json::from_str(&j).ok()))
    }

    /// プロセス（proc_key）の通信を相手ごとにまとめる（since 以降、件数の多い順、最大 limit）
    pub fn process_destinations(&self, proc_key: &str, since: i64, limit: i64) -> Result<Vec<DestSummary>> {
        let mut st = self.conn.prepare(
            "SELECT COALESCE(kind,''), COALESCE(domain, rip, ''), MAX(rip), CASE WHEN kind='listen' THEN COALESCE(lport,rport) ELSE rport END AS port,
                    COUNT(*), MIN(ts), MAX(ts), MAX(COALESCE(score,0)),
                    MAX(CASE level WHEN 'critical' THEN 4 WHEN 'warn' THEN 3 WHEN 'notice' THEN 2 WHEN 'info' THEN 1 ELSE 0 END),
                    MAX(json_extract(json,'$.destination.as.number')), MAX(json_extract(json,'$.destination.as.organization.name')),
                    MAX(json_extract(json,'$.destination.geo.country_iso_code')), MAX(json_extract(json,'$.kanmon.net_type'))
             FROM events WHERE proc_key=?1 AND ts>=?2
             GROUP BY 1, 2, 4 ORDER BY 5 DESC, 2 LIMIT ?3",
        )?;
        let rows = st.query_map(params![proc_key, since, limit], |r| {
            Ok(DestSummary {
                kind: r.get(0)?,
                target: r.get(1)?,
                ip: r.get(2)?,
                port: r.get(3)?,
                count: r.get(4)?,
                first: r.get(5)?,
                last: r.get(6)?,
                max_score: r.get(7)?,
                level: match r.get::<_, i64>(8)? {
                    4 => "critical",
                    3 => "warn",
                    2 => "notice",
                    1 => "info",
                    _ => "",
                }
                .to_string(),
                as_number: r.get(9)?,
                as_org: r.get(10)?,
                country: r.get(11)?,
                net_type: r.get(12)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// プロセスの登録情報（processes 表）
    pub fn process_row(&self, proc_key: &str) -> Result<Option<ProcessSummary>> {
        Ok(self
            .conn
            .query_row(
                "SELECT proc_key, executable, sha256, sig_status, team_id, signing_id, package, first_seen, last_seen
                 FROM processes WHERE proc_key=?1",
                [proc_key],
                |r| {
                    Ok(ProcessSummary {
                        proc_key: r.get(0)?,
                        executable: r.get(1)?,
                        sha256: r.get(2)?,
                        sig_status: r.get(3)?,
                        team_id: r.get(4)?,
                        signing_id: r.get(5)?,
                        package: r.get(6)?,
                        first_seen: r.get(7)?,
                        last_seen: r.get(8)?,
                    })
                },
            )
            .optional()?)
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
    fn profile_stats_and_volume() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(s.baseline_stats("p", "pdest").unwrap(), crate::profile::Stats::default());
        s.baseline_touch("p", "a.com", "pdest", 100).unwrap();
        s.baseline_touch("p", "b.com", "pdest", 300).unwrap();
        s.baseline_touch("p", "a.com", "pdest", 500).unwrap();
        s.baseline_touch("p", "x", "hour", 900).unwrap();
        let st = s.baseline_stats("p", "pdest").unwrap();
        assert_eq!((st.known, st.oldest, st.newest), (2, Some(100), Some(300)));
        assert_eq!(s.volume_profile("p").unwrap(), None);
        s.volume_record("p", 5_000_000, 10).unwrap();
        s.volume_record("p", 2_000_000, 20).unwrap();
        assert_eq!(s.volume_profile("p").unwrap(), Some((5_000_000, 2)));
    }

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
        let b = serde_json::json!({"event": {"id": "b1"}, "network": {"kind": "beacon_report"},
                                   "process": {"proc_key": "pk"}, "kanmon": {"dest_key": "203.0.113.0/24", "level": "notice"}});
        s.insert_event(&b, 1000).unwrap();
        assert!(s.beacon_reported_since("pk", "203.0.113.0/24", 900).unwrap());
        assert!(!s.beacon_reported_since("pk", "203.0.113.0/24", 1001).unwrap());
        assert!(!s.beacon_reported_since("pk", "198.51.100.0/24", 0).unwrap());
        assert!(!s.beacon_reported_since("other", "203.0.113.0/24", 0).unwrap());
        assert_eq!(s.meta_get("k").unwrap().as_deref(), Some("v"));
    }

    fn hev(
        id: &str,
        ts_level: (&str, &str),
        pid: u32,
        name: &str,
        domain: Option<&str>,
        signals: &[&str],
    ) -> serde_json::Value {
        let sig: Vec<serde_json::Value> = signals.iter().map(|s| serde_json::json!({"id": s, "points": 10})).collect();
        let mut v = serde_json::json!({
            "@timestamp": "2026-11-27T10:00:00+09:00",
            "event": {"id": id},
            "network": {"kind": "connect", "direction": "outbound", "transport": "tcp"},
            "process": {"pid": pid, "name": name, "executable": format!("/usr/bin/{name}"), "proc_key": format!("k-{name}"),
                        "start": "2026-11-27T09:00:00+09:00",
                        "ancestors": [{"pid": 70, "name": "zsh", "start": "2026-11-27T08:00:00+09:00"}, {"pid": 1, "name": "launchd"}]},
            "destination": {"ip": "203.0.113.80", "port": 443, "as": {"number": 64500, "organization": {"name": "EXAMPLE"}}},
            "kanmon": {"level": ts_level.1, "score": 30, "signals": sig, "net_type": "residential"}
        });
        if let Some(d) = domain {
            v["destination"]["domain"] = serde_json::json!(d);
        }
        let _ = ts_level.0;
        v
    }

    #[test]
    fn history_queries() {
        let s = Store::open_in_memory().unwrap();
        s.insert_event(&hev("a", ("", "notice"), 100, "updater", Some("x.example.test"), &["R1", "S2"]), 1000).unwrap();
        s.insert_event(&hev("b", ("", "warn"), 100, "updater", None, &["R11"]), 2000).unwrap();
        s.insert_event(&hev("c", ("", "info"), 101, "curl_x", Some("50%off.example.test"), &[]), 3000).unwrap();
        // 古い形（ancestors なし、parent と parent_chain）
        let mut old = hev("d", ("", "info"), 102, "git", None, &[]);
        old["process"].as_object_mut().unwrap().remove("ancestors");
        old["process"].as_object_mut().unwrap().remove("start");
        old["process"]["parent"] = serde_json::json!({"pid": 70, "name": "zsh"});
        old["process"]["parent_chain"] = serde_json::json!(["zsh", "Terminal", "launchd"]);
        s.insert_event(&old, 4000).unwrap();

        let all = ["notice", "warn", "critical"];
        let ids = |v: Vec<(i64, serde_json::Value)>| -> Vec<String> {
            v.iter().map(|e| e.1["event"]["id"].as_str().unwrap().to_string()).collect()
        };
        assert_eq!(ids(s.history(0, None, &all, None, None, None, 10).unwrap()), ["b", "a"]);
        assert_eq!(
            ids(s.history(0, Some((2000, "b")), &all, None, None, None, 10).unwrap()),
            ["a"],
            "before でページ送り"
        );
        assert_eq!(ids(s.history(0, None, &all, Some("R1"), None, None, 10).unwrap()), ["a"], "R11 は R1 に当たらない");
        assert_eq!(ids(s.history(0, None, &all, None, Some("x.example"), None, 10).unwrap()), ["a"]);
        assert_eq!(ids(s.history(0, None, &all, None, None, Some("k-curl_x"), 10).unwrap()), Vec::<String>::new());
        assert_eq!(ids(s.history(0, None, &all, None, None, Some("k-updater"), 10).unwrap()), ["b", "a"]);
        let info = ["info", "notice", "warn", "critical"];
        assert_eq!(ids(s.history(0, None, &info, None, Some("50%"), None, 10).unwrap()), ["c"], "% は文字として探す");
        assert_eq!(ids(s.history(0, None, &info, None, Some("curl_"), None, 10).unwrap()), ["c"]);
        assert!(s.history(0, None, &info, None, Some("%"), None, 10).unwrap().len() == 1);

        let days = s.daily_counts(0).unwrap();
        assert_eq!(days.iter().map(|d| d.2).sum::<i64>(), 2);
        assert_eq!(s.event_by_id("b").unwrap().unwrap()["kanmon"]["level"], "warn");
        assert!(s.event_by_id("zz").unwrap().is_none());

        let (rows, cut) = s.tree_rows(0, i64::MAX, 10).unwrap();
        assert!(!cut);
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0].rules, ["R1", "S2"]);
        assert_eq!(rows[0].ancestors[0].pid, Some(70));
        assert_eq!(rows[0].start.as_deref(), Some("2026-11-27T09:00:00+09:00"));
        let o = &rows[3];
        assert_eq!(o.start, None);
        assert_eq!(
            o.ancestors.iter().map(|a| (a.pid, a.name.clone().unwrap())).collect::<Vec<_>>(),
            [(Some(70), "zsh".to_string()), (None, "Terminal".into()), (None, "launchd".into())]
        );
        let (rows, cut) = s.tree_rows(0, i64::MAX, 2).unwrap();
        assert!(cut && rows.len() == 2);

        let d = s.process_destinations("k-updater", 0, 10).unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(d.iter().map(|x| x.count).sum::<i64>(), 2);
        let ip = d.iter().find(|x| x.target == "203.0.113.80").unwrap();
        assert_eq!(
            (ip.level.as_str(), ip.as_number, ip.net_type.as_deref()),
            ("warn", Some(64500), Some("residential"))
        );

        s.insert_event(&hev("a2", ("", "notice"), 100, "updater", None, &[]), 1000).unwrap();
        assert_eq!(
            ids(s.history(0, Some((1000, "a2")), &all, None, None, None, 10).unwrap()),
            ["a"],
            "同じ秒の残りも取れる"
        );
    }
}
