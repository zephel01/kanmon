//! ブラウザの履歴ビューア（`kanmonctl web`）が使う集計（v0.5.7）。
//!
//! - 「つながり」：保存済みのイベントから、親子のプロセスの木を組み、各プロセスに通信（接続先・待受・受けた接続）をぶら下げる
//! - プロセスは「pid ＋ 開始時刻」で 1 つとみなす（pid は使い回されるため）。開始時刻の無い古いイベントは「pid ＋ 名前」
//! - kanmon は通信したプロセスしか記録しないので、通信しなかったプロセスは祖先として名前だけ出る
//!
//! ここは純関数だけ（DB からの読み出しは store.rs）。入力はすべて外部由来（プロセス名・ドメイン）なので、
//! 表示側でエスケープする前提で文字列のまま返す。

use serde::Serialize;
use std::collections::{BTreeSet, HashMap};

/// 木を組むためのイベント 1 件（DB の列と JSON の一部）
#[derive(Debug, Clone, Default)]
pub struct Row {
    pub ts: i64,
    pub id: String,
    pub kind: String,
    pub level: String,
    pub score: i64,
    pub pid: Option<u32>,
    pub name: Option<String>,
    pub executable: Option<String>,
    pub proc_key: Option<String>,
    pub start: Option<String>,
    pub sig: Option<String>,
    pub transport: Option<String>,
    pub rip: Option<String>,
    pub rport: Option<i64>,
    pub lport: Option<i64>,
    pub domain: Option<String>,
    pub net_type: Option<String>,
    pub rules: Vec<String>,
    /// 近い順（親 → 祖父 …）。pid の無い段は名前だけ（v0.5.6 までのイベントの parent_chain）
    pub ancestors: Vec<Anc>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Anc {
    pub pid: Option<u32>,
    pub name: Option<String>,
    pub start: Option<String>,
}

/// 通信のまとまり（同じ種類・相手・ポート）
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Activity {
    pub kind: String,
    /// 相手（ドメインがあればドメイン、無ければ IP。待受は待受アドレス）
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_type: Option<String>,
    pub count: u64,
    pub first: i64,
    pub last: i64,
    pub level: String,
    pub max_score: i64,
    pub rules: Vec<String>,
    /// 最も点数の高い（同点なら新しい）イベントの id（詳細画面へ）
    pub event_id: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Node {
    pub id: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proc_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    /// 通信を記録したプロセスか（false は祖先として名前だけ分かるもの）
    pub observed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<usize>,
    pub children: Vec<usize>,
    /// 自分の通信で最も重いレベル（無ければ空）
    pub level: String,
    /// 自分と子孫で最も重いレベル
    pub worst: String,
    pub activity: Vec<Activity>,
    /// 通信のまとまりを上限で切ったか
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub activity_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Tree {
    pub nodes: Vec<Node>,
    pub roots: Vec<usize>,
    /// 読んだイベントの数
    pub events: usize,
    /// イベントかプロセスの数を上限で切ったか
    pub truncated: bool,
}

pub const MAX_ACTIVITY: usize = 50;

/// プロセスごとの通信のまとまり（種類・相手・ポート → まとまり）
type ActMap = HashMap<(String, String, Option<i64>), Activity>;

pub fn level_rank(l: &str) -> u8 {
    match l {
        "critical" => 4,
        "warn" => 3,
        "notice" => 2,
        "info" => 1,
        _ => 0,
    }
}

fn heavier(a: &str, b: &str) -> String {
    if level_rank(b) > level_rank(a) { b } else { a }.to_string()
}

/// プロセスの識別キー：pid ＋ 開始時刻（無ければ pid ＋ 名前）
fn proc_id(pid: u32, start: Option<&str>, name: &str) -> String {
    match start {
        Some(s) => format!("p:{pid}:{s}"),
        None => format!("p:{pid}:~{name}"),
    }
}

fn basename(p: &str) -> String {
    p.rsplit('/').next().unwrap_or(p).to_string()
}

/// 木を組む。`min_level` 以上を含む枝だけ残す（"" ならすべて）。`max_nodes` を超えたら切る
pub fn build_tree(rows: &[Row], min_level: &str, max_nodes: usize, truncated_rows: bool) -> Tree {
    let mut nodes: Vec<Node> = vec![];
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut acts: Vec<ActMap> = vec![];
    let mut truncated = truncated_rows;

    let mut get = |key: String, make: &dyn Fn(usize) -> Node, nodes: &mut Vec<Node>, acts: &mut Vec<ActMap>| -> usize {
        if let Some(&i) = index.get(&key) {
            return i;
        }
        let i = nodes.len();
        nodes.push(make(i));
        acts.push(HashMap::new());
        index.insert(key, i);
        i
    };

    for r in rows {
        let Some(pid) = r.pid else { continue };
        if nodes.len() >= max_nodes {
            truncated = true;
            break;
        }
        let name = r.name.clone().or_else(|| r.executable.as_deref().map(basename)).unwrap_or_else(|| "?".into());
        let me = get(
            proc_id(pid, r.start.as_deref(), &name),
            &|i| Node {
                id: i,
                pid: Some(pid),
                name: name.clone(),
                executable: None,
                start: r.start.clone(),
                proc_key: None,
                sig: None,
                observed: true,
                parent: None,
                children: vec![],
                level: String::new(),
                worst: String::new(),
                activity: vec![],
                activity_truncated: false,
            },
            &mut nodes,
            &mut acts,
        );
        {
            let n = &mut nodes[me];
            // 祖先として先に作られていた場合もここで詳しくする
            n.observed = true;
            if n.executable.is_none() {
                n.executable = r.executable.clone();
            }
            if n.proc_key.is_none() {
                n.proc_key = r.proc_key.clone();
            }
            if n.sig.is_none() {
                n.sig = r.sig.clone();
            }
            n.level = heavier(&n.level, &r.level);
        }
        // 通信のまとまり
        let target = r.domain.clone().or_else(|| r.rip.clone()).unwrap_or_default();
        let port = if r.kind == "listen" { r.lport.or(r.rport) } else { r.rport };
        let a = acts[me].entry((r.kind.clone(), target.clone(), port)).or_insert_with(|| Activity {
            kind: r.kind.clone(),
            target,
            ip: r.rip.clone(),
            port,
            transport: r.transport.clone(),
            net_type: r.net_type.clone(),
            count: 0,
            first: r.ts,
            last: r.ts,
            level: String::new(),
            max_score: i64::MIN,
            rules: vec![],
            event_id: r.id.clone(),
        });
        a.count += 1;
        a.first = a.first.min(r.ts);
        a.last = a.last.max(r.ts);
        a.level = heavier(&a.level, &r.level);
        if r.score > a.max_score || (r.score == a.max_score && r.ts >= a.last) {
            a.max_score = r.score;
            a.event_id = r.id.clone();
        }
        let mut rs: BTreeSet<String> = a.rules.drain(..).collect();
        rs.extend(r.rules.iter().cloned());
        a.rules = rs.into_iter().collect();

        // 祖先を近い順にたどり、親子をつなぐ（既に親があれば上書きしない）
        let mut child = me;
        // pid の無い段（古いイベント）は、上から下への名前の並びをキーにして兄弟で共有する
        let names_from_top: Vec<String> =
            r.ancestors.iter().rev().map(|a| a.name.clone().unwrap_or_else(|| "?".into())).collect();
        for (depth, anc) in r.ancestors.iter().enumerate() {
            if nodes[child].parent.is_some() {
                break;
            }
            let aname = anc.name.clone().unwrap_or_else(|| "?".into());
            let key = match anc.pid {
                Some(apid) => proc_id(apid, anc.start.as_deref(), &aname),
                None => format!("c:{}", names_from_top[..names_from_top.len() - depth].join("/")),
            };
            let pi = get(
                key,
                &|i| Node {
                    id: i,
                    pid: anc.pid,
                    name: aname.clone(),
                    executable: None,
                    start: anc.start.clone(),
                    proc_key: None,
                    sig: None,
                    observed: false,
                    parent: None,
                    children: vec![],
                    level: String::new(),
                    worst: String::new(),
                    activity: vec![],
                    activity_truncated: false,
                },
                &mut nodes,
                &mut acts,
            );
            if pi == child {
                break;
            }
            nodes[child].parent = Some(pi);
            nodes[pi].children.push(child);
            child = pi;
        }
    }

    // 通信のまとまりを重い順・回数の多い順に並べ、上限で切る
    for (i, m) in acts.into_iter().enumerate() {
        let mut v: Vec<Activity> = m.into_values().collect();
        v.sort_by(|a, b| {
            level_rank(&b.level).cmp(&level_rank(&a.level)).then(b.count.cmp(&a.count)).then(a.target.cmp(&b.target))
        });
        if v.len() > MAX_ACTIVITY {
            v.truncate(MAX_ACTIVITY);
            nodes[i].activity_truncated = true;
        }
        nodes[i].activity = v;
    }

    // 循環（壊れたデータ）を断ち、子孫で最も重いレベルを出す
    let n = nodes.len();
    for i in 0..n {
        let mut seen = BTreeSet::new();
        let mut cur = i;
        while let Some(p) = nodes[cur].parent {
            if !seen.insert(cur) || p == i {
                let p = nodes[cur].parent.take().unwrap();
                nodes[p].children.retain(|&c| c != cur);
                break;
            }
            cur = p;
        }
    }
    fn worst(nodes: &mut [Node], i: usize) -> String {
        let kids = nodes[i].children.clone();
        let mut w = nodes[i].level.clone();
        for c in kids {
            let cw = worst(nodes, c);
            w = heavier(&w, &cw);
        }
        nodes[i].worst = w.clone();
        w
    }
    let roots: Vec<usize> = (0..n).filter(|&i| nodes[i].parent.is_none()).collect();
    for &r in &roots {
        worst(&mut nodes, r);
    }

    // 子と根を、重い順・名前順に並べる
    let order = |nodes: &[Node], v: &mut Vec<usize>| {
        v.sort_by(|&a, &b| {
            level_rank(&nodes[b].worst)
                .cmp(&level_rank(&nodes[a].worst))
                .then(nodes[a].name.cmp(&nodes[b].name))
                .then(a.cmp(&b))
        })
    };
    for i in 0..n {
        let mut c = std::mem::take(&mut nodes[i].children);
        order(&nodes, &mut c);
        nodes[i].children = c;
    }
    let mut roots = roots;
    order(&nodes, &mut roots);

    let mut tree = Tree { nodes, roots, events: rows.len(), truncated };
    if level_rank(min_level) > 0 {
        prune(&mut tree, level_rank(min_level));
    }
    tree
}

/// `rank` 以上を含まない枝を落とし、番号を詰め直す
fn prune(t: &mut Tree, rank: u8) {
    let keep: Vec<bool> = t.nodes.iter().map(|n| level_rank(&n.worst) >= rank).collect();
    let mut map = vec![usize::MAX; t.nodes.len()];
    let mut out = vec![];
    for (i, n) in t.nodes.iter().enumerate() {
        if keep[i] {
            map[i] = out.len();
            out.push(n.clone());
        }
    }
    for n in out.iter_mut() {
        n.id = map[n.id];
        n.parent = n.parent.map(|p| map[p]);
        n.children = n.children.iter().filter(|&&c| keep[c]).map(|&c| map[c]).collect();
    }
    t.roots = t.roots.iter().filter(|&&r| keep[r]).map(|&r| map[r]).collect();
    t.nodes = out;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anc(pid: u32, name: &str, start: &str) -> Anc {
        Anc { pid: Some(pid), name: Some(name.into()), start: Some(start.into()) }
    }

    fn row(ts: i64, pid: u32, name: &str, start: &str, ancestors: Vec<Anc>) -> Row {
        Row {
            ts,
            id: format!("e{ts}"),
            kind: "connect".into(),
            level: "info".into(),
            pid: Some(pid),
            name: Some(name.into()),
            executable: Some(format!("/usr/bin/{name}")),
            start: Some(start.into()),
            transport: Some("tcp".into()),
            rip: Some("198.51.100.20".into()),
            rport: Some(443),
            ancestors,
            ..Default::default()
        }
    }

    fn names(t: &Tree, ids: &[usize]) -> Vec<String> {
        ids.iter().map(|&i| t.nodes[i].name.clone()).collect()
    }

    #[test]
    fn links_parents_and_groups_activity() {
        let up = vec![anc(3301, "zsh", "t3"), anc(812, "Terminal", "t2"), anc(1, "launchd", "t0")];
        let mut a = row(10, 4417, "updater", "t4", up.clone());
        a.rip = Some("203.0.113.80".into());
        a.level = "warn".into();
        a.score = 65;
        a.rules = vec!["R1".into(), "S2".into()];
        let mut a2 = a.clone();
        a2.ts = 20;
        a2.id = "e20".into();
        a2.score = 40;
        a2.level = "notice".into();
        a2.rules = vec!["A5".into()];
        let c = row(30, 4420, "curl", "t5", up.clone());
        // zsh 自身も通信した（祖先として先に作られたノードが、詳しくなる）
        let z = row(40, 3301, "zsh", "t3", vec![anc(812, "Terminal", "t2"), anc(1, "launchd", "t0")]);
        let t = build_tree(&[a, a2, c, z], "", 100, false);
        assert_eq!(names(&t, &t.roots), ["launchd"]);
        let launchd = &t.nodes[t.roots[0]];
        assert!(!launchd.observed);
        assert_eq!(launchd.worst, "warn");
        let term = &t.nodes[launchd.children[0]];
        let zsh = &t.nodes[term.children[0]];
        assert_eq!((zsh.name.as_str(), zsh.observed, zsh.worst.as_str()), ("zsh", true, "warn"));
        assert_eq!(names(&t, &zsh.children), ["updater", "curl"], "重い順");
        let upd = &t.nodes[zsh.children[0]];
        assert_eq!(upd.activity.len(), 1);
        let act = &upd.activity[0];
        assert_eq!((act.count, act.first, act.last), (2, 10, 20));
        assert_eq!((act.level.as_str(), act.max_score, act.event_id.as_str()), ("warn", 65, "e10"));
        assert_eq!(act.rules, ["A5", "R1", "S2"]);
    }

    #[test]
    fn pid_reuse_is_split_by_start() {
        let up = vec![anc(1, "launchd", "t0")];
        let t = build_tree(&[row(1, 500, "a", "s1", up.clone()), row(2, 500, "b", "s2", up)], "", 100, false);
        let l = &t.nodes[t.roots[0]];
        assert_eq!(l.children.len(), 2, "同じ pid でも開始時刻が違えば別のプロセス");
    }

    #[test]
    fn old_events_share_name_only_ancestors() {
        // v0.5.6 までのイベント：pid は親だけ、上は名前だけ
        let mk = |ts, pid, name: &str| {
            let mut r = row(ts, pid, name, "", vec![]);
            r.start = None;
            r.ancestors = vec![
                Anc { pid: Some(70), name: Some("zsh".into()), start: None },
                Anc { pid: None, name: Some("Terminal".into()), start: None },
                Anc { pid: None, name: Some("launchd".into()), start: None },
            ];
            r
        };
        let t = build_tree(&[mk(1, 80, "curl"), mk(2, 81, "git")], "", 100, false);
        assert_eq!(names(&t, &t.roots), ["launchd"]);
        let term = &t.nodes[t.nodes[t.roots[0]].children[0]];
        assert_eq!(term.pid, None);
        let zsh = &t.nodes[term.children[0]];
        assert_eq!((zsh.pid, zsh.children.len()), (Some(70), 2));
    }

    #[test]
    fn prune_keeps_only_alert_branches_and_caps() {
        let up = vec![anc(1, "launchd", "t0")];
        let mut bad = row(1, 10, "bad", "s1", up.clone());
        bad.level = "notice".into();
        let ok = row(2, 11, "ok", "s2", up.clone());
        let t = build_tree(&[bad.clone(), ok.clone()], "notice", 100, false);
        assert_eq!(t.nodes.len(), 2);
        let root = &t.nodes[t.roots[0]];
        assert_eq!(names(&t, &root.children), ["bad"]);
        assert_eq!(t.nodes[root.children[0]].parent, Some(t.roots[0]));
        // 上限
        let t = build_tree(&[bad, ok], "", 2, false);
        assert!(t.truncated);
        // 通信のまとまりの上限
        let rows: Vec<Row> = (0..60)
            .map(|i| {
                let mut r = row(i, 10, "bad", "s1", up.clone());
                r.rport = Some(1000 + i);
                r
            })
            .collect();
        let t = build_tree(&rows, "", 100, false);
        let n = t.nodes.iter().find(|n| n.name == "bad").unwrap();
        assert_eq!(n.activity.len(), MAX_ACTIVITY);
        assert!(n.activity_truncated);
    }

    #[test]
    fn broken_cycle_does_not_hang() {
        // 祖先に自分が入っている（壊れたデータ）
        let r = row(1, 10, "x", "s1", vec![anc(11, "y", "s2"), anc(10, "x", "s1")]);
        let t = build_tree(&[r], "", 100, false);
        assert!(!t.roots.is_empty());
    }
}
