// kanmon の履歴ビューア（kanmonctl web が配る。読み取り専用）
// 外から来た文字列（プロセス名・ドメイン・パス）は必ず textContent で出す。HTML として組み立てない。
"use strict";

(function () {
  // ---- トークン：最初の URL の ?t= を覚え、アドレス欄からは消す ----
  const params = new URLSearchParams(location.search);
  if (params.get("t")) {
    sessionStorage.setItem("kanmon-token", params.get("t"));
    history.replaceState(null, "", "/" + location.hash);
  }
  const TOKEN = sessionStorage.getItem("kanmon-token") || "";

  // ---- 小さな道具 ----
  function h(tag, props) {
    const e = document.createElement(tag);
    if (props) {
      for (const k of Object.keys(props)) {
        const v = props[k];
        if (v == null || v === false) continue;
        if (k === "class") e.className = v;
        else if (k === "text") e.textContent = String(v);
        else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
        else e.setAttribute(k, v === true ? "" : String(v));
      }
    }
    for (let i = 2; i < arguments.length; i++) add(e, arguments[i]);
    return e;
  }
  function add(e, c) {
    if (arguments.length > 2) {
      for (let i = 1; i < arguments.length; i++) add(e, arguments[i]);
      return;
    }
    if (c == null || c === false) return;
    if (Array.isArray(c)) c.forEach((x) => add(e, x));
    else if (c instanceof Node) e.appendChild(c);
    else e.appendChild(document.createTextNode(String(c)));
  }
  const main = document.getElementById("main");
  function show() {
    main.replaceChildren();
    for (const c of arguments) add(main, c);
  }
  const pad = (n) => String(n).padStart(2, "0");
  function fmtDate(d) {
    if (!(d instanceof Date) || isNaN(d)) return "";
    return pad(d.getMonth() + 1) + "/" + pad(d.getDate()) + " " + pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }
  const fmtTs = (s) => (s ? fmtDate(new Date(s)) : "");
  const fmtUnix = (n) => (n ? fmtDate(new Date(n * 1000)) : "");
  // 実行ファイルが読めなかった祖先（pid 1 など）は "?" で来る
  const nm = (s) => (s && s !== "?" ? s : "（名前不明）");
  const LV = { critical: "critical", warn: "warn", notice: "notice", info: "info" };
  function lv(l) {
    return l && LV[l] ? h("span", { class: "lv lv-" + LV[l], text: l }) : null;
  }
  function link(text, hash) {
    return h("a", { class: "link", href: "#" + hash, text: text });
  }
  function kv(pairs) {
    const d = h("div", { class: "kv" });
    for (const [k, v] of pairs) {
      if (v == null || v === "" || (Array.isArray(v) && !v.length)) continue;
      // 中身の無い要素（相手のいない待受の「相手」など）は行ごと出さない
      if (v instanceof Node && !v.textContent.trim()) continue;
      add(d, h("div", { text: k }));
      add(d, h("div", null, v));
    }
    return d;
  }
  const enc = encodeURIComponent;
  function q(obj) {
    return Object.keys(obj)
      .filter((k) => obj[k] != null && obj[k] !== "")
      .map((k) => enc(k) + "=" + enc(obj[k]))
      .join("&");
  }
  function parseHash() {
    const raw = location.hash.replace(/^#/, "") || "/history";
    const [path, qs] = raw.split("?");
    const parts = path.split("/").filter(Boolean).map(decodeURIComponent);
    return { parts: parts, args: new URLSearchParams(qs || "") };
  }
  const statusEl = document.getElementById("status");
  async function api(cmd, args) {
    statusEl.textContent = "読み込み中…";
    try {
      const r = await fetch("/api/" + cmd + "?" + q(args || {}), { headers: { "X-Kanmon-Token": TOKEN }, cache: "no-store" });
      const j = await r.json();
      if (!r.ok || j.error) throw new Error(j.error || "HTTP " + r.status);
      statusEl.textContent = "";
      return j;
    } catch (e) {
      statusEl.textContent = "";
      throw e;
    }
  }
  function errorView(e) {
    show(h("p", { class: "err", text: "読み込めませんでした: " + e.message }),
      h("p", { class: "muted", text: "kanmond が動いているか、kanmonctl web が表示した URL から開いたかを確かめてください。" }));
  }
  function select(opts, value, onchange) {
    const s = h("select", { onchange: (e) => onchange(e.target.value) });
    for (const [v, label] of opts) add(s, h("option", { value: v, text: label, selected: v === String(value) }));
    return s;
  }
  function setTab(t) {
    document.querySelectorAll("nav a").forEach((a) => a.classList.toggle("on", a.dataset.tab === t));
  }

  // ---- 履歴 ----
  async function viewHistory(args) {
    setTab("history");
    const st = {
      hours: args.get("hours") || "168",
      level: args.get("level") || "notice",
      rule: args.get("rule") || "",
      q: args.get("q") || "",
    };
    const go = (patch) => { location.hash = "#/history?" + q(Object.assign({}, st, patch)); };
    const search = h("input", { type: "search", placeholder: "プロセス・ドメイン・IP", value: st.q });
    search.addEventListener("keydown", (e) => { if (e.key === "Enter") go({ q: search.value.trim() }); });
    const rule = h("input", { type: "search", placeholder: "ルール ID（R1 など）", value: st.rule, size: 12 });
    rule.addEventListener("keydown", (e) => { if (e.key === "Enter") go({ rule: rule.value.trim() }); });
    const bar = h("div", { class: "bar" },
      select([["24", "24 時間"], ["168", "7 日"], ["720", "30 日"], ["2160", "90 日"]], st.hours, (v) => go({ hours: v })),
      select([["notice", "notice 以上"], ["warn", "warn 以上"], ["critical", "critical"], ["info", "info も含む"]], st.level, (v) => go({ level: v })),
      search, rule, h("button", { text: "絞り込む", onclick: () => go({ q: search.value.trim(), rule: rule.value.trim() }) }));
    let data;
    try {
      data = await api("history", Object.assign({ limit: 200 }, st));
    } catch (e) { return errorView(e); }
    const tbody = h("tbody");
    const more = h("div");
    function addRows(items) {
      for (const it of items) {
        const dest = it.domain || it.ip || "";
        const tr = h("tr", { class: "click", onclick: () => { location.hash = "#/event/" + enc(it.id); } },
          h("td", { class: "mono nowrap", text: fmtTs(it.ts) }),
          h("td", { class: "nowrap" }, lv(it.level), " ", String(it.score)),
          h("td", null, (it.rules || []).join(" ")),
          h("td", null, it.process || "", it.pid != null ? h("span", { class: "muted", text: " pid " + it.pid }) : null),
          h("td", { class: "mono", text: dest + (it.port != null ? ":" + it.port : "") }),
          h("td", { text: it.title }));
        add(tbody, tr);
      }
    }
    function moreButton(next) {
      more.replaceChildren();
      if (!next) return;
      add(more, h("button", {
        text: "さらに読む", onclick: async () => {
          try {
            const d = await api("history", Object.assign({ limit: 200, before: next }, st));
            addRows(d.items);
            moreButton(d.more ? d.next_before : null);
          } catch (e) { statusEl.textContent = e.message; }
        },
      }));
    }
    addRows(data.items);
    moreButton(data.more ? data.next_before : null);
    show(bar, chart(data.days), h("table", null,
      h("thead", null, h("tr", null, ["時刻", "点", "ルール", "プロセス", "相手", "内容"].map((t) => h("th", { text: t })))), tbody),
      data.items.length ? null : h("p", { class: "muted", text: "この条件の警告はありません。" }), more);
  }

  function chart(days) {
    if (!days || !days.length) return null;
    const by = {};
    for (const d of days) { (by[d.day] = by[d.day] || {})[d.level] = d.count; }
    const keys = Object.keys(by).sort();
    const max = Math.max(...keys.map((k) => (by[k].notice || 0) + (by[k].warn || 0) + (by[k].critical || 0)), 1);
    const c = h("div", { class: "chart", title: "日ごとの件数（notice・warn・critical）" });
    for (const k of keys) {
      const col = h("div", { class: "col", title: k + "  notice " + (by[k].notice || 0) + " / warn " + (by[k].warn || 0) + " / critical " + (by[k].critical || 0) });
      for (const l of ["notice", "warn", "critical"]) {
        const n = by[k][l] || 0;
        if (n) {
          const seg = h("div", { class: "seg-" + l });
          seg.style.height = Math.max(2, Math.round((n / max) * 80)) + "px";
          add(col, seg);
        }
      }
      add(c, col);
    }
    return h("div", null, c, h("div", { class: "chart-days muted" }, h("span", { text: keys[0] }), h("span", { text: keys[keys.length - 1] })));
  }

  // ---- 警告の詳細 ----
  async function viewEvent(id) {
    setTab("history");
    let d;
    try { d = await api("event", { id: id }); } catch (e) { return errorView(e); }
    const v = d.event || {};
    const p = v.process || {}, k = v.kanmon || {}, dst = v.destination || {}, net = v.network || {};
    const anc = (p.ancestors || []).map((a) => nm(a.name) + "(" + a.pid + ")").join(" ← ");
    const sigs = h("div");
    for (const s of k.signals || []) {
      add(sigs, h("div", null, h("span", { class: "mono", text: s.id }), " +" + (s.points != null ? s.points : "?") + " ", s.description || s.name || ""));
    }
    show(
      h("p", null, link("← 履歴へ", "/history")),
      h("h2", null, lv(k.level), " ", d.title || ""),
      kv([
        ["時刻", fmtTs(v["@timestamp"])],
        ["点", k.score != null ? String(k.score) : ""],
        ["ルール", sigs],
        ["種類", [net.kind, net.direction, net.transport].filter(Boolean).join(" / ")],
        ["プロセス", [p.name || "", p.pid != null ? " pid " + p.pid : "", p.proc_key ? " " : "", p.proc_key ? link("このプロセスの通信を見る", "/process/" + enc(p.proc_key)) : null]],
        ["実行ファイル", h("span", { class: "mono", text: p.executable || "" })],
        ["起動", fmtTs(p.start)],
        ["署名", p.code_signature ? [p.code_signature.status, p.code_signature.team_id].filter(Boolean).join(" ") : ""],
        ["親", anc || (p.parent_chain || []).join(" ← ")],
        ["相手", h("span", { class: "mono", text: [dst.domain, dst.ip && dst.ip + (dst.port != null ? ":" + dst.port : "")].filter(Boolean).join("  ") })],
        ["AS", dst.as ? "AS" + dst.as.number + " " + ((dst.as.organization || {}).name || "") : ""],
        ["国", (dst.geo || {}).country_iso_code || ""],
        ["回線", k.net_type || ""],
      ]),
      h("h3", { text: "通知の文" }), h("pre", { text: d.body || "" }),
      h("h3", { text: "元の JSON" }), h("pre", { text: JSON.stringify(v, null, 2) }));
  }

  // ---- プロセス ----
  async function viewProcess(key, args) {
    setTab("history");
    const hours = args.get("hours") || "168";
    let d;
    try { d = await api("process", { proc_key: key, hours: hours }); } catch (e) { return errorView(e); }
    const pr = d.process || {};
    const rows = h("tbody");
    for (const x of d.destinations || []) {
      add(rows, h("tr", null,
        h("td", { text: x.kind }),
        h("td", { class: "mono", text: x.target + (x.port != null ? ":" + x.port : "") }),
        h("td", { text: x.as_number ? "AS" + x.as_number + " " + (x.as_org || "") : "" }),
        h("td", { text: [x.country, x.net_type].filter(Boolean).join(" ") }),
        h("td", { text: String(x.count) }),
        h("td", { class: "mono", text: fmtUnix(x.first) + " 〜 " + fmtUnix(x.last) }),
        h("td", null, lv(x.level))));
    }
    const alerts = h("tbody");
    for (const it of d.alerts || []) {
      add(alerts, h("tr", { class: "click", onclick: () => { location.hash = "#/event/" + enc(it.id); } },
        h("td", { class: "mono nowrap", text: fmtTs(it.ts) }), h("td", { class: "nowrap" }, lv(it.level), " " + it.score),
        h("td", { text: (it.rules || []).join(" ") }), h("td", { text: it.title })));
    }
    show(
      h("p", null, link("← 履歴へ", "/history")),
      h("h2", { text: (pr.executable || key).split("/").pop() }),
      kv([
        ["実行ファイル", h("span", { class: "mono", text: pr.executable || "" })],
        ["署名", [pr.sig_status, pr.team_id, pr.signing_id, pr.package].filter(Boolean).join(" ")],
        ["SHA-256", h("span", { class: "mono", text: pr.sha256 || "" })],
        ["初めて見た", fmtUnix(pr.first_seen)],
        ["最後に見た", fmtUnix(pr.last_seen)],
        ["期間", select([["24", "24 時間"], ["168", "7 日"], ["720", "30 日"], ["2160", "90 日"]], hours, (v) => { location.hash = "#/process/" + enc(key) + "?hours=" + v; })],
      ]),
      h("h3", { text: "通信した相手（多い順）" }),
      h("table", null, h("thead", null, h("tr", null, ["種類", "相手", "AS", "国・回線", "回数", "最初 〜 最後", "最も重い"].map((t) => h("th", { text: t })))), rows),
      h("h3", { text: "警告" }),
      (d.alerts || []).length ? h("table", null, alerts) : h("p", { class: "muted", text: "この期間の警告はありません。" }));
  }

  // ---- つながり ----
  const treeState = { open: new Set(), sel: null };
  async function viewTree(args) {
    setTab("tree");
    const hours = args.get("hours") || "24";
    const min = args.has("min") ? args.get("min") : "notice";
    const go = (patch) => { location.hash = "#/tree?" + q(Object.assign({ hours: hours, min: min }, patch)); };
    const bar = h("div", { class: "bar" },
      select([["1", "1 時間"], ["6", "6 時間"], ["24", "24 時間"], ["72", "3 日"], ["168", "7 日"]], hours, (v) => go({ hours: v })),
      select([["notice", "notice 以上を含む木だけ"], ["warn", "warn 以上を含む木だけ"], ["", "すべて"]], min, (v) => go({ min: v })),
      h("span", { class: "muted", text: "通信したプロセスだけが出ます。色はその下で出た最も重い警告。" }));
    let t;
    try { t = await api("tree", { hours: hours, min_level: min }); } catch (e) { return errorView(e); }
    const nodes = t.nodes || [];
    const left = h("div"), right = h("div");
    if (treeState.sel == null || !nodes[treeState.sel]) {
      // 初めは、最も重いものまでの道を開いて選ぶ
      let cur = (t.roots || [])[0];
      treeState.open = new Set();
      while (cur != null && nodes[cur]) {
        treeState.open.add(cur);
        const kids = nodes[cur].children || [];
        if (!kids.length || !nodes[kids[0]].worst) break;
        cur = kids[0];
      }
      treeState.sel = cur != null ? cur : null;
    }
    function drawTree() {
      left.replaceChildren();
      const walk = (i, depth) => {
        const n = nodes[i];
        const kids = n.children || [];
        const isOpen = treeState.open.has(i);
        const row = h("div", { class: "row" + (treeState.sel === i ? " sel" : ""), onclick: () => {
          if (kids.length || (n.activity || []).length) { isOpen ? treeState.open.delete(i) : treeState.open.add(i); }
          treeState.sel = i; drawTree(); drawDetail();
        } },
          h("span", { class: "tw", text: kids.length || (n.activity || []).length ? (isOpen ? "▾" : "▸") : "·" }),
          h("span", { class: n.observed ? "" : "ghost", text: nm(n.name) }),
          n.pid != null ? h("span", { class: "muted", text: "pid " + n.pid }) : null,
          lv(n.worst));
        row.style.paddingLeft = 6 + depth * 16 + "px";
        add(left, row);
        if (!isOpen) return;
        for (const a of n.activity || []) {
          const arrow = a.kind === "listen" ? "◎ 待受" : a.kind === "accept" ? "← 受けた" : a.kind === "connect" ? "→" : a.kind;
          const r = h("div", { class: "row act" },
            h("span", { class: "tw" }), h("span", { text: arrow }),
            h("span", { class: "mono", text: a.target + (a.port != null ? ":" + a.port : "") }),
            a.count > 1 ? h("span", { class: "muted", text: "×" + a.count }) : null,
            a.level !== "info" ? lv(a.level) : null);
          r.style.paddingLeft = 22 + depth * 16 + "px";
          add(left, r);
        }
        if (n.activity_truncated) add(left, h("div", { class: "row act muted", text: "（ほかにもあります。プロセスの画面で見られます）" }));
        for (const c of kids) walk(c, depth + 1);
      };
      for (const r of t.roots || []) walk(r, 0);
      if (!(t.roots || []).length) add(left, h("p", { class: "muted", text: "この条件に当たるプロセスはありません。" }));
    }
    function drawDetail() {
      right.replaceChildren();
      const n = nodes[treeState.sel];
      if (!n) return;
      const path = [];
      for (let p = n.parent; p != null && nodes[p]; p = nodes[p].parent) path.push(nm(nodes[p].name) + (nodes[p].pid != null ? "(" + nodes[p].pid + ")" : ""));
      add(right, [h("h2", { text: nm(n.name) }),
        h("div", { class: "muted", text: [n.pid != null ? "pid " + n.pid : "", n.start ? "起動 " + fmtTs(n.start) : ""].filter(Boolean).join("・") }),
        kv([
          ["実行ファイル", h("span", { class: "mono", text: n.executable || "" })],
          ["署名", n.sig || ""],
          ["親", path.join(" ← ")],
          ["", n.proc_key ? link("このプロセスの通信をすべて見る", "/process/" + enc(n.proc_key)) : (n.observed ? "" : "通信は記録されていません（祖先として名前だけ分かる）")],
        ])]);
      for (const a of n.activity || []) {
        add(right, h("div", { class: "card" },
          h("div", null, h("span", { class: "muted", text: a.kind + " " }), h("span", { class: "mono", text: a.target + (a.port != null ? ":" + a.port : "") }),
            a.ip && a.ip !== a.target ? h("span", { class: "mono muted", text: "  " + a.ip }) : null),
          h("div", { class: "muted", text: [a.transport, a.net_type, a.count + " 回", fmtUnix(a.first) + " 〜 " + fmtUnix(a.last)].filter(Boolean).join("・") }),
          a.level && a.level !== "info" ? h("div", null, lv(a.level), " " + (a.rules || []).join(" ") + " ", link("警告の詳細", "/event/" + enc(a.event_id))) : null));
      }
    }
    drawTree();
    drawDetail();
    const split = h("div", { class: "split" }, left, right);
    show(bar, t.truncated ? h("p", { class: "muted", text: "件数が多いので途中で切りました。期間を短くしてください。" }) : null, split);
  }

  // ---- 振り分け ----
  function route() {
    const { parts, args } = parseHash();
    if (parts[0] === "event" && parts[1]) return viewEvent(parts[1]);
    if (parts[0] === "process" && parts[1]) return viewProcess(parts[1], args);
    if (parts[0] === "tree") {
      return viewTree(args);
    }
    return viewHistory(args);
  }
  window.addEventListener("hashchange", () => { treeState.sel = null; route(); });
  if (!TOKEN) {
    show(h("p", { class: "err", text: "kanmonctl web が表示した URL（?t= 付き）から開いてください。" }));
  } else {
    route();
  }
})();
