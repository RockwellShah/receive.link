// receive.link metrics dashboard — LOCAL, read-only. Serves http://localhost:8788 and proxies
// named SQL queries to the Cloudflare Analytics Engine SQL API, so the API token stays server-side
// and never reaches the browser. Run: `bun run scripts/metrics-dash.ts`
//
// Token: CF_ANALYTICS_TOKEN env, else ~/.cloudflare/analytics-token, else ~/.cloudflare/token.
// Needs the "Account Analytics: Read" permission only. Everything here is aggregate and PII-free
// by construction: the datasets contain event names, one whitelisted dimension, counts, and bytes
// (see worker/src/http.ts logEvent) — there is nothing identifying to display.

import { readFileSync } from "node:fs";
import { homedir } from "node:os";

const ACCOUNT_ID = "30d5a45850ef3f60dcd4b75a5b5dd39b";
const DATASETS: Record<string, string> = {
  prod: "receive_link_metrics",
  staging: "receive_link_metrics_staging",
  mon: "receive_link_metrics_mon",
};
const PORT = 8788;

function token(): string {
  if (process.env.CF_ANALYTICS_TOKEN) return process.env.CF_ANALYTICS_TOKEN.trim();
  for (const f of ["analytics-token", "token"]) {
    try {
      const t = readFileSync(`${homedir()}/.cloudflare/${f}`, "utf8").trim();
      if (t) return t;
    } catch {
      /* try the next location */
    }
  }
  throw new Error("no Cloudflare token: set CF_ANALYTICS_TOKEN or create ~/.cloudflare/analytics-token");
}

async function sql(query: string): Promise<{ data?: Record<string, unknown>[]; error?: string }> {
  const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/analytics_engine/sql`, {
    method: "POST",
    headers: { authorization: `Bearer ${token()}` },
    body: query,
  });
  const text = await res.text();
  try {
    const j = JSON.parse(text) as { data?: Record<string, unknown>[]; errors?: { message: string }[]; success?: boolean };
    if (j.success === false) return { error: j.errors?.[0]?.message ?? "query failed" };
    return { data: j.data ?? [] };
  } catch {
    return { error: text.slice(0, 200) || `HTTP ${res.status}` };
  }
}

// Sampling-correct aggregates: AE may downsample under load, so counts are SUM(_sample_interval * n).
const q = {
  totals: (ds: string, days: number) =>
    `SELECT blob1 AS event, blob2 AS dim,
            SUM(_sample_interval * double1) AS n,
            SUM(_sample_interval * double2) AS bytes
     FROM ${ds}
     WHERE timestamp > NOW() - INTERVAL '${days}' DAY
     GROUP BY event, dim
     ORDER BY n DESC
     FORMAT JSON`,
  byDay: (ds: string, days: number) =>
    `SELECT toStartOfInterval(timestamp, INTERVAL '1' DAY) AS day, blob1 AS event,
            SUM(_sample_interval * double1) AS n,
            SUM(_sample_interval * double2) AS bytes
     FROM ${ds}
     WHERE timestamp > NOW() - INTERVAL '${days}' DAY
     GROUP BY day, event
     ORDER BY day
     FORMAT JSON`,
};

Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/api/data") {
      const env = url.searchParams.get("env") ?? "prod";
      const ds = DATASETS[env];
      if (!ds) return Response.json({ error: "unknown env" }, { status: 400 });
      const [t7, t1, days] = await Promise.all([sql(q.totals(ds, 7)), sql(q.totals(ds, 1)), sql(q.byDay(ds, 14))]);
      return Response.json({ totals7d: t7, totals24h: t1, byDay: days });
    }
    if (url.pathname === "/") return new Response(PAGE, { headers: { "content-type": "text/html; charset=utf-8" } });
    return new Response("not found", { status: 404 });
  },
});
console.log(`receive.link metrics dashboard: http://localhost:${PORT}`);

// ---------------------------------------------------------------------------------------------
// The page. Stat tiles for the four launch questions, one single-hue bar chart (deliveries/day),
// and two tables (all events, abuse walls). Single series everywhere, so identity never rides on
// color; values wear ink, not series color; the tables are the built-in table view.
const PAGE = `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>receive.link metrics</title>
<style>
  :root { --ink:#1A1F2B; --mut:#74767E; --ln:#D9E2D4; --card:#fff; --bg:#ECF1E9; --g:#23A267; --bad:#D2502E; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.5 system-ui, sans-serif; padding:28px 20px 60px; }
  .wrap { max-width: 1040px; margin: 0 auto; }
  h1 { font-size:20px; margin:0; letter-spacing:-.01em; }
  h1 .dot { color: var(--g); }
  .top { display:flex; align-items:center; justify-content:space-between; gap:16px; margin-bottom:20px; flex-wrap:wrap; }
  .tabs { display:flex; gap:6px; }
  .tabs button { font:inherit; font-size:13px; font-weight:700; border:1px solid var(--ln); background:var(--card); color:var(--mut); border-radius:999px; padding:6px 14px; cursor:pointer; }
  .tabs button.on { background:var(--g); border-color:var(--g); color:#fff; }
  .meta { font-size:12.5px; color:var(--mut); }
  .tiles { display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:12px; margin-bottom:12px; }
  .tile { background:var(--card); border:1px solid var(--ln); border-radius:14px; padding:16px 18px; }
  .tile .k { font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:.06em; color:var(--mut); }
  .tile .v { font-size:28px; font-weight:800; letter-spacing:-.01em; margin-top:2px; font-variant-numeric:tabular-nums; }
  .tile .s { font-size:12.5px; color:var(--mut); margin-top:2px; }
  .card { background:var(--card); border:1px solid var(--ln); border-radius:14px; padding:18px; margin-bottom:12px; }
  .card h2 { font-size:14px; margin:0 0 12px; }
  table { width:100%; border-collapse:collapse; font-size:13.5px; }
  th { text-align:left; font-size:11.5px; text-transform:uppercase; letter-spacing:.05em; color:var(--mut); font-weight:700; padding:6px 8px; border-bottom:1px solid var(--ln); }
  td { padding:6px 8px; border-bottom:1px solid #EEF3EC; font-variant-numeric:tabular-nums; }
  td.num { text-align:right; }
  th.num { text-align:right; }
  .empty { color:var(--mut); font-size:13.5px; }
  .err { color:var(--bad); font-size:13.5px; }
  .chart { display:flex; align-items:flex-end; gap:6px; height:120px; padding-top:18px; }
  .bcol { flex:1; display:flex; flex-direction:column; justify-content:flex-end; align-items:center; gap:4px; min-width:0; position:relative; }
  .bar { width:100%; max-width:38px; background:var(--g); border-radius:4px 4px 0 0; min-height:2px; }
  .blab { font-size:10.5px; color:var(--mut); white-space:nowrap; overflow:hidden; max-width:100%; }
  .bval { font-size:11px; font-weight:700; color:var(--ink); }
  .tip { position:fixed; pointer-events:none; background:var(--ink); color:#fff; font-size:12px; padding:6px 9px; border-radius:8px; display:none; z-index:9; }
</style>
<div class="wrap">
  <div class="top">
    <h1>receive<span class="dot">.</span>link metrics</h1>
    <div class="tabs" id="tabs"></div>
    <div class="meta" id="meta">loading…</div>
  </div>
  <div class="tiles" id="tiles"></div>
  <div class="card"><h2>Files delivered per day (14d)</h2><div class="chart" id="chart"></div><div class="empty" id="chartempty" hidden>No deliveries in range.</div></div>
  <div class="card"><h2>All events (7 days)</h2><div id="events"></div></div>
  <div class="card"><h2>Abuse walls (7 days, by wall)</h2><div id="abuse"></div></div>
</div>
<div class="tip" id="tip"></div>
<script>
const ABUSE = ["rate_limited","proof_failed","invalid_link","revoked_link_attempt","upload_too_large","webhook_bad_signature","forbidden_origin","byte_budget_exceeded","recipient_over_capacity","invalid_ciphertext"];
let env = localStorage.getItem("dash-env") || "prod";
const gb = b => b >= 1e12 ? (b/1e12).toFixed(2)+" TB" : b >= 1e9 ? (b/1e9).toFixed(2)+" GB" : b >= 1e6 ? (b/1e6).toFixed(1)+" MB" : b >= 1e3 ? (b/1e3).toFixed(1)+" KB" : Math.round(b)+" B";
const num = n => Math.round(n).toLocaleString();
const el = id => document.getElementById(id);

function tabs() {
  el("tabs").innerHTML = ["prod","staging","mon"].map(e =>
    \`<button class="\${e===env?"on":""}" onclick="setEnv('\${e}')">\${e}</button>\`).join("");
}
function setEnv(e) { env = e; localStorage.setItem("dash-env", e); tabs(); load(); }

function sum(rows, ev, field) { return rows.filter(r => r.event === ev).reduce((a, r) => a + Number(r[field] || 0), 0); }

function table(rows, cols) {
  if (!rows.length) return '<div class="empty">Nothing yet.</div>';
  return '<table><tr>' + cols.map(c => \`<th class="\${c.num?"num":""}">\${c.h}</th>\`).join("") + '</tr>' +
    rows.map(r => '<tr>' + cols.map(c => \`<td class="\${c.num?"num":""}">\${c.f(r)}</td>\`).join("") + '</tr>').join("") + '</table>';
}

async function load() {
  el("meta").textContent = "loading…";
  const res = await fetch("/api/data?env=" + env);
  const d = await res.json();
  const err = d.totals7d?.error || d.totals24h?.error || d.byDay?.error;
  if (err && !(d.totals7d?.data || []).length) {
    el("meta").innerHTML = '<span class="err">' + err + '</span>';
    el("tiles").innerHTML = ""; el("events").innerHTML = '<div class="empty">No data (dataset may be empty until its first event, or the token lacks Account Analytics Read).</div>'; el("abuse").innerHTML = ""; el("chart").innerHTML = "";
    return;
  }
  const t7 = d.totals7d.data || [], t1 = d.totals24h.data || [], byDay = d.byDay.data || [];
  el("meta").textContent = "updated " + new Date().toLocaleTimeString();

  // Tiles: the four launch questions.
  const delivered7 = sum(t7, "delivered", "n"), deliveredB = sum(t7, "delivered", "bytes");
  const dl7 = sum(t7, "download_served", "n"), dlB = sum(t7, "download_served", "bytes");
  const walls = sum(t7, "download_402", "n"), minted = sum(t7, "checkout_minted", "n"), credited = sum(t7, "billing_credited", "n"), creditedB = sum(t7, "billing_credited", "bytes");
  const abuse24 = t1.filter(r => ABUSE.includes(r.event)).reduce((a, r) => a + Number(r.n), 0);
  el("tiles").innerHTML = [
    { k: "Deliveries · 7d", v: num(delivered7), s: gb(deliveredB) + " received" },
    { k: "Downloads · 7d", v: num(dl7), s: gb(dlB) + " served" },
    { k: "402 → paid · 7d", v: num(walls) + " → " + num(credited), s: num(minted) + " checkouts · " + gb(creditedB) + " credited" },
    { k: "Abuse events · 24h", v: num(abuse24), s: "all walls combined" },
  ].map(t => \`<div class="tile"><div class="k">\${t.k}</div><div class="v">\${t.v}</div><div class="s">\${t.s}</div></div>\`).join("");

  // Chart: deliveries per day, single hue, direct label on max + latest only, hover tooltip on all.
  const days = {};
  for (const r of byDay.filter(r => r.event === "delivered")) {
    const day = String(r.day).slice(5, 10);
    days[day] = (days[day] || 0) + Number(r.n);
  }
  const entries = Object.entries(days);
  el("chartempty").hidden = entries.length > 0;
  const max = Math.max(1, ...entries.map(e => e[1]));
  el("chart").innerHTML = entries.map(([day, n], i) => {
    const label = n === max || i === entries.length - 1 ? \`<div class="bval">\${num(n)}</div>\` : "";
    return \`<div class="bcol" data-tip="\${day}: \${num(n)} deliveries">\${label}<div class="bar" style="height:\${Math.max(2, (n/max)*84)}px"></div><div class="blab">\${day}</div></div>\`;
  }).join("");

  // Events table (7d), dim rolled into the event row where present.
  el("events").innerHTML = table(t7, [
    { h: "Event", f: r => r.event + (r.dim ? ' <span style="color:var(--mut)">· ' + r.dim + "</span>" : "") },
    { h: "Count", num: true, f: r => num(r.n) },
    { h: "Bytes", num: true, f: r => Number(r.bytes) ? gb(Number(r.bytes)) : "" },
  ]);

  // Abuse table: only the walls, dim = which limiter/reason.
  el("abuse").innerHTML = table(t7.filter(r => ABUSE.includes(r.event)), [
    { h: "Wall", f: r => r.event },
    { h: "Kind", f: r => r.dim || "" },
    { h: "Count · 7d", num: true, f: r => num(r.n) },
  ]);
}

document.addEventListener("mouseover", e => {
  const t = e.target.closest("[data-tip]"), tip = el("tip");
  if (!t) { tip.style.display = "none"; return; }
  tip.textContent = t.dataset.tip; tip.style.display = "block";
});
document.addEventListener("mousemove", e => { const tip = el("tip"); tip.style.left = (e.clientX + 12) + "px"; tip.style.top = (e.clientY + 12) + "px"; });

tabs(); load(); setInterval(load, 120_000);
</script>`;
