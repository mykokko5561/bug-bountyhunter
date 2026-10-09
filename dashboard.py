"""
dashboard.py
------------
Katman 1'in (FastAPI) uzerine binen GORSEL KONTROL PANELI.

Mevcut sisteme hicbir seyi bozmadan eklenir: ayni SQLite veritabanini
(database.get_connection) OKUR ve tek sayfada canli gosterir:
  - ozet kutulari (toplam istek, secret, subdomain, severity dagilimi)
  - recon bulgulari (severity renkli, en yuksek once)
  - canli subdomainler
  - triyaj kuyrugu (AI'a giden, inceleme bekleyenler)
  - "Tarama Baslat" formu -> tipki Telegram /scan gibi autopwn.py'yi calistirir

Sayfa her 4 saniyede kendini yeniler (polling), boylece Telegram'dan
/scan dedigin anda bulgular burada da canli belirir. WebSocket gerekmez.

KURULUM (main.py'ye 2 satir):
    import dashboard
    app.include_router(dashboard.router)
Sonra tarayici:  http://127.0.0.1:8000/dashboard

Route'lar /dashboard ve /dash/* altinda — mevcut /health /ingest
/requests /stats ile CAKISMAZ.
"""

import os
import re
import sys
import subprocess

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from database import get_connection

router = APIRouter()

_PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

# Telegram /scan ile ayni domain dogrulamasi — kabuk calismaz, sadece
# autopwn.py'ye argv olarak gider, ama yine de temiz bir domain sart.
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")

_SEV_ORDER = ("critical", "high", "medium", "low", "info")


# --------------------------------------------------------------------------
# JSON API'leri — sayfa bunlari periyodik ceker
# --------------------------------------------------------------------------
@router.get("/dash/summary")
def dash_summary():
    """Ust kutular icin ozet sayilar."""
    try:
        with get_connection() as conn:
            total_req = conn.execute("SELECT COUNT(*) c FROM requests").fetchone()["c"]
            secrets = conn.execute(
                "SELECT COUNT(*) c FROM requests WHERE contains_secret = 1"
            ).fetchone()["c"]
            status_rows = conn.execute(
                "SELECT triage_status, COUNT(*) c FROM requests GROUP BY triage_status"
            ).fetchall()
            subs_total = conn.execute("SELECT COUNT(*) c FROM subdomains").fetchone()["c"]
            subs_alive = conn.execute(
                "SELECT COUNT(*) c FROM subdomains WHERE alive = 1"
            ).fetchone()["c"]
            sev_rows = conn.execute(
                "SELECT LOWER(COALESCE(severity,'info')) s, COUNT(*) c "
                "FROM recon_findings GROUP BY s"
            ).fetchall()
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"error": str(e)}, status_code=500)

    status = {r["triage_status"]: r["c"] for r in status_rows}
    sev = {r["s"]: r["c"] for r in sev_rows}
    return {
        "requests_total": total_req,
        "secrets": secrets,
        "pending_triage": status.get("sent_to_ai", 0),
        "reported": status.get("reported", 0),
        "subs_total": subs_total,
        "subs_alive": subs_alive,
        "severity": {k: sev.get(k, 0) for k in _SEV_ORDER},
        "status": status,
    }


@router.get("/dash/findings")
def dash_findings():
    sev_sql = ("CASE LOWER(COALESCE(severity,'info')) "
               "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
               "WHEN 'low' THEN 3 ELSE 4 END")
    try:
        with get_connection() as conn:
            rows = conn.execute(
                f"SELECT id, host, source, LOWER(COALESCE(severity,'info')) severity, "
                f"name, matched_at, found_at "
                f"FROM recon_findings ORDER BY {sev_sql}, found_at DESC LIMIT 40"
            ).fetchall()
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"error": str(e)}, status_code=500)
    return [dict(r) for r in rows]


@router.get("/dash/subs")
def dash_subs():
    try:
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT subdomain, status_code, tech, title FROM subdomains "
                "WHERE alive = 1 ORDER BY subdomain LIMIT 60"
            ).fetchall()
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"error": str(e)}, status_code=500)
    return [dict(r) for r in rows]


@router.get("/dash/queue")
def dash_queue():
    try:
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT id, method, url, ai_verdict FROM requests "
                "WHERE triage_status = 'sent_to_ai' ORDER BY created_at DESC LIMIT 20"
            ).fetchall()
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"error": str(e)}, status_code=500)
    return [dict(r) for r in rows]


class ScanRequest(BaseModel):
    domain: str
    no_nuclei: bool = False
    no_browser: bool = False


@router.post("/dash/scan")
def dash_scan(req: ScanRequest):
    """Telegram /scan ile ayni: autopwn.py'yi arka planda baslatir."""
    raw = (req.domain or "").strip()
    domain = raw.replace("https://", "").replace("http://", "").split("/")[0].lstrip("*.")
    if not _DOMAIN_RE.match(domain):
        return JSONResponse({"ok": False, "error": f"gecersiz domain: {domain}"},
                            status_code=400)
    cmd = [sys.executable, "autopwn.py", domain]
    if req.no_nuclei:
        cmd.append("--no-nuclei")
    if req.no_browser:
        cmd.append("--no-browser")
    try:
        subprocess.Popen(
            cmd,
            cwd=_PROJECT_DIR,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)
    return {"ok": True, "domain": domain}


# --------------------------------------------------------------------------
# Sayfa
# --------------------------------------------------------------------------
@router.get("/dashboard", response_class=HTMLResponse)
def dashboard_page():
    return _PAGE


_PAGE = r"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bug Bounty Control</title>
<style>
  :root{
    --bg:#0b0f14; --panel:#131a22; --panel2:#0f141b; --border:#232c38;
    --text:#e6edf3; --muted:#8b98a9; --accent:#39d353; --amber:#e3b341;
    --red:#f85149; --orange:#fb8500; --blue:#4493f8;
    --mono:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
    font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;font-size:14px}
  header{padding:14px 20px;border-bottom:1px solid var(--border);display:flex;
    align-items:center;gap:10px;position:sticky;top:0;background:var(--bg);z-index:5}
  header .dot{width:9px;height:9px;border-radius:50%;background:var(--accent);
    box-shadow:0 0 8px var(--accent);animation:pulse 2s infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
  header h1{font-size:15px;font-weight:600;margin:0;letter-spacing:.3px}
  header .sub{color:var(--muted);font-size:12px;margin-left:auto}
  .wrap{max-width:1200px;margin:0 auto;padding:18px 16px}
  .tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
  .tile{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:14px 16px}
  .tile .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.6px}
  .tile .v{font-size:26px;font-weight:700;margin-top:4px;font-variant-numeric:tabular-nums}
  .sev-row{display:flex;gap:6px;flex-wrap:wrap;margin-top:6px}
  .chip{font-size:11px;padding:2px 8px;border-radius:999px;font-weight:700;font-variant-numeric:tabular-nums}
  .c-critical{background:rgba(248,81,73,.16);color:var(--red)}
  .c-high{background:rgba(251,133,0,.16);color:var(--orange)}
  .c-medium{background:rgba(227,179,65,.16);color:var(--amber)}
  .c-low{background:rgba(68,147,248,.16);color:var(--blue)}
  .c-info{background:rgba(139,152,169,.16);color:var(--muted)}
  .controls{margin-top:16px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;
    background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:12px}
  input[type=text]{flex:1;min-width:200px;font-family:var(--mono);font-size:13px;
    border-radius:8px;border:1px solid var(--border);background:var(--panel2);
    color:var(--text);padding:9px 11px;outline:none}
  label.ck{color:var(--muted);font-size:12px;display:flex;align-items:center;gap:5px}
  button{background:var(--accent);color:#05140a;border:none;font-weight:700;
    cursor:pointer;padding:9px 18px;border-radius:8px;font:inherit}
  button:hover{filter:brightness(1.08)}
  .hint{color:var(--muted);font-size:12px;margin:8px 2px 0;min-height:16px}
  .grid{display:grid;grid-template-columns:1.3fr 1fr;gap:14px;margin-top:16px}
  @media(max-width:820px){.grid{grid-template-columns:1fr}}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:hidden}
  .card h2{font-size:12px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);
    margin:0;padding:11px 14px;border-bottom:1px solid var(--border);display:flex;
    justify-content:space-between;align-items:center}
  .card .n{color:var(--text);background:var(--panel2);border:1px solid var(--border);
    border-radius:999px;padding:1px 8px;font-size:11px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  td,th{padding:8px 14px;text-align:left;border-bottom:1px solid var(--border);
    vertical-align:top}
  th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.4px}
  tr:last-child td{border-bottom:none}
  .mono{font-family:var(--mono);font-size:12px;word-break:break-all}
  .sev-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
  .d-critical{background:var(--red)} .d-high{background:var(--orange)}
  .d-medium{background:var(--amber)} .d-low{background:var(--blue)} .d-info{background:var(--muted)}
  .src{color:var(--muted);font-size:11px}
  .empty{color:var(--muted);text-align:center;padding:26px 0;font-size:13px}
  .flash{animation:flash 1.2s ease-out}
  @keyframes flash{0%{background:rgba(57,211,83,.18)}100%{background:transparent}}
</style>
</head>
<body>
<header>
  <span class="dot"></span>
  <h1>Bug Bounty — Control Panel</h1>
  <span class="sub" id="sub">connecting…</span>
</header>
<div class="wrap">

  <div class="tiles" id="tiles"></div>

  <div class="controls">
    <input type="text" id="domain" placeholder="target domain (e.g. example.com) — IN-SCOPE ONLY"
           autocomplete="off" spellcheck="false">
    <label class="ck"><input type="checkbox" id="nonuclei"> --no-nuclei</label>
    <label class="ck"><input type="checkbox" id="nobrowser"> --no-browser</label>
    <button id="scanBtn">Run Scan</button>
  </div>
  <div class="hint" id="hint"></div>

  <div class="grid">
    <div class="card">
      <h2>Recon Findings <span class="n" id="fN">0</span></h2>
      <div id="findings"><div class="empty">loading…</div></div>
    </div>
    <div class="card">
      <h2>Triage Queue <span class="n" id="qN">0</span></h2>
      <div id="queue"><div class="empty">loading…</div></div>
    </div>
  </div>

  <div class="card" style="margin-top:14px">
    <h2>Live Subdomains <span class="n" id="sN">0</span></h2>
    <div id="subs"><div class="empty">loading…</div></div>
  </div>

</div>

<script>
const $ = (id)=>document.getElementById(id);
function esc(s){return String(s==null?"":s).replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}
let prevFindingIds = new Set();

async function j(url, opt){ const r = await fetch(url, opt); return r.json(); }

async function tick(){
  try{
    const [sum, fnd, q, subs] = await Promise.all([
      j("/dash/summary"), j("/dash/findings"), j("/dash/queue"), j("/dash/subs")
    ]);
    renderTiles(sum);
    renderFindings(fnd);
    renderQueue(q);
    renderSubs(subs);
    $("sub").textContent = "live • " + new Date().toLocaleTimeString();
  }catch(e){ $("sub").textContent = "offline"; }
}

function renderTiles(s){
  if(s.error){ return; }
  const sev = s.severity||{};
  const sevChips = ["critical","high","medium","low","info"]
    .map(k=>`<span class="chip c-${k}">${k[0].toUpperCase()}: ${sev[k]||0}</span>`).join("");
  $("tiles").innerHTML = `
    <div class="tile"><div class="k">Captured Requests</div><div class="v">${s.requests_total||0}</div></div>
    <div class="tile"><div class="k">Secrets</div><div class="v">${s.secrets||0}</div></div>
    <div class="tile"><div class="k">Subdomains (alive)</div><div class="v">${s.subs_alive||0}<span style="font-size:14px;color:var(--muted)"> / ${s.subs_total||0}</span></div></div>
    <div class="tile"><div class="k">Triage Queue</div><div class="v">${s.pending_triage||0}</div></div>
    <div class="tile"><div class="k">Reported</div><div class="v">${s.reported||0}</div></div>
    <div class="tile"><div class="k">By Severity</div><div class="sev-row">${sevChips}</div></div>`;
}

function renderFindings(rows){
  $("fN").textContent = rows.length||0;
  if(!rows.length){ $("findings").innerHTML = '<div class="empty">no recon findings yet</div>'; return; }
  let html = '<table><thead><tr><th>#</th><th>Finding</th><th>Location</th></tr></thead><tbody>';
  for(const r of rows){
    const sev = (r.severity||"info");
    const isNew = !prevFindingIds.has(r.id);
    html += `<tr class="${isNew?'flash':''}"><td class="src">${r.id}</td>`+
      `<td><span class="sev-dot d-${sev}"></span>${esc(r.name||r.source)}`+
      `<div class="src">${esc(r.source)} · ${sev}</div></td>`+
      `<td class="mono">${esc(r.matched_at||r.host)}</td></tr>`;
  }
  html += '</tbody></table>';
  $("findings").innerHTML = html;
  prevFindingIds = new Set(rows.map(r=>r.id));
}

function renderQueue(rows){
  $("qN").textContent = rows.length||0;
  if(!rows.length){ $("queue").innerHTML = '<div class="empty">nothing awaiting triage</div>'; return; }
  let html = '<table><thead><tr><th>#</th><th>Verdict</th><th>Request</th></tr></thead><tbody>';
  for(const r of rows){
    html += `<tr><td class="src">${r.id}</td><td>${esc(r.ai_verdict||"-")}</td>`+
      `<td class="mono">${esc(r.method)} ${esc((r.url||"").slice(0,70))}</td></tr>`;
  }
  html += '</tbody></table>';
  $("queue").innerHTML = html;
}

function renderSubs(rows){
  $("sN").textContent = rows.length||0;
  if(!rows.length){ $("subs").innerHTML = '<div class="empty">no subdomains yet — run a scan first</div>'; return; }
  let html = '<table><thead><tr><th>Subdomain</th><th>Code</th><th>Tech</th></tr></thead><tbody>';
  for(const r of rows){
    html += `<tr><td class="mono">${esc(r.subdomain)}</td>`+
      `<td class="src">${r.status_code||""}</td>`+
      `<td class="src">${esc(r.tech||"")}</td></tr>`;
  }
  html += '</tbody></table>';
  $("subs").innerHTML = html;
}

async function startScan(){
  const domain = $("domain").value.trim();
  if(!domain){ $("hint").textContent = "Enter a domain."; return; }
  $("scanBtn").disabled = true; $("hint").textContent = "starting…";
  try{
    const res = await j("/dash/scan", {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({domain, no_nuclei:$("nonuclei").checked, no_browser:$("nobrowser").checked})
    });
    if(res.ok){ $("hint").textContent = "✓ Scan started: "+res.domain+" — findings will appear below live."; }
    else { $("hint").textContent = "✗ "+(res.error||"rejected"); }
  }catch(e){ $("hint").textContent = "request failed"; }
  $("scanBtn").disabled = false;
}

$("scanBtn").addEventListener("click", startScan);
$("domain").addEventListener("keydown", e=>{ if(e.key==="Enter") startScan(); });
tick();
setInterval(tick, 4000);
</script>
</body>
</html>"""
