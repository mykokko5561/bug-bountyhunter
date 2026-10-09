"""
layer1_scan.py — Katman 1: Active Recon (Alive Check + Nuclei)
Layer 0'ın bulduğu subdomainleri işler:
  1) Alive check (kendi httpx kodumuz): status, title, server, tech, final_url
  2) Nuclei (subprocess, opsiyonel): canlı hostlara tarama
Bulgular merkezi DB'deki `recon_findings` tablosuna yazılır.
`subdomains` tablosundaki alive/status_code vb. güncellenir.

CLI:
    python layer1_scan.py -r bykea.net
    python layer1_scan.py -r bykea.net --no-nuclei
    python layer1_scan.py --unchecked

Bağımlılıklar: httpx  |  nuclei (opsiyonel, PATH'te)
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import sys
import tempfile
import warnings
from datetime import datetime, timezone
from pathlib import Path

import httpx

from database import init_db, get_connection

HTTP_CONCURRENCY = 50
HTTP_TIMEOUT = 10.0

NUCLEI_BIN = "nuclei"
NUCLEI_RATE_LIMIT = 50          # saniyede istek — nazik ol (WAF/ban riski)
NUCLEI_SEVERITY = "info,low,medium,high,critical"
NUCLEI_TIMEOUT_S = 1800

_FINGERPRINTS = {
    "server": {"nginx": "nginx", "apache": "Apache", "cloudflare": "Cloudflare",
               "kong": "Kong Gateway", "envoy": "Envoy", "gunicorn": "Gunicorn",
               "kestrel": "ASP.NET Kestrel"},
    "x-powered-by": {"express": "Express.js", "php": "PHP",
                     "asp.net": "ASP.NET", "next.js": "Next.js"},
}


# --------------------------------------------------------------------------- #
# DB
# --------------------------------------------------------------------------- #
def get_subdomains(root: str | None = None, only_unchecked: bool = False) -> list[str]:
    q, params, conds = "SELECT subdomain FROM subdomains", [], []
    if root:
        conds.append("root = ?"); params.append(root)
    if only_unchecked:
        conds.append("last_checked IS NULL")
    if conds:
        q += " WHERE " + " AND ".join(conds)
    with get_connection() as conn:
        return [r["subdomain"] for r in conn.execute(q, params).fetchall()]


def save_finding(host: str, source: str, severity: str,
                 name: str, matched_at: str, raw: str) -> None:
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO recon_findings (host, source, severity, name, matched_at, raw, found_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (host, source, severity, name, matched_at, raw,
             datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()


def update_alive(sub: str, alive: bool, status, title, server, tech, final_url) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE subdomains SET alive=?, status_code=?, title=?, server=?, "
            "tech=?, final_url=?, last_checked=? WHERE subdomain=?",
            (int(alive), status, title, server, tech, final_url,
             datetime.now(timezone.utc).isoformat(), sub),
        )
        conn.commit()


# --------------------------------------------------------------------------- #
# Alive check
# --------------------------------------------------------------------------- #
def _extract_title(html: str) -> str | None:
    lo = html.lower()
    i = lo.find("<title")
    if i == -1:
        return None
    j, k = lo.find(">", i), lo.find("</title>", i)
    if j == -1 or k == -1:
        return None
    return html[j + 1:k].strip()[:200] or None


def _fingerprint(headers: httpx.Headers) -> str | None:
    found = []
    for header, rules in _FINGERPRINTS.items():
        val = headers.get(header, "").lower()
        for needle, label in rules.items():
            if needle in val:
                found.append(label)
    if "kong" in headers.get("via", "").lower() or headers.get("x-kong-upstream-latency"):
        found.append("Kong Gateway")
    return ", ".join(sorted(set(found))) or None


async def _check_one(client, sub: str, sem: asyncio.Semaphore) -> dict:
    async with sem:
        for scheme in ("https", "http"):
            try:
                r = await client.get(f"{scheme}://{sub}")
                body = r.text if len(r.content) < 500_000 else ""
                return {"sub": sub, "alive": True, "status": r.status_code,
                        "title": _extract_title(body), "server": r.headers.get("server"),
                        "tech": _fingerprint(r.headers), "final_url": str(r.url)}
            except (httpx.HTTPError, httpx.TimeoutException):
                continue
        return {"sub": sub, "alive": False, "status": None, "title": None,
                "server": None, "tech": None, "final_url": None}


async def alive_check(subs: list[str]) -> list[str]:
    print(f"[alive] {len(subs)} host kontrol ediliyor...")
    sem = asyncio.Semaphore(HTTP_CONCURRENCY)
    limits = httpx.Limits(max_connections=HTTP_CONCURRENCY)
    alive_hosts: list[str] = []
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True,
                                 verify=False, limits=limits,
                                 headers={"User-Agent": "Mozilla/5.0 (compatible; recon/1.0)"}) as client:
        for coro in asyncio.as_completed([_check_one(client, s, sem) for s in subs]):
            res = await coro
            update_alive(res["sub"], res["alive"], res["status"],
                         res["title"], res["server"], res["tech"], res["final_url"])
            if res["alive"]:
                alive_hosts.append(res["final_url"])
                tech = f" [{res['tech']}]" if res["tech"] else ""
                print(f"[alive] {res['status']} {res['final_url']}{tech}")
    print(f"[alive] {len(alive_hosts)}/{len(subs)} canlı")
    return alive_hosts


# --------------------------------------------------------------------------- #
# Nuclei
# --------------------------------------------------------------------------- #
def run_nuclei(targets: list[str]) -> int:
    if not shutil.which(NUCLEI_BIN):
        print(f"[nuclei] '{NUCLEI_BIN}' PATH'te yok — tarama atlandı")
        return 0
    if not targets:
        print("[nuclei] canlı hedef yok")
        return 0

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as tf:
        tf.write("\n".join(targets))
        targets_file = tf.name
    out_file = targets_file + ".jsonl"
    cmd = [NUCLEI_BIN, "-list", targets_file, "-jsonl", "-o", out_file,
           "-rate-limit", str(NUCLEI_RATE_LIMIT), "-severity", NUCLEI_SEVERITY,
           "-silent", "-no-color"]
    print(f"[nuclei] {len(targets)} hedef taranıyor (rate={NUCLEI_RATE_LIMIT}/s)...")
    try:
        subprocess.run(cmd, timeout=NUCLEI_TIMEOUT_S, check=False)
    except subprocess.TimeoutExpired:
        print("[nuclei] zaman aşımı — kısmi sonuçlar")
    except Exception as exc:  # noqa: BLE001
        print(f"[nuclei] hata: {exc}")
        return 0

    count = 0
    try:
        with open(out_file, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                info = obj.get("info", {})
                save_finding(obj.get("host", ""), "nuclei",
                             info.get("severity", "unknown"),
                             info.get("name", obj.get("template-id", "")),
                             obj.get("matched-at", ""), line)
                count += 1
                print(f"[nuclei] [{info.get('severity','?').upper()}] "
                      f"{info.get('name','')} @ {obj.get('matched-at','')}")
    except FileNotFoundError:
        pass
    finally:
        for f in (targets_file, out_file):
            try:
                Path(f).unlink()
            except OSError:
                pass
    print(f"[nuclei] {count} bulgu")
    return count


# --------------------------------------------------------------------------- #
# Koordinatör
# --------------------------------------------------------------------------- #
async def run_scan(root: str | None = None, only_unchecked: bool = False,
                   do_nuclei: bool = True) -> dict:
    init_db()
    subs = get_subdomains(root, only_unchecked)
    if not subs:
        print("[scan] subdomain yok — önce Layer 0'ı çalıştır")
        return {"alive": 0, "findings": 0}
    print(f"\n{'='*60}\n  SCAN: {root or 'tüm kökler'} ({len(subs)} subdomain)\n{'='*60}\n")
    alive_hosts = await alive_check(subs)
    findings = run_nuclei(alive_hosts) if do_nuclei else 0
    print(f"\n{'='*60}\n  BİTTİ: {len(alive_hosts)} canlı, {findings} bulgu\n{'='*60}\n")
    return {"alive": len(alive_hosts), "findings": findings}


async def _main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="Layer 1 — Alive Check + Nuclei")
    p.add_argument("-r", "--root")
    p.add_argument("--unchecked", action="store_true")
    p.add_argument("--no-nuclei", action="store_true")
    args = p.parse_args()
    await run_scan(args.root, args.unchecked, not args.no_nuclei)


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    warnings.filterwarnings("ignore")
    asyncio.run(_main())
