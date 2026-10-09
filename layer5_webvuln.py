"""
layer5_webvuln.py — Katman 5: Web Açık Kontrolleri (auth/Cloudflare gerektirmez)
Keşfedilen subdomainlere karşı otomatik, düşük-gürültü web açık testleri:

  1) Subdomain Takeover  : CNAME boşta kalan servise işaret ediyor mu?
                           (GitHub Pages, S3, Heroku, Azure, Fastly, vb. parmak izleri)
  2) CORS Misconfig      : Origin: evil.com yansıtılıyor + credentials açık mı?
  3) Sensitive Paths     : /.git/config, /.env, /swagger.json gibi açık dosyalar
                           (gerçekçi tarayıcı header'ları ile — CF 403'ü azaltır)

Bulgular merkezi DB'ye (recon_findings, source='webvuln') yazılır.
Sadece scope'a dahil hedeflerde çalıştır.

CLI:
    python layer5_webvuln.py -r bykea.net
    python layer5_webvuln.py -r bykea.com --only cors
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import warnings
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from database import init_db, get_connection

try:
    import dns.asyncresolver
    import dns.resolver
    import dns.exception
    _HAS_DNS = True
except ImportError:
    _HAS_DNS = False

HTTP_TIMEOUT = 12.0
CONCURRENCY = 30

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/128.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# Subdomain takeover parmak izleri: (CNAME içinde geçen ifade, yanıt gövdesindeki imza)
TAKEOVER_FINGERPRINTS = [
    ("github.io", "There isn't a GitHub Pages site here"),
    ("herokuapp.com", "No such app"),
    ("herokudns.com", "No such app"),
    ("s3.amazonaws.com", "NoSuchBucket"),
    ("amazonaws.com", "The specified bucket does not exist"),
    ("azurewebsites.net", "404 Web Site not found"),
    ("cloudapp.net", "404 Web Site not found"),
    ("fastly.net", "Fastly error: unknown domain"),
    ("ghost.io", "The thing you were looking for is no longer here"),
    ("cargocollective.com", "404 Not Found"),
    ("wpengine.com", "The site you were looking for couldn't be found"),
    ("pantheonsite.io", "The gods are wise"),
    ("surge.sh", "project not found"),
    ("bitbucket.io", "Repository not found"),
    ("readme.io", "Project doesnt exist"),
    ("zendesk.com", "Help Center Closed"),
    ("netlify.app", "Not Found - Request ID"),
]

SENSITIVE_PATHS = [
    "/.git/config", "/.env", "/.env.local", "/config.json", "/swagger.json",
    "/swagger-ui.html", "/api/swagger.json", "/openapi.json", "/.well-known/security.txt",
    "/actuator", "/actuator/health", "/actuator/env", "/server-status",
    "/.aws/credentials", "/backup.zip", "/db.sql", "/phpinfo.php",
    "/api/v1", "/graphql", "/metrics", "/debug", "/status",
]


# --------------------------------------------------------------------------- #
# DB
# --------------------------------------------------------------------------- #
def get_hosts(root: str | None, only_alive: bool = False) -> list[str]:
    q, params, conds = "SELECT subdomain, alive FROM subdomains", [], []
    if root:
        conds.append("root = ?"); params.append(root)
    if only_alive:
        conds.append("alive = 1")
    if conds:
        q += " WHERE " + " AND ".join(conds)
    with get_connection() as conn:
        return [r["subdomain"] for r in conn.execute(q, params).fetchall()]


def save(host: str, severity: str, name: str, detail: str) -> None:
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO recon_findings (host, source, severity, name, matched_at, raw, found_at) "
            "VALUES (?, 'webvuln', ?, ?, ?, ?, ?)",
            (host, severity, name, detail, detail, datetime.now(timezone.utc).isoformat()))
        conn.commit()


# --------------------------------------------------------------------------- #
# 1) Subdomain Takeover
# --------------------------------------------------------------------------- #
async def check_takeover(hosts: list[str]) -> int:
    if not _HAS_DNS:
        print("[takeover] dnspython yok — atlanıyor")
        return 0
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    found = 0
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, verify=False,
                                 follow_redirects=True, headers=BROWSER_HEADERS) as client:
        for host in hosts:
            # CNAME çöz
            cname = None
            try:
                ans = await resolver.resolve(host, "CNAME")
                cname = str(ans[0].target).rstrip(".").lower()
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.Timeout, dns.exception.DNSException):
                continue
            if not cname:
                continue
            # CNAME bilinen bir servise mi işaret ediyor?
            for service, signature in TAKEOVER_FINGERPRINTS:
                if service in cname:
                    print(f"[takeover] {host} -> CNAME {cname} ({service}) — imza kontrol ediliyor")
                    try:
                        r = await client.get(f"https://{host}")
                        if signature.lower() in r.text.lower():
                            msg = f"{host} -> {cname} ({service}); imza bulundu: '{signature}'"
                            print(f"[takeover] ⚠  ELE GEÇİRİLEBİLİR: {msg}")
                            save(host, "high", f"Subdomain Takeover ({service})", msg)
                            found += 1
                    except (httpx.HTTPError, httpx.TimeoutException):
                        pass
                    break
    print(f"[takeover] {found} aday")
    return found


# --------------------------------------------------------------------------- #
# 2) CORS Misconfiguration
# --------------------------------------------------------------------------- #
async def check_cors(hosts: list[str]) -> int:
    evil = "https://evil-attacker.example.com"
    found = 0
    sem = asyncio.Semaphore(CONCURRENCY)

    async def one(client, host):
        nonlocal found
        async with sem:
            for scheme in ("https",):
                url = f"{scheme}://{host}/"
                try:
                    headers = dict(BROWSER_HEADERS)
                    headers["Origin"] = evil
                    r = await client.get(url, headers=headers)
                except (httpx.HTTPError, httpx.TimeoutException):
                    continue
                acao = r.headers.get("access-control-allow-origin", "")
                acac = r.headers.get("access-control-allow-credentials", "")
                # En tehlikeli: Origin yansıtılıyor + credentials true
                if acao == evil and acac.lower() == "true":
                    msg = f"{url} — ACAO yansıtıyor ({acao}) + ACAC:true — kimlikli CORS!"
                    print(f"[cors] ⚠  {msg}")
                    save(host, "high", "CORS: reflected origin + credentials", msg)
                    found += 1
                elif acao == "*" and acac.lower() == "true":
                    # spec dışı ama bazen görülür
                    msg = f"{url} — ACAO:* + ACAC:true (tarayıcı reddeder ama yanlış yapılandırma)"
                    print(f"[cors] {msg}")
                    save(host, "low", "CORS: wildcard + credentials", msg)
                    found += 1
                elif acao == evil:
                    msg = f"{url} — ACAO yansıtıyor ({acao}), credentials yok"
                    print(f"[cors] {msg}")
                    save(host, "medium", "CORS: reflected origin", msg)
                    found += 1

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, verify=False,
                                 follow_redirects=True) as client:
        await asyncio.gather(*[one(client, h) for h in hosts])
    print(f"[cors] {found} bulgu")
    return found


# --------------------------------------------------------------------------- #
# 3) Sensitive Paths
# --------------------------------------------------------------------------- #
async def check_paths(hosts: list[str]) -> int:
    found = 0
    sem = asyncio.Semaphore(CONCURRENCY)

    async def one(client, host, path):
        nonlocal found
        async with sem:
            url = f"https://{host}{path}"
            try:
                r = await client.get(url)
            except (httpx.HTTPError, httpx.TimeoutException):
                return
            # 200 + hata sayfası değil + Cloudflare challenge değil
            if r.status_code == 200 and "challenge-platform" not in r.text \
                    and len(r.text) > 20:
                # basit içerik doğrulaması
                lo = r.text.lower()
                is_real = any(k in lo for k in (
                    "[core]", "aws_", "swagger", "openapi", "\"paths\"",
                    "actuator", "password", "secret", "api_key", "<?php"))
                sev = "high" if is_real else "info"
                msg = f"{url} -> 200 ({len(r.text)} byte)"
                print(f"[paths] {'⚠  ' if is_real else ''}{msg}")
                save(host, sev, f"Açık path: {path}", msg)
                found += 1

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, verify=False,
                                 follow_redirects=False, headers=BROWSER_HEADERS) as client:
        tasks = [one(client, h, p) for h in hosts for p in SENSITIVE_PATHS]
        await asyncio.gather(*tasks)
    print(f"[paths] {found} bulgu")
    return found


# --------------------------------------------------------------------------- #
# Koordinatör
# --------------------------------------------------------------------------- #
async def run(root: str | None, only: str | None) -> dict:
    init_db()
    hosts = get_hosts(root)
    if not hosts:
        print("[webvuln] host yok — önce /recon çalıştır")
        return {}
    print(f"\n{'='*60}\n  WEB VULN: {root or 'tüm'} ({len(hosts)} host)\n{'='*60}\n")
    res = {}
    if only in (None, "takeover"):
        res["takeover"] = await check_takeover(hosts)
    if only in (None, "cors"):
        res["cors"] = await check_cors(hosts)
    if only in (None, "paths"):
        res["paths"] = await check_paths(hosts)
    print(f"\n{'='*60}\n  BİTTİ: {res}\n{'='*60}\n")
    return res


async def _main() -> None:
    p = argparse.ArgumentParser(description="Layer 5 — Web Vuln Checks")
    p.add_argument("-r", "--root")
    p.add_argument("--only", choices=["takeover", "cors", "paths"],
                   help="Sadece bu kontrolü çalıştır")
    args = p.parse_args()
    await run(args.root, args.only)


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    warnings.filterwarnings("ignore")
    asyncio.run(_main())
