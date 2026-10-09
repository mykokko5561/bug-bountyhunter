"""
layer0_recon.py — Katman 0: Subdomain Discovery
crt.sh (passive CT logları) + DNS brute force.
Bulunan subdomainleri merkezi DB'deki `subdomains` tablosuna yazar.

Sadece scope'a dahil (in-scope) domainlere karşı çalıştır.

CLI:
    python layer0_recon.py bykea.net
    python layer0_recon.py bykea.net --no-crtsh
    python layer0_recon.py bykea.net -w wordlist.txt

Bağımlılıklar: httpx, dnspython
"""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timezone

import httpx

# Merkezi DB katmanı (tek kaynak)
from database import init_db, get_connection

try:
    import dns.asyncresolver
    import dns.resolver
    import dns.exception
    _HAS_DNS = True
except ImportError:
    _HAS_DNS = False


# --------------------------------------------------------------------------- #
# Ayarlar
# --------------------------------------------------------------------------- #
DNS_CONCURRENCY = 200        # eşzamanlı DNS sorgusu (yüksek = hızlı)
DNS_TIMEOUT = 2.0            # çözülmeyen isim bu kadar bekler
CRTSH_TIMEOUT = 60.0
PROGRESS_EVERY = 50          # kaç sorguda bir ilerleme yazsın

DEFAULT_WORDLIST = [
    "www", "api", "app", "apps", "dev", "development", "stage", "staging",
    "test", "testing", "qa", "uat", "beta", "alpha", "demo", "sandbox",
    "admin", "administrator", "portal", "dashboard", "panel", "console",
    "auth", "login", "sso", "oauth", "account", "accounts", "id", "identity",
    "gateway", "gw", "proxy", "edge", "cdn", "static", "assets", "media",
    "img", "images", "files", "upload", "uploads", "download", "downloads",
    "db", "database", "sql", "mysql", "postgres", "redis", "mongo", "elastic",
    "internal", "intranet", "corp", "private", "secure", "vpn",
    "mail", "smtp", "imap", "pop", "webmail", "mx",
    "git", "gitlab", "github", "jenkins", "ci", "cd", "build", "deploy",
    "docker", "registry", "k8s", "kube", "kubernetes",
    "monitor", "monitoring", "grafana", "prometheus", "metrics", "status",
    "log", "logs", "logging", "kibana", "splunk",
    "backup", "backups", "old", "legacy", "archive", "tmp", "temp",
    "mobile", "m", "wap", "ios", "android", "bff",
    "payment", "payments", "pay", "billing", "invoice", "invoices", "checkout",
    "order", "orders", "cart", "shop", "store", "market",
    "user", "users", "customer", "customers", "member", "members",
    "driver", "drivers", "partner", "partners", "vendor", "merchant",
    "map", "maps", "geo", "geocode", "location", "track", "tracking",
    "notify", "notification", "push", "sms", "email",
    "config", "configuration", "settings", "conf",
    "docs", "doc", "wiki", "support", "help", "faq",
    "ws", "websocket", "socket", "stream", "rtc", "signal",
    "v1", "v2", "v3", "api-v1", "api-v2", "public", "external",
    "kong", "raptor", "loadboard", "kronos", "tomoe", "nominatim",  # bykea-özel
]


# --------------------------------------------------------------------------- #
# DB yardımcıları (merkezi get_connection üzerinden)
# --------------------------------------------------------------------------- #
def save_subdomain(root: str, subdomain: str, source: str,
                   resolved_ip: str | None = None) -> bool:
    """Yeni subdomain ekler. Zaten varsa False (dedup). INSERT OR IGNORE
    kullanır: UNIQUE çakışmasında exception fırlatmaz, log kirletmez."""
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT OR IGNORE INTO subdomains (root, subdomain, source, resolved_ip, first_seen) "
            "VALUES (?, ?, ?, ?, ?)",
            (root, subdomain.lower().strip(), source, resolved_ip, now),
        )
        conn.commit()
        return cur.rowcount > 0


# --------------------------------------------------------------------------- #
# Kaynak 1: crt.sh (passive)
# --------------------------------------------------------------------------- #
async def enum_crtsh(root: str) -> set[str]:
    found: set[str] = set()
    url = f"https://crt.sh/?q=%25.{root}&output=json"
    try:
        async with httpx.AsyncClient(timeout=CRTSH_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                print(f"[crt.sh] HTTP {resp.status_code} — atlanıyor")
                return found
            try:
                data = resp.json()
            except json.JSONDecodeError:
                data = []
                for line in resp.text.splitlines():
                    line = line.strip().rstrip(",")
                    if line.startswith("{"):
                        try:
                            data.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            for cert in data:
                for name in cert.get("name_value", "").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(root) and name != root:
                        found.add(name)
    except (httpx.HTTPError, httpx.TimeoutException) as exc:
        print(f"[crt.sh] hata: {exc}")
    print(f"[crt.sh] {len(found)} subdomain bulundu")
    return found


# --------------------------------------------------------------------------- #
# Kaynak 2: DNS brute
# --------------------------------------------------------------------------- #
async def _resolve_one(resolver, host: str, sem: asyncio.Semaphore):
    async with sem:
        for rdtype in ("A", "AAAA"):
            try:
                answer = await resolver.resolve(host, rdtype)
                return host, answer[0].to_text()
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except (dns.resolver.Timeout, dns.exception.DNSException):
                continue
    return None


async def enum_dns_brute(root: str, wordlist: list[str]) -> set[tuple[str, str]]:
    if not _HAS_DNS:
        print("[dns] dnspython kurulu değil — `pip install dnspython`")
        return set()
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    sem = asyncio.Semaphore(DNS_CONCURRENCY)
    tasks = [_resolve_one(resolver, f"{w}.{root}", sem) for w in wordlist]
    total = len(tasks)
    done = 0
    results: set[tuple[str, str]] = set()
    print(f"[dns] {total} isim deneniyor ({DNS_CONCURRENCY} eşzamanlı, {DNS_TIMEOUT}s timeout)...")
    for coro in asyncio.as_completed(tasks):
        res = await coro
        done += 1
        if res:
            results.add(res)
            print(f"[dns] ✓ {res[0]} -> {res[1]}")
        if done % PROGRESS_EVERY == 0 or done == total:
            pct = round(done / total * 100)
            print(f"[dns] … {done}/{total} (%{pct}) — {len(results)} bulundu")
    print(f"[dns] {len(results)} subdomain çözümlendi")
    return results


# --------------------------------------------------------------------------- #
# Koordinatör
# --------------------------------------------------------------------------- #
async def run_recon(root: str, wordlist: list[str] | None = None,
                    use_crtsh: bool = True, use_dns: bool = True) -> dict:
    root = root.lower().strip().lstrip("*.")
    wordlist = wordlist or DEFAULT_WORDLIST
    init_db()  # merkezi şema garanti (standalone çalıştırma için)

    print(f"\n{'='*60}\n  RECON: {root}  (crt.sh={use_crtsh}, dns={use_dns}/{len(wordlist)})\n{'='*60}\n")

    all_subs: dict[str, dict] = {}
    if use_crtsh:
        for sub in await enum_crtsh(root):
            all_subs.setdefault(sub, {"source": "crtsh", "ip": None})
    if use_dns:
        for sub, ip in await enum_dns_brute(root, wordlist):
            if sub in all_subs:
                all_subs[sub]["ip"] = ip
                all_subs[sub]["source"] = "crtsh+dns"
            else:
                all_subs[sub] = {"source": "dns", "ip": ip}

    new_count = sum(
        save_subdomain(root, sub, meta["source"], meta["ip"])
        for sub, meta in all_subs.items()
    )

    print(f"\n{'='*60}\n  BİTTİ: {len(all_subs)} toplam, {new_count} yeni\n{'='*60}\n")
    return {"root": root, "total_found": len(all_subs),
            "new_saved": new_count, "subdomains": sorted(all_subs)}


def _load_wordlist(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return [w.strip() for w in fh if w.strip() and not w.startswith("#")]


async def _main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="Layer 0 — Subdomain Discovery")
    p.add_argument("domain")
    p.add_argument("-w", "--wordlist")
    p.add_argument("--no-crtsh", action="store_true")
    p.add_argument("--no-dns", action="store_true")
    args = p.parse_args()
    wl = _load_wordlist(args.wordlist) if args.wordlist else None
    summary = await run_recon(args.domain, wl, not args.no_crtsh, not args.no_dns)
    print("Subdomainler:")
    for s in summary["subdomains"]:
        print(f"  {s}")


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(_main())
