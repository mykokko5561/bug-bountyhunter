"""
autopwn.py — TAM OTONOM PIPELINE
Telegram /scan <domain> komutu bunu çağırır. Tek komutla tüm zincir:

  1) Layer 0  — Subdomain discovery (crt.sh + DNS brute)
  2) Layer 1  — Alive check + Nuclei
  3) Layer 5  — Web vuln (takeover + CORS + açık path)
  4) Layer 4  — Otonom tarayıcı crawl (canlı hostlar) -> API yakala -> /ingest
                 -> Ollama triage -> (ilginçse) Telegram bildirim -> /idor

Her aşamada Telegram'a ilerleme mesajı atar (env'de token+chat_id varsa).

CLI:
    python autopwn.py bykea.com
    python autopwn.py bykea.com --no-nuclei --no-browser
    python autopwn.py bykea.com --depth 2
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import warnings

import httpx

import layer0_recon
import layer1_scan
import layer5_webvuln
import layer4_browser
from database import init_db, get_connection


def notify(text: str) -> None:
    """Telegram'a mesaj (token/chat_id yoksa sessiz geçer)."""
    token = os.environ.get("BUGBOUNTY_TG_TOKEN")
    chat_id = os.environ.get("BUGBOUNTY_TG_CHAT_ID")
    if not token or not chat_id:
        return
    try:
        httpx.post(f"https://api.telegram.org/bot{token}/sendMessage",
                   json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"},
                   timeout=10.0)
    except httpx.HTTPError:
        pass


def get_alive_urls(root: str, limit: int = 15) -> list[str]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT subdomain, final_url FROM subdomains "
            "WHERE root = ? AND alive = 1 LIMIT ?", (root, limit)).fetchall()
    return [r["final_url"] or f"https://{r['subdomain']}" for r in rows]


async def full_scan(domain: str, do_nuclei: bool = True, do_browser: bool = True,
                    depth: int = 1) -> None:
    domain = domain.lower().strip().lstrip("*.")
    init_db()
    notify(f"🚀 <b>Otonom tarama başladı:</b> {domain}")
    print(f"\n{'#'*60}\n#  AUTOPWN: {domain}\n{'#'*60}")

    # 1) Subdomain discovery
    r0 = await layer0_recon.run_recon(domain)
    notify(f"1/4 🌐 Subdomain: <b>{r0['total_found']}</b> bulundu ({r0['new_saved']} yeni)")

    # 2) Alive + Nuclei
    r1 = await layer1_scan.run_scan(root=domain, do_nuclei=do_nuclei)
    notify(f"2/4 📡 Canlı: <b>{r1['alive']}</b> | Nuclei bulgu: <b>{r1['findings']}</b>")

    # 3) Web vuln
    r5 = await layer5_webvuln.run(domain, None)
    tk = r5.get("takeover", 0); co = r5.get("cors", 0); pa = r5.get("paths", 0)
    notify(f"3/4 🔓 Web vuln: takeover={tk}, CORS={co}, path={pa}")

    # 4) Otonom browser crawl (canlı hostlar) -> API yakala
    total_pages = 0
    if do_browser:
        alive = get_alive_urls(domain)
        if alive:
            notify(f"4/4 🕷️ Browser crawl başladı ({len(alive)} host)…")
            for url in alive:
                try:
                    await layer4_browser.crawl_mode(
                        url, depth=depth, headless=True,
                        source=f"autopwn:{domain}", use_session=True)
                    total_pages += 1
                except Exception as exc:  # noqa: BLE001
                    print(f"[autopwn] crawl hatası ({url}): {str(exc)[:80]}")
            notify(f"4/4 🕷️ Browser crawl bitti ({total_pages} host tarandı)")
        else:
            notify("4/4 🕷️ Canlı host yok, browser crawl atlandı")

    notify(f"✅ <b>Otonom tarama bitti:</b> {domain}\n"
           f"Bulgular: /findings\nYakalanan istekler: /pending\n"
           f"Subdomainler: /subs {domain}")
    print(f"\n{'#'*60}\n#  AUTOPWN BİTTİ: {domain}\n{'#'*60}\n")


async def _main() -> None:
    p = argparse.ArgumentParser(description="autopwn — tam otonom pipeline")
    p.add_argument("domain")
    p.add_argument("--no-nuclei", action="store_true")
    p.add_argument("--no-browser", action="store_true")
    p.add_argument("--depth", type=int, default=1)
    args = p.parse_args()
    await full_scan(args.domain, not args.no_nuclei, not args.no_browser, args.depth)


if __name__ == "__main__":
    if sys.platform == "win32":
        # Playwright Windows'ta Proactor loop ister
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    warnings.filterwarnings("ignore")
    asyncio.run(_main())
