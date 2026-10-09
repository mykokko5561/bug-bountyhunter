"""
recon_pipeline.py — Layer 0 -> Layer 1 zincirini sırayla çalıştırır.
Telegram /recon komutu bunu arka planda başlatır.
Bitince Telegram'a özet mesaj atar (env'de token+chat_id varsa).

CLI:
    python recon_pipeline.py bykea.net
    python recon_pipeline.py bykea.net --no-nuclei
"""

import argparse
import asyncio
import os
import sys

import httpx

import layer0_recon
import layer1_scan


def _notify_telegram(text: str) -> None:
    """Bitiş özetini Telegram'a yollar. Token/chat_id yoksa sessizce geçer."""
    token = os.environ.get("BUGBOUNTY_TG_TOKEN")
    chat_id = os.environ.get("BUGBOUNTY_TG_CHAT_ID")
    if not token or not chat_id:
        return
    try:
        httpx.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"},
            timeout=10.0,
        )
    except httpx.HTTPError:
        pass


async def run(domain: str, do_nuclei: bool = True) -> None:
    r0 = await layer0_recon.run_recon(domain)
    r1 = await layer1_scan.run_scan(root=domain, do_nuclei=do_nuclei)
    _notify_telegram(
        f"✅ <b>Recon bitti: {domain}</b>\n"
        f"🌐 Subdomain: {r0['total_found']} ({r0['new_saved']} yeni)\n"
        f"📡 Canlı: {r1['alive']}\n"
        f"🔎 Nuclei bulgu: {r1['findings']}\n\n"
        f"Detay: /subs {domain}  ve  /findings"
    )


def main() -> None:
    p = argparse.ArgumentParser(description="Recon pipeline: Layer 0 -> Layer 1")
    p.add_argument("domain")
    p.add_argument("--no-nuclei", action="store_true")
    args = p.parse_args()
    asyncio.run(run(args.domain, not args.no_nuclei))


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    main()
