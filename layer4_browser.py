"""
layer4_browser.py — Katman 4: Otonom Tarayıcı Crawler (Playwright)
Gerçek Chromium kullanır -> Cloudflare/WAF'ı geçer, SPA/JS render eder,
TÜM ağ isteklerini (XHR/fetch dahil) otomatik yakalar ve FastAPI /ingest'e
yollar. Mevcut requests-tabanlı crawler.py'nin Cloudflare'a takılan yerini
çözer. Tamamen otonom çalışır.

İki mod:
  1) --login  : Tarayıcı açılır, SEN bir kez elle giriş yaparsın (OTP dahil),
                oturum bykea_session.json'a kaydedilir. (Auth gereken hedefler için)
  2) (varsayılan/crawl) : Kaydedilmiş oturumla otonom gezer, API çağrılarını
                          yakalar. Oturum yoksa anonim gezer.

Kurulum (bir kez):
    pip install playwright
    playwright install chromium

CLI:
    python layer4_browser.py --login https://pay.bykea.com
    python layer4_browser.py https://pay.bykea.com --depth 2
    python layer4_browser.py https://pay.bykea.com --headless --source bykea
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections import deque
from urllib.parse import urljoin, urlparse

import httpx

try:
    from playwright.async_api import async_playwright
    _HAS_PW = True
except ImportError:
    _HAS_PW = False

# playwright-stealth: otomasyon izini gizler -> Cloudflare/WAF gerçek Chrome sanır.
# Kur: pip install playwright-stealth
try:
    from playwright_stealth import stealth_async
    _HAS_STEALTH = True
except Exception:  # noqa: BLE001
    _HAS_STEALTH = False

INGEST_URL = "http://127.0.0.1:8000/ingest"
SESSION_FILE = "bykea_session.json"
MAX_PAGES = 40  # kontrolsüz crawl'ı önler; büyük sitelerde bu kadar sayfada durur

# Cloudflare/WAF bypass: otomasyon bayraklarını kapat + gerçekçi UA
_STEALTH_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--disable-features=IsolateOrigins,site-per-process",
    "--no-sandbox",
]
_REAL_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


async def _launch_browser(pw, headless):
    """Gerçek Chrome kanalını dener (fingerprint gerçek), yoksa Chromium.
    Otomasyon izini azaltan args ile."""
    for ch in ("chrome", "msedge", None):
        try:
            kwargs = {"headless": headless, "args": _STEALTH_ARGS}
            if ch:
                kwargs["channel"] = ch
            b = await pw.chromium.launch(**kwargs)
            print(f"[browser] kanal: {ch or 'chromium'}" + (" +stealth" if _HAS_STEALTH else ""))
            return b
        except Exception:  # noqa: BLE001
            continue
    return await pw.chromium.launch(headless=headless)


def _real_context_opts(extra: dict | None = None) -> dict:
    """Gerçekçi tarayıcı context ayarları (WAF'ı yumuşatır)."""
    opts = {
        "user_agent": _REAL_UA,
        "viewport": {"width": 1366, "height": 768},
        "locale": "en-US",
        "timezone_id": "Europe/Istanbul",
    }
    if extra:
        opts.update(extra)
    return opts


async def _prep_page(page):
    """Sayfaya stealth uygula (varsa) — navigator.webdriver vs. gizle."""
    if _HAS_STEALTH:
        try:
            await stealth_async(page)
        except Exception:  # noqa: BLE001
            pass

SKIP_EXT = {".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".mp4"}

# Bu tiplerdeki istekleri yakala (asıl API trafiği)
CAPTURE_TYPES = {"xhr", "fetch", "document", "script"}


def _skip(url: str) -> bool:
    return any(urlparse(url).path.lower().endswith(e) for e in SKIP_EXT)


async def _ingest(client: httpx.AsyncClient, method: str, url: str,
                  headers: dict, body: str | None, source: str,
                  status_code: int | None = None,
                  response_size: int | None = None) -> None:
    """Yakalanan istek+cevabı FastAPI /ingest'e yollar (mevcut pipeline)."""
    try:
        await client.post(INGEST_URL, json={
            "method": method, "url": url, "host": urlparse(url).netloc,
            "headers": {k: v for k, v in headers.items()
                        if k.lower() not in ("cookie", "set-cookie")},
            "body": body, "source_program": source,
            "status_code": status_code, "response_size": response_size,
        }, timeout=5)
    except httpx.HTTPError:
        pass


# --------------------------------------------------------------------------- #
# Login modu — oturumu kaydet
# --------------------------------------------------------------------------- #
async def login_mode(start_url: str) -> None:
    if not _HAS_PW:
        print("[browser] playwright yok — `pip install playwright && playwright install chromium`")
        return
    async with async_playwright() as pw:
        browser = await _launch_browser(pw, headless=False)
        context = await browser.new_context(**_real_context_opts())
        page = await context.new_page()
        await _prep_page(page)
        await page.goto(start_url)
        print("\n" + "=" * 60)
        print("  TARAYICI AÇILDI — elle GİRİŞ YAP (telefon, OTP, vs.)")
        print("  Giriş bitince bu terminale dön ve ENTER'a bas.")
        print("=" * 60 + "\n")
        # Terminalden ENTER bekle (async ortamda)
        await asyncio.get_event_loop().run_in_executor(None, input)
        await context.storage_state(path=SESSION_FILE)
        print(f"[browser] oturum kaydedildi -> {SESSION_FILE}")
        await browser.close()


# --------------------------------------------------------------------------- #
# Crawl modu — otonom gez + yakala
# --------------------------------------------------------------------------- #
async def crawl_mode(start_url: str, depth: int, headless: bool,
                     source: str, use_session: bool) -> None:
    if not _HAS_PW:
        print("[browser] playwright yok — `pip install playwright && playwright install chromium`")
        return

    base_domain = urlparse(start_url).netloc
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(start_url, 0)])
    captured = 0

    async with httpx.AsyncClient() as ingest_client:
        async with async_playwright() as pw:
            browser = await _launch_browser(pw, headless=headless)
            ctx_kwargs = {}
            if use_session:
                import os
                if os.path.exists(SESSION_FILE):
                    ctx_kwargs["storage_state"] = SESSION_FILE
                    print(f"[browser] oturum yüklendi: {SESSION_FILE}")
                else:
                    print(f"[browser] {SESSION_FILE} yok — anonim geziliyor")
            context = await browser.new_context(**_real_context_opts(ctx_kwargs))
            page = await context.new_page()
            await _prep_page(page)

            # TÜM istek+cevapları yakala (response event'i ikisini birden verir)
            async def on_response(resp):
                nonlocal captured
                # Tüm gövde try/except içinde: tarayıcı kapanınca (TargetClosedError)
                # sessizce geç, hata yığını basma.
                try:
                    req = resp.request
                    if req.resource_type not in CAPTURE_TYPES or _skip(req.url):
                        return
                    body = None
                    if req.method in ("POST", "PUT", "PATCH"):
                        try:
                            body = req.post_data
                        except Exception:  # noqa: BLE001
                            body = None
                    resp_size = None
                    try:
                        resp_size = len(await resp.body())
                    except Exception:  # noqa: BLE001
                        pass
                    try:
                        headers = await req.all_headers()
                    except Exception:  # noqa: BLE001
                        headers = {}
                    await _ingest(ingest_client, req.method, req.url,
                                  headers, body, source,
                                  status_code=resp.status, response_size=resp_size)
                    captured += 1
                except Exception:  # noqa: BLE001
                    pass  # kapanış sırasındaki kalıntı event'leri yut

            page.on("response", lambda resp: asyncio.create_task(on_response(resp)))

            print(f"\n{'='*60}\n  OTONOM CRAWL: {start_url} (derinlik={depth}, headless={headless})\n{'='*60}\n")

            while queue:
                if len(visited) >= MAX_PAGES:
                    print(f"[browser] sayfa limiti ({MAX_PAGES}) doldu — duruyor")
                    break
                url, d = queue.popleft()
                if url in visited or d > depth or _skip(url):
                    continue
                visited.add(url)
                try:
                    # domcontentloaded: erken tetiklenir, kalıcı bağlantılarda takılmaz
                    await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                    # XHR/fetch çağrılarının tetiklenip yakalanması için bekle
                    await page.wait_for_timeout(4000)
                    print(f"[browser] ({d}) {url[:80]} — toplam {captured} istek yakalandı")
                    if d >= depth:
                        continue
                    # Sayfadaki aynı-domain linkleri topla
                    hrefs = await page.eval_on_selector_all(
                        "a[href]", "els => els.map(e => e.href)")
                    for href in hrefs:
                        full = urljoin(url, href)
                        if urlparse(full).netloc == base_domain and full not in visited:
                            queue.append((full, d + 1))
                except Exception as exc:  # noqa: BLE001
                    print(f"[browser] hata ({url[:60]}): {str(exc)[:80]}")
                    continue

            print(f"\n{'='*60}\n  BİTTİ: {len(visited)} sayfa, {captured} istek yakalandı -> /ingest\n{'='*60}\n")
            await browser.close()


async def _main() -> None:
    p = argparse.ArgumentParser(description="Layer 4 — Otonom Tarayıcı Crawler (Playwright)")
    p.add_argument("url", help="Başlangıç URL")
    p.add_argument("--login", action="store_true",
                   help="Login modu: elle giriş yap, oturumu kaydet")
    p.add_argument("--depth", type=int, default=2, help="Crawl derinliği")
    p.add_argument("--headless", action="store_true", help="Görünmez tarayıcı")
    p.add_argument("--no-session", action="store_true",
                   help="Kaydedilmiş oturumu kullanma (anonim gez)")
    p.add_argument("--source", default="browser", help="Kaynak program adı")
    args = p.parse_args()

    if args.login:
        await login_mode(args.url)
    else:
        await crawl_mode(args.url, args.depth, args.headless,
                         args.source, not args.no_session)


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    asyncio.run(_main())
