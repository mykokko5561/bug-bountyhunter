"""
layer6_apkfetch.py — Katman 6: Otonom APK İndir + Analiz + Sil
Telegram /apk <package> komutu bunu çağırır. Tam otonom:

  1) Playwright (gerçek Chromium) ile APKPure'den APK'yı indirir
     — Cloudflare'ı geçer, elle indirme/yükleme YOK
  2) layer3_apk ile static analiz (kod ÇALIŞTIRILMAZ — sadece string okuma)
  3) İş bitince APK'yı diskten SİLER (finally garantisi)

GÜVENLİK:
  - Static analiz: APK bir ZIP gibi okunur, Android bytecode asla çalıştırılmaz
    -> malware aktive olamaz (DEX sadece Android/emülatörde çalışır)
  - Zip-bomb koruması layer3'te (dosya-başı + toplam boyut limiti)
  - APK indirildiği geçici klasöre iner, analiz sonrası silinir
  - İzole ortamda (VPS/container) çalıştırmak ekstra güvenlik katmanıdır

CLI:
    python layer6_apkfetch.py com.myntra.android --root myntra.com
    python layer6_apkfetch.py com.bykea.pk

Bağımlılıklar: playwright (zaten kurulu)
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import tempfile

try:
    from playwright.async_api import async_playwright
    _HAS_PW = True
except ImportError:
    _HAS_PW = False

import layer3_apk

# APK boyut tavanı — bundan büyük indirmeyi reddet (disk + zip-bomb ön savunması)
MAX_APK_MB = 500


async def fetch_apk(package: str, out_dir: str) -> str | None:
    """
    APKPure'den paketi indirir (Playwright ile, Cloudflare geçerek).
    Başarılıysa APK dosya yolunu döner, olmazsa None.
    """
    if not _HAS_PW:
        print("[apkfetch] playwright yok — `pip install playwright && playwright install chromium`")
        return None

    # APKPure'ün indirme sayfaları (birkaç kalıp deneriz)
    candidate_urls = [
        f"https://apkpure.com/x/{package}/download",
        f"https://apkpure.com/{package}/download",
    ]

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=False)  # headed = Cloudflare'ı daha iyi geçer
        context = await browser.new_context(accept_downloads=True)
        page = await context.new_page()

        for url in candidate_urls:
            try:
                print(f"[apkfetch] deneniyor: {url}")
                await page.goto(url, wait_until="domcontentloaded", timeout=45000)
                await page.wait_for_timeout(5000)  # Cloudflare + sayfa yüklensin

                # İndirme linkini/butonunu bul (birkaç olası seçici)
                selectors = [
                    "a.download-start-btn",
                    "a#download_link",
                    "a[href*='d.apkpure']",
                    "a.da",
                    "a[href$='.apk']",
                    "a[href*='XAPK']",
                ]
                clicked = False
                for sel in selectors:
                    el = await page.query_selector(sel)
                    if el:
                        try:
                            async with page.expect_download(timeout=120000) as dl_info:
                                await el.click()
                            download = await dl_info.value
                            fname = download.suggested_filename or f"{package}.apk"
                            path = os.path.join(out_dir, fname)
                            await download.save_as(path)
                            size_mb = os.path.getsize(path) / 1048576
                            if size_mb > MAX_APK_MB:
                                print(f"[apkfetch] APK çok büyük ({size_mb:.0f}MB > {MAX_APK_MB}MB) — reddedildi")
                                os.remove(path)
                                await browser.close()
                                return None
                            print(f"[apkfetch] indirildi: {path} ({size_mb:.1f}MB)")
                            await browser.close()
                            return path
                        except Exception as exc:  # noqa: BLE001
                            print(f"[apkfetch] tıklama/indirme hatası ({sel}): {str(exc)[:80]}")
                            continue
                if not clicked:
                    print(f"[apkfetch] indirme linki bulunamadı: {url}")
            except Exception as exc:  # noqa: BLE001
                print(f"[apkfetch] sayfa hatası ({url}): {str(exc)[:80]}")
                continue

        await browser.close()
    print("[apkfetch] APK indirilemedi — APKPure yapısı değişmiş olabilir")
    return None


async def run(package: str, root: str | None) -> dict:
    """İndir -> analiz et -> sil. Sonuç özeti döner."""
    tmp_dir = tempfile.mkdtemp(prefix="apk_")
    apk_path = None
    result = {"package": package, "downloaded": False, "hosts": 0,
              "secrets": 0, "endpoints": 0}
    try:
        print(f"\n{'='*60}\n  APK FETCH: {package}\n{'='*60}\n")
        apk_path = await fetch_apk(package, tmp_dir)
        if not apk_path:
            return result
        result["downloaded"] = True

        # Static analiz (kod çalıştırılmaz)
        strings = layer3_apk.extract_strings(apk_path)
        res = layer3_apk.analyze(strings, root)
        layer3_apk.save_results(res, root, f"{package}.apk")

        result["hosts"] = len(res["hosts"])
        result["secrets"] = len(res["secrets"])
        result["endpoints"] = len(res["paths"])
        print(f"\n[apkfetch] Analiz bitti: {result['hosts']} host, "
              f"{result['secrets']} secret, {result['endpoints']} endpoint")
        return result
    finally:
        # APK'yı HER DURUMDA sil (hata olsa bile)
        if apk_path and os.path.exists(apk_path):
            try:
                os.remove(apk_path)
                print(f"[apkfetch] APK silindi: {apk_path}")
            except OSError as exc:
                print(f"[apkfetch] silme hatası: {exc}")
        # Geçici klasörü de temizle
        try:
            for f in os.listdir(tmp_dir):
                os.remove(os.path.join(tmp_dir, f))
            os.rmdir(tmp_dir)
        except OSError:
            pass


def _notify(text: str) -> None:
    token = os.environ.get("BUGBOUNTY_TG_TOKEN")
    chat_id = os.environ.get("BUGBOUNTY_TG_CHAT_ID")
    if not token or not chat_id:
        return
    try:
        import httpx
        httpx.post(f"https://api.telegram.org/bot{token}/sendMessage",
                   json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"},
                   timeout=10.0)
    except Exception:  # noqa: BLE001
        pass


async def _main() -> None:
    p = argparse.ArgumentParser(description="Layer 6 — Otonom APK indir+analiz+sil")
    p.add_argument("package", help="Android paket adı, örn: com.myntra.android")
    p.add_argument("--root", help="Sadece bu kök domaine ait host/URL'leri kaydet")
    args = p.parse_args()

    r = await run(args.package, args.root)
    if r["downloaded"]:
        _notify(f"📦 <b>APK analizi bitti:</b> {args.package}\n"
                f"🌐 Host: {r['hosts']} | 🔑 Secret: {r['secrets']} | "
                f"🔗 Endpoint: {r['endpoints']}\n"
                f"Bulgular: /subs ve /findings\n"
                f"(APK silindi)")
    else:
        _notify(f"⚠️ APK indirilemedi: {args.package}\n"
                f"APKPure yapısı değişmiş olabilir — elle APK atıp "
                f"layer3_apk.py ile analiz edilebilir.")


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    asyncio.run(_main())
