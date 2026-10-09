"""
layer3_apk.py — Katman 3: APK Static Analyzer
Bir Android APK'sını (com.bykea.pk gibi) açıp içindeki gömülü sırları çıkarır:
  - bykea.net (ve tüm) URL'leri ve hostları  -> subdomains tablosuna
  - API endpoint path'leri (/api/.., /v1/.., /booking/..)
  - Gömülü sırlar: Google API key, AWS key, Firebase, generic token/secret
  - Kong / gateway ipuçları

Saf Python: APK bir ZIP'tir. classes*.dex, resources.arsc, *.xml, *.so
dosyalarından yazdırılabilir string'leri çeker (Unix `strings` mantığı),
sonra regex uygular. jadx kadar derin değil ama hardcoded URL/key'lerin
çoğunu yakalar — ve hiçbir harici araç gerektirmez.

Bulgular merkezi DB'ye (recon_findings, source='apk') yazılır.

CLI:
    python layer3_apk.py bykea.apk
    python layer3_apk.py bykea.apk --root bykea.net   # sadece bu host'ları kaydet
"""

from __future__ import annotations

import argparse
import re
import sys
import zipfile
from datetime import datetime, timezone

from database import init_db, get_connection

# Yazdırılabilir ASCII dizileri (en az 5 karakter)
_STRINGS_RE = re.compile(rb"[\x20-\x7e]{5,}")

# URL ve host desenleri
_URL_RE = re.compile(r"https?://[a-zA-Z0-9.\-_]+(?::\d+)?(?:/[^\s\"'<>\\]*)?")
_HOST_RE = re.compile(r"\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}\b")

# API endpoint path'leri
_PATH_RE = re.compile(r"/(?:api|v\d|booking|bookings|invoice|invoices|wallet|"
                      r"user|users|driver|drivers|partner|payment|payments|"
                      r"auth|login|otp|ride|rides|order|orders|trip|trips)"
                      r"[a-zA-Z0-9/_\-{}]*")

# Gömülü sır desenleri
_SECRET_PATTERNS = {
    "Google API Key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Firebase URL": re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com"),
    "Google OAuth": re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "Generic API Key": re.compile(r"(?i)(?:api[_-]?key|apikey|secret|token|passwd|password)"
                                  r"[\"'\s:=]{1,4}[A-Za-z0-9_\-]{16,}"),
    "Stripe Key": re.compile(r"(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{16,}"),
}


_INTERESTING = (".dex", ".arsc", ".xml", ".so", ".json", ".js", ".properties")


# Zip-bomb koruması: tek bir dosya bu boyuttan büyük açılıyorsa atla,
# toplam açılan veri bu limiti geçerse dur. Kötü niyetli/bozuk APK'ya karşı.
_MAX_FILE_UNCOMPRESSED = 200 * 1024 * 1024     # tek dosya 200MB
_MAX_TOTAL_UNCOMPRESSED = 2 * 1024 * 1024 * 1024  # toplam 2GB
_bytes_read = [0]  # mutable sayaç (recurse boyunca paylaşılır)


def _strings_from_zip(z: zipfile.ZipFile, out: list[str], depth: int = 0) -> None:
    """Bir ZIP içindeki ilgili dosyalardan string çeker; iç içe .apk varsa recurse eder.
    Zip-bomb'a karşı dosya-başı ve toplam boyut limiti uygular."""
    for info in z.infolist():
        name = info.filename
        low = name.lower()
        # Zip-bomb guard: bildirilen açılmış boyut çok büyükse atla
        if info.file_size > _MAX_FILE_UNCOMPRESSED:
            print(f"[apk] atlandı (çok büyük, {info.file_size//1048576}MB): {name}")
            continue
        if _bytes_read[0] > _MAX_TOTAL_UNCOMPRESSED:
            print("[apk] toplam boyut limiti aşıldı — durduruluyor (zip-bomb koruması)")
            return
        # XAPK/APKS: içinde başka .apk'lar olabilir -> recurse
        if low.endswith(".apk") and depth < 3:
            try:
                import io
                data = z.read(name)
                _bytes_read[0] += len(data)
                inner = zipfile.ZipFile(io.BytesIO(data))
                print(f"[apk] iç paket açılıyor: {name}")
                _strings_from_zip(inner, out, depth + 1)
            except (zipfile.BadZipFile, RuntimeError, OSError):
                pass
            continue
        if not low.endswith(_INTERESTING):
            continue
        try:
            data = z.read(name)
            _bytes_read[0] += len(data)
        except (zipfile.BadZipFile, RuntimeError, OSError):
            continue
        for m in _STRINGS_RE.finditer(data):
            try:
                out.append(m.group().decode("ascii"))
            except UnicodeDecodeError:
                continue


def extract_strings(apk_path: str) -> list[str]:
    """APK/XAPK/APKS içindeki dosyalardan yazdırılabilir string'leri çeker."""
    out: list[str] = []
    with zipfile.ZipFile(apk_path) as z:
        print(f"[apk] {len(z.namelist())} dosya içeriyor")
        _strings_from_zip(z, out)
    print(f"[apk] {len(out):,} string çıkarıldı")
    return out


def analyze(strings: list[str], root: str | None) -> dict:
    urls, hosts, paths = set(), set(), set()
    secrets: list[tuple[str, str]] = []

    for s in strings:
        for u in _URL_RE.findall(s):
            urls.add(u)
        for p in _PATH_RE.findall(s):
            if len(p) > 4:
                paths.add(p)
        for label, pat in _SECRET_PATTERNS.items():
            for hit in pat.findall(s):
                val = hit if isinstance(hit, str) else hit[0]
                secrets.append((label, s.strip()[:160]))

    # URL'lerden host çıkar
    for u in urls:
        m = _HOST_RE.search(u)
        if m:
            hosts.add(m.group().lower())

    # root filtresi
    if root:
        hosts = {h for h in hosts if h.endswith(root)}
        urls = {u for u in urls if root in u}

    return {"urls": sorted(urls), "hosts": sorted(hosts),
            "paths": sorted(paths), "secrets": secrets}


def save_results(res: dict, root: str | None, apk_name: str) -> None:
    init_db()
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        # Bulunan host'ları subdomains'e ekle (dedup)
        for h in res["hosts"]:
            r = root or (".".join(h.split(".")[-2:]))
            conn.execute(
                "INSERT OR IGNORE INTO subdomains (root, subdomain, source, first_seen) "
                "VALUES (?, ?, 'apk', ?)", (r, h, now))
        # Sırları recon_findings'e (yüksek severity)
        for label, ctx in res["secrets"]:
            conn.execute(
                "INSERT INTO recon_findings (host, source, severity, name, matched_at, raw, found_at) "
                "VALUES (?, 'apk', 'high', ?, ?, ?, ?)",
                (apk_name, f"Gömülü sır: {label}", ctx, ctx, now))
        # İlginç endpoint path'lerini de kaydet (info)
        for p in res["paths"][:200]:
            conn.execute(
                "INSERT INTO recon_findings (host, source, severity, name, matched_at, raw, found_at) "
                "VALUES (?, 'apk', 'info', ?, ?, ?, ?)",
                (apk_name, "API endpoint (APK)", p, p, now))
        conn.commit()


def main() -> None:
    p = argparse.ArgumentParser(description="Layer 3 — APK Static Analyzer")
    p.add_argument("apk", help="APK dosya yolu")
    p.add_argument("--root", help="Sadece bu kök domaine ait host/URL'leri kaydet")
    args = p.parse_args()

    print(f"\n{'='*60}\n  APK ANALİZ: {args.apk}\n{'='*60}\n")
    strings = extract_strings(args.apk)
    res = analyze(strings, args.root)

    print(f"\n[+] {len(res['hosts'])} host bulundu:")
    for h in res["hosts"]:
        print(f"    {h}")
    print(f"\n[+] {len(res['urls'])} URL (ilk 30):")
    for u in res["urls"][:30]:
        print(f"    {u}")
    print(f"\n[+] {len(res['paths'])} endpoint path (ilk 40):")
    for pth in res["paths"][:40]:
        print(f"    {pth}")
    print(f"\n[+] {len(res['secrets'])} olası sır:")
    seen = set()
    for label, ctx in res["secrets"]:
        key = (label, ctx[:40])
        if key in seen:
            continue
        seen.add(key)
        print(f"    [{label}] {ctx[:100]}")

    save_results(res, args.root, args.apk.split("/")[-1].split("\\")[-1])
    print(f"\n{'='*60}\n  Kaydedildi -> /subs ve /findings ile bak\n{'='*60}")


if __name__ == "__main__":
    main()
