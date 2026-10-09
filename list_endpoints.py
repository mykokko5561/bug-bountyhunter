"""
list_endpoints.py — Yakalanan tüm portal.arc.io isteklerini DB'den çeker,
benzersiz path+query desenlerini listeler. IDOR avı için ID/UUID taşıyan
(0x cüzdan adresi OLMAYAN) uçları bulmaya odaklanır.

Kullanım (bug bounty klasöründe, database.py ile aynı yerde):
    python list_endpoints.py
"""
import re
import sqlite3
from urllib.parse import urlparse

DB_PATH = "data/bugbounty.db"

ID_PATTERNS = [
    re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I),  # UUID
    re.compile(r"[?&](id|userId|accountId|walletId|uid|user_id|account_id)=[^&]+", re.I),
    re.compile(r"/\d{3,}(/|$|\?)"),  # numeric path id
]
ONCHAIN_HINTS = ("walletAddress=0x", "vaultAddress=0x", "/0x")


def main():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT DISTINCT method, url FROM requests WHERE host LIKE '%arc.io%' ORDER BY url"
    ).fetchall()
    conn.close()

    print(f"[i] Toplam benzersiz istek: {len(rows)}\n")

    interesting = []
    all_paths = set()
    for r in rows:
        url = r["url"]
        path = urlparse(url).path
        all_paths.add((r["method"], path))

        is_onchain = any(h in url for h in ONCHAIN_HINTS)
        has_id = any(p.search(url) for p in ID_PATTERNS)
        if has_id and not is_onchain:
            interesting.append((r["method"], url))

    print("=== TÜM BENZERSİZ PATH'LER ===")
    for method, path in sorted(all_paths):
        print(f"  {method:6} {path}")

    print(f"\n=== ID/UUID TAŞIYAN & ON-CHAIN OLMAYAN (IDOR ADAYLARI) — {len(interesting)} adet ===")
    for method, url in interesting:
        print(f"  {method:6} {url}")

    if not interesting:
        print("  (bulunamadı — ID parametreli private endpoint yok, farklı taktik gerekir)")


if __name__ == "__main__":
    main()