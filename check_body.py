from database import get_connection

with get_connection() as conn:
    # Body dolu olan kayıtlar
    dolu = conn.execute(
        "SELECT COUNT(*) c FROM requests WHERE body IS NOT NULL AND body != '' AND body != 'null'"
    ).fetchone()["c"]

    # Body null olan ama POST olan kayıtlar
    bos = conn.execute(
        "SELECT COUNT(*) c FROM requests WHERE (body IS NULL OR body = '') AND method = 'POST'"
    ).fetchone()["c"]

    # Son 3 body'si dolu kayıt
    ornekler = conn.execute(
        "SELECT id, url, body FROM requests WHERE body IS NOT NULL AND body != '' AND body != 'null' ORDER BY created_at DESC LIMIT 3"
    ).fetchall()

print(f"Body DOLU kayıt sayısı: {dolu}")
print(f"Body BOŞ (POST) kayıt sayısı: {bos}")
print()
if ornekler:
    for r in ornekler:
        print(f"#{r['id']} {r['url'][:60]}")
        print(f"  body[:100]: {r['body'][:100]}")
else:
    print("Hiçbir kayıtta body yok — plugin body yakalamıyor.")
