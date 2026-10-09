from database import get_connection

with get_connection() as conn:
    # 16:00 sonrası gelen graphql istekleri
    new_graphql = conn.execute(
        "SELECT COUNT(*) c FROM requests WHERE url LIKE '%graphql%' AND created_at > '2026-09-11 16:00'"
    ).fetchone()["c"]

    # Toplam duplicate sayısı
    total = conn.execute("SELECT COUNT(*) c FROM requests").fetchone()["c"]

    # pending graphql
    pending_graphql = conn.execute(
        "SELECT COUNT(*) c FROM requests WHERE url LIKE '%graphql%' AND triage_status = 'pending'"
    ).fetchone()["c"]

    print(f"16:00 sonrası graphql kayıt: {new_graphql}")
    print(f"Toplam kayıt: {total}")
    print(f"Pending graphql: {pending_graphql}")

    # En yeni graphql kaydı
    row = conn.execute(
        "SELECT id, url, triage_status, created_at FROM requests WHERE url LIKE '%graphql%' ORDER BY created_at DESC LIMIT 1"
    ).fetchone()
    if row:
        print(f"En yeni graphql: #{row['id']} [{row['triage_status']}] {row['created_at']}")
        print(f"  {row['url'][:80]}")
