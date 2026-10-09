from database import get_connection

with get_connection() as conn:
    # Body dolu GraphQL kayıtları
    rows = conn.execute("""
        SELECT id, url, triage_status, body, created_at
        FROM requests
        WHERE url LIKE '%graphql%'
          AND body IS NOT NULL AND body != ''
        ORDER BY created_at DESC
        LIMIT 10
    """).fetchall()

    print(f"Body dolu GraphQL kayıt sayısı:")
    count = conn.execute(
        "SELECT COUNT(*) c FROM requests WHERE url LIKE '%graphql%' AND body IS NOT NULL AND body != ''"
    ).fetchone()["c"]
    print(f"  Toplam: {count}")
    print()

    for r in rows:
        print(f"#{r['id']} [{r['triage_status']}] {r['created_at']}")
        print(f"  URL: {r['url'][-60:]}")
        print(f"  Body[:150]: {r['body'][:150]}")
        print()
