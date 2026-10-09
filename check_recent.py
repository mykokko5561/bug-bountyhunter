from database import get_connection
with get_connection() as conn:
    rows = conn.execute(
        "SELECT id, method, url, triage_status, created_at FROM requests ORDER BY created_at DESC LIMIT 5"
    ).fetchall()
    for r in rows:
        print(dict(r))
