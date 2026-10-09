from database import get_connection

with get_connection() as conn:
    rows = conn.execute("""
        SELECT id, url, ai_verdict, ai_reasoning, body, created_at
        FROM requests
        WHERE triage_status = 'sent_to_ai'
        ORDER BY 
            CASE WHEN body IS NOT NULL AND body != '' THEN 0 ELSE 1 END,
            created_at DESC
        LIMIT 10
    """).fetchall()

if not rows:
    print("Hiç sent_to_ai kaydı yok.")
else:
    for r in rows:
        body = r["body"]
        print(f"#{r['id']} [{r['ai_verdict']}] {r['created_at']}")
        print(f"  URL: ...{r['url'][-70:]}")
        print(f"  Body: {body[:300] if body else 'NULL'}")
        print(f"  Neden: {r['ai_reasoning'][:100] if r['ai_reasoning'] else '-'}")
        print()
