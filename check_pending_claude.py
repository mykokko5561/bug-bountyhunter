from database import get_connection

with get_connection() as conn:
    r = conn.execute(
        "SELECT COUNT(*) c FROM requests WHERE triage_status='sent_to_ai' AND ai_verdict IN ('idor','bac','business_logic')"
    ).fetchone()
    print("Claude bekleyen:", r["c"])

    r2 = conn.execute(
        "SELECT COUNT(*) c FROM requests WHERE triage_status='sent_to_ai'"
    ).fetchone()
    print("Toplam sent_to_ai:", r2["c"])
