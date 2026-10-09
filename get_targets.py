"""
get_targets.py
--------------
Ollama'nın 'sent_to_ai' olarak işaretlediği tüm istekleri
SQLite veritabanından çekip temiz JSON formatında terminale basar.

Kullanım:
    python get_targets.py                    # tüm sent_to_ai kayıtlar
    python get_targets.py --id 115           # tek kayıt
    python get_targets.py --category bac     # sadece bac kararları
    python get_targets.py --last 5           # en son 5 kayıt
"""

import argparse
import json
import sys
from database import init_db, get_connection


def fetch_targets(
    record_id: int | None = None,
    category: str | None = None,
    last: int | None = None,
) -> list[dict]:
    query = """
        SELECT
            id, method, url, host,
            headers_json, body,
            status_code, response_size,
            contains_secret, secret_matches,
            triage_status, ai_verdict, ai_reasoning,
            created_at
        FROM requests
        WHERE triage_status = 'sent_to_ai'
    """
    params: list = []

    if record_id is not None:
        query += " AND id = ?"
        params.append(record_id)

    if category:
        query += " AND ai_verdict = ?"
        params.append(category)

    query += " ORDER BY created_at DESC"

    if last:
        query += " LIMIT ?"
        params.append(last)

    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()

    results = []
    for row in rows:
        try:
            headers = json.loads(row["headers_json"] or "{}")
        except json.JSONDecodeError:
            headers = {}

        try:
            body_parsed = json.loads(row["body"] or "null")
        except json.JSONDecodeError:
            body_parsed = row["body"]

        try:
            secrets = json.loads(row["secret_matches"] or "[]")
        except json.JSONDecodeError:
            secrets = []

        results.append({
            "id": row["id"],
            "verdict": row["ai_verdict"],
            "reasoning": row["ai_reasoning"],
            "method": row["method"],
            "url": row["url"],
            "host": row["host"],
            "status_code": row["status_code"],
            "response_size": row["response_size"],
            "contains_secret": bool(row["contains_secret"]),
            "secret_matches": secrets,
            "headers": headers,
            "body": body_parsed,
            "created_at": row["created_at"],
        })

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Escalate edilmiş hedefleri DB'den çek")
    parser.add_argument("--id", type=int, help="Tek bir kaydın ID'si")
    parser.add_argument("--category", choices=["idor", "bac", "business_logic", "secret_exposure", "none"])
    parser.add_argument("--last", type=int, help="En son N kaydı getir")
    args = parser.parse_args()

    init_db()
    targets = fetch_targets(
        record_id=args.id,
        category=args.category,
        last=args.last,
    )

    if not targets:
        print("Sonuç bulunamadı.", file=sys.stderr)
        sys.exit(0)

    print(json.dumps(targets, indent=2, ensure_ascii=False))
    print(f"\n# Toplam: {len(targets)} kayıt", file=sys.stderr)


if __name__ == "__main__":
    main()
