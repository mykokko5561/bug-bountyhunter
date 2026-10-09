"""
cleanup_db.py
-------------
Eski/yanlış etiketlenmiş kayıtları veritabanından temizler.

Yapılanlar:
1. _rsc parametresi içeren Next.js RSC prefetch kayıtlarını 'filtered_out' yapar
2. Body'si null olan ama mutation olan kayıtları 'pending' geri alır
   (body olmadan analiz anlamsız, yeniden yakalanacak)

Kullanım:
    python cleanup_db.py --dry-run   # sadece göster, değiştirme
    python cleanup_db.py             # gerçekten uygula
"""

import argparse
import sqlite3
from database import init_db, get_connection


def cleanup(dry_run: bool = True) -> None:
    init_db()

    with get_connection() as conn:
        # 1. RSC prefetch kayıtları -> filtered_out
        rsc_rows = conn.execute(
            "SELECT id, url FROM requests WHERE url LIKE '%_rsc=%' AND triage_status = 'sent_to_ai'"
        ).fetchall()

        print(f"\n[RSC Prefetch False-Positive] {len(rsc_rows)} kayıt:")
        for r in rsc_rows:
            print(f"  #{r['id']} {r['url'][:80]}")

        if not dry_run and rsc_rows:
            conn.execute(
                "UPDATE requests SET triage_status='filtered_out', ai_verdict='none', "
                "ai_reasoning='RSC prefetch - Next.js framework gürültüsü, geriye dönük temizlendi.' "
                "WHERE url LIKE '%_rsc=%' AND triage_status = 'sent_to_ai'"
            )

        # 2. Body null olan mutationlar -> pending (yeniden yakalanacak)
        body_null_rows = conn.execute(
            """SELECT id, url FROM requests
               WHERE body IS NULL
                 AND triage_status = 'sent_to_ai'
                 AND url LIKE '%graphql%'"""
        ).fetchall()

        print(f"\n[Body Eksik GraphQL] {len(body_null_rows)} kayıt -> pending'e alınıyor:")
        for r in body_null_rows:
            print(f"  #{r['id']} {r['url'][:80]}")

        if not dry_run and body_null_rows:
            conn.execute(
                "UPDATE requests SET triage_status='pending', ai_verdict=NULL, ai_reasoning=NULL, "
                "updated_at=datetime('now') "
                "WHERE body IS NULL AND triage_status='sent_to_ai' AND url LIKE '%graphql%'"
            )

        # 3. verdict=none + secret regex false-positive kayıtları -> filtered_out
        fp_rows = conn.execute(
            """SELECT id, url FROM requests
               WHERE triage_status = 'sent_to_ai'
                 AND ai_verdict = 'none'
                 AND ai_reasoning LIKE '%secret regex tetikledi%'"""
        ).fetchall()

        print(f"\n[Secret Regex False-Positive] {len(fp_rows)} kayıt -> filtered_out:")
        for r in fp_rows:
            print(f"  #{r['id']} {r['url'][:80]}")

        if not dry_run and fp_rows:
            conn.execute(
                "UPDATE requests SET triage_status='filtered_out', "
                "updated_at=datetime('now') "
                "WHERE triage_status='sent_to_ai' AND ai_verdict='none' "
                "AND ai_reasoning LIKE '%secret regex tetikledi%'"
            )

        # 4. Kasada/Segment/bot-protection kayıtları -> filtered_out
        bot_rows = conn.execute(
            """SELECT id, url FROM requests
               WHERE triage_status = 'sent_to_ai'
                 AND (url LIKE '%/tl%' OR url LIKE '%/fp%' OR url LIKE '%/mfc%'
                      OR url LIKE '%segment_cdn%' OR url LIKE '%statsig%'
                      OR url LIKE '%datadog%')"""
        ).fetchall()

        print(f"\n[Bot-Koruma/Analitik Gürültü] {len(bot_rows)} kayıt -> filtered_out:")
        for r in bot_rows:
            print(f"  #{r['id']} {r['url'][:80]}")

        if not dry_run and bot_rows:
            conn.execute(
                "UPDATE requests SET triage_status='filtered_out', "
                "ai_verdict='none', ai_reasoning='Bot-koruma/analitik SDK gürültüsü, geriye dönük temizlendi.', "
                "updated_at=datetime('now') "
                "WHERE triage_status='sent_to_ai' "
                "AND (url LIKE '%/tl%' OR url LIKE '%/fp%' OR url LIKE '%/mfc%' "
                "OR url LIKE '%segment_cdn%' OR url LIKE '%statsig%' OR url LIKE '%datadog%')"
            )

        if not dry_run:
            conn.commit()
            print("\n✅ Temizlik tamamlandı.")
        else:
            print("\n[DRY RUN] Değişiklik yapılmadı. Gerçek temizlik için: python cleanup_db.py")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", default=False)
    args = parser.parse_args()
    cleanup(dry_run=args.dry_run)
