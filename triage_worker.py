"""
triage_worker.py
-----------------
Katman 3'ün çalıştırıcısı. `pending` durumundaki istekleri veritabanından
çeker, Local AI'dan (Ollama) triyaj kararı ister, sonucu veritabanına yazar.

KULLANIM:
    # Tek seferlik çalıştır (örn. cron / manuel tetikleme için ideal):
    python triage_worker.py --once

    # Sürekli çalışan servis modu (örn. systemd/pm2 altında):
    python triage_worker.py --daemon --interval 30

Varsayılan model "qwen2.5:14b-instruct" olarak ayarlandı — 16GB VRAM'e (RTX 5060 Ti)
rahat sığar ve JSON-mode çıktıda Llama3 8B'den daha tutarlı sonuç verir.
Farklı bir model kullanmak istersen --model parametresiyle değiştirebilirsin.
"""

import argparse
import logging
import sqlite3
import time

from database import init_db, get_connection
from dedup_engine import is_bot_protection_noise
from ollama_client import OllamaClient
from triage_preprocessor import preprocess_request
from triage_prompts import SYSTEM_PROMPT, build_enriched_prompt
import json

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("bugbounty.triage_worker")

VALID_CATEGORIES = {"idor", "bac", "business_logic", "secret_exposure", "none"}


def fetch_pending_batch(limit: int) -> list[sqlite3.Row]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM requests WHERE triage_status = 'pending' "
            "ORDER BY created_at ASC LIMIT ?",
            (limit,),
        ).fetchall()
    return rows


def update_triage_result(
    request_id: int,
    new_status: str,
    ai_verdict: str | None,
    ai_reasoning: str | None,
) -> None:
    try:
        with get_connection() as conn:
            conn.execute(
                """
                UPDATE requests
                SET triage_status = ?, ai_verdict = ?, ai_reasoning = ?,
                    updated_at = datetime('now')
                WHERE id = ?
                """,
                (new_status, ai_verdict, ai_reasoning, request_id),
            )
            conn.commit()
    except sqlite3.Error as e:
        logger.error("Triyaj sonucu yazılamadı (id=%s): %s", request_id, e)


def validate_llm_verdict(verdict: dict | None) -> dict | None:
    """
    Modelden gelen JSON'ın beklenen şemaya uyup uymadığını doğrular.
    Uymuyorsa None döner (çağıran taraf bunu 'triyaj başarısız' sayar).
    """
    if not isinstance(verdict, dict):
        return None

    required_keys = {"interesting", "category", "confidence", "reason"}
    if not required_keys.issubset(verdict.keys()):
        logger.warning("LLM yanıtında eksik alan(lar) var: %s", verdict)
        return None

    if not isinstance(verdict["interesting"], bool):
        return None
    if verdict["category"] not in VALID_CATEGORIES:
        verdict["category"] = "none"
    try:
        verdict["confidence"] = float(verdict["confidence"])
    except (TypeError, ValueError):
        verdict["confidence"] = 0.0

    return verdict


def process_batch(client: OllamaClient, batch_size: int, min_confidence: float) -> dict:
    """Bir batch işler, özet istatistik döner."""
    rows = fetch_pending_batch(batch_size)
    stats = {"processed": 0, "escalated": 0, "filtered_out": 0, "failed": 0}

    for row in rows:
        stats["processed"] += 1

        # LLM'e sormadan önce ucuz/kesin bir eleme: bot-koruma telemetrisi
        # (Kasada/PerimeterX vb.) ise hiç LLM çağrısı yapmadan filtrele.
        # Bu hem hızlandırır hem de küçük modelin UUID-benzeri path'leri
        # yanlışlıkla IDOR sanmasını baştan engeller.
        if is_bot_protection_noise(row["url"]):
            update_triage_result(
                request_id=row["id"],
                new_status="filtered_out",
                ai_verdict="none",
                ai_reasoning="Framework/altyapı gürültüsü (bot-koruma, analitik SDK veya Next.js prefetch deseni), regex ile elendi.",
            )
            stats["filtered_out"] += 1
            logger.debug("Bot-koruma gürültüsü elendi (id=%s): %s", row["id"], row["url"])
            continue

        try:
            headers = json.loads(row["headers_json"] or "{}")
        except json.JSONDecodeError:
            headers = {}

        # Preprocessor: GraphQL, base64 ID, risk sinyallerini çıkar
        enriched = preprocess_request(
            method=row["method"],
            url=row["url"],
            host=row["host"],
            headers=headers,
            body=row["body"],
        )

        # Preprocessor riski zaten yüksekse LLM'e sormadan escalate et
        already_flagged_secret = bool(row["contains_secret"])
        if enriched.pre_risk_score >= 0.85 and not already_flagged_secret:
            logger.info(
                "PRE-RISK ESCALATE (id=%s, score=%.2f): %s %s -> %s",
                row["id"], enriched.pre_risk_score, row["method"], row["url"],
                enriched.risk_reasons,
            )
            update_triage_result(
                request_id=row["id"],
                new_status="sent_to_ai",
                ai_verdict="bac",
                ai_reasoning=f"[Pre-risk {enriched.pre_risk_score:.2f}] {'; '.join(enriched.risk_reasons)}",
            )
            stats["escalated"] += 1
            continue

        user_prompt = build_enriched_prompt(enriched)

        raw_verdict = client.generate_json(SYSTEM_PROMPT, user_prompt)
        verdict = validate_llm_verdict(raw_verdict)

        if verdict is None:
            # Model çöktü / geçersiz JSON döndü -> güvenli tarafta kal,
            # isteği "pending" bırak ki bir sonraki turda tekrar denensin.
            logger.warning("Triyaj başarısız (id=%s), pending bırakıldı.", row["id"])
            stats["failed"] += 1
            continue

        # contains_secret zaten Katman 2'de regex ile tespit edildiyse,
        # LLM ne derse desin escalate et — regex kesinliği LLM tahmininden üstündür.
        should_escalate = (
            already_flagged_secret
            or (verdict["interesting"] and verdict["confidence"] >= min_confidence)
        )

        new_status = "sent_to_ai" if should_escalate else "filtered_out"
        reasoning = verdict["reason"]
        attack_hint = verdict.get("attack_hint")
        if attack_hint:
            reasoning = f"{reasoning} | HINT: {attack_hint}"
        if already_flagged_secret and not verdict["interesting"]:
            reasoning = f"[secret regex tetikledi] {reasoning}"

        update_triage_result(
            request_id=row["id"],
            new_status=new_status,
            ai_verdict=verdict["category"],
            ai_reasoning=reasoning,
        )

        if should_escalate:
            stats["escalated"] += 1
            logger.info("ESCALATE (id=%s, %s): %s %s -> %s",
                        row["id"], verdict["category"], row["method"], row["url"], reasoning)
        else:
            stats["filtered_out"] += 1
            logger.debug("Filtrelendi (id=%s): %s", row["id"], reasoning)

    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Local AI Triyaj Worker")
    parser.add_argument("--model", default="qwen2.5:14b-instruct", help="Ollama model adı")
    parser.add_argument("--host", default="http://localhost:11434", help="Ollama sunucu adresi")
    parser.add_argument("--batch-size", type=int, default=20)
    parser.add_argument("--min-confidence", type=float, default=0.55,
                         help="Bu eşiğin altındaki 'interesting=true' kararları filtrelenir")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--once", action="store_true", help="Tek batch işle ve çık (cron için)")
    mode.add_argument("--daemon", action="store_true", help="Sürekli poll et")
    parser.add_argument("--interval", type=int, default=30, help="--daemon modunda bekleme (saniye)")
    args = parser.parse_args()

    init_db()
    client = OllamaClient(model=args.model, host=args.host)

    if not client.is_alive():
        logger.critical(
            "Ollama'ya ulaşılamıyor veya model yüklü değil (model=%s, host=%s). "
            "Çalıştır: `ollama pull %s`", args.model, args.host, args.model,
        )
        raise SystemExit(1)

    if args.once:
        stats = process_batch(client, args.batch_size, args.min_confidence)
        logger.info("Batch tamamlandı: %s", stats)
        return

    logger.info("Daemon modu başladı (interval=%ss, model=%s)", args.interval, args.model)
    while True:
        try:
            stats = process_batch(client, args.batch_size, args.min_confidence)
            if stats["processed"] > 0:
                logger.info("Batch tamamlandı: %s", stats)
        except KeyboardInterrupt:
            logger.info("Durduruldu (KeyboardInterrupt).")
            break
        except Exception as e:  # Beklenmeyen hata döngüyü öldürmesin.
            logger.exception("Daemon döngüsünde beklenmeyen hata: %s", e)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
