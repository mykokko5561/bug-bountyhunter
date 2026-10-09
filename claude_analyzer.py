"""
claude_analyzer.py
-------------------
Katman 4: Keskin Nişancı (Claude API Entegrasyonu)

Ollama'nın 'sent_to_ai' olarak işaretlediği istekleri otomatik olarak
Claude API'ye gönderir, 3 adımlı CoT analizi yaptırır ve sonucu:
  1. DB'ye yazar (ai_reasoning alanına)
  2. Telegram'a attack_hint ile bildirir

KULLANIM:
    python claude_analyzer.py --once       # Bekleyen tüm sent_to_ai'ları işle
    python claude_analyzer.py --daemon     # Sürekli çalış (her 120 saniyede)
    python claude_analyzer.py --id 123     # Tek bir kaydı analiz et
"""

import argparse
import json
import logging
import os
import sqlite3
import time
import urllib.request
import urllib.error

from database import init_db, get_connection

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("bugbounty.claude_analyzer")

CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
# Token ekonomisi: model env'den ayarlanabilir. Maliyet-hassas isen .env'e
# CLAUDE_MODEL=claude-haiku-4-5-20251001 yaz -> ~10x ucuz (Ollama zaten ön-filtreliyor).
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")
MAX_TOKENS = int(os.environ.get("CLAUDE_MAX_TOKENS", "500"))
# Skill enjeksiyonu prompt'a eklensin mi? .env'e SKILLS_IN_PROMPT=0 -> kapat (token tasarrufu)
SKILLS_IN_PROMPT = os.environ.get("SKILLS_IN_PROMPT", "1") != "0"


SYSTEM_PROMPT = """You are an elite bug bounty analyst. Analyze the HTTP request for IDOR/BAC/Business Logic vulnerabilities.

Be extremely concise. End with ONLY this JSON:
```json
{
  "exploitable": true/false,
  "severity": "critical/high/medium/low",
  "attack_hint": "one line test",
  "payload": "exact change needed"
}
```"""


def build_analysis_prompt(row: sqlite3.Row) -> str:
    """DB kaydından analiz promptu oluştur."""
    try:
        headers = json.loads(row["headers_json"] or "{}")
    except json.JSONDecodeError:
        headers = {}

    # Cookie ve uzun header'ları kırp
    safe_headers = {
        k: v for k, v in headers.items()
        if k.lower() not in ("cookie", "set-cookie")
        and len(str(v)) < 200
    }

    body = row["body"] or ""
    if len(body) > 1500:
        body = body[:1500] + "...[truncated]"

    base = f"""Analyze this HTTP request for security vulnerabilities:

**Method:** {row['method']}
**URL:** {row['url']}
**Headers:** {json.dumps(safe_headers, ensure_ascii=False)}
**Body:** {body}

**Pre-triage verdict:** {row['ai_verdict']} — {row['ai_reasoning']}

Perform your 3-step analysis."""

    # Uzman metodoloji enjeksiyonu (skills_loader): ai_verdict + URL'den
    # zafiyet sınıfını tespit edip playbook'u ekle. SKILLS_IN_PROMPT=0 ile kapatılır.
    if not SKILLS_IN_PROMPT:
        return base
    try:
        from skills_loader import detect_and_load
        signal = f"{row['ai_verdict']} {row['url']} {row['ai_reasoning']}"
        # Kalite önceliği: 2 skill, tam metodoloji (Claude derin analiz için).
        methodology, names = detect_and_load(signal, max_skills=2, max_chars=3000)
        if methodology:
            base += (f"\n\n--- EXPERT METHODOLOGY ({', '.join(names)}) ---\n"
                     f"{methodology}\n--- Use this methodology in your analysis. ---")
    except Exception:  # noqa: BLE001
        pass

    return base


def call_claude_api(prompt: str) -> str | None:
    """Claude API'ye istek at, yanıtı döndür."""
    payload = json.dumps({
        "model": CLAUDE_MODEL,
        "max_tokens": MAX_TOKENS,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": prompt}]
    }).encode("utf-8")

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        logger.error("ANTHROPIC_API_KEY ortam değişkeni eksik!")
        return None

    req = urllib.request.Request(
        CLAUDE_API_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
            "x-api-key": api_key,
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["content"][0]["text"]
    except urllib.error.HTTPError as e:
        logger.error("Claude API HTTP hatası: %s %s", e.code, e.read().decode())
        return None
    except Exception as e:
        logger.error("Claude API hatası: %s", e)
        return None


def extract_json_verdict(text: str) -> dict:
    """Claude yanıtından JSON bloğunu çıkar."""
    import re

    # ```json ... ``` bloğunu ara
    match = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # ``` ... ``` bloğunu ara (json etiketi olmadan)
    match = re.search(r"```\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Düz JSON bloğunu ara
    match = re.search(r"\{[^{}]*\"exploitable\"[^{}]*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    return {}


def send_telegram_notification(chat_id: str, token: str, row: sqlite3.Row,
                                analysis: str, verdict: dict) -> None:
    """Telegram'a analiz sonucunu gönder."""
    exploitable = verdict.get("exploitable", False)
    severity = verdict.get("severity", "unknown")
    attack_hint = verdict.get("attack_hint", "-")
    payload = verdict.get("payload", "-")

    emoji = "🚨" if exploitable else "ℹ️"
    sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡",
                 "low": "🟢", "info": "⚪"}.get(severity, "⚪")

    text = (
        f"{emoji} <b>Claude Analizi #{row['id']}</b>\n"
        f"{sev_emoji} <b>Severity:</b> {severity.upper()}\n"
        f"<b>Exploitable:</b> {'✅ EVET' if exploitable else '❌ Hayır'}\n\n"
        f"<b>URL:</b> <code>{row['url'][-80:]}</code>\n\n"
        f"<b>Attack Hint:</b> {attack_hint}\n\n"
        f"<b>Payload:</b>\n<code>{payload[:400]}</code>"
    )[:3800]

    data = json.dumps({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML"
    }).encode("utf-8")

    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        logger.error("Telegram bildirimi gönderilemedi: %s", e)


def analyze_single(row: sqlite3.Row, tg_token: str | None,
                   tg_chat_id: str | None) -> None:
    """Tek bir kaydı analiz et."""
    logger.info("Analiz ediliyor (id=%s): %s %s",
                row["id"], row["method"], row["url"][:60])

    prompt = build_analysis_prompt(row)
    analysis = call_claude_api(prompt)

    if not analysis:
        logger.warning("Claude yanıt vermedi (id=%s)", row["id"])
        return

    verdict = extract_json_verdict(analysis)
    combined_reasoning = f"[Claude] {analysis[:6000]}"

    try:
        with get_connection() as conn:
            conn.execute(
                """UPDATE requests SET
                   triage_status = 'analyzed',
                   ai_reasoning = ?,
                   updated_at = datetime('now')
                   WHERE id = ?""",
                (combined_reasoning, row["id"])
            )
            conn.commit()
    except sqlite3.Error as e:
        logger.error("DB güncelleme hatası (id=%s): %s", row["id"], e)
        return

    logger.info("Analiz tamamlandı (id=%s) — exploitable=%s, severity=%s",
                row["id"], verdict.get("exploitable"), verdict.get("severity"))

    if tg_token and tg_chat_id and verdict.get("exploitable"):
        send_telegram_notification(tg_chat_id, tg_token, row, analysis, verdict)


def process_batch(limit: int = 5, tg_token: str | None = None,
                  tg_chat_id: str | None = None) -> int:
    """sent_to_ai durumundaki kayıtları işle."""
    try:
        with get_connection() as conn:
            rows = conn.execute(
                """SELECT * FROM requests
                   WHERE triage_status = 'sent_to_ai'
                   AND ai_verdict IN ('idor', 'bac', 'business_logic')
                   AND (ai_reasoning LIKE '%pre-risk 0.9%'
                        OR ai_reasoning LIKE '%pre-risk 1.%'
                        OR ai_reasoning LIKE '%mutation%'
                        OR ai_reasoning LIKE '%GraphQL mutation%')
                   ORDER BY created_at ASC
                   LIMIT ?""",
                (limit,)
            ).fetchall()
    except sqlite3.Error as e:
        logger.error("DB sorgu hatası: %s", e)
        return 0

    for row in rows:
        analyze_single(row, tg_token, tg_chat_id)
        time.sleep(2)  # Rate limiting

    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Claude API Derin Analiz")
    parser.add_argument("--once", action="store_true", help="Bir batch işle çık")
    parser.add_argument("--daemon", action="store_true", help="Sürekli çalış")
    parser.add_argument("--interval", type=int, default=120, help="Daemon bekleme (saniye)")
    parser.add_argument("--id", type=int, help="Tek kayıt analiz et")
    parser.add_argument("--limit", type=int, default=5, help="Batch boyutu")
    args = parser.parse_args()

    init_db()

    tg_token = os.environ.get("BUGBOUNTY_TG_TOKEN")
    tg_chat_id = os.environ.get("BUGBOUNTY_TG_CHAT_ID")

    if args.id:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM requests WHERE id = ?", (args.id,)
            ).fetchone()
        if row:
            analyze_single(row, tg_token, tg_chat_id)
        else:
            logger.error("Kayıt bulunamadı: id=%s", args.id)
        return

    if args.once:
        count = process_batch(args.limit, tg_token, tg_chat_id)
        logger.info("Tamamlandı: %d kayıt işlendi.", count)
        return

    if args.daemon:
        logger.info("Daemon modu başladı (interval=%ss)", args.interval)
        while True:
            try:
                count = process_batch(args.limit, tg_token, tg_chat_id)
                if count > 0:
                    logger.info("Batch tamamlandı: %d kayıt.", count)
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.exception("Daemon hatası: %s", e)
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
