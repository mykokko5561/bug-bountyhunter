"""
import_caido_export.py
----------------------
Caido'nun JSON export dosyasından GraphQL isteklerini okuyup
body dahil DB'ye yazar. Mevcut kayıtlar üzerine body'yi günceller.

Kullanım:
    python import_caido_export.py --file "C:\\Users\\mykok\\Desktop\\2026-09-11-201528_json_requests.json"
"""

import argparse
import json
import logging
import sqlite3
from pathlib import Path

from database import init_db, get_connection
from dedup_engine import compute_dedup_hash, is_bot_protection_noise

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger("import")


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--file", required=True, help="Caido JSON export dosyası")
    p.add_argument("--limit", type=int, default=0, help="Kaç istek işlensin (0=hepsi)")
    return p.parse_args()


def extract_body(request: dict) -> str | None:
    """Caido JSON formatından body'yi çıkar — raw base64 HTTP formatından parse et."""
    import base64
    raw = request.get("raw", "")

    if not raw:
        return None

    # Caido raw alanı base64 encoded
    try:
        if isinstance(raw, str):
            decoded = base64.b64decode(raw).decode("utf-8", errors="ignore")
        elif isinstance(raw, list):
            decoded = bytes(raw).decode("utf-8", errors="ignore")
        else:
            return None
    except Exception:
        return None

    # HTTP raw formatı: header'lar + boş satır + body
    if "\r\n\r\n" in decoded:
        body = decoded.split("\r\n\r\n", 1)[1]
    elif "\n\n" in decoded:
        body = decoded.split("\n\n", 1)[1]
    else:
        return None

    return body.strip() or None


def extract_headers(request: dict) -> dict:
    import base64
    raw = request.get("raw", "")
    headers = {}

    if not raw:
        return headers

    try:
        decoded = base64.b64decode(raw).decode("utf-8", errors="ignore") if isinstance(raw, str) else ""
    except Exception:
        return headers

    header_section = decoded.split("\r\n\r\n", 1)[0] if "\r\n\r\n" in decoded else decoded.split("\n\n", 1)[0]
    lines = header_section.split("\r\n") if "\r\n" in header_section else header_section.split("\n")

    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip()] = value.strip()

    return headers


def process_export(filepath: Path, limit: int) -> None:
    init_db()

    logger.info("Dosya okunuyor: %s", filepath)
    with open(filepath, encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    # Caido export formatı: liste veya {"requests": [...]}
    if isinstance(data, list):
        requests = data
    elif isinstance(data, dict):
        requests = data.get("requests", data.get("items", []))
    else:
        logger.error("Tanınmayan format")
        return

    logger.info("Toplam istek: %d", len(requests))

    if limit:
        requests = requests[:limit]

    updated = 0
    inserted = 0
    skipped = 0

    for req in requests:
        try:
            # URL ve method
            url = req.get("path") or ""
            method = (req.get("method") or "GET").upper()
            host = req.get("host") or ""
            is_tls = req.get("is_tls", True)
            port = req.get("port", 443)
            query = req.get("query", "")

            # Tam URL oluştur
            scheme = "https" if is_tls else "http"
            if query:
                full_url = f"{scheme}://{host}{url}?{query}"
            else:
                full_url = f"{scheme}://{host}{url}"

            # Sadece GraphQL isteklerini al
            if "graphql" not in full_url.lower():
                continue

            # Bot-koruma gürültüsünü atla
            if is_bot_protection_noise(full_url):
                continue

            body = extract_body(req)
            headers = extract_headers(req)

            if not body:
                skipped += 1
                continue

            dedup_hash = compute_dedup_hash(method, full_url, body)

            with get_connection() as conn:
                existing = conn.execute(
                    "SELECT id, body FROM requests WHERE dedup_hash = ?",
                    (dedup_hash,)
                ).fetchone()

                if existing:
                    if not existing["body"]:
                        conn.execute(
                            "UPDATE requests SET body = ?, updated_at = datetime('now') WHERE dedup_hash = ?",
                            (body, dedup_hash)
                        )
                        conn.commit()
                        updated += 1
                    else:
                        skipped += 1
                else:
                    conn.execute(
                        """INSERT INTO requests
                           (dedup_hash, method, url, host, headers_json, body,
                            status_code, response_size, is_static, contains_secret, triage_status)
                           VALUES (?,?,?,?,?,?,?,?,0,0,'pending')""",
                        (
                            dedup_hash, method, full_url, host,
                            json.dumps(headers, ensure_ascii=False),
                            body,
                            req.get("response", {}).get("status") if isinstance(req.get("response"), dict) else None,
                            len(body),
                        )
                    )
                    conn.commit()
                    inserted += 1

        except (json.JSONDecodeError, sqlite3.Error, KeyError) as e:
            logger.debug("İstek atlandı: %s", e)
            continue

    logger.info("Bitti — güncellenen: %d, yeni eklenen: %d, atlanan: %d",
                updated, inserted, skipped)


if __name__ == "__main__":
    args = parse_args()
    process_export(Path(args.file), args.limit)
