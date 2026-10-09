"""
main.py
-------
Merkezi Omurga (Katman 1).
Caido köprüsü buraya POST atar, Telegram bot buradan GET ile sorgular.

Çalıştırma:
    uvicorn main:app --reload --port 8000

NOT: Görsel kontrol paneli (dashboard.py) bu FastAPI uygulamasına
router olarak bağlanır — ayrı bir process GEREKMEZ. start.bat zaten
`uvicorn main:app` çalıştırdığı için panel otomatik ayağa kalkar:
    http://127.0.0.1:8000/dashboard
"""

import json
import logging
import sqlite3

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

from database import init_db, get_connection
from dedup_engine import compute_dedup_hash, is_static_asset
from models import IncomingRequest, IngestResponse, RequestRecord
from secret_scanner import scan_for_secrets

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("bugbounty.main")

app = FastAPI(
    title="Bug Bounty Micro-SaaS — Merkezi Omurga",
    description="Caido loglarını tekilleştiren ve sistemin hafızasını tutan API.",
    version="0.1.0",
)

# --- Görsel kontrol paneli (dashboard.py) ---
# Mevcut sisteme hiçbir şeyi bozmadan eklenir: aynı SQLite'ı OKUR ve
# /dashboard altında canlı gösterir. Scanner/bot akışına dokunmaz.
import dashboard  # noqa: E402
app.include_router(dashboard.router)


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    logger.info("Merkezi Omurga ayağa kalktı.")


@app.get("/health")
def health_check() -> dict:
    return {"status": "ok"}


@app.post("/ingest", response_model=IngestResponse, status_code=201)
def ingest_request(payload: IncomingRequest) -> IngestResponse:
    """
    Caido köprüsünün her yakaladığı isteği gönderdiği ana giriş noktası.

    Akış:
        1. Statik dosya mı? -> Kaydetme, direkt reddet (gürültüyü azalt).
        2. Dedup hash üret.
        3. Zaten varsa -> "duplicate" dön, DB'ye tekrar yazma.
        4. Yoksa -> yeni kayıt oluştur, "created" dön.
    """
    if is_static_asset(payload.url):
        logger.debug("Statik dosya elendi: %s", payload.url)
        return IngestResponse(
            status="rejected_static",
            dedup_hash="",
            message="Statik dosya (css/js/img vb.) triyaja alınmadı.",
        )

    dedup_hash = compute_dedup_hash(payload.method, payload.url, payload.body)

    # Secret tarama: Cookie ve Set-Cookie dışındaki header'lar + body taranır.
    # Cookie header'ı KASİTLI olarak hariç tutulur: içindeki JWT/token'lar
    # Whatnot'un kendi auth cookie'leri (örn. __Secure-access-token) — bunlar
    # sızmış değil, kasıtlı olarak tarayıcıda tutulan normal kimlik doğrulama
    # mekanizması. Cookie'yi de tararsak her authenticated istek false-positive
    # olarak işaretlenir ve sistemi kullanılamaz hale getirir.
    EXCLUDED_HEADER_KEYS = {"cookie", "set-cookie"}
    header_blob = " ".join(
        v for k, v in payload.headers.items()
        if k.lower() not in EXCLUDED_HEADER_KEYS
    )
    all_hits = scan_for_secrets(header_blob, payload.body, context_url=payload.url)
    # Sadece GERÇEK (benign olmayan) secret'lar flag'lenir. Firebase/Google
    # public key'leri, 3. parti analytics token'ları gürültü olarak elenir.
    real_hits = [m for m in all_hits if not m.benign]
    contains_secret = 1 if real_hits else 0
    secret_matches_json = (
        json.dumps([{"type": m.secret_type, "value": m.masked_value} for m in real_hits],
                   ensure_ascii=False)
        if real_hits else None
    )
    if real_hits:
        logger.warning("GERÇEK SECRET TESPİT EDİLDİ (%s): %s %s", payload.host, payload.method, payload.url)

    try:
        with get_connection() as conn:
            existing = conn.execute(
                "SELECT id FROM requests WHERE dedup_hash = ?", (dedup_hash,)
            ).fetchone()

            if existing:
                logger.info("Duplicate istek elendi (id=%s): %s %s",
                            existing["id"], payload.method, payload.url)
                return IngestResponse(
                    status="duplicate",
                    id=existing["id"],
                    dedup_hash=dedup_hash,
                    message="Bu istek daha önce kaydedilmiş.",
                )

            cursor = conn.execute(
                """
                INSERT INTO requests
                    (dedup_hash, method, url, host, headers_json, body,
                     status_code, response_size, is_static, contains_secret,
                     secret_matches, source_program)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
                """,
                (
                    dedup_hash,
                    payload.method,
                    payload.url,
                    payload.host,
                    json.dumps(payload.headers, ensure_ascii=False),
                    payload.body,
                    payload.status_code,
                    payload.response_size,
                    contains_secret,
                    secret_matches_json,
                    payload.source_program,
                ),
            )
            conn.commit()
            new_id = cursor.lastrowid

        logger.info("Yeni istek kaydedildi (id=%s): %s %s", new_id, payload.method, payload.url)
        msg = "Yeni istek başarıyla kaydedildi, triyaj bekliyor."
        if real_hits:
            msg += f" UYARI: {len(real_hits)} adet olası secret tespit edildi."
        return IngestResponse(
            status="created",
            id=new_id,
            dedup_hash=dedup_hash,
            message=msg,
        )

    except sqlite3.IntegrityError:
        # Race condition: iki köprü isteği aynı anda aynı hash'i yazmaya çalıştı.
        logger.warning("Integrity çakışması (muhtemel race condition): %s", dedup_hash)
        return IngestResponse(
            status="duplicate",
            dedup_hash=dedup_hash,
            message="Eşzamanlı yazma nedeniyle duplicate olarak işaretlendi.",
        )
    except sqlite3.Error as e:
        logger.error("Veritabanı hatası ingest sırasında: %s", e)
        raise HTTPException(status_code=500, detail="Veritabanı işlemi başarısız oldu.")


@app.get("/requests", response_model=list[RequestRecord])
def list_requests(
    triage_status: str | None = Query(default=None),
    host: str | None = Query(default=None),
    limit: int = Query(default=50, le=200),
) -> list[RequestRecord]:
    """Telegram bot ve dashboard için filtrelenebilir liste endpoint'i."""
    query = "SELECT * FROM requests WHERE 1=1"
    params: list = []

    if triage_status:
        query += " AND triage_status = ?"
        params.append(triage_status)
    if host:
        query += " AND host = ?"
        params.append(host)

    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    try:
        with get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [RequestRecord(**dict(row)) for row in rows]
    except sqlite3.Error as e:
        logger.error("Veritabanı hatası listeleme sırasında: %s", e)
        raise HTTPException(status_code=500, detail="Kayıtlar alınamadı.")


@app.get("/stats")
def get_stats() -> dict:
    """Sistemin genel durumunu özetler (Telegram bot /stats komutu için)."""
    try:
        with get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) AS c FROM requests").fetchone()["c"]
            by_status = conn.execute(
                "SELECT triage_status, COUNT(*) AS c FROM requests GROUP BY triage_status"
            ).fetchall()
            secrets_found = conn.execute(
                "SELECT COUNT(*) AS c FROM requests WHERE contains_secret = 1"
            ).fetchone()["c"]

        return {
            "total_requests": total,
            "by_triage_status": {row["triage_status"]: row["c"] for row in by_status},
            "secrets_found": secrets_found,
        }
    except sqlite3.Error as e:
        logger.error("Veritabanı hatası stats sırasında: %s", e)
        raise HTTPException(status_code=500, detail="İstatistikler alınamadı.")


@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc: Exception) -> JSONResponse:
    """Beklenmeyen her hatayı yakalar, sistemin çökmesini engeller."""
    logger.exception("Beklenmeyen hata: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Beklenmeyen bir sunucu hatası oluştu."},
    )
