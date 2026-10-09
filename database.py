"""
database.py
------------
Merkezi SQLite yönetim katmanı.
- WAL modu ile eşzamanlı okuma/yazma performansı sağlar (Caido köprüsü yazarken,
  Telegram bot okuyabilir).
- Context manager ile bağlantı sızıntılarını (leak) engeller.
- Şema burada tek noktadan yönetilir (single source of truth).
"""

import sqlite3
import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

logger = logging.getLogger("bugbounty.database")

DB_PATH = Path(__file__).parent / "data" / "bugbounty.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)


SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_hash      TEXT NOT NULL UNIQUE,
    method          TEXT NOT NULL,
    url             TEXT NOT NULL,
    host            TEXT NOT NULL,
    headers_json    TEXT,
    body            TEXT,
    status_code     INTEGER,
    response_size   INTEGER,
    is_static       INTEGER NOT NULL DEFAULT 0,
    contains_secret INTEGER NOT NULL DEFAULT 0,
    secret_matches  TEXT,
    triage_status   TEXT NOT NULL DEFAULT 'pending',
        -- pending | filtered_out | sent_to_ai | analyzed | reported
    ai_verdict      TEXT,
    ai_reasoning    TEXT,
    source_program  TEXT,
    notified_at     TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_requests_dedup_hash ON requests(dedup_hash);
CREATE INDEX IF NOT EXISTS idx_requests_triage_status ON requests(triage_status);
CREATE INDEX IF NOT EXISTS idx_requests_host ON requests(host);

-- Katman 6: Haftalık JS diff izleme için önceki dosya durumunu tutar.
CREATE TABLE IF NOT EXISTS js_snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    js_url          TEXT NOT NULL UNIQUE,
    content_hash    TEXT NOT NULL,
    content_size    INTEGER NOT NULL,
    last_checked_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_changed_at TEXT
);

CREATE TABLE IF NOT EXISTS js_diff_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    js_url          TEXT NOT NULL,
    finding_type    TEXT NOT NULL,   -- new_endpoint | new_secret | size_change
    detail          TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Katman 0: Subdomain keşfi (crt.sh + DNS brute) -> Layer 0/1
CREATE TABLE IF NOT EXISTS subdomains (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    root            TEXT NOT NULL,
    subdomain       TEXT NOT NULL UNIQUE,
    source          TEXT NOT NULL,          -- crtsh | dns | crtsh+dns
    resolved_ip     TEXT,
    first_seen      TEXT NOT NULL DEFAULT (datetime('now')),
    alive           INTEGER NOT NULL DEFAULT 0,
    status_code     INTEGER,
    title           TEXT,
    server          TEXT,
    tech            TEXT,
    final_url       TEXT,
    last_checked    TEXT
);
CREATE INDEX IF NOT EXISTS idx_subdomains_root ON subdomains(root);
CREATE INDEX IF NOT EXISTS idx_subdomains_alive ON subdomains(alive);

-- Katman 1/2: Aktif recon bulguları (nuclei) + IDOR adayları
CREATE TABLE IF NOT EXISTS recon_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host            TEXT NOT NULL,
    source          TEXT NOT NULL,          -- nuclei | idor
    severity        TEXT,                   -- info|low|medium|high|critical
    name            TEXT,
    matched_at      TEXT,
    raw             TEXT,                    -- ham JSON
    found_at        TEXT NOT NULL DEFAULT (datetime('now')),
    triaged         INTEGER NOT NULL DEFAULT 0,
    notified_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_recon_findings_sev ON recon_findings(severity);
CREATE INDEX IF NOT EXISTS idx_recon_findings_triaged ON recon_findings(triaged);
"""

# Eski bir veritabanı üzerinden çalışanlar için güvenli kolon ekleme.
# (CREATE TABLE IF NOT EXISTS yeni kolonları eklemez, bu yüzden ayrıca gerekli.)
_COLUMN_MIGRATIONS = [
    ("requests", "notified_at", "TEXT"),
]


def _run_migrations(conn: sqlite3.Connection) -> None:
    for table, column, col_type in _COLUMN_MIGRATIONS:
        existing_cols = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in existing_cols:
            logger.info("Migrasyon: %s.%s kolonu ekleniyor", table, column)
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")


def init_db() -> None:
    """Uygulama başlangıcında bir kez çağrılır. Şemayı garanti eder."""
    try:
        with get_connection() as conn:
            conn.executescript(SCHEMA)
            _run_migrations(conn)
            conn.commit()
        logger.info("Veritabanı şeması başarıyla doğrulandı/oluşturuldu: %s", DB_PATH)
    except sqlite3.Error as e:
        logger.critical("Veritabanı şeması oluşturulamadı: %s", e)
        raise


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    """
    Her kullanımda güvenli bir bağlantı açar, işlem bitince kapatır.
    WAL modu: yazma sırasında okumaların bloklanmasını engeller.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        yield conn
    except sqlite3.Error as e:
        logger.error("Veritabanı bağlantı hatası: %s", e)
        conn.rollback()
        raise
    finally:
        conn.close()
