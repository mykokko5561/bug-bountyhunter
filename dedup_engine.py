"""
dedup_engine.py
---------------
Tekilleştirme (deduplication) mantığının kalbi.

KRİTİK TASARIM NOTU:
Dedup key'i sadece URL üzerinden üretmek YANLIŞTIR. Business Logic / IDOR
zafiyetleri genelde AYNI endpoint'e FARKLI parametrelerle (örn. user_id=5
vs user_id=6) giden isteklerde saklanır. Eğer sadece URL hash'lersek,
bu isteklerin çoğu "duplicate" sayılıp elenir ve altın değerindeki
isteği kaybederiz.

Bu yüzden hash şu bileşenlerden üretilir:
    METHOD + NORMALIZE_EDILMIS_URL (query string dahil, sıralanmış) + BODY_HASH

Query string'i sıralıyoruz ki ?a=1&b=2 ile ?b=2&a=1 aynı hash'i üretsin
(gerçek duplicate'ler doğru elensin), ama parametre DEĞERİ değişince
(user_id=5 -> user_id=6) hash de değişsin (gerçek varyasyonlar korunsun).
"""

import hashlib
import logging
import re
from urllib.parse import urlparse, parse_qsl, urlencode

logger = logging.getLogger("bugbounty.dedup")

# Bug bounty açısından gürültü olan, analiz değeri taşımayan statik uzantılar.
STATIC_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".mp4", ".mp3",
}


def is_static_asset(url: str) -> bool:
    """URL bir statik dosyaya mı işaret ediyor? True ise triyaja gönderilmez."""
    try:
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)
    except ValueError:
        # Bozuk URL gelirse güvenli tarafta kal: statik değil, analiz edilsin.
        logger.warning("URL parse edilemedi, statik-değil varsayılıyor: %s", url)
        return False


# Kasada, PerimeterX, Akamai gibi bot-koruma SDK'ları kendi telemetri/
# fingerprint trafiğini sitenin KENDİ domain'i üzerinden, rastgele görünümlü
# path segmentleriyle proxy'ler (reklam engelleyici/bot tespitini zorlaştırmak
# için). Bu path'ler UUID'ye benzediği için local AI'ı "IDOR/BAC" diye yanlış
# yönlendirebiliyor — biz bunu regex ile daha ucuza ve daha güvenilir yakalayıp
# LLM'e sormadan elemeliyiz.
#
# Kalıp: /{uuid}/{uuid}/{2-4 harfli kısa kod}  (örn. /.../.../fp, /.../.../tl)
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_BOT_PROTECTION_PATH_PATTERN = re.compile(
    rf"^/{_UUID}/{_UUID}/[a-z]{{2,4}}$", re.IGNORECASE
)
# Bilinen bot-koruma sorgu parametreleri (Kasada'nın "kpsdk" imzası gibi).
_BOT_PROTECTION_QUERY_MARKERS = ("x-kpsdk-", "kpsdk_", "_px", "akamai_")


def is_bot_protection_noise(url: str) -> bool:
    """
    Kasada/PerimeterX/Akamai tarzı bot-koruma telemetri isteklerini VE
    Segment gibi analitik SDK'ların reverse-proxy edilmiş çağrılarını tespit
    eder. Bunların hiçbiri gerçek uygulama mantığı içermez, sadece
    fingerprint/telemetri/analitik verisi taşır — IDOR/BAC testi için
    değersizdir.
    """
    try:
        parsed = urlparse(url)
        path_lower = parsed.path.lower()

        if _BOT_PROTECTION_PATH_PATTERN.match(parsed.path):
            return True

        query_lower = parsed.query.lower()
        if any(marker in query_lower for marker in _BOT_PROTECTION_QUERY_MARKERS):
            return True

        # Segment.io ve benzeri analitik SDK'ların site-üzerinden proxy'lenen
        # çağrıları: path'te "segment_cdn", "segment/v1", "analytics-write"
        # gibi imzalar + sonunda /settings, /batch, /identify, /track gibi
        # Segment'e özgü sabit son-endpoint'ler.
        if "segment_cdn" in path_lower or "segment/v1" in path_lower:
            return True

        # Statsig feature-flag SDK'sının telemetri endpoint'i
        if "statsig/rgstr" in path_lower or "statsig/v1" in path_lower:
            return True

        # Datadog RUM log beacon
        if "datadog/api/v2/logs" in path_lower:
            return True

        # Next.js App Router'ın React Server Components prefetch mekanizması:
        # tarayıcı bir linkin üzerine gelince veya link viewport'a girince
        # OTOMATİK olarak "?_rsc=<hash>" ile arka plan isteği atar. Bu hash
        # kullanıcı kaynağı değil, framework'ün build/route cache anahtarıdır.
        query_params = dict(parse_qsl(parsed.query))
        if "_rsc" in query_params:
            return True

        return False
    except ValueError:
        return False


def _normalize_url(url: str) -> str:
    """Query string parametrelerini sıralayarak URL'i normalize eder."""
    parsed = urlparse(url)
    sorted_query = urlencode(sorted(parse_qsl(parsed.query)))
    normalized = parsed._replace(query=sorted_query, fragment="")
    return normalized.geturl()


def compute_dedup_hash(method: str, url: str, body: str | None) -> str:
    """
    İsteğin benzersiz parmak izini üretir.
    body None ise boş string'e düşürülür (GET istekleri için).
    """
    normalized_url = _normalize_url(url)
    body_content = body or ""

    fingerprint_source = f"{method.upper()}::{normalized_url}::{body_content}"
    digest = hashlib.md5(fingerprint_source.encode("utf-8", errors="ignore")).hexdigest()

    logger.debug("Dedup hash üretildi: %s -> %s", fingerprint_source[:120], digest)
    return digest
