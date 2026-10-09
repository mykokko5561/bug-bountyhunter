"""
triage_preprocessor.py
-----------------------
Katman 3'ün yeni ön-işleme katmanı. LLM'e istek gönderilmeden önce
yapısal analiz yapar ve zenginleştirilmiş bir bağlam üretir.

Manuel Whatnot testinden öğrenilenler:
- Modern SPA'lar ağırlıklı olarak GraphQL kullanıyor: /services/graphql/
- GraphQL'de `operationName` tek başına en güçlü risk sinyali
- `variables` içindeki ID'ler genelde Base64 Relay Global ID formatında
  (örn. "UHVibGljVXNlck5vZGU6MTc5NzQwMDk=" → "PublicUserNode:17974009")
- REST endpoint'lerde path segmentlerindeki sıralı sayısal ID'ler
  (örn. /api/v1/orders/42) en klasik IDOR yüzeyi
- UUID içeren endpoint'ler tahmin edilemez olduğu için genelde düşük öncelikli

Bu modül LLM'e "ham HTTP isteği" yerine "ne anlama geliyor" bilgisini veriyor.
"""

import base64
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qsl

logger = logging.getLogger("bugbounty.preprocessor")


# GraphQL operasyon tipine göre risk ağırlıkları
# Mutation > Query, çünkü mutation state değiştirir (ödeme, sipariş, mesaj vb.)
GRAPHQL_OPERATION_RISK: dict[str, float] = {
    # Kırmızı: state-changing + kullanıcı kaynağı
    "mutation": 0.9,
    # Turuncu: kullanıcıya özel okuma işlemleri
    "query_user_resource": 0.7,
    # Sarı: genel okuma
    "query_public": 0.3,
    # Yeşil: analitik/telemetri
    "analytics": 0.0,
}

# operationName içindeki bu anahtar kelimeler yüksek riske işaret eder
HIGH_VALUE_OP_KEYWORDS = {
    # Ödeme ve finans
    "payment", "checkout", "order", "invoice", "refund", "transfer",
    "wallet", "balance", "price", "billing", "subscription", "purchase",
    # Kullanıcı ve kimlik
    "user", "account", "profile", "address", "admin", "role", "permission",
    "privilege", "settings", "preferences", "notification",
    # Mesajlaşma ve sosyal
    "message", "inbox", "conversation", "directmessage", "dm", "send",
    # Dosya ve içerik
    "upload", "delete", "update", "create", "edit", "remove", "modify",
    # Satış ve ticaret
    "seller", "buyer", "listing", "auction", "bid", "offer", "shipping",
}

# Düşük değerli operasyonlar (filtrele)
LOW_VALUE_OP_KEYWORDS = {
    "analytics", "telemetry", "tracking", "beacon", "log", "metric",
    "config", "public", "static", "search", "browse", "feed",
}

# Sıralı/tahmin edilebilir ID formatları (en yüksek IDOR riski)
_NUMERIC_PATH_ID = re.compile(r"/(\d{3,12})(?:/|$|\?)")
_UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I
)
_BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

# Relay Global ID'nin imzası (decode sonrası)
_RELAY_ID_PATTERN = re.compile(r"^([A-Za-z]+Node|[A-Za-z]+):(\d+)$")


@dataclass
class DecodedId:
    raw: str
    id_type: str        # "relay_global", "uuid", "numeric", "base64_opaque"
    decoded: str        # insan okunabilir
    numeric_value: Optional[int] = None  # varsa gerçek sayısal değer


@dataclass
class GraphQLContext:
    operation_type: str       # "query" | "mutation" | "subscription" | "unknown"
    operation_name: str
    variables: dict
    risk_score: float         # 0.0 - 1.0
    decoded_ids: list[DecodedId] = field(default_factory=list)


@dataclass
class EnrichedRequest:
    """LLM'e gönderilecek zenginleştirilmiş istek bağlamı."""
    method: str
    url: str
    host: str
    path: str

    # Parametre analizi
    path_ids: list[str]           # path'te bulunan sayısal ID'ler
    query_params: dict[str, str]
    decoded_query_ids: list[DecodedId]

    # GraphQL (varsa)
    graphql: Optional[GraphQLContext]

    # Genel özetler
    has_auth: bool                # Authorization/Cookie başlığı var mı?
    content_type: str
    body_preview: str             # İlk 400 karakter
    all_decoded_ids: list[DecodedId]  # Tüm decode edilmiş ID'ler

    # Önceden hesaplanmış risk sinyalleri
    pre_risk_score: float         # 0.0 - 1.0
    risk_reasons: list[str]


def _try_decode_base64_relay(value: str) -> Optional[DecodedId]:
    """
    Bir string'in Base64 Relay Global ID olup olmadığını test eder.
    Ör: "UHVibGljVXNlck5vZGU6MTc5NzQwMDk=" → "PublicUserNode:17974009"
    """
    try:
        # URL-safe ve normal base64'ü dene
        for v in [value, value.replace("-", "+").replace("_", "/")]:
            # padding düzelt
            padding = 4 - len(v) % 4
            padded = v + ("=" * padding) if padding != 4 else v
            decoded = base64.b64decode(padded).decode("utf-8", errors="strict")
            m = _RELAY_ID_PATTERN.match(decoded)
            if m:
                numeric = int(m.group(2)) if m.group(2).isdigit() else None
                return DecodedId(
                    raw=value,
                    id_type="relay_global",
                    decoded=decoded,
                    numeric_value=numeric,
                )
    except Exception:
        pass
    return None


def _extract_ids_from_text(text: str) -> list[DecodedId]:
    """Metin içindeki tüm tanınabilir ID'leri çıkarır."""
    found: list[DecodedId] = []
    seen_raws: set[str] = set()

    # Base64 → Relay Global ID
    for m in _BASE64_PATTERN.finditer(text):
        raw = m.group(0)
        if raw in seen_raws or len(raw) < 20:
            continue
        seen_raws.add(raw)
        decoded = _try_decode_base64_relay(raw)
        if decoded:
            found.append(decoded)

    # UUID
    for m in _UUID_PATTERN.finditer(text):
        raw = m.group(0)
        if raw not in seen_raws:
            seen_raws.add(raw)
            found.append(DecodedId(raw=raw, id_type="uuid", decoded=raw))

    # Sıralı sayısal ID (path segmentleri)
    for m in _NUMERIC_PATH_ID.finditer(text):
        raw = m.group(1)
        if raw not in seen_raws:
            seen_raws.add(raw)
            found.append(DecodedId(
                raw=raw, id_type="numeric", decoded=raw, numeric_value=int(raw)
            ))

    return found


def _analyze_graphql(body: str) -> Optional[GraphQLContext]:
    """GraphQL isteğini parse edip risk bağlamı üretir."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None

    if "query" not in data and "operationName" not in data:
        return None

    op_name = data.get("operationName", "Unknown")
    variables = data.get("variables") or {}
    query_str = data.get("query", "")

    # operation tipini belirle
    op_type = "unknown"
    q = query_str.strip().lower()
    if q.startswith("mutation"):
        op_type = "mutation"
    elif q.startswith("query"):
        op_type = "query"
    elif q.startswith("subscription"):
        op_type = "subscription"

    # Risk skoru hesapla
    op_lower = op_name.lower()
    risk = 0.2  # başlangıç
    reasons = []

    if op_type == "mutation":
        risk += 0.4
        reasons.append("GraphQL mutation (state-changing)")

    if any(kw in op_lower for kw in HIGH_VALUE_OP_KEYWORDS):
        risk += 0.3
        matched = [kw for kw in HIGH_VALUE_OP_KEYWORDS if kw in op_lower]
        reasons.append(f"Yüksek değerli operation keyword'ler: {matched}")

    if any(kw in op_lower for kw in LOW_VALUE_OP_KEYWORDS):
        risk -= 0.2

    # Variables içindeki ID'leri decode et
    vars_text = json.dumps(variables, ensure_ascii=False)
    decoded_ids = _extract_ids_from_text(vars_text)

    if decoded_ids:
        relay_ids = [d for d in decoded_ids if d.id_type == "relay_global"]
        numeric_ids = [d for d in decoded_ids if d.id_type == "numeric"]
        if relay_ids:
            risk += 0.2
            reasons.append(f"Relay Global ID: {[d.decoded for d in relay_ids]}")
        if numeric_ids:
            risk += 0.15
            reasons.append(f"Sayısal ID: {[d.decoded for d in numeric_ids]}")

    risk = min(1.0, max(0.0, risk))
    logger.debug("GraphQL analiz: op=%s, type=%s, risk=%.2f", op_name, op_type, risk)

    return GraphQLContext(
        operation_type=op_type,
        operation_name=op_name,
        variables=variables,
        risk_score=risk,
        decoded_ids=decoded_ids,
    )


def preprocess_request(
    method: str,
    url: str,
    host: str,
    headers: dict,
    body: Optional[str],
) -> EnrichedRequest:
    """
    Bir HTTP isteğini tam analiz edip LLM için zenginleştirilmiş bağlam üretir.
    """
    parsed = urlparse(url)
    path = parsed.path

    # Path'teki sayısal ID'ler
    path_ids = [m.group(1) for m in _NUMERIC_PATH_ID.finditer(path)]

    # Query parametreleri + içlerindeki ID'ler
    query_params = dict(parse_qsl(parsed.query))
    query_text = parsed.query
    decoded_query_ids = _extract_ids_from_text(query_text)

    # Auth varlığı
    h_lower = {k.lower(): v for k, v in headers.items()}
    has_auth = bool(h_lower.get("authorization") or h_lower.get("cookie"))

    content_type = h_lower.get("content-type", "")
    body_preview = (body or "")[:400]

    # Body analizi
    graphql: Optional[GraphQLContext] = None
    body_ids: list[DecodedId] = []

    if body:
        if "application/json" in content_type:
            graphql = _analyze_graphql(body)
            if graphql is None:
                body_ids = _extract_ids_from_text(body[:1000])
        else:
            body_ids = _extract_ids_from_text(body[:1000])

    # Tüm ID'leri birleştir
    all_ids = decoded_query_ids + body_ids
    if graphql:
        all_ids += graphql.decoded_ids

    # Pre-risk skoru ve gerekçeler
    risk = 0.0
    reasons: list[str] = []

    if graphql:
        risk = graphql.risk_score
        if graphql.operation_type == "mutation":
            reasons.append(f"GraphQL mutation: {graphql.operation_name}")
        else:
            reasons.append(f"GraphQL query: {graphql.operation_name}")
        for d in graphql.decoded_ids:
            if d.id_type == "relay_global":
                reasons.append(f"Relay ID: {d.decoded}")
    else:
        # REST analizi
        method_up = method.upper()
        if method_up in ("POST", "PUT", "PATCH", "DELETE"):
            risk += 0.35
            reasons.append(f"State-changing method: {method_up}")
        if path_ids:
            risk += 0.25
            reasons.append(f"Path'te sayısal ID: {path_ids}")
        relay_ids = [d for d in all_ids if d.id_type == "relay_global"]
        if relay_ids:
            risk += 0.3
            reasons.append(f"Relay ID: {[d.decoded for d in relay_ids]}")
        if has_auth:
            risk += 0.1

    risk = min(1.0, max(0.0, risk))

    return EnrichedRequest(
        method=method,
        url=url,
        host=host,
        path=path,
        path_ids=path_ids,
        query_params=query_params,
        decoded_query_ids=decoded_query_ids,
        graphql=graphql,
        has_auth=has_auth,
        content_type=content_type,
        body_preview=body_preview,
        all_decoded_ids=all_ids,
        pre_risk_score=risk,
        risk_reasons=reasons,
    )
