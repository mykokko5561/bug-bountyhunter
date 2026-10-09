"""
triage_prompts.py (v2)
-----------------------
Preprocessor'dan gelen zenginleştirilmiş bağlamı kullanarak
LLM'e çok daha isabetli bir prompt üretir.
"""

from triage_preprocessor import EnrichedRequest


SYSTEM_PROMPT = """You are an expert bug bounty triage filter specializing in:
- IDOR (Insecure Direct Object Reference)
- BAC (Broken Access Control)
- Business Logic vulnerabilities

You receive a PRE-ANALYZED HTTP request with decoded IDs and risk signals already extracted.
Your job: make the final escalation decision.

ESCALATE when:
- GraphQL MUTATION touching user/account/order/payment/message resources
- GraphQL QUERY with Relay Global IDs (e.g. "PublicUserNode:12345") referencing specific user resources
- REST endpoint with numeric path IDs + authenticated session + state-changing method
- Any operation involving: payment, transfer, admin, permission, role, order, refund, wallet

DO NOT ESCALATE when:
- Analytics, telemetry, logging operations (even if authenticated)
- Public read-only queries with no user-specific IDs
- Static asset loading, health checks
- Operations with only UUIDs (non-sequential, hard to predict)

IMPORTANT: If pre_risk_score >= 0.7, lean toward escalating unless you have a strong reason not to.

Respond STRICT JSON only:
{
  "interesting": true or false,
  "category": "idor" | "bac" | "business_logic" | "secret_exposure" | "none",
  "confidence": float 0-1,
  "reason": "<40 words English explanation",
  "attack_hint": "one concrete test idea or null"
}"""


def build_enriched_prompt(req: EnrichedRequest) -> str:
    """Zenginleştirilmiş bağlamdan LLM prompt'u üretir."""

    lines = [
        f"METHOD: {req.method}",
        f"URL: {req.url}",
        f"HAS_AUTH: {req.has_auth}",
        f"PRE_RISK_SCORE: {req.pre_risk_score:.2f}",
    ]

    if req.risk_reasons:
        lines.append(f"RISK_SIGNALS: {', '.join(req.risk_reasons)}")

    if req.graphql:
        gql = req.graphql
        lines.append(f"GRAPHQL_TYPE: {gql.operation_type}")
        lines.append(f"GRAPHQL_OPERATION: {gql.operation_name}")

        if gql.decoded_ids:
            id_summary = []
            for d in gql.decoded_ids:
                if d.id_type == "relay_global":
                    id_summary.append(f"RelayID({d.decoded})")
                elif d.id_type == "numeric":
                    id_summary.append(f"NumericID({d.decoded})")
                elif d.id_type == "uuid":
                    id_summary.append(f"UUID({d.raw[:8]}...)")
            lines.append(f"DECODED_IDS_IN_VARIABLES: {', '.join(id_summary)}")

        # Variables'ı kırparak göster (sadece değer tiplerini)
        vars_summary = _summarize_variables(gql.variables)
        if vars_summary:
            lines.append(f"VARIABLES_SUMMARY: {vars_summary}")
    else:
        if req.path_ids:
            lines.append(f"PATH_NUMERIC_IDS: {req.path_ids}")
        if req.decoded_query_ids:
            lines.append(f"QUERY_DECODED_IDS: {[d.decoded for d in req.decoded_query_ids]}")
        if req.body_preview:
            lines.append(f"BODY_PREVIEW: {req.body_preview[:300]}")

    prompt = "\n".join(lines)

    # Uzman metodoloji enjeksiyonu (skills_loader): tespit edilen zafiyet
    # sınıfının playbook'unu prompt'a ekle — tahmin yerine metodoloji.
    try:
        from skills_loader import detect_and_load
        signal_text = prompt + " " + " ".join(req.risk_reasons or [])
        methodology, names = detect_and_load(signal_text, max_skills=1, max_chars=1200)
        if methodology:
            prompt += (f"\n\n--- UZMAN METODOLOJİ ({', '.join(names)}) ---\n"
                       f"{methodology}\n--- Bu metodolojiyi dikkate al. ---")
    except Exception:  # noqa: BLE001
        pass

    return prompt


def _summarize_variables(variables: dict, max_depth: int = 2) -> str:
    """GraphQL variables'ı kısa ve okunabilir biçimde özetler."""
    if not variables:
        return ""

    parts = []
    for key, val in list(variables.items())[:10]:
        if val is None:
            parts.append(f"{key}=null")
        elif isinstance(val, bool):
            parts.append(f"{key}={val}")
        elif isinstance(val, (int, float)):
            parts.append(f"{key}={val}")
        elif isinstance(val, str):
            if len(val) > 40:
                parts.append(f"{key}=<string:{len(val)}chars>")
            else:
                parts.append(f"{key}={val!r}")
        elif isinstance(val, list):
            parts.append(f"{key}=[{len(val)} items]")
        elif isinstance(val, dict):
            parts.append(f"{key}={{...{len(val)} keys}}")
        else:
            parts.append(f"{key}=?")

    return " | ".join(parts)


# Geriye dönük uyumluluk: triage_worker.py eski fonksiyonu çağırabilir
def build_user_prompt(
    method: str,
    url: str,
    headers: dict,
    body=None,
    max_body_chars: int = 800,
) -> str:
    """Eski API — sadece zenginleştirilmiş versiyonu kullan."""
    from triage_preprocessor import preprocess_request
    req = preprocess_request(method, url, url.split("/")[2] if "/" in url else url, headers, body)
    return build_enriched_prompt(req)
