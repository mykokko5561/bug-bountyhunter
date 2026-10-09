"""
chain_builder.py — Zafiyet Zincirleme (BurpNake fikri, bizim DB'ye uyarlandı)
recon_findings + requests tablosundaki bulguları tarar, bilinen zincir
kalıplarıyla eşleştirir ve düşük/orta bulguları KRİTİK zincire yükseltir.

Örn: Open Redirect + OAuth state eksikliği = Account Takeover
     XSS + CORS misconfig = token çalma = ATO
     IDOR + sensitive data exposure = toplu veri sızıntısı

Zincir bulunca recon_findings'e 'chain' kaynağıyla yüksek severity kayıt açar.
"""

from __future__ import annotations

from datetime import datetime, timezone

try:
    from database import init_db, get_connection
    _HAS_DB = True
except Exception:  # noqa: BLE001
    _HAS_DB = False


# Zincir kalıpları: gereken zafiyet sinyalleri -> sonuç
KNOWN_CHAINS = [
    {
        "name": "Open Redirect + OAuth = Account Takeover",
        "requires": ["open redirect", "oauth"],
        "severity": "critical",
        "impact": "OAuth akışında state/redirect doğrulaması eksikse token çalma ile hesap ele geçirme",
    },
    {
        "name": "XSS + CORS = Account Takeover",
        "requires": ["xss", "cors"],
        "severity": "critical",
        "impact": "XSS ile CORS misconfig birleşince oturum token/cookie çalınabilir",
    },
    {
        "name": "IDOR + Sensitive Data = Mass Data Exposure",
        "requires": ["idor", ["sensitive", "data exposure", "information disclosure"]],
        "severity": "high",
        "impact": "IDOR ile diğer kullanıcıların hassas verisine toplu erişim",
    },
    {
        "name": "SSRF + Cloud Metadata = Infra Takeover",
        "requires": ["ssrf", ["metadata", "169.254", "cloud"]],
        "severity": "critical",
        "impact": "SSRF ile cloud metadata (169.254.169.254) erişimi = AWS/GCP anahtar sızıntısı",
    },
    {
        "name": "postMessage KS leak + no framing protection = ATO",
        "requires": ["postmessage", ["frame", "x-frame", "clickjack"]],
        "severity": "critical",
        "impact": "Origin doğrulamayan postMessage + framing korumasının olmaması = token hırsızlığı",
    },
    {
        "name": "Subdomain Takeover + Cookie scope = Session theft",
        "requires": ["subdomain takeover", "cookie"],
        "severity": "high",
        "impact": "Ele geçirilen subdomain + geniş cookie scope = oturum çalma",
    },
]


def _text_of(finding: dict) -> str:
    return " ".join(str(finding.get(k, "")) for k in ("name", "matched_at", "raw", "host")).lower()


def _matches_signal(signal, blob: str) -> bool:
    """signal str ise 'içeriyor mu', list ise 'herhangi biri var mı'."""
    if isinstance(signal, list):
        return any(s.lower() in blob for s in signal)
    return signal.lower() in blob


def analyze_chains(findings: list[dict]) -> list[dict]:
    """Bulgu listesini zincir kalıplarıyla eşleştir."""
    blob_all = " || ".join(_text_of(f) for f in findings)
    host_set = {f.get("host", "") for f in findings}
    chains = []
    for chain in KNOWN_CHAINS:
        matched = [sig for sig in chain["requires"] if _matches_signal(sig, blob_all)]
        coverage = len(matched) / len(chain["requires"])
        if coverage == 1.0:  # tüm parçalar mevcut
            chains.append({
                "name": chain["name"],
                "severity": chain["severity"],
                "impact": chain["impact"],
                "coverage": coverage,
                "hosts": sorted(h for h in host_set if h),
            })
    return chains


def run(db_path: str | None = None) -> list[dict]:
    if not _HAS_DB:
        print("[chain] database yok")
        return []
    init_db()
    with get_connection() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT host, name, matched_at, raw FROM recon_findings"
        ).fetchall()]
    chains = analyze_chains(rows)
    if chains:
        now = datetime.now(timezone.utc).isoformat()
        with get_connection() as conn:
            for c in chains:
                conn.execute(
                    "INSERT INTO recon_findings (host, source, severity, name, matched_at, raw, found_at) "
                    "VALUES (?, 'chain', ?, ?, ?, ?, ?)",
                    (",".join(c["hosts"])[:100] or "chain", c["severity"],
                     f"ZİNCİR: {c['name']}", c["name"], c["impact"], now))
            conn.commit()
        print(f"[chain] {len(chains)} zincir bulundu:")
        for c in chains:
            print(f"  [{c['severity'].upper()}] {c['name']}")
            print(f"      {c['impact']}")
    else:
        print("[chain] eşleşen zincir yok (henüz yeterli bulgu yok)")
    return chains


if __name__ == "__main__":
    # demo
    demo = [
        {"name": "Open Redirect", "raw": "?url= redirect", "host": "x.com"},
        {"name": "OAuth login flow", "raw": "oauth state missing", "host": "x.com"},
    ]
    for c in analyze_chains(demo):
        print("DEMO zincir:", c["name"], "->", c["severity"])
    run()
