"""
validation_gate.py — Rapor Öncesi Doğrulama Kapısı (BurpNake 7-aşama fikri)
Bir bulguyu rapora göndermeden önce 7 aşamadan geçirir. Amaç: false-positive
ve reddedilecek raporları ELEMEK — senin ana derdin ("reddedilmesin").

Aşamalar:
  1. Reproducibility  — adım/PoC/kanıt var mı?
  2. Scope check      — hedef gerçekten in-scope mu?
  3. Impact           — gerçek etki var mı (info-only değil)?
  4. Duplicate        — DB'de aynısı var mı?
  5. False-positive   — bilinen FP kalıbı mı (Firebase public key, security.txt, rate-limit)?
  6. Exploitability   — sömürülebilir mi yoksa teorik mi?
  7. Report quality   — başlık/açıklama/PoC yeterli mi?

Sonuç: CONFIRMED (7/7) | FIRM (5-6) | TENTATIVE (<5) + reddedilme sebepleri.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# HackerOne'da rutin REDDEDİLEN kalıplar (bunları en baştan ele)
KNOWN_REJECT_PATTERNS = [
    (r"security\.txt", "security.txt bulunması/eksikliği — informational, reddedilir"),
    (r"rate[\s_-]?limit", "rate limiting — HackerOne Core Ineligible, reddedilir"),
    (r"firebase.*(AIza|api.?key)|AIza.*firebase", "Firebase public API key — tasarım gereği public, reddedilir"),
    (r"missing.*(header|CSP|HSTS)\b(?!.*exploit)", "sadece eksik güvenlik header'ı — genelde informational"),
    (r"self[\s-]?xss", "self-XSS — etki yok, reddedilir"),
    (r"clickjack.*(login|logout)\b", "hassas olmayan sayfada clickjacking — düşük/reddedilir"),
    (r"version.?disclosure|banner", "sürüm/banner disclosure — informational"),
    (r"verbose.?error(?!.*(stack|sql|secret))", "genel verbose error — etki yoksa informational"),
]

SCOPE_OK_DEFAULT = True  # scope_manager yoksa geçir


@dataclass
class GateResult:
    confidence: str = "TENTATIVE"
    passed: int = 0
    total: int = 7
    stages: dict = field(default_factory=dict)
    rejections: list = field(default_factory=list)
    should_report: bool = False


def _in_scope(url: str) -> bool:
    try:
        from scope_manager import scope_manager
        return scope_manager.is_in_scope(url)
    except Exception:  # noqa: BLE001
        return SCOPE_OK_DEFAULT


def validate(finding: dict) -> GateResult:
    """
    finding beklenen alanlar (esnek):
      title/name, url/host, severity, poc (curl/python), evidence,
      steps, category
    """
    r = GateResult()
    blob = " ".join(str(finding.get(k, "")) for k in
                    ("title", "name", "category", "raw", "evidence", "note")).lower()

    # 1) Reproducibility
    has_poc = bool(finding.get("poc") or finding.get("poc_curl") or finding.get("poc_python"))
    has_steps = bool(finding.get("steps") or finding.get("steps_to_reproduce"))
    has_evidence = bool(finding.get("evidence") or finding.get("matched_at"))
    s1 = has_poc or (has_steps and has_evidence)
    r.stages["reproducibility"] = s1

    # 2) Scope
    url = finding.get("url") or finding.get("host") or finding.get("matched_at") or ""
    s2 = _in_scope(url)
    r.stages["scope"] = s2
    if not s2:
        r.rejections.append("Hedef in-scope değil")

    # 3) Impact (info-only mu?)
    sev = (finding.get("severity") or "").lower()
    s3 = sev not in ("info", "informational", "none", "")
    r.stages["impact"] = s3
    if not s3:
        r.rejections.append("Etki yok / informational")

    # 4) Duplicate
    s4 = not _is_duplicate(finding)
    r.stages["duplicate"] = s4
    if not s4:
        r.rejections.append("DB'de aynı bulgu mevcut (duplicate)")

    # 5) False-positive / bilinen reddedilme kalıbı
    reject_reason = None
    for pat, why in KNOWN_REJECT_PATTERNS:
        if re.search(pat, blob, re.IGNORECASE):
            reject_reason = why
            break
    s5 = reject_reason is None
    r.stages["false_positive"] = s5
    if not s5:
        r.rejections.append(f"Bilinen reddedilme kalıbı: {reject_reason}")

    # 6) Exploitability (teorik mi?)
    theoretical = bool(re.search(r"\b(teorik|theoretical|potential|might|could be|olabilir|aday|candidate)\b", blob))
    s6 = has_poc or not theoretical
    r.stages["exploitability"] = s6
    if not s6:
        r.rejections.append("Sömürülebilirlik kanıtlanmamış (teorik) — PoC ekle")

    # 7) Report quality
    title = finding.get("title") or finding.get("name") or ""
    s7 = len(str(title)) > 8 and (has_poc or has_evidence)
    r.stages["report_quality"] = s7
    if not s7:
        r.rejections.append("Rapor kalitesi düşük (başlık/PoC/kanıt yetersiz)")

    r.passed = sum(1 for v in r.stages.values() if v)
    if r.passed == 7:
        r.confidence = "CONFIRMED"
    elif r.passed >= 5:
        r.confidence = "FIRM"
    else:
        r.confidence = "TENTATIVE"

    # Rapor kararı: scope + FP + impact kesinlikle geçmeli
    r.should_report = r.stages["scope"] and r.stages["false_positive"] and r.stages["impact"] and r.passed >= 5
    return r


def _is_duplicate(finding: dict) -> bool:
    try:
        from database import get_connection
    except Exception:  # noqa: BLE001
        return False
    name = finding.get("title") or finding.get("name") or ""
    loc = finding.get("url") or finding.get("matched_at") or ""
    if not name:
        return False
    try:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) c FROM recon_findings WHERE name=? AND matched_at=?",
                (name, loc)).fetchone()
        return (row["c"] or 0) > 1
    except Exception:  # noqa: BLE001
        return False


if __name__ == "__main__":
    print("=== reddedilecek (security.txt) ===")
    res = validate({"name": "Missing security.txt", "severity": "low", "url": "https://x.com"})
    print(res.confidence, "report:", res.should_report, res.rejections)
    print("\n=== iyi IDOR (PoC'li) ===")
    res = validate({"name": "IDOR in orders endpoint", "severity": "high",
                    "url": "https://api.x.com/orders/1", "poc_curl": "curl ...",
                    "steps": "1..2..3", "evidence": "returned other user data"})
    print(res.confidence, "report:", res.should_report, f"{res.passed}/7")
