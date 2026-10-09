"""
hackerone_reporter.py
---------------------
Doğrulanmış bir bulgu için HackerOne'a otomatik rapor taslağı oluşturur.

HackerOne API token almak için:
    https://hackerone.com/settings/api_token/edit

.env dosyasına ekle:
    H1_API_TOKEN=your_token_here
    H1_USERNAME=mykokko

Kullanım:
    python hackerone_reporter.py --id 676          # DB kaydından rapor oluştur
    python hackerone_reporter.py --list-programs   # Erişilebilir programları listele
"""

import argparse
import json
import logging
import os
import urllib.request
import urllib.error
from base64 import b64encode

from database import init_db, get_connection

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger("bugbounty.h1reporter")

H1_API_BASE = "https://api.hackerone.com/v1"


def get_auth_header() -> str:
    username = os.environ.get("H1_USERNAME", "")
    token = os.environ.get("H1_API_TOKEN", "")
    credentials = b64encode(f"{username}:{token}".encode()).decode()
    return f"Basic {credentials}"


def h1_request(method: str, path: str, body: dict | None = None) -> dict:
    url = f"{H1_API_BASE}{path}"
    data = json.dumps(body).encode() if body else None

    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": get_auth_header(),
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method=method
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        logger.error("H1 API hatası %s: %s", e.code, error_body[:200])
        raise


def list_programs() -> None:
    """Katılabileceğin programları listele."""
    try:
        data = h1_request("GET", "/me/programs")
        programs = data.get("data", [])
        print(f"\n{'Program':<40} {'Handle':<30} {'Max Ödül'}")
        print("-" * 80)
        for p in programs[:20]:
            attrs = p.get("attributes", {})
            handle = attrs.get("handle", "")
            name = attrs.get("name", "")[:38]
            max_bounty = attrs.get("max_bounty", {})
            amount = max_bounty.get("amount", "?") if max_bounty else "?"
            print(f"{name:<40} {handle:<30} ${amount}")
    except Exception as e:
        logger.error("Program listesi alınamadı: %s", e)


def build_report_from_db(record_id: int, program_handle: str) -> dict:
    """DB kaydından H1 rapor payload'ı oluştur."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM requests WHERE id = ?", (record_id,)
        ).fetchone()

    if not row:
        raise ValueError(f"Kayıt bulunamadı: id={record_id}")

    reasoning = row["ai_reasoning"] or ""

    # Claude analizinden severity çıkar
    severity_map = {"critical": "critical", "high": "high",
                    "medium": "medium", "low": "low"}
    severity = "medium"
    for sev in severity_map:
        if sev in reasoning.lower():
            severity = sev
            break

    # operationName'i URL'den çıkar
    import re
    op_match = re.search(r"operationName=([^&]+)", row["url"] or "")
    op_name = op_match.group(1) if op_match else "GraphQL endpoint"

    # Claude analizinden severity çıkar
    severity_map = {"critical": "critical", "high": "high",
                    "medium": "medium", "low": "low"}
    severity = "medium"
    reasoning_lower = (row["ai_reasoning"] or "").lower()
    for sev in ["critical", "high", "medium", "low"]:
        if f"severity: {sev}" in reasoning_lower or f'"severity": "{sev}"' in reasoning_lower:
            severity = sev
            break

    # Operation'a göre spesifik başlık
    title_map = {
        "GetDirectMessageUser": "Privacy Leak: isBlockingMe field exposes block relationships to blocked users via enumerable Relay Global IDs",
        "AcceptBuyerTermsMutation": "Business Logic: AcceptBuyerTermsMutation allows unauthorized LegalEntity enum manipulation to bypass regional restrictions",
        "ShippingQuoteWeb": "IDOR: ShippingQuoteWeb exposes seller shipping fee structures via enumerable listing IDs",
        "SetPhoneNumberV2": "BAC: SetPhoneNumberV2 mutation lacks user authorization check",
        "UpdateUsername": "BAC: UpdateUsername mutation lacks user authorization check",
    }
    title = title_map.get(op_name, f"IDOR/BAC: {op_name} allows unauthorized access to user resources")

    description = f"""## Summary
An authorization vulnerability was found in the following endpoint:

**Method:** {row['method']}
**URL:** `{row['url']}`

## Analysis
{reasoning[:2000]}

## Steps to Reproduce
1. Authenticate to the application
2. Send the following request with a different user's ID:

```
{row['method']} {row['url'].replace('https://www.whatnot.com', '')} HTTP/1.1
Host: {row['host']}

{(row['body'] or '')[:500]}
```

3. Observe that the response contains data belonging to another user

## Impact
An attacker can access or modify resources belonging to other users without proper authorization.

## Severity
{severity.upper()}
"""

    return {
        "data": {
            "type": "report",
            "attributes": {
                "title": title,
                "vulnerability_information": description,
                "severity_rating": severity,
                "weakness_id": 22,  # IDOR weakness ID H1'de
            },
            "relationships": {
                "program": {
                    "data": {"type": "program", "id": program_handle}
                }
            }
        }
    }


def create_draft_report(record_id: int, program_handle: str,
                        dry_run: bool = True) -> None:
    """Rapor oluştur (dry_run=True ise sadece önizle)."""
    payload = build_report_from_db(record_id, program_handle)
    attrs = payload["data"]["attributes"]

    # Validation gate: rapor öncesi FP/reddedilme filtresi
    gate = None
    try:
        from validation_gate import validate
        with get_connection() as conn:
            row = conn.execute("SELECT * FROM requests WHERE id=?", (record_id,)).fetchone()
        finding = {
            "title": attrs["title"], "name": attrs["title"],
            "severity": attrs["severity_rating"],
            "url": row["url"] if row else "",
            "matched_at": row["url"] if row else "",
            "evidence": (row["ai_reasoning"] if row else "") or "",
            "steps": attrs["vulnerability_information"],
            "raw": attrs["vulnerability_information"],
        }
        gate = validate(finding)
    except Exception as e:  # noqa: BLE001
        logger.warning("Validation gate atlandı: %s", e)

    print("\n" + "=" * 60)
    print("RAPOR ÖNİZLEMESİ")
    print("=" * 60)
    print(f"Program: {program_handle}")
    print(f"Başlık: {attrs['title']}")
    print(f"Severity: {attrs['severity_rating'].upper()}")
    if gate:
        print(f"\nVALIDATION GATE: {gate.confidence} ({gate.passed}/7) "
              f"— rapor önerilir: {'EVET' if gate.should_report else 'HAYIR'}")
        for rj in gate.rejections:
            print(f"  ⚠️  {rj}")
    print("\nAçıklama (ilk 500 karakter):")
    print(attrs['vulnerability_information'][:500])
    print("=" * 60)

    if gate and not gate.should_report:
        print("\n🛑 Validation gate bu raporu ÖNERMİYOR — reddedilme riski yüksek.")
        print("   Riskleri gider, sonra tekrar dene.")
        if not dry_run:
            print("   Gönderim iptal edildi (gate geçilmedi).")
            return

    if dry_run:
        print("\n[DRY RUN] Gerçek göndermek için: --no-dry-run ekle")
        return

    try:
        result = h1_request("POST", "/reports", payload)
        report_id = result["data"]["id"]
        print(f"\n✅ Rapor oluşturuldu: https://hackerone.com/reports/{report_id}")
    except Exception as e:
        logger.error("Rapor gönderilemedi: %s", e)


def main() -> None:
    parser = argparse.ArgumentParser(description="HackerOne Otomatik Reporter")
    parser.add_argument("--id", type=int, help="DB kayıt ID'si")
    parser.add_argument("--program", help="H1 program handle (örn: whatnot)")
    parser.add_argument("--list-programs", action="store_true",
                        help="Programları listele")
    parser.add_argument("--no-dry-run", action="store_true",
                        help="Gerçekten gönder (varsayılan: sadece önizle)")
    args = parser.parse_args()

    init_db()

    if args.list_programs:
        list_programs()
        return

    if args.id and args.program:
        create_draft_report(args.id, args.program,
                            dry_run=not args.no_dry_run)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
