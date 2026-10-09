"""
poc_generator.py — PoC Üretici (curl + python) (BurpNake/Strix fikri)
Bir bulgudan çalışan Proof-of-Concept üretir. Raporda somut PoC olması
kabul oranını ciddi artırır (senin "reddedilmesin" derdine doğrudan katkı).

`requests` tablosundaki yakalanmış istekten veya elle verilen istekten
curl + python requests PoC'si çıkarır; IDOR/param testleri için varyant
PoC de üretir.
"""

from __future__ import annotations

import json
import shlex
from urllib.parse import urlparse


def _headers_to_curl(headers: dict) -> str:
    out = []
    for k, v in (headers or {}).items():
        if k.lower() in ("content-length", "host"):
            continue
        out.append(f"-H {shlex.quote(f'{k}: {v}')}")
    return " ".join(out)


def curl_poc(method: str, url: str, headers: dict | None = None,
             body: str | None = None) -> str:
    parts = [f"curl -sk -X {method.upper()}", shlex.quote(url)]
    if headers:
        parts.append(_headers_to_curl(headers))
    if body:
        parts.append(f"--data {shlex.quote(body)}")
    return " ".join(parts)


def python_poc(method: str, url: str, headers: dict | None = None,
               body: str | None = None) -> str:
    h = json.dumps(headers or {}, indent=4, ensure_ascii=False)
    data_line = f"data={body!r}, " if body else ""
    return f'''import requests

url = {url!r}
headers = {h}
r = requests.request({method.upper()!r}, url, headers=headers, {data_line}verify=False)
print(r.status_code, len(r.text))
print(r.text[:500])
'''


def idor_poc(method: str, url: str, headers: dict, orig_id: str, test_id: str,
             where: str = "path") -> dict:
    """IDOR için iki-hesap PoC'si: kendi ID'n vs başkasının ID'si."""
    if where == "path":
        victim_url = url.replace(f"/{orig_id}", f"/{test_id}")
    else:  # query
        victim_url = url.replace(f"={orig_id}", f"={test_id}")
    return {
        "description": f"IDOR: {orig_id} -> {test_id} ({where}). Kendi hesabınla giriş yapıp "
                       f"başka kullanıcının nesnesine eriş.",
        "step1_own": curl_poc(method, url, headers),
        "step2_victim": curl_poc(method, victim_url, headers),
        "verify": "step2 başka kullanıcının verisini 200 ile döndürüyorsa IDOR doğrulandı.",
        "python": python_poc(method, victim_url, headers),
    }


def generate_from_db(request_id: int) -> dict | None:
    """requests tablosundaki bir kayıttan PoC üret."""
    try:
        from database import get_connection
    except Exception:  # noqa: BLE001
        print("[poc] database yok")
        return None
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
    if not row:
        print(f"[poc] #{request_id} bulunamadı")
        return None
    try:
        headers = json.loads(row["headers_json"] or "{}")
    except json.JSONDecodeError:
        headers = {}
    return {
        "curl": curl_poc(row["method"], row["url"], headers, row["body"]),
        "python": python_poc(row["method"], row["url"], headers, row["body"]),
    }


if __name__ == "__main__":
    # demo
    h = {"Authorization": "Bearer TOKEN", "Content-Type": "application/json"}
    print("=== curl ===")
    print(curl_poc("GET", "https://api.example.com/v1/orders/1001", h))
    print("\n=== IDOR PoC ===")
    poc = idor_poc("GET", "https://api.example.com/v1/orders/1001", h, "1001", "1002")
    print(poc["description"])
    print("Kendi:", poc["step1_own"])
    print("Kurban:", poc["step2_victim"])
    print(poc["verify"])
