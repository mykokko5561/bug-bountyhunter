"""
layer2_idor.py — Katman 2: IDOR Auto-Tester
Yakalanmış bir isteği alır, içindeki ID'leri bulur, komşu ID'lerle tekrar
gönderip yetkisiz erişim (IDOR) belirtisi arar.

İki giriş yolu:
  1) --db-id <id>      : Caido'nun `requests` tablosuna yakaladığı isteği çeker
                         (mevcut capture pipeline'ına oturur — /idor komutu bunu kullanır)
  2) <request.json>    : Elle hazırlanmış istek dosyası

GÜVENLİK:
  - Varsayılan SADECE güvenli metodlar (GET/HEAD/OPTIONS) ve GraphQL "query" POST.
  - POST/PUT/PATCH/DELETE başka kullanıcının verisini bozabileceği için
    --allow-writes olmadan atlanır. Sadece scope içi hedeflerde çalıştır.

Adaylar merkezi DB'deki `recon_findings` tablosuna (source='idor') yazılır.

Bağımlılıklar: httpx
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import re
import sys
import warnings
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

import httpx

from database import init_db, get_connection

HTTP_TIMEOUT = 15.0
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _id_variants(original: int) -> list[int]:
    cands = {original - 1, original + 1, original - 100, original + 100, 1, 2, 3}
    return sorted(v for v in cands if v >= 0 and v != original)


# --------------------------------------------------------------------------- #
# ID tespiti
# --------------------------------------------------------------------------- #
def _find_path_ids(path: str) -> list[tuple[str, int]]:
    return [(seg, int(seg)) for seg in path.split("/") if seg.isdigit() and len(seg) >= 2]


def _try_decode_relay_id(value: str) -> tuple[str, int] | None:
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="strict")
    except Exception:  # noqa: BLE001
        return None
    m = re.search(r"(\d+)", decoded)
    if m and ":" in decoded:
        return decoded[: m.start()], int(m.group(1))
    return None


def extract_ids(url: str, body: str | None) -> dict:
    parsed = urlparse(url)
    ids = {"path": [], "query": [], "body_json": [], "relay": []}
    ids["path"] = _find_path_ids(parsed.path)
    for key, val in parse_qsl(parsed.query):
        if val.isdigit() and len(val) >= 2:
            ids["query"].append((key, int(val)))
        else:
            relay = _try_decode_relay_id(val)
            if relay:
                ids["relay"].append(("query", key, val, relay[0], relay[1]))
    if body:
        try:
            _walk_json_ids(json.loads(body), ids["body_json"], ids["relay"])
        except (json.JSONDecodeError, TypeError):
            pass
    return ids


def _walk_json_ids(obj, num_out, relay_out, prefix="") -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            if isinstance(v, int) and v >= 10:
                num_out.append((path, v))
            elif isinstance(v, str):
                relay = _try_decode_relay_id(v)
                if relay:
                    relay_out.append(("body", path, v, relay[0], relay[1]))
            else:
                _walk_json_ids(v, num_out, relay_out, path)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _walk_json_ids(item, num_out, relay_out, f"{prefix}[{i}]")


# --------------------------------------------------------------------------- #
# İstek yeniden yazma
# --------------------------------------------------------------------------- #
def _replace_path_id(url: str, old: str, new: str) -> str:
    p = urlparse(url)
    return urlunparse(p._replace(path="/".join(new if s == old else s for s in p.path.split("/"))))


def _replace_query_id(url: str, key: str, new_val: int) -> str:
    p = urlparse(url)
    pairs = [(k, str(new_val) if k == key else v) for k, v in parse_qsl(p.query)]
    return urlunparse(p._replace(query=urlencode(pairs)))


def _replace_json_id(body: str, dotted: str, new_val: int) -> str:
    obj = json.loads(body)
    parts = re.findall(r"[^.\[\]]+", dotted)
    cur = obj
    for p in parts[:-1]:
        cur = cur[int(p)] if p.isdigit() else cur[p]
    last = parts[-1]
    if last.isdigit():
        cur[int(last)] = new_val
    else:
        cur[last] = new_val
    return json.dumps(obj)


# --------------------------------------------------------------------------- #
# Karşılaştırma
# --------------------------------------------------------------------------- #
def _looks_like_error(status: int, body: str) -> bool:
    if status in (400, 401, 403, 404, 500, 502, 503):
        return True
    lo = body.lower()
    markers = ["not found", "unauthorized", "forbidden", "access denied",
               "no permission", "does not exist", "invalid", "error"]
    return len(body) < 2000 and any(m in lo for m in markers)


def _significantly_different(orig: str, var: str) -> bool:
    if orig == var or not var.strip() or len(var.strip()) < 3:
        return False
    return True


# --------------------------------------------------------------------------- #
# Test motoru
# --------------------------------------------------------------------------- #
async def test_request(method: str, url: str, headers: dict,
                       body: str | None, allow_writes: bool = False) -> list[dict]:
    method = method.upper()
    findings: list[dict] = []

    is_graphql_read = False
    if method == "POST" and body:
        try:
            gobj = json.loads(body)
            q = gobj.get("query", "") if isinstance(gobj, dict) else ""
            if isinstance(q, str) and q.strip().lower().startswith(("query", "{")):
                is_graphql_read = True
        except (json.JSONDecodeError, AttributeError):
            pass

    if method not in SAFE_METHODS and not is_graphql_read and not allow_writes:
        print(f"[idor] {method} atlandı (durum değiştirebilir; --allow-writes gerekir)")
        return findings

    ids = extract_ids(url, body)
    if sum(len(v) for v in ids.values()) == 0:
        print("[idor] test edilebilir ID bulunamadı")
        return findings

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=False,
                                 verify=False) as client:
        orig = await _send(client, method, url, headers, body)
        if orig is None or _looks_like_error(orig["status"], orig["body"]):
            print(f"[idor] baseline geçersiz — atlanıyor")
            return findings
        print(f"[idor] baseline: {orig['status']} ({len(orig['body'])} byte)")

        for seg, val in ids["path"]:
            for nv in _id_variants(val):
                c = await _eval(client, method, _replace_path_id(url, seg, str(nv)),
                                headers, body, orig, f"path:{seg}->{nv}")
                if c: findings.append(c)
        for key, val in ids["query"]:
            for nv in _id_variants(val):
                c = await _eval(client, method, _replace_query_id(url, key, nv),
                                headers, body, orig, f"query:{key}={nv}")
                if c: findings.append(c)
        for dpath, val in ids["body_json"]:
            for nv in _id_variants(val):
                try:
                    nbody = _replace_json_id(body, dpath, nv)
                except (KeyError, IndexError, ValueError):
                    continue
                c = await _eval(client, method, url, headers, nbody, orig,
                                f"body:{dpath}={nv}")
                if c: findings.append(c)
        for loc, key, orig_b64, prefix, val in ids["relay"]:
            for nv in _id_variants(val):
                new_b64 = base64.b64encode(f"{prefix}{nv}".encode()).decode()
                if loc == "query":
                    c = await _eval(client, method, url.replace(orig_b64, new_b64),
                                    headers, body, orig, f"relay-q:{key}->{prefix}{nv}")
                else:
                    c = await _eval(client, method, url, headers,
                                    body.replace(orig_b64, new_b64), orig,
                                    f"relay-b:{key}->{prefix}{nv}")
                if c: findings.append(c)
    return findings


async def _send(client, method, url, headers, body):
    import time as _t
    try:
        _start = _t.perf_counter()
        r = await client.request(method, url, headers=headers,
                                 content=body.encode() if body else None)
        dur_ms = (_t.perf_counter() - _start) * 1000
        return {"status": r.status_code, "body": r.text, "duration_ms": dur_ms}
    except (httpx.HTTPError, httpx.TimeoutException) as exc:
        print(f"[idor] istek hatası: {exc}")
        return None


async def _eval(client, method, url, headers, body, orig, label):
    var = await _send(client, method, url, headers, body)
    if var is None:
        return None

    # 1) Klasik IDOR: 2xx + hata sayfası değil + farklı içerik
    if 200 <= var["status"] < 300 and not _looks_like_error(var["status"], var["body"]):
        if _significantly_different(orig["body"], var["body"]):
            print(f"[idor] ADAY: {label} -> {var['status']} "
                  f"({len(var['body'])} vs {len(orig['body'])} byte)")
            return {"label": label, "url": url, "status": var["status"],
                    "orig_len": len(orig["body"]), "var_len": len(var["body"]),
                    "sample": var["body"][:500]}

    # 2) Blind sinyal (response_differ): time-based / boolean / status anomalisi
    try:
        import response_differ as rd
        bf = rd.extract_features(orig["body"], orig["status"], orig.get("duration_ms", 0))
        nf = rd.extract_features(var["body"], var["status"], var.get("duration_ms", 0))
        diff = rd.compare(bf, nf)
        if diff["is_anomaly"] and diff["signal"] in ("time", "status"):
            print(f"[idor] BLIND SİNYAL: {label} -> {diff['signal']} ({diff['reason']})")
            return {"label": f"{label} [blind:{diff['signal']}]", "url": url,
                    "status": var["status"], "orig_len": len(orig["body"]),
                    "var_len": len(var["body"]), "sample": var["body"][:300],
                    "blind_signal": diff["signal"], "reason": diff["reason"]}
    except Exception:  # noqa: BLE001
        pass
    return None


# --------------------------------------------------------------------------- #
# Kayıt + istek yükleme
# --------------------------------------------------------------------------- #
def save_idor_findings(findings: list[dict]) -> None:
    if not findings:
        return
    init_db()
    with get_connection() as conn:
        for f in findings:
            conn.execute(
                "INSERT INTO recon_findings (host, source, severity, name, matched_at, raw, found_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (urlparse(f["url"]).netloc, "idor", "medium",
                 f"IDOR adayı: {f['label']}", f["url"], json.dumps(f),
                 datetime.now(timezone.utc).isoformat()),
            )
        conn.commit()
    print(f"[idor] {len(findings)} aday kaydedildi")


def load_from_db(request_id: int) -> dict:
    """`requests` tablosundan (Caido capture) bir isteği IDOR test formatına çevirir."""
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM requests WHERE id = ?", (request_id,)).fetchone()
    if row is None:
        raise ValueError(f"#{request_id} bulunamadı (requests tablosu)")
    try:
        headers = json.loads(row["headers_json"] or "{}")
    except json.JSONDecodeError:
        headers = {}
    return {"method": row["method"], "url": row["url"],
            "headers": headers, "body": row["body"]}


def load_from_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


async def _main() -> None:
    p = argparse.ArgumentParser(description="Layer 2 — IDOR Auto-Tester")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("request_json", nargs="?", help="İstek JSON dosyası")
    src.add_argument("--db-id", type=int, help="`requests` tablosundaki kayıt id")
    p.add_argument("--allow-writes", action="store_true",
                   help="TEHLİKELİ: POST/PUT/DELETE de test et")
    args = p.parse_args()

    if args.db_id is not None:
        req = load_from_db(args.db_id)
    else:
        req = load_from_json(args.request_json)

    findings = await test_request(req.get("method", "GET"), req["url"],
                                  req.get("headers", {}), req.get("body"),
                                  args.allow_writes)
    save_idor_findings(findings)

    if findings:
        print(f"\n{'='*60}\n  {len(findings)} IDOR ADAYI — manuel doğrula!\n{'='*60}")
        for f in findings:
            print(f"  {f['label']}: {f['status']} ({f['var_len']} vs {f['orig_len']} byte)")
    else:
        print("\n[idor] IDOR adayı yok")


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    warnings.filterwarnings("ignore")
    asyncio.run(_main())
