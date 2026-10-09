"""
dom_analyzer.py — DOM/HTML Analizi (Strix + BurpNake fikri)
Yakalanan HTML yanıtlarından gerçek saldırı yüzeyini çıkarır — böylece
AI/triyaj var olmayan parametre UYDURMAZ (anti-hallucination):

  - Gizli form alanları (<input type=hidden>) + tüm form parametreleri
  - Form action URL'leri + method
  - Geliştirici yorum satırları (<!-- ... -->) — sızan endpoint/TODO/kimlik
  - JS içine gömülü API endpoint'leri (/api/.., /v1/..)
  - Gömülü ID/parametre isimleri (data-* , name=)

`requests` tablosundaki HTML yanıtlarını tarar, çıkardığı parametreleri
Layer 2 IDOR'a besler.

Bağımlılık: beautifulsoup4 (varsa), yoksa regex fallback.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

try:
    from bs4 import BeautifulSoup
    _HAS_BS4 = True
except ImportError:
    _HAS_BS4 = False


_API_RE = re.compile(r"""['"](/(?:api|v\d|rest|graphql|internal|admin|user|account)"""
                     r"""[a-zA-Z0-9/_\-.{}]*)['"]""")
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_INTERESTING_COMMENT = re.compile(r"(todo|fixme|hack|password|key|token|secret|api|endpoint|"
                                  r"debug|test|admin|internal|deprecated|/v\d|/api)", re.IGNORECASE)
_INPUT_RE = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_ATTR_RE = re.compile(r'(\w+)\s*=\s*["\']([^"\']*)["\']')


@dataclass
class DomSurface:
    forms: list[dict] = field(default_factory=list)      # {action, method, params, hidden}
    endpoints: list[str] = field(default_factory=list)   # JS/HTML'den API path'leri
    comments: list[str] = field(default_factory=list)    # ilginç geliştirici yorumları
    hidden_fields: list[str] = field(default_factory=list)
    param_names: list[str] = field(default_factory=list)  # tüm input/param isimleri


def analyze_html(html: str, base_url: str = "") -> DomSurface:
    surf = DomSurface()
    if not html:
        return surf

    # --- Endpoints (JS + HTML) ---
    for m in _API_RE.finditer(html):
        ep = m.group(1)
        if ep not in surf.endpoints and len(ep) > 4:
            surf.endpoints.append(ep)

    # --- Yorumlar ---
    for c in _COMMENT_RE.findall(html):
        c = c.strip()
        if c and _INTERESTING_COMMENT.search(c):
            surf.comments.append(c[:200])

    if _HAS_BS4:
        _analyze_bs4(html, base_url, surf)
    else:
        _analyze_regex(html, surf)

    # dedupe
    surf.param_names = sorted(set(surf.param_names))
    surf.hidden_fields = sorted(set(surf.hidden_fields))
    surf.endpoints = sorted(set(surf.endpoints))
    return surf


def _analyze_bs4(html: str, base_url: str, surf: DomSurface) -> None:
    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = (form.get("method", "GET") or "GET").upper()
        params, hidden = [], []
        for inp in form.find_all(["input", "select", "textarea"]):
            name = inp.get("name")
            if not name:
                continue
            params.append(name)
            surf.param_names.append(name)
            if (inp.get("type", "") or "").lower() == "hidden":
                hidden.append(name)
                surf.hidden_fields.append(name)
        surf.forms.append({
            "action": urljoin(base_url, action) if base_url else action,
            "method": method, "params": params, "hidden": hidden,
        })
    # data-* ve name attribute'leri (form dışı)
    for tag in soup.find_all(attrs={"name": True}):
        surf.param_names.append(tag.get("name"))
    for tag in soup.find_all(attrs={"data-id": True}):
        surf.param_names.append("data-id:" + str(tag.get("data-id"))[:40])


def _analyze_regex(html: str, surf: DomSurface) -> None:
    for inp in _INPUT_RE.findall(html):
        attrs = dict(_ATTR_RE.findall(inp))
        name = attrs.get("name")
        if name:
            surf.param_names.append(name)
            if attrs.get("type", "").lower() == "hidden":
                surf.hidden_fields.append(name)


def summarize(surf: DomSurface) -> str:
    lines = []
    if surf.forms:
        lines.append(f"{len(surf.forms)} form:")
        for f in surf.forms[:10]:
            lines.append(f"  {f['method']} {f['action']}  params={f['params']}")
    if surf.hidden_fields:
        lines.append(f"Gizli alanlar: {surf.hidden_fields}")
    if surf.endpoints:
        lines.append(f"Endpoint'ler ({len(surf.endpoints)}): {surf.endpoints[:20]}")
    if surf.comments:
        lines.append(f"İlginç yorumlar ({len(surf.comments)}):")
        for c in surf.comments[:8]:
            lines.append(f"  <!-- {c} -->")
    return "\n".join(lines) or "DOM yüzeyi boş"


def analyze_captured(db_path: str | None = None, limit: int = 200) -> dict:
    """`requests` tablosundaki HTML yanıtlarını tarar (merkezi DB)."""
    try:
        from database import get_connection
    except Exception:  # noqa: BLE001
        print("[dom] database modülü yok — standalone analyze_html kullan")
        return {}
    total_eps, total_hidden, total_comments = set(), set(), []
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT url, body FROM requests ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    for r in rows:
        body = r["body"] or ""
        if "<" not in body:  # HTML değil
            continue
        surf = analyze_html(body, r["url"])
        total_eps.update(surf.endpoints)
        total_hidden.update(surf.hidden_fields)
        total_comments.extend(surf.comments)
    print(f"[dom] {len(rows)} yanıt tarandı")
    print(f"[dom] {len(total_eps)} endpoint, {len(total_hidden)} gizli alan, "
          f"{len(total_comments)} ilginç yorum")
    return {"endpoints": sorted(total_eps), "hidden": sorted(total_hidden),
            "comments": total_comments}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="DOM Analyzer")
    p.add_argument("--file", help="HTML dosyası analiz et")
    p.add_argument("--captured", action="store_true", help="requests tablosundaki HTML'leri tara")
    args = p.parse_args()
    if args.file:
        with open(args.file, encoding="utf-8", errors="ignore") as fh:
            print(summarize(analyze_html(fh.read())))
    elif args.captured:
        analyze_captured()
    else:
        # demo
        demo = '''<form action="/api/v1/transfer" method="POST">
          <input type="hidden" name="account_id" value="123">
          <input name="amount"></form>
          <!-- TODO: remove debug endpoint /api/internal/debug -->
          <script>fetch("/api/v2/users/me")</script>'''
        print(summarize(analyze_html(demo)))
