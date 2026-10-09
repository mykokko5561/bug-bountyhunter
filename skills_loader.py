"""
skills_loader.py — Uzman Zafiyet Metodolojisi Yükleyici
skills/ klasöründeki playbook'ları (Strix'ten, Apache 2.0) yükler ve
triyaj/analiz prompt'larına enjekte eder. Böylece Ollama/Claude "tahmin"
yerine uzman metodolojiyle çalışır.

Kaynak: usestrix/strix (Apache 2.0) — vulnerability skill playbook'ları.
Kullanım:
    from skills_loader import get_skill, detect_and_load
    methodology = get_skill("idor")
    # veya bir metinden otomatik sınıf tespiti:
    text, names = detect_and_load("IDOR candidate on /api/orders/1")
"""

from __future__ import annotations

import os
import re

_SKILLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "skills")

# zafiyet anahtar kelimesi -> skill dosyası eşlemesi
_KEYWORD_MAP = {
    "idor": "idor", "bola": "idor", "object-level": "idor",
    "bac": "broken_function_level_authorization", "bfla": "broken_function_level_authorization",
    "privilege": "broken_function_level_authorization",
    "xss": "xss", "cross-site scripting": "xss", "dom xss": "xss",
    "sqli": "sql_injection", "sql injection": "sql_injection",
    "nosql": "nosql_injection",
    "ssrf": "ssrf",
    "ssti": "ssti", "template injection": "ssti",
    "rce": "rce", "command injection": "rce", "remote code": "rce",
    "xxe": "xxe",
    "csrf": "csrf",
    "open redirect": "open_redirect", "redirect": "open_redirect",
    "jwt": "authentication_jwt", "auth": "authentication_jwt", "token": "authentication_jwt",
    "mass assignment": "mass_assignment",
    "prototype pollution": "prototype_pollution",
    "deserial": "insecure_deserialization",
    "path traversal": "path_traversal_lfi_rfi", "lfi": "path_traversal_lfi_rfi",
    "rfi": "path_traversal_lfi_rfi", "file read": "path_traversal_lfi_rfi",
    "file upload": "insecure_file_uploads", "upload": "insecure_file_uploads",
    "race condition": "race_conditions", "race": "race_conditions",
    "business logic": "business_logic", "logic": "business_logic",
    "subdomain takeover": "subdomain_takeover", "takeover": "subdomain_takeover",
    "information disclosure": "information_disclosure", "disclosure": "information_disclosure",
    "sensitive data": "information_disclosure", "secret": "information_disclosure",
    "header injection": "header_injection", "crlf": "header_injection",
    "request smuggling": "http_request_smuggling", "smuggling": "http_request_smuggling",
    "postmessage": "browser_security", "cors": "browser_security", "clickjack": "browser_security",
    "prompt injection": "llm_prompt_injection", "llm": "llm_prompt_injection",
    "weak password": "weak_password_detection", "password": "weak_password_detection",
    "argument injection": "argument_injection",
    "recon": "asset_discovery", "subdomain": "asset_discovery", "asset": "asset_discovery",
}


def list_skills() -> list[str]:
    if not os.path.isdir(_SKILLS_DIR):
        return []
    return sorted(f[:-3] for f in os.listdir(_SKILLS_DIR) if f.endswith(".md"))


def get_skill(name: str, max_chars: int = 4000) -> str:
    """Skill playbook'unu döner (isim ya da anahtar kelime kabul eder)."""
    fname = _KEYWORD_MAP.get(name.lower(), name.lower())
    path = os.path.join(_SKILLS_DIR, f"{fname}.md")
    if not os.path.exists(path):
        return ""
    with open(path, encoding="utf-8", errors="ignore") as fh:
        content = fh.read()
    return content[:max_chars]


def detect_and_load(text: str, max_skills: int = 2, max_chars: int = 3000) -> tuple[str, list[str]]:
    """Metinden zafiyet sınıf(lar)ını tespit edip ilgili metodolojileri döner."""
    low = text.lower()
    hits: list[str] = []
    for kw, fname in _KEYWORD_MAP.items():
        if kw in low and fname not in hits:
            hits.append(fname)
    hits = hits[:max_skills]
    blocks = []
    for fname in hits:
        skill = get_skill(fname, max_chars)
        if skill:
            blocks.append(f"### Metodoloji: {fname}\n{skill}")
    return "\n\n".join(blocks), hits


def enrich_prompt(base_prompt: str, finding_text: str) -> str:
    """Bir triyaj prompt'unu ilgili uzman metodolojiyle zenginleştirir."""
    methodology, names = detect_and_load(finding_text)
    if not methodology:
        return base_prompt
    return (f"{base_prompt}\n\n"
            f"--- İLGİLİ UZMAN METODOLOJİ ({', '.join(names)}) ---\n"
            f"{methodology}\n"
            f"--- Bu metodolojiyi kullanarak analiz et. ---")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Skill Loader")
    p.add_argument("--list", action="store_true")
    p.add_argument("--get", help="skill adı ya da anahtar kelime")
    p.add_argument("--detect", help="metinden sınıf tespit et")
    args = p.parse_args()
    if args.list:
        skills = list_skills()
        print(f"{len(skills)} skill:")
        for s in skills:
            print(" ", s)
    elif args.get:
        print(get_skill(args.get)[:1500])
    elif args.detect:
        text, names = detect_and_load(args.detect)
        print("Tespit:", names)
        print(text[:800])
    else:
        # demo
        print("Skill sayısı:", len(list_skills()))
        _, names = detect_and_load("IDOR candidate + CORS misconfig on /api")
        print("Demo tespit:", names)
