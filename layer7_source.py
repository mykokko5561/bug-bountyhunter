"""
layer7_source.py — Katman 7: Source Code Analyzer
Hedefin AÇIK KAYNAK reposunu (GitHub) çekip zafiyet pattern'leri arar.
Cloudflare/auth duvarına takılmaz — kodu okur, canlı siteye vurmaz.
Bulgular canlı in-scope hedefte doğrulanmak üzere işaretlenir.

Metodoloji: Strix skill playbook'ları + gerçek saha bulguları
(ör. Kaltura kmc-ng postMessage KS sızıntısı).

Flagship analiz: postMessage handler'larında origin doğrulaması eksikliği
(multiline). Ayrıca DOM XSS sink, hardcoded secret, open redirect,
SQLi concat, command injection, JWT alg:none, SSRF, deserialization.

Kullanım:
    python layer7_source.py https://github.com/kaltura/kmc-ng
    python layer7_source.py /tmp/kmc-ng            # yerel klasör
    python layer7_source.py https://github.com/org/repo --root kaltura.com

Bağımlılıklar: git (clone için)
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

# Merkezi DB (yoksa standalone çalışır, sadece yazdırır)
try:
    from database import init_db, get_connection
    _HAS_DB = True
except Exception:  # noqa: BLE001
    _HAS_DB = False

# Taranacak kaynak uzantıları
_CODE_EXT = (".js", ".ts", ".jsx", ".tsx", ".vue", ".py", ".rb", ".php",
             ".java", ".go", ".cs", ".mjs", ".cjs", ".html")
# Atlanacak dizinler (gürültü)
_SKIP_DIRS = {"node_modules", ".git", "dist", "build", "vendor", "__pycache__",
              "test", "tests", "spec", "specs", "e2e", "mock", "mocks",
              "fixtures", "examples", "example", ".angular", "coverage",
              "polyfills", "assets"}
_SKIP_FILE_HINTS = (".min.js", ".spec.", ".test.", ".mock.", ".d.ts", ".map")

MAX_FILE_BYTES = 1_500_000  # 1.5MB üstü dosyayı atla (bundle vb.)


# --------------------------------------------------------------------------- #
# Tek-satır regex kuralları: (isim, severity, pattern, ipucu)
# --------------------------------------------------------------------------- #
RULES: list[tuple[str, str, re.Pattern, str]] = [
    ("DOM XSS: innerHTML", "medium",
     re.compile(r"\.(inner|outer)HTML\s*=\s*(?!['\"`]\s*['\"`])"),
     "Dinamik innerHTML — kaynak kullanıcı girdisiyse DOM XSS. Canlıda parametreyle test et."),
    ("DOM XSS: insertAdjacentHTML", "medium",
     re.compile(r"\.insertAdjacentHTML\s*\("),
     "insertAdjacentHTML — girdi sanitize edilmiyorsa DOM XSS."),
    ("DOM XSS: document.write", "medium",
     re.compile(r"document\.write(ln)?\s*\("),
     "document.write — kullanıcı girdisiyle XSS."),
    ("DOM XSS: React dangerouslySetInnerHTML", "medium",
     re.compile(r"dangerouslySetInnerHTML"),
     "dangerouslySetInnerHTML — girdi kontrol edilmiyorsa XSS."),
    ("DOM XSS: jQuery .html()", "low",
     re.compile(r"\$\([^)]*\)\.html\s*\("),
     "jQuery .html() dinamik içerikle — XSS riski."),
    ("Code exec: eval", "high",
     re.compile(r"(?<![\w.])eval\s*\("),
     "eval() — kullanıcı girdisi geçiyorsa RCE/XSS. Bağlamı incele."),
    ("Code exec: new Function", "medium",
     re.compile(r"new\s+Function\s*\("),
     "new Function() — dinamik kod çalıştırma."),
    ("Open Redirect", "medium",
     re.compile(r"(location\.(href|replace|assign)\s*=?\s*\(?|res\.redirect\s*\(|window\.open\s*\()"),
     "Yönlendirme hedefi kullanıcı girdisiyse open redirect. Canlıda ?url=/redirect param test et."),
    ("SQLi: string concat query", "high",
     re.compile(r"""(execute|query|raw)\s*\(\s*[`'"][^`'"]*(SELECT|INSERT|UPDATE|DELETE)\b[^;]{0,80}(\+\s*\w|\$\{|%\s*\(|\.format\(|f['"])""", re.IGNORECASE),
     "SQL sorgusu kullanıcı girdisiyle birleştirilmiş (execute/query içinde) — parametrize değilse SQLi."),
    ("Command Injection", "high",
     re.compile(r"(child_process\.(exec|execSync|spawn|execFile)\s*\(|\bos\.system\s*\(|\bos\.popen\s*\(|subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True|Runtime\.getRuntime\(\)\.exec\()"),
     "Gerçek komut çalıştırma çağrısı — argümanı kullanıcı girdisiyse command injection."),
    ("Path Traversal: file read", "medium",
     re.compile(r"(readFile(Sync)?|createReadStream|sendFile|res\.download|open)\s*\([^)]*(req\.(params|query|body)|request\.|\+\s*\w+|\$\{)"),
     "Dosya yolu kullanıcı girdisiyle — path traversal (../)."),
    ("SSRF: server-side fetch", "high",
     re.compile(r"(requests\.(get|post|request)|axios\.(get|post)|urllib\.request\.urlopen|httpx\.(get|post))\s*\([^)]*(req\.(params|query|body)|request\.|params\[|query\[|user_?input|target_?url)"),
     "Sunucu tarafı istek hedefi kullanıcı girdisiyle — SSRF."),
    ("JWT: alg none / no verify", "high",
     re.compile(r"(alg['\"]?\s*[:=]\s*['\"]?none|algorithms?\s*[:=]\s*\[\s*['\"]none|verify\s*[:=]\s*false|jwt\.decode\([^)]*verify\s*=\s*False)", re.IGNORECASE),
     "JWT alg:none / imza doğrulaması kapalı — auth bypass."),
    ("Deserialization", "high",
     re.compile(r"(pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader)|unserialize\s*\(|readObject\s*\()"),
     "Güvensiz deserialization — RCE riski."),
    ("CORS: reflected/wildcard+creds", "medium",
     re.compile(r"Access-Control-Allow-Origin['\"]?\s*[,:]\s*(req\.|origin|\*|['\"]\*)", re.IGNORECASE),
     "CORS origin yansıtma/wildcard — credentials açıksa veri çalma."),
    ("Hardcoded secret: Google/AIza", "high",
     re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
     "Google API key. Firebase ise public olabilir; başka Google servisi ise gerçek sızıntı."),
    ("Hardcoded secret: AWS", "high",
     re.compile(r"AKIA[0-9A-Z]{16}"),
     "AWS access key — gerçek sızıntı."),
    ("Hardcoded secret: Stripe live", "high",
     re.compile(r"sk_live_[0-9A-Za-z]{16,}"),
     "Stripe live secret key."),
    ("Hardcoded secret: private key", "high",
     re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP)? ?PRIVATE KEY-----"),
     "Gömülü özel anahtar."),
    ("Hardcoded secret: generic", "medium",
     re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*['\"][0-9A-Za-z\-_/+.]{16,}['\"]"),
     "Olası gömülü sır — public/placeholder değilse incele."),
]


# --------------------------------------------------------------------------- #
# Flagship: postMessage handler'da origin doğrulaması eksik mi?
# --------------------------------------------------------------------------- #
_MSG_LISTENER = re.compile(r"addEventListener\s*\(\s*['\"]message['\"]")


# origin KARŞILAŞTIRMASI (doğrulama) — postMessage hedefi olarak kullanım (e.origin) DEĞİL
_ORIGIN_CHECK = re.compile(
    r"\.origin\s*(===|!==|==|!=)"          # e.origin === ...
    r"|(===|!==|==|!=)\s*[\w.]*\.origin"    # ... === location.origin
    r"|\.origin\.(includes|indexOf|match|startsWith|endsWith|test)"
    r"|allowed[_-]?origins?"
    r"|trusted[_-]?origins?"
    r"|if\s*\([^)]*\borigin\b[^)]*(===|==|!==|!=|includes|indexOf)",
    re.IGNORECASE)

_PM_SENDS_SENSITIVE = re.compile(
    r"postMessage\s*\([^;]{0,200}\b(ks|token|session|auth|jwt|password|secret|cookie|credential)\b",
    re.IGNORECASE)


def _find_postmessage_issues(path: str, text: str) -> list[dict]:
    """Dosyada message listener varsa VE dosyada hiç origin KARŞILAŞTIRMASI yoksa flag'ler.
    (Handler ayrı fonksiyonda tanımlansa bile dosya bütününe bakar → düşük FP.)"""
    listeners = list(_MSG_LISTENER.finditer(text))
    if not listeners:
        return []
    if _ORIGIN_CHECK.search(text):
        return []  # dosyada origin doğrulaması var → temiz kabul et
    line_no = text.count("\n", 0, listeners[0].start()) + 1
    leaks = bool(_PM_SENDS_SENSITIVE.search(text))
    sev = "high" if leaks else "medium"
    note = ("Dosyada 'message' postMessage listener'ı var ama origin DOĞRULAMASI YOK"
            + (" ve postMessage ile hassas veri (ks/token/session) gönderiliyor — "
               "herhangi bir origin token'ı çalabilir → hesap ele geçirme (Kaltura kmc-ng kedit-hoster ile aynı sınıf)"
               if leaks else " — postMessage tabanlı XSS / veri sızıntısı riski")
            + ". Canlı in-scope hedefte origin allowlist var mı doğrula.")
    snippet = text[listeners[0].start():listeners[0].start() + 140].replace("\n", " ")
    return [{"category": "postMessage: missing origin check",
             "severity": sev, "line": line_no, "snippet": snippet, "note": note}]


# --------------------------------------------------------------------------- #
# Tarama
# --------------------------------------------------------------------------- #
def _iter_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in _SKIP_DIRS]
        for fn in filenames:
            if not fn.lower().endswith(_CODE_EXT):
                continue
            if any(h in fn.lower() for h in _SKIP_FILE_HINTS):
                continue
            fp = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(fp) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield fp


def scan_repo(root: str, repo_label: str) -> list[dict]:
    findings: list[dict] = []
    lines_cache: dict[str, list[str]] = {}
    file_count = 0

    for fp in _iter_files(root):
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        file_count += 1
        rel = os.path.relpath(fp, root)

        # 1) Flagship postMessage analizi (sadece JS/TS/HTML)
        if fp.lower().endswith((".js", ".ts", ".jsx", ".tsx", ".vue", ".mjs", ".html")):
            for issue in _find_postmessage_issues(fp, text):
                issue["file"] = rel
                findings.append(issue)

        # 2) Tek-satır regex kuralları
        lines = text.splitlines()
        for name, sev, pat, hint in RULES:
            for lm in pat.finditer(text):
                line_no = text.count("\n", 0, lm.start()) + 1
                snippet = lines[line_no - 1].strip()[:180] if 0 < line_no <= len(lines) else ""
                # gürültü elemesi: yorum satırı / import değilse
                low = snippet.lower()
                if low.startswith(("//", "*", "#", "import ", "from ")) and "secret" not in name.lower():
                    continue
                findings.append({"category": name, "severity": sev, "file": rel,
                                 "line": line_no, "snippet": snippet, "note": hint})

    # dedupe (aynı dosya+satır+kategori)
    seen = set()
    unique = []
    for f in findings:
        key = (f["file"], f["line"], f["category"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    print(f"[source] {file_count} dosya tarandı, {len(unique)} bulgu")
    return unique


# --------------------------------------------------------------------------- #
# Kayıt
# --------------------------------------------------------------------------- #
def save_findings(findings: list[dict], repo_label: str, root: str | None) -> None:
    if not _HAS_DB:
        return
    init_db()
    now = datetime.now(timezone.utc).isoformat()
    host = root or repo_label
    with get_connection() as conn:
        for f in findings:
            raw = f"{f['file']}:{f['line']}  {f['snippet']}  || {f['note']}"
            conn.execute(
                "INSERT INTO recon_findings (host, source, severity, name, matched_at, raw, found_at) "
                "VALUES (?, 'sourcecode', ?, ?, ?, ?, ?)",
                (host, f["severity"], f"{f['category']}",
                 f"{f['file']}:{f['line']}", raw, now))
        conn.commit()
    print(f"[source] {len(findings)} bulgu DB'ye yazıldı (/findings ile gör)")


# --------------------------------------------------------------------------- #
# Clone + koordinatör
# --------------------------------------------------------------------------- #
def _clone(repo_url: str, dest: str) -> bool:
    try:
        subprocess.run(["git", "clone", "--depth", "1", repo_url, dest],
                       check=True, capture_output=True, timeout=300)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(f"[source] clone hatası: {exc}")
        return False


def run(target: str, root: str | None) -> list[dict]:
    tmp = None
    if target.startswith(("http://", "https://", "git@")):
        tmp = tempfile.mkdtemp(prefix="src_")
        label = target.rstrip("/").split("/")[-1].replace(".git", "")
        print(f"[source] clone: {target}")
        if not _clone(target, tmp):
            return []
        scan_root = tmp
    else:
        scan_root = target
        label = os.path.basename(os.path.abspath(target))

    print(f"\n{'='*60}\n  SOURCE ANALİZ: {label}\n{'='*60}\n")
    try:
        findings = scan_repo(scan_root, label)
        save_findings(findings, label, root)
        # özet: severity dağılımı + en kritikler
        by_sev = {}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        print(f"\n[source] Severity: {by_sev}")
        # postMessage bulguları = en yüksek güven, önce onları göster
        pm = [x for x in findings if "postMessage" in x["category"]]
        if pm:
            print(f"\n=== ⭐ postMessage (en yüksek güven, {len(pm)}) ===")
            for f in pm[:15]:
                print(f"  [{f['severity']}] {f['file']}:{f['line']}")
                print(f"      {f['note'][:120]}")
        print(f"\n=== YÜKSEK ÖNCELİKLİ (high) — ilk 25 ===")
        for f in [x for x in findings if x["severity"] == "high"][:25]:
            print(f"  [{f['category']}] {f['file']}:{f['line']}")
            print(f"      {f['snippet'][:110]}")
        return findings
    finally:
        if tmp:
            subprocess.run(["rm", "-rf", tmp], capture_output=True)


def main() -> None:
    p = argparse.ArgumentParser(description="Layer 7 — Source Code Analyzer")
    p.add_argument("target", help="GitHub repo URL veya yerel klasör yolu")
    p.add_argument("--root", help="Bulguları bu kök domaine bağla (in-scope etiketi)")
    args = p.parse_args()
    run(args.target, args.root)


if __name__ == "__main__":
    main()
