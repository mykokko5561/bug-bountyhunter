"""
secret_scanner.py
------------------
Katman 2'nin ikinci görevi: Caido'dan gelen header + body içeriğinde
sızmış API anahtarlarını / token'ları regex ile yakalamak.

TASARIM NOTU:
Eşleşen değerin TAMAMINI değil, sadece başını/sonunu gösteren MASKELENMİŞ
halini saklıyoruz. Sebep: bu SQLite dosyası ileride log/ekran paylaşımı,
git commit hatası gibi durumlarda sızabilir — bulduğumuz secret'ı ikinci
bir sızıntı kaynağına çevirmeyelim. Ham değer sadece tespit anında bellekte
tutulur, DB'ye yazılmaz.
"""

import re
import logging
from dataclasses import dataclass

logger = logging.getLogger("bugbounty.secret_scanner")


@dataclass(frozen=True)
class SecretPattern:
    name: str
    pattern: re.Pattern
    # inherently_public: bu tip key TASARIM GEREĞİ istemci tarafında bulunur
    # (Firebase/Google browser key'leri gibi) — tek başına raporlanabilir DEĞİL.
    inherently_public: bool = False


@dataclass(frozen=True)
class SecretMatch:
    secret_type: str
    masked_value: str
    benign: bool = False   # True ise: gürültü (public-by-design ya da 3. parti bağlam)


# Bu hostlara giden trafikte "secret" görmek normaldir — bunlar 3. parti
# servislerin kendi public/analitik anahtarları, Myntra'nın sızıntısı değil.
_BENIGN_HOST_SUBSTRINGS = (
    "googleapis.com", "gstatic.com", "google-analytics.com", "googletagmanager.com",
    "doubleclick.net", "google.com/", "firebaseio.com", "firebaseinstallations",
    "firebaseremoteconfig", "firebase.com", "crashlytics", "app-measurement.com",
    "facebook.com", "connect.facebook", "clarity.ms", "branch.io", "segment.io",
    "sentry.io", "newrelic.com", "cloudflareinsights.com",
)

# Regex derlemeleri modül yüklenirken bir kez yapılır (performans).
# Not: Bu liste canlıdır — yeni servis keşfedildikçe buraya eklenmeli.
_PATTERNS: list[SecretPattern] = [
    SecretPattern("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    SecretPattern("AWS Secret Key", re.compile(r"(?i)aws(.{0,20})?(secret|access)?(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]")),
    # Google/Firebase AIza key'leri: Google resmen "public, koda konabilir" diyor.
    # Erişimi Security Rules kontrol eder, key değil. Tek başına açık DEĞİL.
    SecretPattern("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), inherently_public=True),
    SecretPattern("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    SecretPattern("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Za-z]{8,}/B[0-9A-Za-z]{8,}/[0-9A-Za-z]{24}")),
    SecretPattern("Stripe Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    SecretPattern("Stripe Restricted Key", re.compile(r"rk_live_[0-9a-zA-Z]{24,}")),
    SecretPattern("GitHub Token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    # JWT: yakalanan trafikte genelde KENDİ oturum token'ımızdır (sızıntı değil).
    # Gerçek bulgu olması için başka kullanıcıya ait / yanlış yerde olmalı.
    SecretPattern("Generic Bearer JWT", re.compile(r"eyJ[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+"), inherently_public=True),
    SecretPattern("Private Key Block", re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP)? ?PRIVATE KEY-----")),
    SecretPattern(
        "Generic API Key Assignment",
        re.compile(r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,64}['\"]"),
    ),
    SecretPattern("Firebase URL", re.compile(r"[a-z0-9-]+\.firebaseio\.com"), inherently_public=True),
]


def _is_benign_context(url: str | None) -> bool:
    """İstek 3. parti (Google/analytics vb.) bir hosta mı gidiyor?"""
    if not url:
        return False
    low = url.lower()
    return any(h in low for h in _BENIGN_HOST_SUBSTRINGS)


def _mask(value: str) -> str:
    """Bir secret'ı DB'ye yazmadan önce güvenli hale getirir: ilk4...son4"""
    if len(value) <= 10:
        return "***redacted***"
    return f"{value[:4]}...{value[-4:]} (len={len(value)})"


def scan_for_secrets(*text_blobs: str | None, context_url: str | None = None) -> list[SecretMatch]:
    """
    Verilen metin bloklarının (headers, body vb.) hepsini tarar.
    context_url verilirse, 3. parti host + public-by-design key'ler
    'benign' (gürültü) olarak işaretlenir — böylece gerçek sızıntı ile
    Firebase/analytics public key'i karışmaz.
    Hatalı/None girişlere karşı dayanıklıdır.
    """
    matches: list[SecretMatch] = []
    benign_host = _is_benign_context(context_url)

    for blob in text_blobs:
        if not blob:
            continue
        try:
            for spec in _PATTERNS:
                for found in spec.pattern.finditer(blob):
                    raw_value = found.group(0)
                    # benign = public-by-design key VEYA 3. parti hosta giden trafik
                    benign = spec.inherently_public or benign_host
                    matches.append(SecretMatch(
                        secret_type=spec.name,
                        masked_value=_mask(raw_value),
                        benign=benign,
                    ))
        except (re.error, TypeError) as e:
            logger.warning("Secret tarama sırasında hata (yoksayıldı): %s", e)
            continue

    if matches:
        real = [m.secret_type for m in matches if not m.benign]
        if real:
            logger.info("GERÇEK secret tespit edildi: %s", real)
        else:
            logger.debug("Sadece benign key'ler (public-by-design): %s",
                         [m.secret_type for m in matches])

    return matches


def has_real_secret(matches: list[SecretMatch]) -> bool:
    """En az bir gerçek (benign olmayan) secret var mı?"""
    return any(not m.benign for m in matches)
