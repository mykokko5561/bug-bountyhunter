"""
response_differ.py — Blind Zafiyet Tespiti (BurpNake'ten uyarlandı, geliştirildi)
Yanıt özelliklerini (uzunluk, kelime, satır, status, süre) çıkarır ve baseline
ile karşılaştırır. Hata mesajı dönmeyen senaryolarda (Blind SQLi, Blind SSRF,
time-based) anomaliyi yakalar.

Layer 2 (IDOR/param testi) bunu kullanır: aynı isteğin farklı payload'larını
gönderip yanıt farkını ölçer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Any


# time-based zafiyet eşiği (ms) — bu kadar gecikme şüpheli
TIME_ANOMALY_MS = 4000
# içerik farkı eşiği: kelime sayısı bu orandan fazla değişirse anomali
CONTENT_DIFF_RATIO = 0.10


@dataclass
class ResponseFeatures:
    status_code: int
    length: int
    word_count: int
    line_count: int
    duration_ms: float


def extract_features(body: str, status_code: int, duration_ms: float = 0.0) -> ResponseFeatures:
    """Bir yanıttan karşılaştırılabilir özellikleri çıkarır (sadece gövde)."""
    # header/body ayır (ham yanıt verildiyse)
    sep = body.find("\r\n\r\n")
    if sep != -1:
        body = body[sep + 4:]
    words = re.findall(r"\b\w+\b", body)
    return ResponseFeatures(
        status_code=status_code,
        length=len(body),
        word_count=len(words),
        line_count=body.count("\n") + 1,
        duration_ms=duration_ms,
    )


def compare(base: ResponseFeatures, new: ResponseFeatures) -> dict[str, Any]:
    """İki yanıtı karşılaştırır, anomali sınıflandırır."""
    result: dict[str, Any] = {
        "is_anomaly": False,
        "signal": None,           # 'status' | 'content' | 'time' | 'boolean'
        "confidence": "low",
        "status_diff": new.status_code != base.status_code,
        "length_diff": abs(new.length - base.length),
        "word_diff": abs(new.word_count - base.word_count),
        "time_diff_ms": round(new.duration_ms - base.duration_ms, 1),
        "reason": "",
    }

    # 1) Status değişimi — en güçlü sinyal (ör. 200 -> 500 = error-based)
    if result["status_diff"]:
        result.update(is_anomaly=True, signal="status", confidence="high",
                      reason=f"Status {base.status_code} -> {new.status_code}")
        return result

    # 2) Time-based — WAITFOR/sleep/pg_sleep gibi
    if result["time_diff_ms"] > TIME_ANOMALY_MS:
        result.update(is_anomaly=True, signal="time", confidence="high",
                      reason=f"Zaman gecikmesi {result['time_diff_ms']}ms (time-based blind?)")
        return result

    # 3) İçerik farkı — boolean-based blind (true/false farklı yanıt)
    base_wc = max(base.word_count, 1)
    if result["word_diff"] > max(15, base_wc * CONTENT_DIFF_RATIO):
        result.update(is_anomaly=True, signal="content", confidence="medium",
                      reason=f"İçerik farkı: {result['word_diff']} kelime "
                             f"(len Δ{result['length_diff']}) — boolean-based blind olabilir")
        return result

    return result


def boolean_test(true_resp: ResponseFeatures, false_resp: ResponseFeatures,
                 baseline: ResponseFeatures) -> dict[str, Any]:
    """
    Boolean-based blind için 3'lü test: TRUE koşulu baseline'a benzemeli,
    FALSE koşulu farklı olmalı (ya da tersi). İkisi de baseline'dan aynı
    yönde saparsa sinyal zayıf.
    """
    t = compare(baseline, true_resp)
    f = compare(baseline, false_resp)
    # TRUE ≈ baseline, FALSE ≠ baseline (veya tam tersi) => güçlü boolean sinyali
    if (not t["is_anomaly"]) and f["is_anomaly"]:
        return {"is_anomaly": True, "signal": "boolean", "confidence": "high",
                "reason": "TRUE koşulu baseline'a benziyor, FALSE farklı — boolean-based blind"}
    if t["is_anomaly"] and (not f["is_anomaly"]):
        return {"is_anomaly": True, "signal": "boolean", "confidence": "high",
                "reason": "FALSE koşulu baseline'a benziyor, TRUE farklı — boolean-based blind"}
    return {"is_anomaly": False, "signal": "boolean", "confidence": "low", "reason": "boolean sinyali yok"}


if __name__ == "__main__":
    # hızlı kendi kendine test
    base = extract_features("hello world " * 100, 200, 120)
    same = extract_features("hello world " * 100, 200, 130)
    diff = extract_features("error sql syntax", 500, 140)
    slow = extract_features("hello world " * 100, 200, 5200)
    print("aynı:", compare(base, same)["is_anomaly"], "(False bekleniyor)")
    print("status:", compare(base, diff)["signal"], "(status bekleniyor)")
    print("time:", compare(base, slow)["signal"], "(time bekleniyor)")
