"""
probe_pw.py — Arc portal.arc.io /api/pw/* uçlarını kaydedilmiş session ile
otomatik prob eder, JSON response'ları ekrana ve dosyaya yazar.

Kullanım (bug bounty klasöründe, layer4 ile aynı yerde):
    python probe_pw.py
"""
import json
import httpx

SESSION_FILE = "bykea_session.json"
BASE = "https://portal.arc.io"

REAL_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36")

ENDPOINTS = [
    ("GET", "/api/pw/me"),
    ("POST", "/api/pw/wallets"),
    ("POST", "/api/pw/agent-wallets"),
]


def load_cookies():
    with open(SESSION_FILE, "r", encoding="utf-8") as f:
        state = json.load(f)
    jar = {}
    for c in state.get("cookies", []):
        if "arc.io" in c.get("domain", ""):
            jar[c["name"]] = c["value"]
    return jar


def main():
    cookies = load_cookies()
    if not cookies:
        print("[!] bykea_session.json'da arc.io cookie'si bulunamadı — önce --login yap.")
        return
    print(f"[i] {len(cookies)} cookie yüklendi: {list(cookies.keys())}\n")

    headers = {
        "user-agent": REAL_UA,
        "accept": "*/*",
        "referer": "https://portal.arc.io/",
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
    }

    results = {}
    with httpx.Client(cookies=cookies, headers=headers, timeout=15) as client:
        for method, path in ENDPOINTS:
            url = BASE + path
            try:
                if method == "GET":
                    r = client.get(url)
                else:
                    r = client.post(url, json={})
                print("=" * 70)
                print(f"{method} {path} -> {r.status_code}")
                try:
                    body = r.json()
                    print(json.dumps(body, indent=2, ensure_ascii=False)[:3000])
                    results[path] = body
                except Exception:
                    print(r.text[:1000])
                    results[path] = r.text[:1000]
            except Exception as e:
                print(f"[hata] {method} {path}: {e}")

    with open("pw_probe_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print("\n[i] Tüm sonuçlar pw_probe_results.json'a yazıldı.")


if __name__ == "__main__":
    main()