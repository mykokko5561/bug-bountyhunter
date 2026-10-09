"""
crawler.py
-----------
Hedef siteyi otomatik olarak tarayan modül.
Authenticated istekler için cookie/session kullanır.
Bulunan URL'leri FastAPI /ingest'e gönderir.

Kullanım:
    python crawler.py --url https://www.whatnot.com --depth 3
    python crawler.py --url https://www.whatnot.com --cookie "usid=..."
"""

import argparse
import logging
import re
import time
from urllib.parse import urljoin, urlparse
from collections import deque

import requests
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger("bugbounty.crawler")

INGEST_URL = "http://127.0.0.1:8000/ingest"
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

# Atlanacak uzantılar
SKIP_EXTENSIONS = {".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                   ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp"}


def should_skip(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in SKIP_EXTENSIONS)


def send_to_ingest(session: requests.Session, method: str, url: str,
                   headers: dict, body: str | None, source: str) -> None:
    try:
        resp = session.post(INGEST_URL, json={
            "method": method,
            "url": url,
            "host": urlparse(url).netloc,
            "headers": {k: v for k, v in headers.items()
                        if k.lower() not in ("cookie", "set-cookie")},
            "body": body,
            "source_program": source,
        }, timeout=5)
        if resp.status_code == 201:
            data = resp.json()
            if data.get("status") == "created":
                logger.info("Yeni URL: %s %s", method, url[:80])
    except requests.exceptions.RequestException:
        pass


def crawl(base_url: str, depth: int, cookie: str | None,
          source: str, delay: float) -> None:
    """BFS ile siteyi tara."""
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    if cookie:
        session.headers["Cookie"] = cookie

    base_domain = urlparse(base_url).netloc
    visited = set()
    queue = deque([(base_url, 0)])

    logger.info("Tarama başlıyor: %s (derinlik=%d)", base_url, depth)

    while queue:
        url, current_depth = queue.popleft()

        if url in visited or current_depth > depth:
            continue

        if should_skip(url):
            continue

        visited.add(url)

        try:
            resp = session.get(url, timeout=10, allow_redirects=True)
            send_to_ingest(session, "GET", resp.url, dict(resp.request.headers),
                           None, source)

            if current_depth >= depth:
                continue

            content_type = resp.headers.get("content-type", "")
            if "html" not in content_type:
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            # Linkleri topla
            for tag in soup.find_all(["a", "form", "button"]):
                href = tag.get("href") or tag.get("action")
                if not href:
                    continue
                full_url = urljoin(url, href)
                parsed = urlparse(full_url)

                # Sadece aynı domain
                if parsed.netloc != base_domain:
                    continue
                if full_url not in visited:
                    queue.append((full_url, current_depth + 1))

            # API endpoint'lerini JS içinden bul
            scripts = soup.find_all("script")
            for script in scripts:
                if script.string:
                    apis = re.findall(
                        r'["\'](/api/[a-zA-Z0-9/_\-?.=&]+)["\']',
                        script.string
                    )
                    for api in apis:
                        full_api = f"{parsed.scheme}://{base_domain}{api}"
                        if full_api not in visited:
                            queue.append((full_api, current_depth + 1))

            time.sleep(delay)

        except requests.exceptions.RequestException as e:
            logger.debug("Hata (%s): %s", url[:60], e)
            continue

    logger.info("Tarama tamamlandı. Ziyaret edilen: %d URL", len(visited))


def main() -> None:
    parser = argparse.ArgumentParser(description="Bug Bounty Crawler")
    parser.add_argument("--url", required=True, help="Başlangıç URL")
    parser.add_argument("--depth", type=int, default=3, help="Tarama derinliği")
    parser.add_argument("--cookie", help="Session cookie string")
    parser.add_argument("--source", default="crawler", help="Kaynak program adı")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="İstekler arası bekleme (saniye)")
    args = parser.parse_args()

    crawl(args.url, args.depth, args.cookie, args.source, args.delay)


if __name__ == "__main__":
    main()
