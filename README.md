# Bug Bounty Hunter - AI Micro-SaaS

6 katmanlı otomatik bug bounty sistemi.

## Bileşenler
- `main.py` — FastAPI merkezi API (SQLite WAL)
- `triage_worker.py` — Ollama (qwen2.5:14b) ile otomatik triage
- `claude_analyzer.py` — Claude API ile derin analiz
- `telegram_bot.py` — Telegram bot (/scan, /report, /stats)
- `crawler.py` — BFS web crawler
- `hackerone_reporter.py` — HackerOne API entegrasyonu
- `script.js` — Caido proxy plugin

## Kurulum
```bash
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
cp .env.example .env   # API key'leri ekle
start.bat
```

## .env
```
ANTHROPIC_API_KEY=sk-ant-...
BUGBOUNTY_TG_TOKEN=...
BUGBOUNTY_TG_CHAT_ID=...
HACKERONE_API_TOKEN=...
HACKERONE_USERNAME=...
```
