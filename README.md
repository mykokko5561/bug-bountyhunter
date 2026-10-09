# Autonomous AI Bug Bounty Hunter

**A local-first, self-improving AI system that automates the full bug bounty workflow — recon → scan → AI triage → report — and is controllable from both a live web dashboard and Telegram.**

Built for **ForgeHacks Online 2026 — AI + Cybersecurity track**.

---

## The Problem

Bug bounty recon is slow, repetitive, and noisy. A hunter manually runs subdomain discovery, probes for live hosts, fires scanners, crawls apps, and then wades through thousands of captured requests to find the handful worth a closer look. The hard part isn't running the tools — it's **triage**: deciding which of those thousands of requests is actually a vulnerability worth a report.

This project turns that pipeline into an **autonomous AI agent**. It captures real traffic, deduplicates and secret-scans it, and uses a **locally-run LLM** to reason about each request like an analyst would — flagging IDOR candidates, broken access control, and leaked secrets — then drafts the HackerOne report. A human stays in the loop for the final call, controlling the whole system from a phone or a browser.

It is not a wrapper around a scanner. The AI triage layer, the GraphQL-aware preprocessor, and the self-improving case memory are the core.

---

## What makes it different

- **Local-first AI.** Triage runs on **Ollama + Qwen2.5-14B** on the user's own GPU — no cloud API, no keys, no data leaving the machine. A cloud model (Claude) is an *optional* deep-analysis layer, not a dependency.
- **Self-improving.** Every triaged case is embedded into a **ChromaDB** vector store, so the system learns from past programs and gets better at spotting what matters.
- **GraphQL-aware.** A custom preprocessor decodes Base64 Relay IDs and normalizes GraphQL operations before triage — this is what surfaced a real IDOR in a live GraphQL API (see below).
- **Secure by design.** Commands are launched as argument vectors (no shell string concatenation), targets are validated against strict patterns, and the Telegram control surface is locked to a single authorized chat ID.
- **Two control surfaces, one brain.** The same SQLite state drives a live **web dashboard** and a **Telegram bot** — launch a scan from either, and findings appear live in both.

---

## Architecture

A layered, event-driven pipeline. Caido proxy captures traffic → a custom JS plugin webhooks it to the FastAPI backbone → the AI layers triage and escalate.

| Layer | Component | Role |
|-------|-----------|------|
| **0** | `layer0_recon.py` | Subdomain discovery (crt.sh + DNS brute-force) |
| **1** | `layer1_scan.py` | Alive check (httpx) + Nuclei vulnerability scan |
| **2** | `layer2_idor.py` | IDOR / broken-access-control candidate detection |
| **3** | `layer3_apk.py`, `layer6_apkfetch.py` | Mobile APK endpoint extraction |
| **4** | `layer4_browser.py` | Headless-browser crawl (bypasses WAF/Cloudflare), captures API calls |
| **5** | `layer5_webvuln.py` | Subdomain takeover, CORS misconfig, exposed paths |
| **7** | `layer7_source.py` | Open-source repo analysis (postMessage, DOM XSS, secrets) |
| **Core** | `main.py` (FastAPI) | Central backbone — ingest, dedup, secret-scan, state (SQLite) |
| **Triage** | `triage_worker.py` | **Local LLM (Ollama/Qwen2.5-14B)** classifies every request |
| **Deep** | `claude_analyzer.py` | Optional deep analysis via Claude API |
| **Memory** | ChromaDB | Vector store of past cases → self-improvement |
| **Control** | `dashboard.py` + `telegram_bot.py` | Live web panel + 20-command Telegram bot |

### Data flow
```
Caido proxy ──JS plugin──▶ /ingest (FastAPI)
                               │  dedup + secret scan
                               ▼
                         SQLite (requests)
                               │
                    triage_worker (Ollama/Qwen2.5)
                               │  verdict + reasoning
                               ▼
                   escalated? ──▶ Telegram alert + Dashboard
                               │
                    hackerone_reporter ──▶ H1 report draft
```

---

## The Dashboard (new for ForgeHacks)

A single-page control panel served by the existing FastAPI app at `/dashboard`. It reads the live SQLite state and auto-refreshes:

- Real-time tiles: captured requests, secrets found, live subdomains, triage queue, severity distribution
- Recon findings table (severity-colored, newest highlighted)
- Triage queue (what the AI escalated for human review)
- Live subdomain inventory
- **Launch a scan** directly from the browser (same engine as Telegram `/scan`)

Because it mounts onto the running `uvicorn main:app` process, it needs **no extra service** — it comes up with the rest of the system.

---

## Telegram control (20 commands)

Run and monitor the entire system from your phone: `/scan`, `/recon`, `/browse`, `/source`, `/idor`, `/findings`, `/subs`, `/report`, `/stats`, `/pending`, `/show`, and more. High/critical findings are pushed proactively.

---

## Real-world validation

This system was used for **actual bug bounty hunting on HackerOne** (handle: `mykokko`, ID-verified). Representative findings, responsibly disclosed through HackerOne:

- **IDOR in a live GraphQL API** — an authorization-check endpoint leaked another user's permission status; surfaced by the GraphQL-aware triage layer.
- **Subdomain takeover** — a dangling CNAME pointing to an unclaimed SaaS host.
- **Unauthenticated internal endpoint** — an exposed metrics/settings endpoint discovered via recon.

All testing was performed strictly within authorized program scopes.

---

## Tech stack

Python · FastAPI · SQLite · **Ollama / Qwen2.5-14B** · ChromaDB · Playwright · python-telegram-bot · Nuclei · httpx · Caido · Claude API (optional)

---

## Run it

```bash
# 1. Install deps (Python 3.12)
py -m pip install -r requirements.txt

# 2. Local LLM
ollama pull qwen2.5:14b-instruct

# 3. Configure
copy .env.example .env     # add Telegram token + chat id (Claude key optional)

# 4. Launch everything (FastAPI + Dashboard + Telegram bot + triage daemon)
start.bat

# Dashboard:  http://127.0.0.1:8000/dashboard
# Telegram:   send /stats to your bot
```

---

## Ethics & scope

This is a defensive research tool for **authorized bug bounty programs only**. It performs detection, not exploitation, and every scan must target a domain inside a program's published scope. The author handles scope and disclosure responsibly through HackerOne.
