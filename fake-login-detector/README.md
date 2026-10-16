# Fake Login Page Detector

> Hackathon entry — October 2026  
> **Catches phishing clone pages in < 8 seconds, with explainable evidence.**

## What it does

Takes a suspect URL, finds the genuine page it may be imitating, compares the two, and returns:
- A **clone-likelihood score** (0–100) and a verdict
- A **side-by-side screenshot comparison** with a diff overlay
- **Structured reasons**: domain lookalike, copied HTML, foreign form action, hotlinked assets, logo match

## Architecture

```
browser → Playwright fetcher → PageSnapshot
                                    ↓
              ┌─────────────────────────────────────┐
              │  Five independent analyzers          │
              │  domain | form | dom | visual | assets│
              └────────────────────┬────────────────-┘
                                   ↓
                           scoring.py (weighted, overrides)
                                   ↓
                           ScanResult → API → UI / Extension
```

## Quick Start

```bash
cd fake-login-detector/backend

# 1. Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install Playwright browser
playwright install chromium

# 4. Start the server
python -m app.main
# → http://localhost:8000
# → http://localhost:8000/api/health
```

## Running Tests

```bash
cd fake-login-detector/backend
.venv\Scripts\activate
pytest tests/ -v
```

## Test Pages (Phase 4+)

Start all 10 test pages:

```bash
cd fake-login-detector/testpages
python serve_all.py
```

Pages run on ports 5001–5010. Register the ports in your `hosts` file for
lookalike-domain realism (optional, documented in `testpages/README.md`).

## Build Phases

| Phase | Status | Description |
|-------|--------|-------------|
| 0 | ✅ Done | Scaffold, models, config, URL utils, confusables, Analyzer protocol |
| 1 | ⏳ | Domain + form analyzers, brand registry, 30 unit tests |
| 2 | ⏳ | Playwright fetcher, DOM analyzer, genuine-snapshot cache |
| 3 | ⏳ | Visual + assets analyzers, scoring, orchestrator, full API |
| 4 | ⏳ | 10 test pages, e2e tests, calibration script |
| 5 | ⏳ | Vanilla JS frontend (gauge, slider, reasons, breakdown, attack-path) |
| 6 | ⏳ | Manifest V3 extension (3 tiers + warning page) |
| 7 | ⏳ | Wow features: diff slider polish, PDF report, honeypot, optional AI summary |
| 8 | ⏳ | Hardening, prewarm script, one-command start, demo checklist |

## Repository Layout

```
fake-login-detector/
  backend/
    app/           # FastAPI app, analyzers, utils
    config/        # brands.json, scoring.json
    tests/         # unit + e2e + fixtures
    scripts/       # calibrate.py, prewarm.py
    requirements.txt
  frontend/        # Vanilla HTML/CSS/JS (Phase 5)
  extension/       # Manifest V3 extension (Phase 6)
  shared/          # domain_test_vectors.json (parity between Python + JS)
  testpages/       # 10 local test pages served on ports 5001–5010 (Phase 4)
  artifacts/       # Runtime screenshots, diffs, reports (gitignored)
```

## Configuration

All tunable values live in `backend/config/scoring.json` and `backend/app/config.py`.
No magic numbers in analyzer code.

Feature flags (set via environment variable or `.env`):
- `FAKELD_ENABLE_WHOIS=true` — domain age check (requires internet)
- `FAKELD_ENABLE_VIRUSTOTAL=true` — VirusTotal reputation (requires API key)
- `FAKELD_ENABLE_AI_SUMMARY=true` — LLM summary (requires API key)

## Hackathon Pitch

> "An attacker cloned our portal 10 minutes ago and VirusTotal knows nothing.  
>  Here is how we caught it in 8 seconds — and exactly why."
