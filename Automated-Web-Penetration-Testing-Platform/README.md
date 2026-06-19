# Sentinel — Automated Web Penetration Testing Platform

AI-driven OWASP Top 10 scanner with live progress, client-ready PDF reports, and
domain-ownership guardrails. Monorepo: React/TypeScript frontend, FastAPI
backend, Celery workers, ZAP + Nuclei + custom scanners, LLM post-processing.

## Layout

```
apps/
  frontend/    # React 19 + TypeScript + Vite + Zustand
  backend/     # FastAPI + SQLAlchemy 2 (async) + Pydantic v2
workers/       # Celery tasks (scan, AI analysis, report generation)
packages/
  scan-engine/ # ZAP, Nuclei, Nmap wrappers + orchestrator
  ai-agent/    # LLM providers + FP filter / ranker / remediation / summary
  report-gen/  # Jinja2 + WeasyPrint PDF builder
infra/         # docker-compose + nginx + DB init SQL
docs/          # architecture, API spec, deployment notes
```

## Quick start (Docker)

```sh
cp .env.example .env
# edit .env, set JWT_SECRET, POSTGRES_PASSWORD, ANTHROPIC_API_KEY, ZAP_API_KEY
make build
make up
```

- Frontend: http://localhost:5173 (or http://localhost through Nginx)
- API: http://localhost:8000  ·  Docs: http://localhost:8000/docs
- Postgres: localhost:5432  ·  Redis: localhost:6379  ·  ZAP: localhost:8080

## Quick start (local dev, no Docker)

```sh
# backend
cd apps/backend
python -m venv .venv && . .venv/bin/activate
pip install -e .[dev]
uvicorn app.main:app --reload

# frontend
cd apps/frontend
npm install
npm run dev
```

## Pipeline

1. `POST /api/scans` validates URL (SSRF guard) + checks domain ownership →
   inserts a `Scan` row → enqueues `scan.run` Celery task.
2. Worker advances scan through `validating → recon → scanning → ai_analyzing
   → generating_report → completed`, persisting state and publishing to Redis
   channel `scan:{id}`.
3. FastAPI relays Redis pub/sub to subscribed WebSocket clients
   (`/ws/scan/{id}`); the React `useScanStore` updates UI in real time.
4. On completion, a PDF report is written to `REPORTS_DIR` and exposed via
   `GET /api/reports/{report_id}`.

## Security guardrails

- SSRF guard rejects private IPs, link-local, loopback, internal hostnames.
- Domain verification (DNS TXT / meta tag / well-known file) required before
  any scan can be enqueued; tokens expire after 90 days.
- Rate limiter middleware (60 req/min default, in-memory; swap to Redis for
  multi-instance deployments).
- JWT auth (HS256, 24h default).

## What is wired vs stubbed

- **Wired**: frontend skeleton, FastAPI routes, models, schemas, JWT, SSRF
  guard, target verification, WebSocket + Redis relay, Celery wiring, Docker
  compose, Nginx, scan-task status pipeline (publishes progress, marks
  completion).
- **Stubbed**: `ScanOrchestrator` scanner registrations (ZAP/Nuclei/Nmap
  wrappers + parsers TBD), each AI agent class (FP filter, ranker, remediation,
  summarizer), `PDFReportBuilder` integration in the Celery pipeline.

## Roadmap

See `docs/` and the project plan. Next ticks:
- Implement `ZAPScanner`, `NucleiScanner`, `NmapScanner` + parsers.
- Implement Anthropic / OpenAI / Ollama LLM providers and the 4 agents.
- Wire `PDFReportBuilder` into `scan_task.run_pentest_scan`.
- Frontend: real scan page consuming `useScanStore`, results page, history,
  domain verification UI.
