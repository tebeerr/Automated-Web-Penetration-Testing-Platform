# Sentinel — Automated Web Penetration Testing Platform

Sentinel is a self-hosted, OWASP-aligned web vulnerability scanner with a
modern dashboard, real-time scan progress, custom security probes, and
client-ready PDF reports. It is designed to be small, transparent, and easy
to extend — a single-process Python backend, an in-process scheduler, a
SQLite database by default, and a React/TypeScript frontend.

The project intentionally trades horizontal scalability for delivery speed
and operability: every moving part can run on a developer laptop with no
external services.

---

## Table of contents

1. [Feature overview](#feature-overview)
2. [Architecture](#architecture)
3. [Repository layout](#repository-layout)
4. [How a scan runs (end-to-end)](#how-a-scan-runs-end-to-end)
5. [Security model](#security-model)
6. [Quick start](#quick-start)
7. [Configuration reference](#configuration-reference)
8. [HTTP API](#http-api)
9. [Adding a new probe](#adding-a-new-probe)
10. [Frontend overview](#frontend-overview)
11. [Roadmap](#roadmap)

---

## Feature overview

- **OWASP Top 10 probes** — pluggable Python modules covering A03 (Injection,
  via SQLi + reflected XSS), A05 (Security Misconfiguration, via header
  audit), and A07 (Authentication Failures, via cookie / auth-surface
  inspection). The probe set is registered in one list — adding a new probe
  takes a single import.
- **Real-time scan dashboard** — the frontend polls scan status every two
  seconds while a scan is in flight, animating a radar sweep, an OWASP
  category checklist, and a live findings table.
- **PDF report generation** — completed scans render a Jinja2 + WeasyPrint
  HTML template into a PDF saved under `REPORTS_DIR`, downloadable via the
  reports API.
- **JWT-protected API** — registration, login, scan ownership checks, and
  scan cancellation all go through a single user model with HS256 tokens.
- **Domain ownership guardrails** — optional verification (DNS TXT / meta
  tag / well-known file) gates scans to domains the user actually owns.
  Token-based, expires every 90 days. Off by default to keep dev frictionless.
- **SSRF defense** — every target URL is parsed, hostname-resolved, and
  rejected if it points at a loopback, private, link-local, or reserved
  address. Only `http` and `https` schemes are accepted.
- **In-process job scheduler** — APScheduler runs scan jobs in the same
  Python process as the API. No Redis, no Celery, no worker container.
- **SQLite-first, Postgres-ready** — schema is built from SQLAlchemy 2 async
  models using portable column types. Flip a single env var to move to
  Postgres without touching the models.

---

## Architecture

```
                                ┌───────────────────────────────────────┐
                                │           Browser (React)             │
                                │                                       │
                                │ ┌───────────┐  ┌────────────────────┐ │
                                │ │ Zustand   │  │ Components         │ │
                                │ │ scanStore │◄─┤ Sidebar / Dashboard│ │
                                │ │ (polling) │  │ ScanPanel / Radar  │ │
                                │ └─────┬─────┘  └────────────────────┘ │
                                └───────┼───────────────────────────────┘
                                        │  HTTPS REST (JSON)
                                        ▼
┌──────────────────────────── apps/backend ───────────────────────────────┐
│                                                                         │
│  ┌──────────────────────────── FastAPI ASGI ────────────────────────┐   │
│  │                                                                  │   │
│  │  Middleware:  CORS  ·  RateLimiter (in-memory token bucket)      │   │
│  │                                                                  │   │
│  │  /api/auth/*       /api/targets/*      /api/scans/*              │   │
│  │  /api/reports/*    /api/health                                   │   │
│  │                                                                  │   │
│  │      │                          │                                │   │
│  │      │ ScanCreate               │ schedule one-shot job          │   │
│  │      ▼                          ▼                                │   │
│  │  ┌──────────────┐         ┌────────────────────┐                 │   │
│  │  │ url_validator│         │   APScheduler      │                 │   │
│  │  │  (SSRF guard)│         │   (AsyncIO)        │                 │   │
│  │  └──────┬───────┘         └──────────┬─────────┘                 │   │
│  │         │                            │ run_scan_job(scan_id)     │   │
│  │         ▼                            ▼                           │   │
│  │  ┌──────────────────────────────────────────────┐                │   │
│  │  │       services/scan_runner.py                │                │   │
│  │  │  - load Scan from DB                         │                │   │
│  │  │  - drive ScanOrchestrator (progress cb)      │                │   │
│  │  │  - persist Vulnerability rows                │                │   │
│  │  │  - render PDF, persist Report row            │                │   │
│  │  └──────────────┬───────────────────────────────┘                │   │
│  │                 │                                                │   │
│  └─────────────────┼────────────────────────────────────────────────┘   │
│                    │                                                    │
│                    ▼                                                    │
│      ┌─────────── packages/scan-engine ────────────┐                    │
│      │                                             │                    │
│      │   BaseProbe ◄── ScanOrchestrator (httpx)    │                    │
│      │      ▲                                      │                    │
│      │      │                                      │                    │
│      │  ┌───┴──────┬───────────┬──────────┐        │                    │
│      │  │ Headers  │ SQLiProbe │ XSSProbe │ Auth   │                    │
│      │  └──────────┴───────────┴──────────┴────────┘                    │
│      │                                             │                    │
│      └─────────────────────────────────────────────┘                    │
│                                                                         │
│      ┌─────────── packages/report-gen ─────────────┐                    │
│      │   Jinja2 template → WeasyPrint → PDF        │                    │
│      └─────────────────────────────────────────────┘                    │
│                                                                         │
│      ┌───────── SQLAlchemy 2 async ────────────────┐                    │
│      │   users · verified_targets · scans          │                    │
│      │   vulnerabilities · reports · rl_feedback   │                    │
│      └─────────────────────────────────────────────┘                    │
└─────────────────────────────────────────────────────────────────────────┘
                    │
                    ▼
              SQLite file (default)   ─or─   PostgreSQL (DATABASE_URL)
```

Key properties:

- **Single process.** The API server, scheduler, and probe executor all
  share one Python event loop. State changes during a scan (status, progress,
  current phase) are visible to API readers immediately via the shared DB.
- **One-way data flow on the frontend.** The Zustand store is the only
  writer of scan / vulnerability state; components read selectors. Long-poll
  intervals are owned by the store and cleared automatically when a scan
  reaches a terminal status.
- **Probes are isolated.** Each probe receives a `ProbeContext` containing
  a pre-built `httpx.AsyncClient` and the target URL. It returns a list of
  `Finding` dataclasses. Probe crashes are caught and logged — they don't
  abort the scan.

---

## Repository layout

```
apps/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── deps.py                # FastAPI dependency injection
│   │   │   ├── middleware/
│   │   │   │   └── rate_limiter.py    # In-memory token bucket
│   │   │   └── routes/
│   │   │       ├── auth.py            # register / login / me
│   │   │       ├── targets.py         # domain verification
│   │   │       ├── scans.py           # create / list / get / cancel / vulns
│   │   │       └── reports.py         # list + PDF download
│   │   ├── models/                    # SQLAlchemy 2 async ORM
│   │   │   ├── user.py
│   │   │   ├── verified_target.py
│   │   │   ├── scan.py                # ScanStatus enum
│   │   │   ├── vulnerability.py       # SeverityLevel enum
│   │   │   ├── report.py
│   │   │   └── rl_feedback.py
│   │   ├── schemas/                   # Pydantic v2 request/response models
│   │   ├── services/
│   │   │   ├── security.py            # passlib bcrypt + JWT
│   │   │   ├── url_validator.py       # SSRF guard
│   │   │   ├── target_verification.py # DNS / meta / file checks
│   │   │   ├── scheduler.py           # APScheduler singleton
│   │   │   └── scan_runner.py         # scan job entry point
│   │   ├── config.py                  # pydantic-settings
│   │   ├── database.py                # async engine + Session factory
│   │   └── main.py                    # FastAPI app + lifespan
│   ├── pyproject.toml
│   └── .env                           # local config (gitignored)
└── frontend/
    ├── src/
    │   ├── components/
    │   │   ├── Sidebar.tsx
    │   │   ├── Dashboard.tsx
    │   │   ├── ScanPanel.tsx
    │   │   ├── Radar.tsx
    │   │   └── pages/Placeholder.tsx
    │   ├── services/api.ts            # axios client
    │   ├── store/scanStore.ts         # Zustand: start/poll/cancel
    │   ├── types/index.ts
    │   ├── App.tsx
    │   └── main.tsx
    ├── package.json
    ├── vite.config.ts
    └── tsconfig.*.json

packages/
├── scan-engine/
│   └── engine/
│       ├── base_scanner.py            # Finding dataclass + Severity enum
│       ├── orchestrator.py            # ScanOrchestrator
│       └── probes/
│           ├── base.py                # BaseProbe + ProbeContext
│           ├── headers.py             # A05 security-header audit
│           ├── sqli.py                # A03 reflected-error SQLi
│           ├── xss.py                 # A03 reflected XSS marker test
│           └── auth.py                # A07 auth-surface checks
└── report-gen/
    └── generator/
        ├── pdf_builder.py             # WeasyPrint render
        └── templates/report_base.html

docs/                                  # design notes (architecture, API spec)

.env.example
.gitignore
Makefile
README.md
```

---

## How a scan runs (end-to-end)

```
1. POST /api/scans/  {target_url, scan_profile}
   ├─ JWT auth (apps/backend/app/api/deps.py)
   ├─ rate limit check (RateLimiterMiddleware)
   ├─ SSRF guard (services/url_validator.validate_target_url)
   │     - scheme must be http/https
   │     - hostname must resolve to a public IP (no loopback/private/etc.)
   ├─ optional domain ownership check (REQUIRE_VERIFIED_TARGET=true)
   ├─ INSERT INTO scans (status='pending', progress=0)
   └─ scheduler.add_job(run_scan_job, args=[scan_id])
        → returns 202 Accepted with the Scan row

2. APScheduler fires run_scan_job(scan_id):
   ├─ load Scan from DB
   ├─ status='validating', progress=2
   ├─ build ScanOrchestrator with ALL_PROBES
   ├─ orchestrator.run(target_url):
   │     for each probe:
   │       progress += step
   │       findings.extend(await probe.run(ctx))
   │     dedupe(findings)
   ├─ INSERT INTO vulnerabilities (one row per finding)
   ├─ status='generating_report'
   ├─ packages/report-gen renders PDF → REPORTS_DIR/sentinel_report_{id}.pdf
   ├─ INSERT INTO reports
   └─ status='completed', progress=100, end_time=now

3. Frontend polls GET /api/scans/{id} every 2s:
   ├─ updates progress bar + radar + OWASP checklist
   └─ when status ∈ {completed, failed, cancelled}:
        stop polling, fetch GET /api/scans/{id}/vulnerabilities,
        offer GET /api/reports/{report_id} download.
```

Status transitions enforced by the runner:

```
pending → validating → recon → scanning → generating_report → completed
                                                            ↘
                                                              failed
            (POST /api/scans/{id}/cancel) → cancelled
```

---

## Security model

- **Authentication.** Passwords are bcrypt-hashed via passlib. Sessions are
  stateless JWTs (HS256, 24h default). The token is stored in
  `localStorage` and attached to every request as `Authorization: Bearer ...`
  by an axios interceptor.
- **SSRF.** `services/url_validator.py` rejects URLs whose hostname resolves
  to a private/loopback/link-local/multicast/reserved address. Only `http`
  and `https` schemes are permitted. Cloud metadata hostnames are blocked
  explicitly. Re-checking after HTTP redirects is the caller's job; probes
  currently disable automatic redirects on injection requests.
- **Domain ownership.** When `REQUIRE_VERIFIED_TARGET=true`, every scan
  request is gated by a row in `verified_targets`. Verification offers three
  methods:
  - `dns_txt` — verify a TXT record matches the issued token.
  - `meta_tag` — fetch the site root and look for
    `<meta name="sentinel-verification" content="...">`.
  - `file_upload` — fetch `/.well-known/sentinel-verification.txt`.
  Tokens are random 32-hex-byte values, renewed every 90 days.
- **Rate limiting.** In-memory token bucket keyed by client IP, 60 req/min
  by default. Designed for single-process deployments; swap for a Redis
  sliding-window if you run more than one API instance.
- **Probe etiquette.** All HTTP requests use a custom `User-Agent`
  identifying the scanner, a configurable inter-request delay
  (`SCAN_REQUEST_DELAY_MS`), and a 15-second per-request timeout. Probes
  must not write any state to the target — they only issue `GET` requests.

---

## Quick start

Requirements:

- Python 3.11+
- Node.js 20+
- (Optional) GTK runtime libraries for WeasyPrint on Windows — see
  [WeasyPrint docs](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html).

```sh
# Clone, set up env
cp .env.example .env

# ── backend ─────────────────────────────────────────────
cd apps/backend
python -m venv .venv
. .venv/bin/activate              # Windows: .venv\Scripts\activate
pip install -e .[dev]

# point env at backend dir or copy .env into apps/backend/
cp ../../.env .

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# ── frontend (in a second shell) ────────────────────────
cd apps/frontend
npm install
npm run dev
```

Then open:

- Frontend: <http://localhost:5173>
- API:      <http://localhost:8000>
- OpenAPI:  <http://localhost:8000/docs>

The `Makefile` wraps the common tasks:

```sh
make install        # install backend (pip) and frontend (npm) deps
make backend        # uvicorn --reload
make frontend       # vite dev server
make api-fmt        # ruff format
make api-lint       # ruff check
make clean          # drop sentinel.db + generated reports
```

---

## Configuration reference

All settings live in `apps/backend/app/config.py` and are populated from the
environment (`.env`). The defaults are dev-friendly; tighten them before
shipping.

| Variable                  | Default                                    | Meaning                                                    |
|---------------------------|--------------------------------------------|------------------------------------------------------------|
| `DEBUG`                   | `false`                                    | Verbose SQL + uvicorn logs.                                |
| `FRONTEND_URL`            | `http://localhost:5173`                    | CORS allow-origin.                                         |
| `DATABASE_URL`            | `sqlite+aiosqlite:///./sentinel.db`        | SQLAlchemy URL. Swap to `postgresql+asyncpg://...` for prod. |
| `JWT_SECRET`              | dev placeholder                            | HS256 signing secret. **Change before deploying.**         |
| `JWT_EXPIRES_MINUTES`     | `1440`                                     | Access-token lifetime.                                     |
| `RATE_LIMIT_PER_MIN`      | `60`                                       | Per-IP request budget.                                     |
| `SCAN_TIMEOUT_SECONDS`    | `600`                                      | Hard ceiling per scan job.                                 |
| `SCAN_REQUEST_DELAY_MS`   | `200`                                      | Delay between probe HTTP requests.                         |
| `SCAN_USER_AGENT`         | `Sentinel-Scanner/0.1 (+...)`              | Sent on every probe request.                               |
| `REQUIRE_VERIFIED_TARGET` | `false`                                    | Enforce domain ownership before scanning.                  |
| `REPORTS_DIR`             | `./reports`                                | Where PDF reports are written.                             |
| `VITE_API_URL`            | `http://localhost:8000`                    | Frontend build-time API base.                              |

---

## HTTP API

A short tour of the most important endpoints — full interactive docs live at
`/docs`.

### Auth

```
POST /api/auth/register       → 201 TokenResponse
POST /api/auth/login          → 200 TokenResponse
GET  /api/auth/me             → 200 UserResponse              (auth required)
```

### Domain verification

```
POST /api/targets/verification/start     → 200 token + instructions
POST /api/targets/verification/confirm   → 200 VerifiedTargetResponse
GET  /api/targets/                       → 200 list[VerifiedTargetResponse]
```

### Scans

```
POST   /api/scans/                       → 202 ScanResponse
GET    /api/scans/                       → 200 list[ScanResponse]
GET    /api/scans/{id}                   → 200 ScanResponse
POST   /api/scans/{id}/cancel            → 200 ScanResponse
GET    /api/scans/{id}/vulnerabilities   → 200 list[VulnerabilityResponse]
```

### Reports

```
GET    /api/reports/                     → 200 list[ReportResponse]
GET    /api/reports/{report_id}          → 200 application/pdf  (file download)
```

### Health

```
GET    /api/health                       → 200 {"status":"ok","version":"..."}
```

---

## Adding a new probe

A probe is a class implementing `BaseProbe.run(ctx)` and returning
`list[Finding]`. The orchestrator handles HTTP client setup, progress
reporting, deduplication, and exception isolation.

```python
# packages/scan-engine/engine/probes/example.py
from engine.base_scanner import Finding, Severity
from engine.probes.base import BaseProbe, ProbeContext


class ExampleProbe(BaseProbe):
    code = "example"
    name = "Example check"
    owasp_category = "A05"
    owasp_name = "Security Misconfiguration"

    async def run(self, ctx: ProbeContext) -> list[Finding]:
        resp = await ctx.client.get(ctx.target_url)
        if resp.status_code == 500:
            return [
                Finding(
                    name="500 on root",
                    description="Root URL returned an unhandled server error.",
                    severity=Severity.LOW,
                    owasp_category=self.owasp_category,
                    owasp_name=self.owasp_name,
                    url_affected=str(resp.url),
                    source_scanner="example",
                )
            ]
        return []
```

Register it:

```python
# packages/scan-engine/engine/probes/__init__.py
from engine.probes.example import ExampleProbe

ALL_PROBES = [
    SecurityHeadersProbe,
    SQLiProbe,
    XSSProbe,
    AuthProbe,
    ExampleProbe,   # ← here
]
```

That's the entire integration — the next scan picks it up automatically.

---

## Frontend overview

- **Stack.** React 19, TypeScript, Vite, Zustand for state, Axios for HTTP,
  no UI framework — styling is hand-rolled CSS with a dark glass-morphism
  theme.
- **Navigation.** A custom `Sidebar` toggles between five sections by
  setting a single piece of state on `App.tsx`. No `react-router` yet to
  keep the bundle small; swap in routing the moment URL deep-linking is
  needed.
- **Scan dashboard.** `Dashboard.tsx` renders four stat cards followed by
  `ScanPanel.tsx`, which owns the target input, the start/stop button, the
  live progress bar, the OWASP A01–A10 checklist, the radar widget, and the
  live findings stream.
- **Polling model.** The Zustand `scanStore` exposes
  `startScan(targetUrl)`, which posts to `/api/scans/`, stores the active
  scan, and starts a 2-second `setInterval` that hits `/api/scans/{id}`.
  As soon as the status is terminal (`completed` / `failed` / `cancelled`),
  the timer is cleared and the vulnerability list is fetched.
- **Styling.** Three layers: `index.css` for globals + CSS variables;
  `App.css` for component-level rules; inline `style` only for one-off
  dynamic values like progress widths and radar rotation transforms.

---

## Roadmap

The current scope is the eight-week intern build. Anything beyond that lives
in `docs/` proposals.

| Week | Focus                                                                  |
|------|------------------------------------------------------------------------|
| 1–3  | Scaffold, SSRF guard, auth, scan model, scheduler, probe orchestrator. |
| 4    | SQLi + XSS probes (current).                                           |
| 5    | Security-headers + auth-hygiene probes (current).                      |
| 6    | Results dashboard polish (vulnerability detail drawer, charts).        |
| 7    | PDF export polish (executive summary, charts, branding).               |
| 8    | Tests, deployment docs, presentation.                                  |

Beyond the intern timeline, candidate enhancements include:

- Postgres migrations via Alembic (the models are already portable).
- Authenticated scans (credentialed crawler).
- Per-probe configuration UI.
- LLM-assisted false-positive triage and remediation narrative.
- Multi-instance deployment with Redis-backed rate limiting and a
  persistent APScheduler job store.
