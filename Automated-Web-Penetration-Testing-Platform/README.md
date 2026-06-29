# Sentinel — Automated Web Penetration Testing Platform

Sentinel is a self-hosted, OWASP-aligned penetration testing platform with a
modern dashboard, real-time scan progress, pluggable security probes, and
client-ready PDF reports. It chains three layers of testing into a single
pipeline:

1. **Reconnaissance** — Nmap port scanning, service/version detection, OS
   fingerprinting, and NSE vulnerability scripts.
2. **Web probing** — in-process OWASP Top 10 probes (SQLi, XSS, security
   headers, auth surface) over `httpx`.
3. **Exploitation & post-exploitation** — Metasploit auxiliary scanners and
   exploit modules driven over `msfrpcd`, with mandatory safety guards and
   session cleanup.

The platform is built to be small, transparent, and easy to extend: a
single-process Python backend, an in-process scheduler, a SQLite database by
default, and a React/TypeScript frontend. The web-probe path runs anywhere
with no external tools. The recon/exploitation pipeline is designed for a
**Kali Linux VM** where `nmap` and `metasploit-framework` are pre-installed.

> ⚠️ **Authorized testing only.** The exploitation pipeline performs active,
> intrusive testing. Only run it against systems you own or are explicitly
> authorized to test. It is **disabled by default** and gated behind multiple
> safety toggles (see [Security model](#security-model)).

---

## Table of contents

1. [Feature overview](#feature-overview)
2. [Scan profiles](#scan-profiles)
3. [Architecture](#architecture)
4. [Repository layout](#repository-layout)
5. [How a scan runs (end-to-end)](#how-a-scan-runs-end-to-end)
6. [Security model](#security-model)
7. [Quick start](#quick-start)
8. [Kali VM setup (recon + exploitation)](#kali-vm-setup-recon--exploitation)
9. [Configuration reference](#configuration-reference)
10. [HTTP API](#http-api)
11. [Adding a new probe](#adding-a-new-probe)
12. [Frontend overview](#frontend-overview)
13. [Roadmap](#roadmap)

---

## Feature overview

- **Three-phase pipeline** — reconnaissance (Nmap) → web probes → exploitation
  (Metasploit) → post-exploitation, selected per-scan via a scan profile.
- **Network reconnaissance (Nmap)** — `NmapReconProbe` wraps `python-nmap` for
  port scanning, service/version detection, optional OS fingerprinting, and NSE
  `--script vuln` runs. Results are stored in a dedicated `recon_results` table
  and exposed via the API.
- **Automated exploitation (Metasploit)** — `MetasploitExploitProbe` maps
  discovered services to Metasploit auxiliary/exploit modules over an `msfrpcd`
  RPC connection, constrained by an allowlist/blocklist and an attempt cap.
- **Post-exploitation enumeration** — `MetasploitPostExploitProbe` runs a
  whitelisted set of read-only enumeration commands against established
  sessions, then **mandatorily closes all sessions**.
- **OWASP Top 10 web probes** — pluggable Python modules covering A03
  (SQLi + reflected XSS), A05 (security-header audit), and A07 (auth-surface
  inspection). Adding a probe takes a single import.
- **Real-time scan dashboard** — the frontend animates a radar sweep, an OWASP
  checklist, an extended phase timeline, and a live findings table.
- **PDF report generation** — completed scans render a Jinja2 + WeasyPrint
  template into a downloadable PDF under `REPORTS_DIR`.
- **JWT-protected API**, **SSRF defense**, **domain ownership guardrails**, and
  an **in-process APScheduler** — no Redis, no Celery, no worker container.
- **SQLite-first, Postgres-ready** via SQLAlchemy 2 async models.

---

## Scan profiles

Every scan carries a `scan_profile` that selects which pipeline phases run:

| Profile          | Recon (Nmap) | Web probes | Exploit (MSF) | Post-exploit | Runner               |
|------------------|:------------:|:----------:|:-------------:|:------------:|----------------------|
| `web_only`       |      —       |     ✓      |       —       |      —       | `scan_runner.py`     |
| `recon_web`      |      ✓       |     ✓      |       —       |      —       | `pipeline_runner.py` |
| `full_pipeline`  |      ✓       |     ✓      |    ✓ (opt)    |   ✓ (opt)    | `pipeline_runner.py` |

`web_only` requires no system tools. `recon_web` and `full_pipeline` require a
Kali-style host with `nmap` (and `msfrpcd` for exploitation). Even under
`full_pipeline`, the exploit and post-exploit phases only run when
`MSF_EXPLOIT_ENABLED` and `POST_EXPLOIT_ENABLED` are explicitly turned on.

---

## Architecture

```
                                ┌───────────────────────────────────────┐
                                │           Browser (React)             │
                                │  Sidebar / Dashboard / ScanPanel      │
                                │  scan-profile selector · radar · poll │
                                └───────┬───────────────────────────────┘
                                        │  HTTPS REST (JSON)
                                        ▼
┌──────────────────────────── apps/backend (FastAPI) ─────────────────────────┐
│                                                                             │
│  Middleware: CORS · RateLimiter                                             │
│  /api/auth · /api/targets · /api/scans · /api/scans/{id}/recon · /api/...   │
│                                                                             │
│  POST /api/scans  { target_url, scan_profile }                             │
│      ├─ SSRF guard (url_validator)                                          │
│      ├─ optional domain verification                                       │
│      └─ scheduler.add_job( run_scan_job | run_pipeline_job , scan_id )      │
│                                  │                                          │
│        ┌─────────────────────────┴───────────────────────────────┐         │
│        ▼ web_only                                  recon/full ▼   │         │
│  services/scan_runner.py                 services/pipeline_runner.py        │
│   - web probes only                       Phase 1  Recon  (NmapReconProbe)  │
│   - persist vulns + PDF                    │       → recon_results table     │
│                                            Phase 2  Web probes (orchestrator)│
│                                            Phase 3  Exploit (MSF probe)*     │
│                                            Phase 4  Post-exploit (MSF probe)*│
│                                            Phase 5  Persist vulns + PDF      │
│                                            (* gated by config toggles)       │
│                                                                             │
│   ┌──────────── packages/scan-engine ────────────┐                          │
│   │  ScanOrchestrator (httpx)                     │                          │
│   │   ├─ Headers · SQLi · XSS · Auth   (web)      │                          │
│   │   ├─ NmapReconProbe                (python-nmap)                         │
│   │   ├─ MetasploitExploitProbe        (msfrpcd)                             │
│   │   └─ MetasploitPostExploitProbe    (msfrpcd)                             │
│   └───────────────────────────────────────────────┘                         │
│                                                                             │
│   services/msf_client.py  → pymetasploit3 → msfrpcd (127.0.0.1:55553)        │
│   packages/report-gen     → Jinja2 → WeasyPrint → PDF                        │
│                                                                             │
│   SQLAlchemy 2 async: users · verified_targets · scans · vulnerabilities    │
│                       · recon_results · reports · rl_feedback               │
└──────────────────────────────┬──────────────────────────────────────────────┘
                               ▼
           SQLite file (default)  ─or─  PostgreSQL (DATABASE_URL)

  External tools (Kali VM):  /usr/bin/nmap   ·   msfrpcd   ·   Metasploit DB
```

Key properties:

- **Single process.** API server, scheduler, and probe executor share one
  Python event loop. Scan status/progress/phase changes are immediately
  visible to API readers via the shared DB.
- **Blocking tools run in an executor.** `python-nmap` and `pymetasploit3` are
  synchronous; the probes and `msf_client` wrap every blocking call in
  `loop.run_in_executor(...)` so the event loop is never stalled.
- **Probes are isolated.** Each probe receives a `ProbeContext` (target URL,
  optional `httpx` client, and a shared `recon_result` slot). The Nmap probe
  populates `ctx.recon_result`; the Metasploit probes consume it. Probe
  crashes are caught and logged — they don't abort the scan.
- **No hard tool dependency for web scans.** The system-tool probes are
  imported lazily inside `pipeline_runner`, so `web_only` scans never require
  `python-nmap` or `pymetasploit3` to be installed.

---

## Repository layout

```
apps/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── deps.py
│   │   │   ├── middleware/rate_limiter.py
│   │   │   └── routes/
│   │   │       ├── auth.py
│   │   │       ├── targets.py
│   │   │       ├── scans.py             # create / list / get / cancel / vulns
│   │   │       ├── recon.py             # GET /api/scans/{id}/recon
│   │   │       └── reports.py
│   │   ├── models/
│   │   │   ├── user.py
│   │   │   ├── verified_target.py
│   │   │   ├── scan.py                  # ScanStatus (+ exploiting/post_exploit)
│   │   │   ├── vulnerability.py
│   │   │   ├── recon_result.py          # Nmap results table
│   │   │   ├── report.py
│   │   │   └── rl_feedback.py
│   │   ├── schemas/
│   │   │   ├── scan.py
│   │   │   ├── recon.py                 # ReconResultResponse
│   │   │   └── ...
│   │   ├── services/
│   │   │   ├── security.py
│   │   │   ├── url_validator.py         # SSRF guard
│   │   │   ├── target_verification.py
│   │   │   ├── scheduler.py
│   │   │   ├── scan_runner.py           # web_only job entry point
│   │   │   ├── pipeline_runner.py       # recon/exploit/post pipeline
│   │   │   └── msf_client.py            # Metasploit RPC wrapper
│   │   ├── config.py                    # pydantic-settings (incl. pipeline cfg)
│   │   ├── database.py
│   │   └── main.py
│   ├── pyproject.toml
│   └── .env
└── frontend/
    └── src/
        ├── components/ (Sidebar, Dashboard, ScanPanel, Radar)
        ├── services/api.ts
        ├── store/scanStore.ts
        ├── types/index.ts
        ├── App.tsx
        └── main.tsx

packages/
├── scan-engine/
│   └── engine/
│       ├── base_scanner.py              # Finding dataclass + Severity enum
│       ├── orchestrator.py              # ScanOrchestrator
│       └── probes/
│           ├── base.py                  # BaseProbe + ProbeContext (recon_result)
│           ├── headers.py               # A05
│           ├── sqli.py                  # A03
│           ├── xss.py                   # A03
│           ├── auth.py                  # A07
│           ├── nmap_recon.py            # Nmap reconnaissance probe
│           ├── msf_exploit.py           # Metasploit exploitation probe
│           └── msf_postexploit.py       # Metasploit post-exploitation probe
└── report-gen/
    └── generator/
        ├── pdf_builder.py
        └── templates/report_base.html

scripts/
└── kali_setup.sh                        # one-shot Kali VM bootstrap

.env.example
Makefile
README.md
```

---

## How a scan runs (end-to-end)

```
1. POST /api/scans  { target_url, scan_profile }
   ├─ JWT auth · rate limit · SSRF guard
   ├─ optional domain ownership check (REQUIRE_VERIFIED_TARGET=true)
   ├─ INSERT INTO scans (status='pending')
   └─ scheduler.add_job(<runner>, args=[scan_id])
        - scan_profile ∈ {recon_web, full_pipeline} → run_pipeline_job
        - otherwise                                  → run_scan_job
      → 202 Accepted with the Scan row

2a. run_scan_job  (web_only):
    validating → scanning → generating_report → completed

2b. run_pipeline_job  (recon_web / full_pipeline):
    Phase 1  status='recon'          NmapReconProbe → recon_results row
    Phase 2  status='scanning'       web probes (Headers/SQLi/XSS/Auth)
    Phase 3  status='exploiting'     MetasploitExploitProbe   (if MSF_EXPLOIT_ENABLED)
    Phase 4  status='post_exploit'   MetasploitPostExploitProbe (if POST_EXPLOIT_ENABLED)
    Phase 5  status='generating_report'
             - persist one Vulnerability row per finding
             - render PDF → REPORTS_DIR, INSERT INTO reports
             - status='completed', progress=100
    finally: msf.cleanup_sessions() + disconnect()

3. Frontend polls GET /api/scans/{id} every 2s; on terminal status it fetches
   GET /api/scans/{id}/vulnerabilities, GET /api/scans/{id}/recon (if any),
   and offers the PDF download.
```

Status transitions:

```
web_only:       pending → validating → scanning → generating_report → completed
recon_web:      pending → recon → scanning → generating_report → completed
full_pipeline:  pending → recon → scanning → exploiting → post_exploit
                        → generating_report → completed
any:            … → failed      |      (POST /api/scans/{id}/cancel) → cancelled
```

---

## Security model

The exploitation pipeline is intrusive by nature. Safety is enforced at every
layer:

| Layer          | Guard                                                            |
|----------------|------------------------------------------------------------------|
| **Frontend**   | Warning banner shown when the `full_pipeline` profile is selected |
| **API**        | SSRF guard blocks loopback/private/link-local/reserved targets    |
| **API**        | Optional domain verification (`REQUIRE_VERIFIED_TARGET=true`)      |
| **API**        | Per-IP rate limiting (`RATE_LIMIT_PER_MIN`)                        |
| **Pipeline**   | `MSF_EXPLOIT_ENABLED=false` by default                            |
| **Pipeline**   | `POST_EXPLOIT_ENABLED=false` by default                           |
| **MSF client** | Module **allowlist** (`MSF_ALLOWED_MODULE_PREFIXES`)              |
| **MSF client** | Module **blocklist** (`MSF_BLOCKED_MODULES`, e.g. DoS / MS17-010) |
| **MSF client** | Max exploit attempts cap (`MSF_MAX_EXPLOIT_ATTEMPTS`)            |
| **MSF client** | Session auto-timeout + **mandatory cleanup** after post-exploit   |
| **Post-exploit** | Only a whitelisted, read-only command set (`POST_EXPLOIT_ACTIONS`) |
| **Web probes** | GET-only; never write state to the target                        |

Other controls:

- **Authentication.** Passwords are bcrypt-hashed (passlib); sessions are
  stateless HS256 JWTs (24h default), sent as `Authorization: Bearer ...`.
- **SSRF.** `services/url_validator.py` rejects non-public hostnames and any
  scheme other than `http`/`https`; cloud-metadata hostnames are blocked.
- **Domain ownership.** When enabled, scans are gated by a `verified_targets`
  row, verifiable via `dns_txt`, `meta_tag`, or `file_upload`. Tokens are
  32-byte hex, renewed every 90 days.
- **Probe etiquette.** Custom `User-Agent`, configurable inter-request delay,
  and per-request timeouts.

---

## Quick start

For `web_only` scans you need only Python and Node — no Nmap/Metasploit.

Requirements:

- Python 3.11+
- Node.js 20+
- (Optional) GTK runtime libraries for WeasyPrint on Windows — see the
  [WeasyPrint docs](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html).

```sh
# Clone, set up env
cp .env.example .env

# ── backend ─────────────────────────────────────────────
cd apps/backend
python -m venv .venv
. .venv/bin/activate              # Windows: .venv\Scripts\activate
pip install -e .[dev]
cp ../../.env .                   # or point the process at the repo-root .env
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# ── frontend (second shell) ─────────────────────────────
cd apps/frontend
npm install
npm run dev
```

Open:

- Frontend: <http://localhost:5173>
- API:      <http://localhost:8000>
- OpenAPI:  <http://localhost:8000/docs>

`Makefile` shortcuts: `make install`, `make backend`, `make frontend`,
`make api-fmt`, `make api-lint`, `make clean`.

---

## Kali VM setup (recon + exploitation)

The `recon_web` and `full_pipeline` profiles require system tools. Run Sentinel
on a Kali Linux VM with `nmap` and `metasploit-framework` installed, and start
the Metasploit RPC daemon.

A bootstrap script is provided:

```sh
bash scripts/kali_setup.sh
```

It installs system dependencies, initializes the Metasploit DB, starts
`msfrpcd` on `127.0.0.1:55553`, sets up the backend/frontend, and appends Kali
pipeline overrides to `.env`.

Manual essentials:

```sh
# Start the Metasploit RPC daemon (password must match MSF_RPC_PASSWORD)
msfrpcd -P sentinel_msf -S -a 127.0.0.1 -p 55553

# Nmap OS detection and some NSE scripts need root
sudo uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Recommended lab target: a **Metasploitable2** VM on an isolated host-only
network. Never point the pipeline at hosts you don't control.

---

## Configuration reference

All settings live in `apps/backend/app/config.py`, populated from `.env`.
Defaults are dev-friendly; tighten them before shipping.

### Core

| Variable                  | Default                               | Meaning                                  |
|---------------------------|---------------------------------------|------------------------------------------|
| `DEBUG`                   | `false`                               | Verbose SQL + uvicorn logs.              |
| `FRONTEND_URL`            | `http://localhost:5173`               | CORS allow-origin.                       |
| `DATABASE_URL`            | `sqlite+aiosqlite:///./sentinel.db`   | SQLAlchemy URL (swap for `postgresql+asyncpg://...`). |
| `JWT_SECRET`              | dev placeholder                       | HS256 signing secret. **Change before deploying.** |
| `JWT_EXPIRES_MINUTES`     | `1440`                                | Access-token lifetime.                   |
| `RATE_LIMIT_PER_MIN`      | `60`                                  | Per-IP request budget.                   |
| `SCAN_TIMEOUT_SECONDS`    | `600`                                 | Hard ceiling per scan job.               |
| `SCAN_REQUEST_DELAY_MS`   | `200`                                 | Delay between probe HTTP requests.       |
| `SCAN_USER_AGENT`         | `Sentinel-Scanner/0.1 (+...)`         | Sent on every probe request.             |
| `REQUIRE_VERIFIED_TARGET` | `false`                               | Enforce domain ownership before scanning.|
| `REPORTS_DIR`             | `./reports`                           | Where PDF reports are written.           |
| `VITE_API_URL`            | `http://localhost:8000`               | Frontend build-time API base.            |

### Pipeline — Nmap

| Variable                | Default                       | Meaning                              |
|-------------------------|-------------------------------|--------------------------------------|
| `PIPELINE_MODE`         | `web_only`                    | Deployment-level default profile hint.|
| `NMAP_PATH`             | `/usr/bin/nmap`               | Path to the `nmap` binary.           |
| `NMAP_SCAN_ARGS`        | `-sV -sC --top-ports 1000 -T4`| Service/version scan arguments.      |
| `NMAP_VULN_ARGS`        | `--script vuln`               | NSE vuln-script arguments.           |
| `NMAP_OS_DETECTION`     | `true`                        | Adds `-O` (requires root).           |
| `NMAP_TIMEOUT_SECONDS`  | `300`                         | Per-scan Nmap timeout.               |

### Pipeline — Metasploit

| Variable                       | Default                                  | Meaning                              |
|--------------------------------|------------------------------------------|--------------------------------------|
| `MSF_RPC_HOST`                 | `127.0.0.1`                              | `msfrpcd` host.                      |
| `MSF_RPC_PORT`                 | `55553`                                  | `msfrpcd` port.                      |
| `MSF_RPC_PASSWORD`             | `sentinel_msf`                           | RPC password. **Change in production.** |
| `MSF_RPC_SSL`                  | `true`                                   | Use SSL to `msfrpcd`.                |
| `MSF_WORKSPACE`                | `sentinel`                               | Metasploit workspace for isolation.  |
| `MSF_EXPLOIT_ENABLED`          | `false`                                  | Master switch for the exploit phase. |
| `MSF_SAFE_EXPLOITS_ONLY`       | `true`                                   | Restrict to non-destructive modules. |
| `MSF_MAX_EXPLOIT_ATTEMPTS`     | `5`                                      | Cap on exploit attempts per scan.    |
| `MSF_SESSION_TIMEOUT`          | `120`                                    | Auto-close sessions after N seconds. |
| `MSF_ALLOWED_MODULE_PREFIXES`  | `auxiliary/scanner/`, `auxiliary/gather/`, `exploit/multi/http/`, `exploit/unix/webapp/` | Module allowlist. |
| `MSF_BLOCKED_MODULES`          | `auxiliary/dos/`, `exploit/windows/smb/ms17_010` | Module blocklist. |
| `POST_EXPLOIT_ENABLED`         | `false`                                  | Master switch for post-exploitation. |
| `POST_EXPLOIT_ACTIONS`         | `sysinfo`, `getuid`, `ifconfig`, `route` | Whitelisted enumeration commands.    |

---

## HTTP API

Full interactive docs at `/docs`.

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
POST   /api/scans/                       → 202 ScanResponse   { target_url, scan_profile }
GET    /api/scans/                       → 200 list[ScanResponse]
GET    /api/scans/{id}                   → 200 ScanResponse
POST   /api/scans/{id}/cancel            → 200 ScanResponse
GET    /api/scans/{id}/vulnerabilities   → 200 list[VulnerabilityResponse]
GET    /api/scans/{id}/recon             → 200 ReconResultResponse   (recon_web / full_pipeline)
```

### Reports

```
GET    /api/reports/                     → 200 list[ReportResponse]
GET    /api/reports/{report_id}          → 200 application/pdf
```

### Health

```
GET    /api/health                       → 200 {"status":"ok","version":"..."}
```

---

## Adding a new probe

A probe implements `BaseProbe.run(ctx)` and returns `list[Finding]`. The
orchestrator handles HTTP client setup, progress reporting, deduplication, and
exception isolation.

### Web probe (httpx-based)

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
            return [Finding(
                name="500 on root",
                description="Root URL returned an unhandled server error.",
                severity=Severity.LOW,
                owasp_category=self.owasp_category,
                owasp_name=self.owasp_name,
                url_affected=str(resp.url),
                source_scanner="example",
            )]
        return []
```

Register it in `packages/scan-engine/engine/probes/__init__.py` by adding the
class to `ALL_PROBES`. The next `web_only`/web phase picks it up automatically.

### System-tool probe (Nmap/Metasploit pattern)

System-tool probes follow a different contract — they take a `config` dict,
may not use `ctx.client`, and wrap blocking calls in an executor. See
`nmap_recon.py` (populates `ctx.recon_result`) and `msf_exploit.py` (consumes
it) for the reference implementation. These probes are **not** added to
`ALL_PROBES`; instead they are constructed and run explicitly by
`services/pipeline_runner.py`, which keeps web-only scans free of the
`python-nmap` / `pymetasploit3` dependencies.

---

## Frontend overview

- **Stack.** React 19, TypeScript, Vite, Zustand for state, Axios for HTTP,
  hand-rolled CSS with a dark glass-morphism theme.
- **Scan panel.** `ScanPanel.tsx` owns the target input, the **scan-profile
  selector** (`web_only` / `recon_web` / `full_pipeline`), a warning banner for
  the full pipeline, the progress bar, the OWASP checklist, the radar widget,
  and the live findings stream.
- **Polling model.** The Zustand `scanStore` posts to `/api/scans/`, stores the
  active scan, and polls `/api/scans/{id}` every 2 seconds. On a terminal
  status it clears the timer and fetches vulnerabilities (and recon results for
  pipeline profiles).

---

## Roadmap

Implemented:

- ✅ Nmap reconnaissance probe + `recon_results` table + `/api/scans/{id}/recon`.
- ✅ Metasploit RPC client, exploitation probe, and service→module mapping with
  allow/block lists and attempt caps.
- ✅ Post-exploitation probe with whitelisted enumeration and mandatory session
  cleanup.
- ✅ `pipeline_runner` orchestrator, extended `ScanStatus` enum, and
  `scan_profile` routing.
- ✅ Frontend scan-profile selector and full-pipeline warning.

Next:

- Extended PDF template (`report_full_pipeline.html`) with dedicated recon,
  exploit, and post-exploit sections.
- Alembic migrations for the new table/enum values (models are already
  portable).
- Frontend recon-results panel and real-time exploitation log stream.
- LLM-assisted false-positive triage and remediation narratives.
- Multi-instance deployment with Redis-backed rate limiting and a persistent
  APScheduler job store.
```
