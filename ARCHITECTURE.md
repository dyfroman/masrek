# Masrek — Architecture Document

## Components

### 1. Orchestrator (`tools/run-all.sh`)

The shell script that actually runs scanners. It is the only component that invokes
external security tools. Both the backend and CI call it as a subprocess.

**Responsibilities:**
- Parse the SCOPE.md allowlist (between markers only)
- Decide mode (passive/active/auto) based on scope
- **Refuse** active scans on out-of-scope hosts (hard exit)
- Run passive checks: HTTP headers, robots.txt, sitemap.xml, testssl.sh
- Run active scanners (ZAP, nuclei, nikto) with rate limiting and timeouts
- Write timestamped output to `results/<host>/<timestamp>/`
- Diff mode: compare current vs previous passive summary

### 2. Backend (`backend/` — FastAPI + SQLite)

REST API that wraps the orchestrator, stores results, and serves normalized findings.

**Responsibilities:**
- **Independent scope enforcement** (defense in depth — does not trust the frontend)
- Launch orchestrator runs as background subprocesses
- Parse raw scanner output into the standard finding format
- Deduplicate findings across scanners
- Map each finding to an OWASP Top 10:2025 category
- Assign severity and verification status
- Store runs and findings in SQLite
- Serve results via REST API
- Compute diffs between runs

### 3. Frontend (`frontend/` — React + Tailwind)

Dashboard for initiating scans and viewing results.

**Responsibilities:**
- URL input with live scope badge (active/passive)
- Findings table with expand-to-detail
- OWASP 2025 category breakdown
- Severity breakdown
- Diff/trend view
- Passive-mode banner explaining limitations
- RTL Hebrew support, accessibility

### 4. CI Workflow (`.github/workflows/security-pipeline.yml`)

GitHub Actions pipeline that runs on every PR.

**Responsibilities:**
- Static analysis (semgrep, gitleaks, trivy) on source code — always
- Dynamic analysis (orchestrator) against a Juice Shop service container — never external
- Security gate: fail PR if verified findings >= threshold
- Post summary comment to PR

---

## Data Flow

```
User / CI
    │
    ├─► [Frontend]  POST /scan {target_url, mode}
    │       │
    │       ▼
    │   [Backend]
    │       │
    │       ├── 1. Parse SCOPE.md allowlist
    │       ├── 2. Scope check: out-of-scope + active → HTTP 403
    │       ├── 3. Create run record in SQLite (status: running)
    │       ├── 4. Spawn subprocess: tools/run-all.sh --target URL --mode MODE
    │       │       │
    │       │       ├── Orchestrator parses SCOPE.md independently
    │       │       ├── Orchestrator refuses if out-of-scope + active
    │       │       ├── PASSIVE: curl headers, robots.txt, sitemap, testssl.sh
    │       │       ├── ACTIVE (if allowed): ZAP, nuclei, nikto
    │       │       └── Writes to results/<host>/<timestamp>/
    │       │
    │       ├── 5. On completion: parse raw results
    │       │       ├── ZAP JSON → standard findings
    │       │       ├── Nuclei JSONL → standard findings
    │       │       ├── Nikto JSON → standard findings
    │       │       ├── Header analysis → standard findings
    │       │       └── Deduplicate, assign OWASP 2025, assign severity
    │       │
    │       ├── 6. Store findings in SQLite
    │       └── 7. Update run record (status: complete, summary counts)
    │
    └─► [Frontend]  GET /runs/{id}
            │
            └── Render: summary cards, findings table, diff tab
```

---

## API Contract

### `POST /scan`

Start a new scan run.

**Request:**
```json
{
  "target_url": "http://localhost:3000",
  "mode": "auto"            // optional: "passive" | "active" | "auto" (default)
}
```

**Response (202 Accepted):**
```json
{
  "run_id": "uuid-here",
  "target_url": "http://localhost:3000",
  "mode": "active",         // resolved mode
  "status": "running",
  "created_at": "2025-01-15T10:30:00Z"
}
```

**Error (403 Forbidden):**
```json
{
  "detail": "Active scanning of 'example.com' is not authorized. Host is not in SCOPE.md allowlist. Only passive checks are available for this target."
}
```

### `GET /runs`

List all scan runs.

**Response:**
```json
{
  "runs": [
    {
      "run_id": "uuid",
      "target_url": "http://localhost:3000",
      "mode": "active",
      "status": "complete",    // "running" | "complete" | "failed"
      "created_at": "...",
      "completed_at": "...",
      "summary": {
        "total": 14,
        "critical": 1,
        "high": 3,
        "medium": 5,
        "low": 4,
        "info": 1
      }
    }
  ]
}
```

### `GET /runs/{run_id}`

Get a single run with all findings.

**Response:**
```json
{
  "run_id": "uuid",
  "target_url": "http://localhost:3000",
  "mode": "active",
  "status": "complete",
  "created_at": "...",
  "completed_at": "...",
  "summary": { "total": 14, "critical": 1, "high": 3, "medium": 5, "low": 4, "info": 1 },
  "findings": [
    {
      "id": "finding-uuid",
      "severity": "high",
      "title": "Missing Content-Security-Policy header",
      "category": "A02:2025",
      "category_name": "Security Misconfiguration",
      "location": "http://localhost:3000",
      "evidence": "Response headers do not include Content-Security-Policy",
      "verified": "yes",
      "fix": "Add a Content-Security-Policy header: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
      "source": "passive-headers",
      "raw_id": null
    }
  ]
}
```

### `GET /runs/{run_id}/diff`

Compare this run to the previous run for the same target.

**Response:**
```json
{
  "current_run_id": "uuid-1",
  "previous_run_id": "uuid-0",
  "target_url": "http://localhost:3000",
  "changes": {
    "new_findings": [...],        // findings in current but not previous
    "resolved_findings": [...],   // findings in previous but not current
    "unchanged_findings": [...],
    "header_changes": {
      "content-security-policy": {
        "before": null,
        "after": "default-src 'self'"
      }
    }
  }
}
```

### `GET /scope`

Return current scope state (used by frontend for the live badge).

**Response:**
```json
{
  "allowlist": ["http://localhost:3000", "http://127.0.0.1:3000"],
  "safety": {
    "rate_limit_rps": 10,
    "max_scan_minutes": 30,
    "destructive_tests": false,
    "auth_brute_force": false,
    "fail_gate_on": "high"
  }
}
```

### `GET /scope/check?host=example.com`

Check if a specific host is in scope.

**Response:**
```json
{
  "host": "example.com",
  "in_scope": false,
  "allowed_mode": "passive"
}
```

---

## SQLite Schema

```sql
CREATE TABLE runs (
    id              TEXT PRIMARY KEY,  -- UUID
    target_url      TEXT NOT NULL,
    target_host     TEXT NOT NULL,
    mode            TEXT NOT NULL CHECK (mode IN ('passive', 'active')),
    status          TEXT NOT NULL DEFAULT 'running'
                        CHECK (status IN ('running', 'complete', 'failed')),
    created_at      TEXT NOT NULL,     -- ISO 8601
    completed_at    TEXT,
    results_dir     TEXT,              -- path to results/<host>/<timestamp>/
    summary_json    TEXT,              -- cached summary counts as JSON
    error_message   TEXT
);

CREATE INDEX idx_runs_target_host ON runs(target_host);
CREATE INDEX idx_runs_created_at ON runs(created_at);

CREATE TABLE findings (
    id              TEXT PRIMARY KEY,  -- UUID
    run_id          TEXT NOT NULL REFERENCES runs(id),
    severity        TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    title           TEXT NOT NULL,
    category        TEXT NOT NULL,     -- e.g. "A02:2025"
    category_name   TEXT NOT NULL,     -- e.g. "Security Misconfiguration"
    location        TEXT NOT NULL,
    evidence        TEXT,
    verified        TEXT NOT NULL DEFAULT 'no'
                        CHECK (verified IN ('yes', 'no', 'needs-manual')),
    fix             TEXT,
    source          TEXT NOT NULL,     -- e.g. "zap", "nuclei", "passive-headers"
    raw_id          TEXT,              -- original ID from the scanner
    dedupe_hash     TEXT NOT NULL      -- SHA256 of (title+location+category) for dedup
);

CREATE INDEX idx_findings_run_id ON findings(run_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_category ON findings(category);
CREATE UNIQUE INDEX idx_findings_dedupe ON findings(run_id, dedupe_hash);
```

---

## Scope Enforcement — Where and How

Scope is enforced at **three independent layers**. Each layer reads SCOPE.md directly
and makes its own decision. No layer trusts another.

| Layer        | Where                  | What happens for out-of-scope + active              |
|--------------|------------------------|------------------------------------------------------|
| Frontend     | URL input component    | Badge shows "Passive only"; mode selector disabled    |
| Backend API  | `POST /scan` handler   | Returns HTTP 403 with explanation; run is not created |
| Orchestrator | `tools/run-all.sh`     | Prints refusal message; exits with code 1             |

**Allowlist parsing rule:** Only lines between `<!-- ALLOWLIST-START -->` and
`<!-- ALLOWLIST-END -->` are treated as allowed hosts. A host mentioned anywhere else
in SCOPE.md (e.g., in the "forbidden" section) is NOT considered allowed.

---

## Directory Layout (Final)

```
masrek/
├── README.md
├── CLAUDE.md
├── SCOPE.md
├── ARCHITECTURE.md
├── docker-compose.yml
├── .gitignore
│
├── tools/
│   └── run-all.sh              # Orchestrator
│
├── backend/
│   ├── requirements.txt
│   ├── Dockerfile
│   └── app/
│       ├── __init__.py
│       ├── main.py             # FastAPI app, routes
│       ├── models.py           # Pydantic models
│       ├── database.py         # SQLite setup, migrations
│       ├── scope.py            # SCOPE.md parser, enforcement
│       ├── scanner.py          # Subprocess runner for run-all.sh
│       ├── parser.py           # Raw results → standard findings
│       └── owasp.py            # OWASP 2025 category mapping
│
├── frontend/
│   ├── package.json
│   ├── Dockerfile
│   ├── vite.config.ts
│   ├── tailwind.config.ts
│   ├── tsconfig.json
│   ├── index.html
│   ├── public/
│   └── src/
│       ├── main.tsx
│       ├── App.tsx
│       ├── api/                # API client
│       ├── components/         # UI components
│       ├── design/             # Design tokens
│       └── pages/              # Route pages
│
├── results/                    # Generated, gitignored
│   ├── sast/
│   ├── dast/
│   └── supplychain/
│
├── reports/                    # Generated, gitignored
│
└── .github/
    └── workflows/
        └── security-pipeline.yml
```
