# Masrek — מסרק

**Automated Web-Application Security Testing Platform**

Masrek ("comb" in Hebrew — combing through your app for vulnerabilities) is a shift-left
DevSecOps platform that automates security scanning, maps findings to OWASP Top 10:2025,
and delivers actionable remediation guidance.

## What it does

1. **You provide a URL** — paste it in the dashboard or pass it to the CLI.
2. **It decides the right mode** — if the host is on your allowlist (`SCOPE.md`), it runs
   a full active scan. Otherwise, it runs passive checks only (equivalent to browsing the site).
3. **It runs industry-standard scanners** — ZAP, nuclei, nikto, semgrep, trivy, gitleaks,
   testssl.sh, and more.
4. **It normalizes and deduplicates** — raw scanner output is parsed into a unified format,
   false positives are triaged, and every real finding gets an OWASP 2025 category.
5. **It shows you what to fix** — each finding includes the location, evidence, and a
   concrete remediation step.
6. **It gates your PRs** — a GitHub Actions workflow fails the build if verified high+ findings
   are present.

## Quick start

### 1. Run a local Juice Shop instance (for active scanning)

```bash
docker run --rm -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
```

### 2. Run the scanner

```bash
# Active scan (localhost is on the allowlist)
bash tools/run-all.sh --target http://localhost:3000

# Passive scan (any host)
bash tools/run-all.sh --target https://juice-shop.herokuapp.com

# Compare to previous scan
bash tools/run-all.sh --target https://juice-shop.herokuapp.com --diff
```

### 3. Start the dashboard

```bash
# Backend
cd backend && pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend
cd frontend && npm install && npm run dev
```

### 4. Or use Docker Compose

```bash
docker compose up
# Dashboard at http://localhost:5173
# API at http://localhost:8000
# Juice Shop at http://localhost:3000
```

## Authorization model

**Active scanning requires explicit authorization.** The file `SCOPE.md` contains a
machine-readable allowlist between `<!-- ALLOWLIST-START -->` and `<!-- ALLOWLIST-END -->`.
Only hosts listed there may be actively scanned.

Out-of-scope hosts receive **passive checks only** — HTTP header analysis, TLS configuration,
robots.txt/sitemap.xml retrieval. This is normal browser-equivalent traffic.

There is **no override** for this restriction. If you need to actively scan a host, add it
to `SCOPE.md` first.

## Safety defaults

| Parameter           | Value   | Meaning                                          |
|---------------------|---------|-------------------------------------------------|
| `rate_limit_rps`    | 10      | Max requests per second per scanner              |
| `max_scan_minutes`  | 30      | Hard timeout per scanner                         |
| `destructive_tests` | false   | No data-modifying payloads                       |
| `auth_brute_force`  | false   | No credential brute-forcing                      |
| `fail_gate_on`      | high    | CI gate fails on verified High+ findings         |

## OWASP Top 10:2025 mapping

Every finding is categorized against the 2025 edition:

| Code | Category                              |
|------|---------------------------------------|
| A01  | Broken Access Control                 |
| A02  | Security Misconfiguration             |
| A03  | Software Supply Chain Failures        |
| A04  | Cryptographic Failures                |
| A05  | Injection                             |
| A06  | Insecure Design                       |
| A07  | Authentication Failures               |
| A08  | Software and Data Integrity Failures  |
| A09  | Security Logging & Alerting Failures  |
| A10  | Mishandling of Exceptional Conditions |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Frontend (React)                       │
│  URL input → scope badge → findings table → diff view    │
└────────────────────────┬────────────────────────────────┘
                         │ REST API
┌────────────────────────┴────────────────────────────────┐
│                  Backend (FastAPI)                        │
│  Scope enforcement → run orchestrator → parse results    │
│  → normalize → deduplicate → OWASP map → store (SQLite)  │
└────────────────────────┬────────────────────────────────┘
                         │ subprocess
┌────────────────────────┴────────────────────────────────┐
│              Orchestrator (run-all.sh)                    │
│  SCOPE.md parse → mode decision → passive stage          │
│  → active stage (if allowed) → results/                  │
└─────────────────────────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
   ┌─────────┐    ┌───────────┐    ┌──────────┐
   │ Passive  │    │  Active   │    │  Static  │
   │ headers  │    │ ZAP/nuclei│    │ semgrep  │
   │ TLS/cert │    │ nikto     │    │ gitleaks │
   │ robots   │    │           │    │ trivy    │
   └─────────┘    └───────────┘    └──────────┘
```

## License

MIT
