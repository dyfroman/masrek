# Masrek — Automated Web-Application Security Testing Platform

## What this project is

A "shift-left" DevSecOps platform that automates security scanning of web applications.
A developer or CI pipeline points it at a running web app; it runs open-source security
scanners, removes noise/false-positives, maps findings to OWASP Top 10:2025 categories,
and produces a clear report with concrete fixes that can gate a Pull Request.

**This is a defensive, remediation-oriented tool — never an attack tool.**
The demo target is OWASP Juice Shop, a deliberately vulnerable training application.

## Non-negotiable guardrails

These rules are encoded into every layer (orchestrator, backend API, CI workflow).
They cannot be overridden by configuration, flags, or UI input.

1. **Authorization is mandatory.** `SCOPE.md` holds the allowlist. The machine-readable
   block between `<!-- ALLOWLIST-START -->` and `<!-- ALLOWLIST-END -->` is the only
   source of truth. Nothing actively scans a host that isn't listed there.

2. **Passive vs Active separation:**
   - **PASSIVE** = normal HTTP traffic only (fetch headers, fingerprint tech, read
     robots.txt/sitemap, check TLS). Allowed against ANY reachable host.
   - **ACTIVE** = intrusive scanning (ZAP active scan, nuclei, nikto). Allowed ONLY
     against hosts on the SCOPE.md allowlist.
   - Mode is auto-decided: in-scope → active, out-of-scope → passive.
   - An out-of-scope target can **NEVER** be actively scanned. There is no override.

3. **Non-destructive by default:** rate-limited (`rate_limit_rps`), time-boxed
   (`max_scan_minutes`), no data modification/deletion, no DoS, no `--dangerous` flags.
   Results stay local.

4. **Fix-oriented:** every finding carries category, location, evidence, and a concrete fix.

5. **Verify before reporting:** triage findings to reduce false positives before surfacing.

## Standard finding format

Every finding — from any scanner, at any layer — is normalized to this structure:

```
[severity] short title
Category : Axx:2025 — <name>
Location : <URL / file:line>
Evidence : <brief proof>
Verified : yes / no / needs-manual
Fix      : <concrete remediation>
```

### Severity scale

| Level    | Meaning                                                    |
|----------|------------------------------------------------------------|
| Critical | Actively exploitable, immediate compromise risk            |
| High     | Exploitable with moderate effort, significant impact        |
| Medium   | Requires specific conditions, moderate impact               |
| Low      | Minor risk, limited impact                                  |
| Info     | Informational, no direct security impact                    |

The CI gate fails on **Verified** findings at or above `fail_gate_on` (default: `high`).

## OWASP Top 10:2025 categories

Every finding is mapped to one of these:

| Code | Name                                  |
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

## Pipeline layers

| Layer         | Tools                              | Runs on         | OWASP coverage       |
|---------------|------------------------------------|-----------------|-----------------------|
| SAST          | semgrep                            | Source code      | A05, A06, A10         |
| Supply chain  | osv-scanner, npm audit, trivy, SBOM| Source code      | A03                   |
| Secrets       | gitleaks                           | Source code      | A02, A04              |
| Recon         | ZAP spider + HTTP fingerprint      | Live instance    | —                     |
| DAST          | ZAP active scan, nuclei, nikto     | Live instance    | A01, A02, A05, A07    |
| TLS           | testssl.sh                         | Live instance    | A04                   |

Static layers (SAST/supply-chain/secrets) run on the app's source code — fast, every PR.
Dynamic layers (DAST) run against a live instance — in CI, an ephemeral service container.

## Tech stack

- **Orchestrator:** `tools/run-all.sh` (Bash)
- **Backend:** Python, FastAPI, SQLite
- **Frontend:** React, Tailwind CSS, RTL Hebrew support
- **CI:** GitHub Actions

## Directory layout

```
README.md  CLAUDE.md  SCOPE.md
tools/run-all.sh
backend/              # FastAPI app
frontend/             # React app
results/{sast,dast,supplychain}/
reports/
.github/workflows/security-pipeline.yml
```

## Development commands

```bash
# Start local Juice Shop target
docker run --rm -d -p 3000:3000 --name juice-shop bkimminich/juice-shop

# Run orchestrator
bash tools/run-all.sh --target http://localhost:3000

# Backend
cd backend && pip install -r requirements.txt && uvicorn app.main:app --reload

# Frontend
cd frontend && npm install && npm run dev
```
