# Masrek — Demo Runbook

## Prerequisites
- Docker Desktop running (Windows/Mac: ensure "host.docker.internal" support is enabled — it is by default)
- Ports 3000, 5173, 8000, 8080 free

## 1. Bring the full stack up

```bash
cd masrek
docker compose down          # clean slate
docker compose up -d --build # rebuild all images
```

First build takes ~5 minutes (downloads nuclei, nikto, testssl.sh into the backend image).
Wait ~60 seconds after `up` for ZAP daemon and Juice Shop to initialize.

| Service    | URL                         | Notes                              |
|------------|-----------------------------|-------------------------------------|
| Dashboard  | http://localhost:5173        | React frontend                      |
| Backend    | http://localhost:8000/health | FastAPI backend                     |
| Juice Shop | http://localhost:3000        | OWASP vulnerable app                |
| ZAP API    | http://localhost:8080        | ZAP daemon (API key: masrek-zap-dev-key) |

Verify everything is up:
```bash
curl -s http://localhost:8000/health    # → {"status":"ok"}
curl -s http://localhost:3000 | head -1 # → <!DOCTYPE html> (juice-shop)
curl -s "http://localhost:8080/JSON/core/view/version/?apikey=masrek-zap-dev-key"  # → {"version":"..."}
```

## 2. Active scan on local Juice Shop

1. Open http://localhost:5173
2. The default URL shows `https://juice-shop.herokuapp.com` — change it to `http://localhost:3000`
3. The badge turns **green**: "סריקה פעילה (Active) — היעד מורשה ב-SCOPE.md"
4. Click **סרוק** (Scan)
5. The progress page shows status: running (פעיל)
6. The preflight check runs first — verifies ZAP API, nuclei, nikto, and target reachability
7. ZAP spiders the target, then runs an active scan. Nuclei and nikto run in parallel.
8. When done, you're redirected to the results page with:
   - Summary cards (total / critical / high / medium / low / info counts)
   - OWASP Top 10:2025 breakdown
   - Findings table, expandable rows with evidence + fix

**What to expect**: XSS findings, missing security headers (CSP, HSTS, Referrer-Policy),
server disclosure (Express/X-Powered-By), SQL injection in search, insecure cookies, and more.
A full active scan can take 10-30 minutes depending on ZAP scan depth.

### Troubleshooting a failed preflight

If the scan fails immediately, the error message tells you exactly what's wrong:
- **"ZAP API unreachable at http://zap:8080"** → ZAP hasn't finished starting. Wait 30s and retry.
- **"target http://host.docker.internal:3000 did not respond"** → Juice Shop isn't ready yet. Check: `docker compose logs juice-shop`
- **"nuclei not installed"** → Backend image wasn't rebuilt. Run: `docker compose build backend`

The preflight error is visible in the dashboard's progress page as a red error banner.

Check scanner logs:
```bash
docker compose logs backend -f   # backend + scanner output
docker compose logs zap -f       # ZAP daemon logs
```

## 3. Passive scan on public instance

1. Go back to http://localhost:5173
2. Enter `https://juice-shop.herokuapp.com`
3. The badge turns **amber**: "פסיבי בלבד — היעד אינו מורשה לסריקה פעילה"
4. A banner explains that only non-intrusive checks run
5. Click **סרוק** — scan completes quickly (headers + TLS only)
6. Results show header-level findings

## 4. View the diff (What Changed)

1. Run the same target a second time (e.g. `http://localhost:3000` again)
2. Open the results, click the **"מה השתנה"** (What Changed) tab
3. Shows: new findings (+), resolved findings (-), unchanged count

## 5. Run history & trends

Navigate to **היסטוריה** (History) to see all past scans.
Each target shows a sparkline of total findings over time — regressions are visible
as an upward trend.

## Container networking (A3)

When you type `http://localhost:3000` in the dashboard, the backend passes this URL
to `run-all.sh`. Inside the container, `localhost` would point at the container itself.
The orchestrator automatically translates `localhost`/`127.0.0.1` → `host.docker.internal`
for ALL tool invocations (curl, ZAP API, nuclei, nikto). The scope check happens BEFORE
this translation, against the original URL and SCOPE.md allowlist.

Both the `backend` and `zap` services have `extra_hosts: ["host.docker.internal:host-gateway"]`
in docker-compose.yml, so `host.docker.internal` resolves to the Docker host machine, where
juice-shop's port 3000 is published.

## Architecture: ZAP as a sibling service (A1)

ZAP runs as its own container in daemon mode, NOT via docker.sock from the backend.
The backend drives ZAP's REST API: spider → active scan → export report.
Nuclei, nikto, and testssl.sh are installed directly in the backend container.

This avoids the container-escape risk of mounting docker.sock into the backend.

## Auth (production)

The dev compose sets `MASREK_AUTH_DISABLED=1`. For production:

1. Remove `MASREK_AUTH_DISABLED=1` from docker-compose.yml
2. Set `MASREK_API_KEY=<your-secret>` in the backend environment
3. In the dashboard, go to **הגדרות** (Settings) and enter the same key
4. All requests will include `Authorization: Bearer <key>`

## Stopping

```bash
docker compose down
```
