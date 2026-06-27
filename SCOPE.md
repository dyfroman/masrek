# Scope & Authorization — Masrek Security Platform

This file is the **single source of truth** for scan authorization.
The orchestrator (`tools/run-all.sh`) and the backend API both parse the machine-readable
allowlist below. A host that does not appear between the `ALLOWLIST-START` and
`ALLOWLIST-END` markers **may never be actively scanned**, regardless of any other
configuration, CLI flag, or UI input.

## Authorized Targets (Active + Passive scanning allowed)

| Host                    | Owner       | Authorization        | Notes                        |
|-------------------------|-------------|----------------------|------------------------------|
| `http://localhost:3000` | Developer   | Local dev instance   | OWASP Juice Shop (Docker)    |
| `http://127.0.0.1:3000` | Developer  | Local dev instance   | Alias for localhost          |

<!-- ALLOWLIST-START -->
http://localhost:3000
http://127.0.0.1:3000
<!-- ALLOWLIST-END -->

## Authorized Source Paths (SAST/SCA scanning allowed)

| Path           | Owner     | Authorization      | Notes                          |
|----------------|-----------|--------------------|--------------------------------|
| `/app/source`  | Developer | Local mount (:ro)  | Mounted source code for SAST   |

<!-- SOURCE-ALLOWLIST-START -->
/app/source
<!-- SOURCE-ALLOWLIST-END -->

## Out of Scope (Forbidden for active scanning)

The following are **never** authorized for active scanning:

- **Any host not listed between the ALLOWLIST markers above.**
- **Production systems** without a written maintenance window and explicit authorization.
- **Shared public instances**, including but not limited to:
  - `https://juice-shop.herokuapp.com` — shared demo; **passive-only**.
  - `https://juice-shop.onrender.com`
  - Any other public OWASP Juice Shop deployment you do not own.
- **Third-party infrastructure** (cloud consoles, SaaS dashboards, partner APIs).

> **Legal reminder:** Actively scanning infrastructure you do not own or lack written
> authorization for may violate computer-fraud laws (CFAA, CMA, or local equivalents).
> Passive checks (fetching HTTP headers, reading robots.txt, checking TLS configuration)
> are equivalent to normal browser traffic and are permitted against any reachable host.

## Safety Parameters

These values are parsed by the orchestrator and the backend to enforce safe defaults.

```yaml
rate_limit_rps: 10
max_scan_minutes: 30
destructive_tests: false
auth_brute_force: false
fail_gate_on: high
```

### Parameter definitions

| Parameter           | Type    | Description                                                        |
|---------------------|---------|--------------------------------------------------------------------|
| `rate_limit_rps`    | int     | Max requests-per-second for any active scanner (nuclei `-rl`, etc) |
| `max_scan_minutes`  | int     | Hard timeout for any single scanner invocation                     |
| `destructive_tests` | bool    | Allow data-modifying payloads (DELETE, DROP, etc). Always `false`. |
| `auth_brute_force`  | bool    | Allow credential-stuffing / brute-force modules. Always `false`.   |
| `fail_gate_on`      | string  | Minimum verified severity that fails the CI gate (`critical`, `high`, `medium`, `low`) |
