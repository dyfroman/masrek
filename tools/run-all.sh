#!/usr/bin/env bash
# Masrek — Orchestrator
# Runs passive and/or active security scans against a target URL.
# Scope enforcement: only hosts listed in SCOPE.md may be actively scanned.
# A1: Accepts --pinned-ip to use a pre-validated IP address for connections.
# A2: Drives sibling ZAP service via REST API (no docker.sock).
# A3: Translates localhost/127.0.0.1 → host.docker.internal for all tools.
# A4: Preflight checks before active stage — fails fast with clear errors.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${MASREK_PROJECT_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
SCOPE_FILE="${SCOPE_FILE:-$PROJECT_ROOT/SCOPE.md}"
RESULTS_BASE="${RESULTS_DIR:-$PROJECT_ROOT/results}"

# ── Defaults ──────────────────────────────────────────────────────────────────
TARGET=""
MODE="auto"
DIFF_MODE=false
PINNED_IP=""
SCAN_TYPE=""  # "full" or "baseline" for ZAP
RATE_LIMIT_RPS=10
MAX_SCAN_MINUTES=30
CHECKS=""  # comma-separated check IDs (A01,A02,...); empty = all

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────

log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  -t, --target URL       Target URL to scan (required)
  -m, --mode MODE        Scan mode: passive | active | auto (default: auto)
      --checks IDS       Comma-separated OWASP check IDs (A01,A02,...; default: all)
      --diff             Compare results to previous run for this host
      --pinned-ip IP     Use this pre-validated IP for connections (set by backend)
      --scan-type TYPE   ZAP scan type: full | baseline (default: full)
  -h, --help             Show this help

Modes:
  passive   Only non-intrusive checks (headers, TLS, robots.txt). Safe for any host.
  active    Full scanning (ZAP, nuclei, nikto). Requires host in SCOPE.md allowlist.
  auto      Passive if out-of-scope, active if in-scope (default).

Examples:
  $(basename "$0") -t http://localhost:3000                  # auto → active (in scope)
  $(basename "$0") -t https://juice-shop.herokuapp.com       # auto → passive (out of scope)
  $(basename "$0") -t http://localhost:3000 --scan-type baseline  # fast ZAP scan
EOF
    exit 0
}

# ── Parse CLI arguments ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--target)    TARGET="$2";    shift 2 ;;
        -m|--mode)      MODE="$2";      shift 2 ;;
        --diff)         DIFF_MODE=true; shift ;;
        --pinned-ip)    PINNED_IP="$2"; shift 2 ;;
        --checks)       CHECKS="$2";    shift 2 ;;
        --scan-type)    SCAN_TYPE="$2"; shift 2 ;;
        -h|--help)      usage ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    log_error "Target URL is required. Use -t/--target."
    exit 1
fi

# Default scan type
[[ -z "$SCAN_TYPE" ]] && SCAN_TYPE="full"

# ── Parse SCOPE.md ───────────────────────────────────────────────────────────

parse_allowlist() {
    if [[ ! -f "$SCOPE_FILE" ]]; then
        log_error "SCOPE.md not found at $SCOPE_FILE"
        exit 1
    fi
    sed -n '/<!-- ALLOWLIST-START -->/,/<!-- ALLOWLIST-END -->/p' "$SCOPE_FILE" \
        | grep -v '<!--' \
        | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
        | grep -v '^$'
}

parse_safety_param() {
    local param="$1"
    grep "^${param}:" "$SCOPE_FILE" | head -1 | awk '{print $2}'
}

# ── Extract host from URL ───────────────────────────────────────────────────

extract_host_port() {
    local url="$1"
    local hostport="${url#*://}"
    hostport="${hostport%%/*}"
    hostport="${hostport%%\?*}"
    echo "$hostport"
}

extract_hostname() {
    local hostport="$1"
    echo "$hostport" | sed 's/:.*//'
}

extract_port() {
    local hostport="$1"
    if echo "$hostport" | grep -q ':'; then
        echo "$hostport" | sed 's/.*://'
    else
        echo ""
    fi
}

safe_dirname() {
    local name="$1"
    echo "$name" | sed 's/[^a-zA-Z0-9._-]/_/g' | sed 's/^\.*//'
}

# ── A2: SSRF guard (defense in depth) ────────────────────────────────────────

is_private_ip() {
    local ip="$1"
    case "$ip" in
        10.*)           return 0 ;;
        172.1[6-9].*)   return 0 ;;
        172.2[0-9].*)   return 0 ;;
        172.3[0-1].*)   return 0 ;;
        192.168.*)      return 0 ;;
        127.*)          return 0 ;;
        169.254.*)      return 0 ;;
        0.0.0.0)        return 0 ;;
        ::1)            return 0 ;;
        ::)             return 0 ;;
    esac
    return 1
}

# ── Scope check ──────────────────────────────────────────────────────────────

ALLOWLIST=$(parse_allowlist)
TARGET_HOSTPORT=$(extract_host_port "$TARGET")
TARGET_HOSTNAME=$(extract_hostname "$TARGET_HOSTPORT")
TARGET_PORT=$(extract_port "$TARGET_HOSTPORT")
IN_SCOPE=false

while IFS= read -r allowed_url; do
    allowed_hostport=$(extract_host_port "$allowed_url")
    if [[ "$TARGET_HOSTPORT" == "$allowed_hostport" ]]; then
        IN_SCOPE=true
        break
    fi
done <<< "$ALLOWLIST"

# A2: SSRF guard — check resolved IP unless allowlisted or pinned-ip was provided
if ! $IN_SCOPE && [[ -z "$PINNED_IP" ]]; then
    RESOLVED_IP=""
    if command -v getent &>/dev/null; then
        RESOLVED_IP=$(getent hosts "$TARGET_HOSTNAME" 2>/dev/null | awk '{print $1}' | head -1)
    elif command -v dig &>/dev/null; then
        RESOLVED_IP=$(dig +short "$TARGET_HOSTNAME" 2>/dev/null | head -1)
    elif command -v nslookup &>/dev/null; then
        RESOLVED_IP=$(nslookup "$TARGET_HOSTNAME" 2>/dev/null | awk '/^Address: / {print $2}' | head -1)
    fi

    if [[ -n "$RESOLVED_IP" ]] && is_private_ip "$RESOLVED_IP"; then
        log_error "REFUSED: Host '$TARGET_HOSTNAME' resolves to private/reserved IP $RESOLVED_IP."
        log_error "Scanning internal addresses is blocked unless the host is in the SCOPE.md allowlist."
        exit 1
    fi
fi

# Read safety params
val=$(parse_safety_param "rate_limit_rps")
[[ -n "$val" ]] && RATE_LIMIT_RPS="$val"
val=$(parse_safety_param "max_scan_minutes")
[[ -n "$val" ]] && MAX_SCAN_MINUTES="$val"

TIMEOUT_SECONDS=$((MAX_SCAN_MINUTES * 60))

# ── Mode decision ────────────────────────────────────────────────────────────

if [[ "$MODE" == "auto" ]]; then
    if $IN_SCOPE; then
        MODE="active"
    else
        MODE="passive"
    fi
fi

if [[ "$MODE" == "active" ]] && ! $IN_SCOPE; then
    log_error "REFUSED: Active scanning of '$TARGET' is not authorized."
    log_error "Host '$TARGET_HOSTPORT' is NOT in the SCOPE.md allowlist."
    log_error "Only hosts between <!-- ALLOWLIST-START --> and <!-- ALLOWLIST-END --> may be actively scanned."
    log_error "To authorize this host, add it to SCOPE.md."
    exit 1
fi

# ── A3: Container→target translation ────────────────────────────────────────
# Inside Docker containers, localhost/127.0.0.1 refers to the container itself.
# When running in compose, sibling services are reachable by service name on
# their internal port. We translate localhost:PORT → juice-shop:PORT when the
# port matches the juice-shop service (3000), falling back to
# host.docker.internal for other ports. The SCOPE.md allowlist is still keyed
# on what the user typed (localhost:3000); translation is scan-time only.

SCAN_TARGET="$TARGET"
IS_LOCALHOST=false

if echo "$TARGET_HOSTNAME" | grep -qE '^(localhost|127\.0\.0\.1)$'; then
    IS_LOCALHOST=true
    # Prefer compose service name (reliable), fall back to host.docker.internal
    if [[ "$TARGET_PORT" == "3000" ]]; then
        SCAN_TARGET=$(echo "$TARGET" | sed "s/$TARGET_HOSTNAME/juice-shop/")
    else
        SCAN_TARGET=$(echo "$TARGET" | sed "s/$TARGET_HOSTNAME/host.docker.internal/")
    fi
    log_info "A3: target translated for container networking: $TARGET → $SCAN_TARGET"
fi

# ── Build curl --resolve flag for IP pinning (A1) ────────────────────────────
# When target is localhost (already translated), skip pinned IP — the translation
# handles reachability. For external targets, pin to the validated IP.

CURL_RESOLVE_FLAG=""
TESTSSL_IP_FLAG=""
if [[ -n "$PINNED_IP" ]] && ! $IS_LOCALHOST; then
    local_port="$TARGET_PORT"
    if [[ -z "$local_port" ]]; then
        if [[ "$TARGET" == https://* ]]; then
            local_port="443"
        else
            local_port="80"
        fi
    fi
    CURL_RESOLVE_FLAG="--resolve ${TARGET_HOSTNAME}:${local_port}:${PINNED_IP}"
    TESTSSL_IP_FLAG="--ip ${PINNED_IP}"
    log_info "IP pinning: ${TARGET_HOSTNAME}:${local_port} -> ${PINNED_IP}"
fi

# ── Prepare output directory ────────────────────────────────────────────────

SAFE_HOST=$(safe_dirname "$TARGET_HOSTPORT")
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_DIR="$RESULTS_BASE/$SAFE_HOST/$TIMESTAMP"
PASSIVE_DIR="$RUN_DIR/passive"
ACTIVE_DIR="$RUN_DIR/active"

mkdir -p "$PASSIVE_DIR"
[[ "$MODE" == "active" ]] && mkdir -p "$ACTIVE_DIR"

# Update latest symlink
LATEST_LINK="$RESULTS_BASE/$SAFE_HOST/latest"
ln -sfn "$TIMESTAMP" "$LATEST_LINK" 2>/dev/null || true

log_info "═══════════════════════════════════════════════════════════════"
log_info " Masrek Security Scanner"
log_info "═══════════════════════════════════════════════════════════════"
log_info " Target:       $TARGET"
log_info " Scan target:  $SCAN_TARGET"
log_info " Host:         $TARGET_HOSTPORT"
log_info " In scope:     $IN_SCOPE"
log_info " Mode:         $MODE"
log_info " Scan type:    $SCAN_TYPE"
log_info " Pinned IP:    ${PINNED_IP:-none}"
log_info " Rate limit:   ${RATE_LIMIT_RPS} rps"
log_info " Timeout:      ${MAX_SCAN_MINUTES} min per tool"
log_info " Output:       $RUN_DIR"
log_info "═══════════════════════════════════════════════════════════════"

# ── Utility: run a tool if it exists, with a timeout ────────────────────────

run_tool() {
    local name="$1"
    shift
    local cmd="$1"
    shift

    if ! command -v "$cmd" &>/dev/null; then
        log_warn "$name: '$cmd' not found, skipping."
        return 0
    fi

    log_info "$name: starting..."
    if timeout "$TIMEOUT_SECONDS" "$@" 2>&1; then
        log_ok "$name: complete."
    else
        local rc=$?
        if [[ $rc -eq 124 ]]; then
            log_warn "$name: timed out after ${MAX_SCAN_MINUTES} minutes."
        else
            log_warn "$name: exited with code $rc (continuing)."
        fi
    fi
}

# ── Check→tool dependency: skip tools no selected check needs ──────────────
# If CHECKS is empty, all tools run (backward compatible).
needs_tool() {
    local tool="$1"
    if [[ -z "$CHECKS" ]]; then return 0; fi
    case "$tool" in
        zap)    echo "$CHECKS" | grep -qE 'A01|A02|A04|A05|A07|A10' ;;
        nuclei) echo "$CHECKS" | grep -qE 'A01|A05|A07|A10' ;;
        nikto)  echo "$CHECKS" | grep -q 'A02' ;;
    esac
}

# ── Defensive ZAP export: capture whatever ZAP has on any exit ───────────────
ZAP_EXPORTED=false
export_zap_results() {
    if $ZAP_EXPORTED; then return; fi
    if [[ -z "${ZAP_API_URL:-}" ]] || [[ -z "${ACTIVE_DIR:-}" ]]; then return; fi
    if [[ "$MODE" != "active" ]]; then return; fi
    if ! needs_tool "zap"; then return; fi
    ZAP_EXPORTED=true
    log_info "ZAP: defensive export — capturing current results..."
    # Stop any running scans so ZAP finalizes alerts
    curl -sf --max-time 10 "${ZAP_API_URL}/JSON/ascan/action/stopAllScans/?apikey=${ZAP_API_KEY:-}" >/dev/null 2>&1 || true
    curl -sf --max-time 10 "${ZAP_API_URL}/JSON/spider/action/stopAllScans/?apikey=${ZAP_API_KEY:-}" >/dev/null 2>&1 || true
    sleep 1
    mkdir -p "$ACTIVE_DIR"
    if curl -sf --max-time 30 \
        "${ZAP_API_URL}/OTHER/core/other/jsonreport/?apikey=${ZAP_API_KEY:-}" \
        -o "$ACTIVE_DIR/zap-report.json" 2>/dev/null; then
        log_ok "ZAP: defensive export complete."
    else
        curl -sf --max-time 30 \
            "${ZAP_API_URL}/JSON/core/view/alerts/?apikey=${ZAP_API_KEY:-}&baseurl=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${SCAN_TARGET:-}', safe=''))" 2>/dev/null)&start=0&count=1000" \
            -o "$ACTIVE_DIR/zap-report.json" 2>/dev/null || true
    fi
}
trap export_zap_results EXIT TERM INT

# ══════════════════════════════════════════════════════════════════════════════
# A4: PREFLIGHT CHECK (active mode only)
# Verifies all tools and the target BEFORE starting the scan. If anything is
# missing or unreachable, the run fails immediately with a clear error.
# ══════════════════════════════════════════════════════════════════════════════

if [[ "$MODE" == "active" ]]; then
    log_info "──── Preflight Check ─────────────────────────────────────────"
    PREFLIGHT_ERRORS=()

    # Check ZAP API is reachable (only if a selected check needs it)
    if needs_tool "zap"; then
        if [[ -n "${ZAP_API_URL:-}" ]]; then
            log_info "Preflight: checking ZAP API at ${ZAP_API_URL}..."
            if curl -sf --max-time 10 "${ZAP_API_URL}/JSON/core/view/version/?apikey=${ZAP_API_KEY:-}" >/dev/null 2>&1; then
                log_ok "Preflight: ZAP API reachable."
            else
                PREFLIGHT_ERRORS+=("ZAP API unreachable at ${ZAP_API_URL}")
            fi
        else
            PREFLIGHT_ERRORS+=("ZAP_API_URL not set — cannot drive ZAP scanner")
        fi
    fi

    # Check nuclei is installed (only if needed)
    if needs_tool "nuclei"; then
        if command -v nuclei &>/dev/null; then
            log_ok "Preflight: nuclei found."
        else
            PREFLIGHT_ERRORS+=("nuclei not installed")
        fi
    fi

    # Check nikto is installed (only if needed)
    if needs_tool "nikto"; then
        if command -v nikto &>/dev/null; then
            log_ok "Preflight: nikto found."
        else
            PREFLIGHT_ERRORS+=("nikto not found on PATH")
        fi
    fi

    # Check target responds (use translated SCAN_TARGET)
    log_info "Preflight: checking target responds at ${SCAN_TARGET}..."
    if curl -sf --max-time 15 -o /dev/null "$SCAN_TARGET" 2>/dev/null; then
        log_ok "Preflight: target responds."
    else
        PREFLIGHT_ERRORS+=("target ${SCAN_TARGET} did not respond (original: ${TARGET})")
    fi

    # Fail fast if any check failed
    if [[ ${#PREFLIGHT_ERRORS[@]} -gt 0 ]]; then
        PREFLIGHT_MSG=""
        for err in "${PREFLIGHT_ERRORS[@]}"; do
            PREFLIGHT_MSG="${PREFLIGHT_MSG}${err}; "
            log_error "PREFLIGHT FAILED: $err"
        done
        # Write to stderr so scanner.py captures it as error_message
        echo "PREFLIGHT FAILED: ${PREFLIGHT_MSG}" >&2
        exit 1
    fi

    log_ok "Preflight: all checks passed."
fi

# ══════════════════════════════════════════════════════════════════════════════
# PASSIVE STAGE — safe for any host
# Uses SCAN_TARGET (translated) for tool invocations.
# ══════════════════════════════════════════════════════════════════════════════

log_info "──── Passive Stage ────────────────────────────────────────────"

# 1. HTTP headers (A1: use --resolve for IP pinning)
log_info "Fetching HTTP headers..."
HEADERS_FILE="$PASSIVE_DIR/headers.txt"
# shellcheck disable=SC2086
curl -sS -D "$HEADERS_FILE" -o /dev/null --max-time 30 $CURL_RESOLVE_FLAG "$SCAN_TARGET" 2>/dev/null || true

# 2. Security headers analysis → summary.json
log_info "Analyzing security headers..."
SUMMARY_FILE="$PASSIVE_DIR/summary.json"

check_header() {
    local header="$1"
    if grep -qi "^${header}:" "$HEADERS_FILE" 2>/dev/null; then
        local value
        value=$(grep -i "^${header}:" "$HEADERS_FILE" | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
        echo "\"present\": true, \"value\": \"$value\""
    else
        echo "\"present\": false, \"value\": null"
    fi
}

server_header() {
    local header="$1"
    if grep -qi "^${header}:" "$HEADERS_FILE" 2>/dev/null; then
        local value
        value=$(grep -i "^${header}:" "$HEADERS_FILE" | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
        echo "\"$value\""
    else
        echo "null"
    fi
}

cat > "$SUMMARY_FILE" <<ENDJSON
{
  "target": "$TARGET",
  "host": "$TARGET_HOSTPORT",
  "timestamp": "$TIMESTAMP",
  "mode": "$MODE",
  "in_scope": $IN_SCOPE,
  "security_headers": {
    "content-security-policy":   { $(check_header "Content-Security-Policy") },
    "strict-transport-security": { $(check_header "Strict-Transport-Security") },
    "x-frame-options":           { $(check_header "X-Frame-Options") },
    "x-content-type-options":    { $(check_header "X-Content-Type-Options") },
    "referrer-policy":           { $(check_header "Referrer-Policy") },
    "permissions-policy":        { $(check_header "Permissions-Policy") }
  },
  "server_info": {
    "server": $(server_header "Server"),
    "x-powered-by": $(server_header "X-Powered-By")
  }
}
ENDJSON

log_ok "Security headers summary written to $SUMMARY_FILE"

# 3. robots.txt (uses translated target)
log_info "Fetching robots.txt..."
# shellcheck disable=SC2086
curl -sS --max-time 15 $CURL_RESOLVE_FLAG "$SCAN_TARGET/robots.txt" -o "$PASSIVE_DIR/robots.txt" 2>/dev/null || true

# 4. sitemap.xml (uses translated target)
log_info "Fetching sitemap.xml..."
# shellcheck disable=SC2086
curl -sS --max-time 15 $CURL_RESOLVE_FLAG "$SCAN_TARGET/sitemap.xml" -o "$PASSIVE_DIR/sitemap.xml" 2>/dev/null || true

# 5. TLS check (only for https)
if [[ "$SCAN_TARGET" == https://* ]]; then
    if command -v testssl.sh &>/dev/null; then
        log_info "testssl.sh: starting..."
        # shellcheck disable=SC2086
        timeout "$TIMEOUT_SECONDS" testssl.sh \
            --jsonfile "$PASSIVE_DIR/testssl.json" \
            --quiet \
            $TESTSSL_IP_FLAG \
            "$SCAN_TARGET" 2>&1 || {
                rc=$?
                [[ $rc -eq 124 ]] && log_warn "testssl.sh: timed out."
            }
        log_ok "testssl.sh: complete."
    else
        log_warn "testssl.sh: not found, skipping."
    fi
else
    log_info "Skipping TLS check (target is not HTTPS)."
fi

log_ok "Passive stage complete."

# ══════════════════════════════════════════════════════════════════════════════
# ACTIVE STAGE — only for in-scope hosts
# A1: NO docker.sock. ZAP is driven via its REST API (sibling service).
# A2: Nuclei and nikto run locally inside the backend container.
# A3: All tools use SCAN_TARGET (translated for container networking).
# ══════════════════════════════════════════════════════════════════════════════

if [[ "$MODE" == "active" ]]; then
    log_info "──── Active Stage ────────────────────────────────────────────"
    [[ -n "$CHECKS" ]] && log_info " Selected checks: $CHECKS"

    # Double-check scope (defense in depth)
    if ! $IN_SCOPE; then
        log_error "CRITICAL: Active stage reached for out-of-scope host. Aborting."
        exit 1
    fi

    # URL-encode helper (uses python3 which is in the container)
    url_encode() {
        python3 -c "import urllib.parse; print(urllib.parse.quote('$1', safe=''))"
    }

    ENCODED_TARGET=$(url_encode "$SCAN_TARGET")

    # ── ZAP via REST API (sibling service, no docker.sock) ───────────────
    if ! needs_tool "zap"; then
        log_info "ZAP: skipped (no selected check needs it)."
    elif [[ -n "${ZAP_API_URL:-}" ]]; then
        ZAP_KEY="${ZAP_API_KEY:-}"

        # Spider the target
        log_info "ZAP: starting spider on ${SCAN_TARGET}..."
        SPIDER_RESP=$(curl -sf --max-time 30 \
            "${ZAP_API_URL}/JSON/spider/action/scan/?apikey=${ZAP_KEY}&url=${ENCODED_TARGET}&maxChildren=50" 2>/dev/null || echo '{}')
        SPIDER_ID=$(echo "$SPIDER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scan',''))" 2>/dev/null || echo "")

        if [[ -n "$SPIDER_ID" && "$SPIDER_ID" != "None" ]]; then
            log_info "ZAP: spider started (id=$SPIDER_ID), polling..."
            SPIDER_ELAPSED=0
            while [[ $SPIDER_ELAPSED -lt $TIMEOUT_SECONDS ]]; do
                SPIDER_STATUS=$(curl -sf --max-time 10 \
                    "${ZAP_API_URL}/JSON/spider/view/status/?apikey=${ZAP_KEY}&scanId=${SPIDER_ID}" 2>/dev/null \
                    | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','0'))" 2>/dev/null || echo "0")
                if [[ "$SPIDER_STATUS" == "100" ]]; then
                    break
                fi
                log_info "ZAP: spider progress ${SPIDER_STATUS}%..."
                sleep 5
                SPIDER_ELAPSED=$((SPIDER_ELAPSED + 5))
            done
            log_ok "ZAP: spider complete."
        else
            log_warn "ZAP: spider did not start (response: $SPIDER_RESP)"
        fi

        # AJAX spider for SPA coverage (discovers JS-rendered endpoints)
        if [[ "$SCAN_TYPE" != "baseline" ]]; then
            log_info "ZAP: starting AJAX spider on ${SCAN_TARGET}..."
            AJAX_SPIDER_RESP=$(curl -sf --max-time 30 \
                "${ZAP_API_URL}/JSON/ajaxSpider/action/scan/?apikey=${ZAP_KEY}&url=${ENCODED_TARGET}" 2>/dev/null || echo '{}')
            AJAX_STARTED=$(echo "$AJAX_SPIDER_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('Result',''))" 2>/dev/null || echo "")

            if [[ "$AJAX_STARTED" == "OK" ]]; then
                log_info "ZAP: AJAX spider running, polling (max 120s)..."
                AJAX_ELAPSED=0
                AJAX_MAX=120
                while [[ $AJAX_ELAPSED -lt $AJAX_MAX ]]; do
                    AJAX_STATUS=$(curl -sf --max-time 10 \
                        "${ZAP_API_URL}/JSON/ajaxSpider/view/status/?apikey=${ZAP_KEY}" 2>/dev/null \
                        | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','stopped'))" 2>/dev/null || echo "stopped")
                    if [[ "$AJAX_STATUS" != "running" ]]; then
                        break
                    fi
                    log_info "ZAP: AJAX spider still running..."
                    sleep 10
                    AJAX_ELAPSED=$((AJAX_ELAPSED + 10))
                done
                if [[ $AJAX_ELAPSED -ge $AJAX_MAX ]]; then
                    curl -sf --max-time 10 "${ZAP_API_URL}/JSON/ajaxSpider/action/stop/?apikey=${ZAP_KEY}" >/dev/null 2>&1 || true
                    log_warn "ZAP: AJAX spider stopped at ${AJAX_MAX}s cap (partial discovery preserved)."
                else
                    log_ok "ZAP: AJAX spider complete."
                fi
            else
                log_warn "ZAP: AJAX spider not available or failed to start (continuing without it)."
            fi
        fi

        # Active scan (skip for baseline)
        if [[ "$SCAN_TYPE" != "baseline" ]]; then
            log_info "ZAP: starting active scan on ${SCAN_TARGET}..."
            ASCAN_RESP=$(curl -sf --max-time 30 \
                "${ZAP_API_URL}/JSON/ascan/action/scan/?apikey=${ZAP_KEY}&url=${ENCODED_TARGET}&recurse=true" 2>/dev/null || echo '{}')
            ASCAN_ID=$(echo "$ASCAN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scan',''))" 2>/dev/null || echo "")

            if [[ -n "$ASCAN_ID" && "$ASCAN_ID" != "None" ]]; then
                log_info "ZAP: active scan started (id=$ASCAN_ID), polling..."
                ASCAN_ELAPSED=0
                while [[ $ASCAN_ELAPSED -lt $TIMEOUT_SECONDS ]]; do
                    ASCAN_STATUS=$(curl -sf --max-time 10 \
                        "${ZAP_API_URL}/JSON/ascan/view/status/?apikey=${ZAP_KEY}&scanId=${ASCAN_ID}" 2>/dev/null \
                        | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','0'))" 2>/dev/null || echo "0")
                    if [[ "$ASCAN_STATUS" == "100" ]]; then
                        break
                    fi
                    log_info "ZAP: active scan progress ${ASCAN_STATUS}%..."
                    sleep 10
                    ASCAN_ELAPSED=$((ASCAN_ELAPSED + 10))
                done
                log_ok "ZAP: active scan complete."
            else
                log_warn "ZAP: active scan did not start (response: $ASCAN_RESP)"
            fi
        else
            log_info "ZAP: baseline mode — skipping active scan."
        fi

        # Export the traditional JSON report (same format as file-based reports)
        log_info "ZAP: exporting JSON report..."
        ZAP_EXPORTED=true
        if curl -sf --max-time 30 \
            "${ZAP_API_URL}/OTHER/core/other/jsonreport/?apikey=${ZAP_KEY}" \
            -o "$ACTIVE_DIR/zap-report.json" 2>/dev/null; then
            log_ok "ZAP: traditional report exported."
        else
            # Fallback: export alerts in API format (parser handles both)
            log_warn "ZAP: jsonreport unavailable, falling back to alerts API..."
            curl -sf --max-time 30 \
                "${ZAP_API_URL}/JSON/core/view/alerts/?apikey=${ZAP_KEY}&baseurl=${ENCODED_TARGET}&start=0&count=1000" \
                -o "$ACTIVE_DIR/zap-report.json" 2>/dev/null || true
        fi
        log_ok "ZAP: report exported."
    else
        log_warn "ZAP: ZAP_API_URL not set, skipping ZAP scan."
    fi

    # ── Nuclei (runs locally in the backend container) ───────────────────
    if ! needs_tool "nuclei"; then
        log_info "Nuclei: skipped (no selected check needs it)."
    elif command -v nuclei &>/dev/null; then
        # Build nuclei flags based on scan type and selected checks
        NUCLEI_EXTRA_FLAGS=()

        if [[ "$SCAN_TYPE" == "baseline" ]]; then
            NUCLEI_TIMEOUT=180  # 3 minutes hard cap for baseline
            NUCLEI_EXTRA_FLAGS+=(-severity medium,high,critical)

            # Derive nuclei tags from selected OWASP checks
            NUCLEI_TAGS=""
            if [[ -n "$CHECKS" ]]; then
                NUCLEI_TAG_LIST=()
                echo "$CHECKS" | grep -q 'A01' && NUCLEI_TAG_LIST+=(ssrf idor traversal exposure lfi)
                echo "$CHECKS" | grep -q 'A02' && NUCLEI_TAG_LIST+=(misconfig config exposure)
                echo "$CHECKS" | grep -q 'A05' && NUCLEI_TAG_LIST+=(xss sqli injection rce ssti xxe)
                echo "$CHECKS" | grep -q 'A07' && NUCLEI_TAG_LIST+=(default-login auth login brute-force)
                echo "$CHECKS" | grep -q 'A10' && NUCLEI_TAG_LIST+=(error)
                if [[ ${#NUCLEI_TAG_LIST[@]} -gt 0 ]]; then
                    NUCLEI_TAGS=$(IFS=,; echo "${NUCLEI_TAG_LIST[*]}")
                fi
            fi

            if [[ -n "$NUCLEI_TAGS" ]]; then
                NUCLEI_EXTRA_FLAGS+=(-tags "$NUCLEI_TAGS")
                log_info "Nuclei: baseline mode — severity≥medium, tags=${NUCLEI_TAGS}"
            else
                NUCLEI_EXTRA_FLAGS+=(-tags "misconfig,exposure,xss,sqli,injection,auth,default-login,ssrf,idor")
                log_info "Nuclei: baseline mode — severity≥medium, default tag set"
            fi
        else
            NUCLEI_TIMEOUT="$TIMEOUT_SECONDS"
            log_info "Nuclei: full mode — all templates"
        fi

        log_info "Nuclei: starting scan (rate limit: ${RATE_LIMIT_RPS} rps, timeout: ${NUCLEI_TIMEOUT}s)..."
        timeout "$NUCLEI_TIMEOUT" nuclei \
            -u "$SCAN_TARGET" \
            -rl "$RATE_LIMIT_RPS" \
            -jsonl \
            -o "$ACTIVE_DIR/nuclei.jsonl" \
            -silent \
            "${NUCLEI_EXTRA_FLAGS[@]}" \
            2>&1 | tee "$ACTIVE_DIR/nuclei.log" || {
                rc=$?
                [[ $rc -eq 124 ]] && log_warn "Nuclei: timed out after $((NUCLEI_TIMEOUT / 60))m (partial results preserved)."
            }
        log_ok "Nuclei: complete."
    else
        log_warn "Nuclei: not found, skipping."
    fi

    # ── Nikto (runs locally in the backend container) ────────────────────
    if ! needs_tool "nikto"; then
        log_info "Nikto: skipped (no selected check needs it)."
    else
        run_tool "Nikto" "nikto" \
            nikto -h "$SCAN_TARGET" -output "$ACTIVE_DIR/nikto.json" -Format json -maxtime "${MAX_SCAN_MINUTES}m"
    fi

    log_ok "Active stage complete."
fi

# ══════════════════════════════════════════════════════════════════════════════
# DIFF MODE — compare to previous run
# ══════════════════════════════════════════════════════════════════════════════

if $DIFF_MODE; then
    log_info "──── Diff Mode ───────────────────────────────────────────────"

    PREV_DIR=$(ls -1d "$RESULTS_BASE/$SAFE_HOST"/20* 2>/dev/null | sort | tail -2 | head -1)

    if [[ -z "$PREV_DIR" ]] || [[ "$PREV_DIR" == "$RUN_DIR" ]]; then
        log_warn "No previous run found for $SAFE_HOST. Nothing to diff."
    else
        PREV_SUMMARY="$PREV_DIR/passive/summary.json"
        CURR_SUMMARY="$PASSIVE_DIR/summary.json"

        if [[ -f "$PREV_SUMMARY" ]] && [[ -f "$CURR_SUMMARY" ]]; then
            log_info "Comparing: $(basename "$PREV_DIR") → $TIMESTAMP"
            DIFF_FILE="$RUN_DIR/diff.txt"

            echo "=== Posture Change Report ===" > "$DIFF_FILE"
            echo "Previous: $(basename "$PREV_DIR")" >> "$DIFF_FILE"
            echo "Current:  $TIMESTAMP" >> "$DIFF_FILE"
            echo "Target:   $TARGET" >> "$DIFF_FILE"
            echo "" >> "$DIFF_FILE"

            if diff -u "$PREV_SUMMARY" "$CURR_SUMMARY" >> "$DIFF_FILE" 2>&1; then
                echo "No changes detected." >> "$DIFF_FILE"
                log_ok "No posture changes detected."
            else
                log_warn "Posture changes detected! See $DIFF_FILE"
            fi
            cat "$DIFF_FILE"
        else
            log_warn "Previous summary.json not found. Cannot diff."
        fi
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

echo ""
log_info "═══════════════════════════════════════════════════════════════"
log_ok   " Scan complete!"
log_info " Results: $RUN_DIR"
log_info " Mode:    $MODE"
if [[ "$MODE" == "passive" ]] && ! $IN_SCOPE; then
    log_warn " Note: Only passive checks ran. Host is not in SCOPE.md allowlist."
    log_warn " For full active scanning, run a local instance:"
    log_warn "   docker run --rm -d -p 3000:3000 bkimminich/juice-shop"
    log_warn " Then scan: $0 -t http://localhost:3000"
fi
log_info "═══════════════════════════════════════════════════════════════"
