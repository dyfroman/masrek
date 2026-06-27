#!/usr/bin/env bash
# run-sast.sh — SAST/SCA orchestrator for source code analysis.
#
# Security invariants:
#   - Source directory is read-only (mounted :ro) — never writes to it.
#   - Never executes any file from the source (no npm install, no build scripts).
#   - Tools run in analysis-only mode (lockfile scanning, static analysis).
#   - Each tool is time-boxed per max_scan_minutes from SCOPE.md.
#   - Output goes to results/<source_name>/<timestamp>/sast/.
#
# Usage:
#   bash run-sast.sh --source /app/source \
#                    --checks A03,A05 \
#                    --results-dir /app/results/source-name/20260628T120000Z/sast \
#                    --max-minutes 30

set -euo pipefail

# ── Parse arguments ──────────────────────────────────────────────────────────

SOURCE_DIR=""
CHECKS=""
RESULTS_DIR=""
MAX_MINUTES=30

while [[ $# -gt 0 ]]; do
    case "$1" in
        --source)      SOURCE_DIR="$2";   shift 2 ;;
        --checks)      CHECKS="$2";       shift 2 ;;
        --results-dir) RESULTS_DIR="$2";  shift 2 ;;
        --max-minutes) MAX_MINUTES="$2";  shift 2 ;;
        *) echo "ERROR: Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$SOURCE_DIR" ]]; then
    echo "ERROR: --source is required" >&2
    exit 1
fi

if [[ -z "$RESULTS_DIR" ]]; then
    echo "ERROR: --results-dir is required" >&2
    exit 1
fi

if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "ERROR: Source directory does not exist: $SOURCE_DIR" >&2
    exit 1
fi

TOOL_TIMEOUT=$((MAX_MINUTES * 60))

# ── Tool dispatch ────────────────────────────────────────────────────────────

needs_sast_tool() {
    local tool="$1"
    # If no checks specified, run all SAST tools
    if [[ -z "$CHECKS" ]]; then
        return 0
    fi
    case "$tool" in
        osv-scanner)
            # A03: Supply Chain
            echo "$CHECKS" | grep -qE '(^|,)A03(,|$)'
            return $?
            ;;
        *)
            return 1
            ;;
    esac
}

# ── Setup ────────────────────────────────────────────────────────────────────

mkdir -p "$RESULTS_DIR"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  MASREK SAST/SCA Scanner                                   ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Source:  $SOURCE_DIR"
echo "║  Checks:  ${CHECKS:-ALL}"
echo "║  Results: $RESULTS_DIR"
echo "║  Timeout: ${MAX_MINUTES}m per tool"
echo "╚══════════════════════════════════════════════════════════════╝"

ERRORS=0

# ── osv-scanner (A03: Supply Chain) ──────────────────────────────────────────

if needs_sast_tool "osv-scanner"; then
    echo ""
    echo "┌── osv-scanner (A03: Supply Chain Failures) ──"
    OSV_OUT="$RESULTS_DIR/osv-scanner.json"

    if command -v osv-scanner &>/dev/null; then
        echo "│  Scanning lockfiles in $SOURCE_DIR ..."
        # --recursive scans all subdirectories for lockfiles
        # --format json for machine-readable output
        # --no-ignore to check vendored deps too
        # Exit code 1 = vulnerabilities found (not an error for us)
        set +e
        timeout "${TOOL_TIMEOUT}s" osv-scanner scan --recursive --format json \
            "$SOURCE_DIR" > "$OSV_OUT" 2>/dev/null
        OSV_EXIT=$?
        set -e

        if [[ $OSV_EXIT -eq 124 ]]; then
            echo "│  WARNING: osv-scanner timed out after ${MAX_MINUTES}m"
            ERRORS=$((ERRORS + 1))
        elif [[ $OSV_EXIT -eq 0 ]]; then
            echo "│  No vulnerabilities found."
        elif [[ $OSV_EXIT -eq 1 ]]; then
            # Exit code 1 = vulnerabilities found
            VULN_COUNT=$(python3 -c "
import json, sys
try:
    data = json.load(open('$OSV_OUT'))
    count = sum(len(p.get('vulnerabilities', [])) for r in data.get('results', []) for p in r.get('packages', []))
    print(count)
except:
    print('?')
" 2>/dev/null || echo "?")
            echo "│  Found $VULN_COUNT vulnerability/ies."
        else
            echo "│  WARNING: osv-scanner exited with code $OSV_EXIT"
            # Still try to parse whatever output exists
        fi

        if [[ -f "$OSV_OUT" ]]; then
            SIZE=$(stat -c%s "$OSV_OUT" 2>/dev/null || echo "0")
            echo "│  Output: $OSV_OUT ($SIZE bytes)"
        fi
    else
        echo "│  WARNING: osv-scanner not installed, skipping."
        ERRORS=$((ERRORS + 1))
    fi
    echo "└──────────────────────────────────────────────"
fi

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "SAST scan complete. Errors: $ERRORS"

if [[ $ERRORS -gt 0 ]]; then
    exit 1
fi
exit 0
