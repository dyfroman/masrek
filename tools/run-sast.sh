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
        trivy)
            # A03: Supply Chain + A08: Integrity
            echo "$CHECKS" | grep -qE '(^|,)(A03|A08)(,|$)'
            return $?
            ;;
        semgrep)
            # A02: Misconfig + A05: Injection + A06: Insecure Design + A07: Auth + A09: Logging
            echo "$CHECKS" | grep -qE '(^|,)(A02|A05|A06|A07|A09)(,|$)'
            return $?
            ;;
        gitleaks)
            # A02: Misconfig (exposed secrets) + A07: Auth (hardcoded credentials)
            echo "$CHECKS" | grep -qE '(^|,)(A02|A07)(,|$)'
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

# ── trivy (A03: Supply Chain + A08: Integrity/IaC) ──────────────────────────

if needs_sast_tool "trivy"; then
    echo ""
    echo "┌── trivy (A03: Supply Chain + A08: Integrity) ──"
    TRIVY_OUT="$RESULTS_DIR/trivy.json"
    TRIVY_SBOM="$RESULTS_DIR/trivy-sbom.cdx.json"

    if command -v trivy &>/dev/null; then
        # Phase 1: vulnerability + misconfig scan (JSON)
        echo "│  Scanning $SOURCE_DIR for vulns + misconfigs ..."
        set +e
        timeout "${TOOL_TIMEOUT}s" trivy fs --format json --scanners vuln,misconfig,secret \
            --skip-java-db-update \
            "$SOURCE_DIR" > "$TRIVY_OUT" 2>/dev/null
        TRIVY_EXIT=$?
        set -e

        if [[ $TRIVY_EXIT -eq 124 ]]; then
            echo "│  WARNING: trivy scan timed out after ${MAX_MINUTES}m"
            ERRORS=$((ERRORS + 1))
        elif [[ $TRIVY_EXIT -eq 0 ]]; then
            VULN_COUNT=$(python3 -c "
import json
try:
    data = json.load(open('$TRIVY_OUT'))
    vulns = sum(len(r.get('Vulnerabilities', [])) for r in data.get('Results', []))
    miscs = sum(len(r.get('Misconfigurations', [])) for r in data.get('Results', []))
    print(f'{vulns} vuln(s), {miscs} misconfig(s)')
except:
    print('?')
" 2>/dev/null || echo "?")
            echo "│  Found $VULN_COUNT."
        else
            echo "│  WARNING: trivy exited with code $TRIVY_EXIT"
        fi

        if [[ -f "$TRIVY_OUT" ]]; then
            SIZE=$(stat -c%s "$TRIVY_OUT" 2>/dev/null || echo "0")
            echo "│  Output: $TRIVY_OUT ($SIZE bytes)"
        fi

        # Phase 2: SBOM generation (CycloneDX)
        echo "│  Generating SBOM (CycloneDX) ..."
        set +e
        timeout "${TOOL_TIMEOUT}s" trivy fs --format cyclonedx \
            --skip-java-db-update \
            "$SOURCE_DIR" > "$TRIVY_SBOM" 2>/dev/null
        SBOM_EXIT=$?
        set -e

        if [[ $SBOM_EXIT -eq 124 ]]; then
            echo "│  WARNING: trivy SBOM generation timed out"
        elif [[ $SBOM_EXIT -eq 0 ]] && [[ -f "$TRIVY_SBOM" ]]; then
            SBOM_SIZE=$(stat -c%s "$TRIVY_SBOM" 2>/dev/null || echo "0")
            echo "│  SBOM: $TRIVY_SBOM ($SBOM_SIZE bytes)"
        else
            echo "│  WARNING: SBOM generation failed (exit $SBOM_EXIT)"
        fi
    else
        echo "│  WARNING: trivy not installed, skipping."
        ERRORS=$((ERRORS + 1))
    fi
    echo "└──────────────────────────────────────────────"
fi

# ── semgrep (A02/A05/A06/A07/A09: source code patterns) ─────────────────────

if needs_sast_tool "semgrep"; then
    echo ""
    echo "┌── semgrep (A02/A05/A06/A07/A09: Code Patterns) ──"
    SEMGREP_OUT="$RESULTS_DIR/semgrep.json"

    if command -v semgrep &>/dev/null; then
        echo "│  Scanning $SOURCE_DIR for code-level vulnerabilities ..."
        # semgrep exit codes: 0=no findings, 1=findings found (not an error for us)
        # --config auto requires metrics; use explicit security rulesets instead
        set +e
        timeout "${TOOL_TIMEOUT}s" semgrep scan \
            --config "p/security-audit" --config "p/bandit" --config "p/secrets" \
            --json --metrics=off \
            "$SOURCE_DIR" > "$SEMGREP_OUT" 2>/dev/null
        SEMGREP_EXIT=$?
        set -e

        if [[ $SEMGREP_EXIT -eq 124 ]]; then
            echo "│  WARNING: semgrep timed out after ${MAX_MINUTES}m"
            ERRORS=$((ERRORS + 1))
        elif [[ $SEMGREP_EXIT -eq 0 ]] || [[ $SEMGREP_EXIT -eq 1 ]]; then
            FINDING_COUNT=$(python3 -c "
import json
try:
    data = json.load(open('$SEMGREP_OUT'))
    print(len(data.get('results', [])))
except:
    print('?')
" 2>/dev/null || echo "?")
            echo "│  Found $FINDING_COUNT finding(s)."
        else
            echo "│  WARNING: semgrep exited with code $SEMGREP_EXIT"
        fi

        if [[ -f "$SEMGREP_OUT" ]]; then
            SIZE=$(stat -c%s "$SEMGREP_OUT" 2>/dev/null || echo "0")
            echo "│  Output: $SEMGREP_OUT ($SIZE bytes)"
        fi
    else
        echo "│  WARNING: semgrep not installed, skipping."
        ERRORS=$((ERRORS + 1))
    fi
    echo "└──────────────────────────────────────────────"
fi

# ── gitleaks (A02/A07: hardcoded secrets, API keys, credentials) ─────────────

if needs_sast_tool "gitleaks"; then
    echo ""
    echo "┌── gitleaks (A02/A07: Hardcoded Secrets) ──"
    GITLEAKS_OUT="$RESULTS_DIR/gitleaks.json"

    if command -v gitleaks &>/dev/null; then
        echo "│  Scanning $SOURCE_DIR for secrets ..."
        # gitleaks exit code 1 = secrets found (not an error for us)
        # `dir` subcommand scans a directory without git history (no --no-git needed)
        # NOTE: gitleaks JSON output contains FULL secret values — treat as sensitive
        set +e
        timeout "${TOOL_TIMEOUT}s" gitleaks dir \
            --report-format json --report-path "$GITLEAKS_OUT" --no-banner \
            "$SOURCE_DIR" 2>/dev/null
        GITLEAKS_EXIT=$?
        set -e

        if [[ $GITLEAKS_EXIT -eq 124 ]]; then
            echo "│  WARNING: gitleaks timed out after ${MAX_MINUTES}m"
            ERRORS=$((ERRORS + 1))
        elif [[ $GITLEAKS_EXIT -eq 0 ]]; then
            echo "│  No secrets found."
        elif [[ $GITLEAKS_EXIT -eq 1 ]]; then
            FINDING_COUNT=$(python3 -c "
import json
try:
    data = json.load(open('$GITLEAKS_OUT'))
    print(len(data) if isinstance(data, list) else '?')
except:
    print('?')
" 2>/dev/null || echo "?")
            echo "│  Found $FINDING_COUNT secret(s)."
            echo "│  WARNING: Raw output contains secret values — do not expose."
        else
            echo "│  WARNING: gitleaks exited with code $GITLEAKS_EXIT"
        fi

        if [[ -f "$GITLEAKS_OUT" ]]; then
            SIZE=$(stat -c%s "$GITLEAKS_OUT" 2>/dev/null || echo "0")
            echo "│  Output: $GITLEAKS_OUT ($SIZE bytes)"
        fi
    else
        echo "│  WARNING: gitleaks not installed, skipping."
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
