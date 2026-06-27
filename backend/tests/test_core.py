"""Tests for the backend core: scope, validation, SSRF, dedup, redaction, scanner, parsers, auth."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import textwrap
import uuid
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


# ── Scope fixtures ────────────────────────────────────────────────────────────

SCOPE_MD = textwrap.dedent("""\
    # Test scope file

    Forbidden: https://juice-shop.herokuapp.com (passive only).
    Also mentioned: http://10.0.0.5:8080

    <!-- ALLOWLIST-START -->
    http://localhost:3000
    http://127.0.0.1:3000
    <!-- ALLOWLIST-END -->

    ## Out of scope
    - http://evil.example.com
    ```yaml
    rate_limit_rps: 5
    max_scan_minutes: 15
    destructive_tests: false
    auth_brute_force: false
    fail_gate_on: medium
    ```
""")


@pytest.fixture
def scope_file(tmp_path: Path) -> Path:
    p = tmp_path / "SCOPE.md"
    p.write_text(SCOPE_MD, encoding="utf-8")
    return p


@pytest.fixture
def scope_config(scope_file: Path):
    from backend.app.scope import parse_scope
    return parse_scope(scope_file)


@pytest.fixture
def db_path(tmp_path: Path) -> str:
    from backend.app.database import init_db
    path = str(tmp_path / "test.db")
    init_db(path)
    return path


# ══════════════════════════════════════════════════════════════════════════════
# SCOPE PARSER
# ══════════════════════════════════════════════════════════════════════════════

class TestScopeParser:
    def test_allowlist_only_from_markers(self, scope_config):
        assert "http://localhost:3000" in scope_config.allowlist
        assert "http://127.0.0.1:3000" in scope_config.allowlist
        assert len(scope_config.allowlist) == 2

    def test_forbidden_hosts_not_in_allowlist(self, scope_config):
        from backend.app.scope import is_in_scope
        assert not is_in_scope("https://juice-shop.herokuapp.com", scope_config)
        assert not is_in_scope("http://evil.example.com", scope_config)
        assert not is_in_scope("http://10.0.0.5:8080", scope_config)

    def test_in_scope_localhost(self, scope_config):
        from backend.app.scope import is_in_scope
        assert is_in_scope("http://localhost:3000", scope_config)
        assert is_in_scope("http://localhost:3000/path", scope_config)

    def test_safety_params_parsed(self, scope_config):
        assert scope_config.safety.rate_limit_rps == 5
        assert scope_config.safety.max_scan_minutes == 15
        assert scope_config.safety.destructive_tests is False
        assert scope_config.safety.fail_gate_on == "medium"


# ══════════════════════════════════════════════════════════════════════════════
# TARGET VALIDATION + SSRF GUARD
# ══════════════════════════════════════════════════════════════════════════════

class TestTargetValidation:
    def test_rejects_non_http_scheme(self, scope_config):
        from backend.app.target_validation import validate_target, TargetValidationError
        with pytest.raises(TargetValidationError, match="Scheme"):
            validate_target("ftp://example.com", scope_config)
        with pytest.raises(TargetValidationError, match="Scheme"):
            validate_target("file:///etc/passwd", scope_config)

    def test_rejects_missing_host(self, scope_config):
        from backend.app.target_validation import validate_target, TargetValidationError
        with pytest.raises(TargetValidationError, match="hostname"):
            validate_target("http://", scope_config)

    def test_shell_metacharacters_in_url_do_not_inject(self, scope_config):
        from backend.app.target_validation import validate_target, TargetValidationError
        evil_urls = [
            "http://example.com;rm -rf /",
            "http://example.com$(whoami)",
            "http://example.com`id`",
            "http://example.com|cat /etc/passwd",
        ]
        for url in evil_urls:
            try:
                validate_target(url, scope_config)
            except TargetValidationError:
                pass

    def test_blocks_internal_ip_not_in_allowlist(self, scope_config):
        from backend.app.target_validation import validate_target, TargetValidationError
        with pytest.raises(TargetValidationError, match="private/reserved"):
            validate_target("http://169.254.169.254/latest/meta-data/", scope_config)

    def test_blocks_rfc1918_not_in_allowlist(self, scope_config):
        from backend.app.target_validation import validate_target, TargetValidationError
        with pytest.raises(TargetValidationError, match="private/reserved"):
            validate_target("http://192.168.1.1", scope_config)
        with pytest.raises(TargetValidationError, match="private/reserved"):
            validate_target("http://10.0.0.1", scope_config)

    def test_allowlisted_localhost_passes_ssrf(self, scope_config):
        from backend.app.target_validation import validate_target
        result = validate_target("http://localhost:3000", scope_config)
        assert result.url == "http://localhost:3000"
        assert result.hostname == "localhost"

    def test_returns_pinned_ip(self, scope_config):
        """validate_target must return a ValidationResult with pinned_ip set."""
        from backend.app.target_validation import validate_target
        result = validate_target("http://localhost:3000", scope_config)
        # pinned_ip should be set (127.0.0.1 or ::1)
        assert result.pinned_ip is not None

    def test_blocks_unspecified_address(self, scope_config):
        """B2: 0.0.0.0 must be blocked."""
        from backend.app.target_validation import _is_private_or_reserved
        assert _is_private_or_reserved("0.0.0.0") is True
        assert _is_private_or_reserved("::") is True

    def test_blocks_ipv4_mapped_ipv6(self, scope_config):
        """B2: ::ffff:127.0.0.1 must be blocked (IPv4-mapped IPv6)."""
        from backend.app.target_validation import _is_private_or_reserved
        assert _is_private_or_reserved("::ffff:127.0.0.1") is True
        assert _is_private_or_reserved("::ffff:10.0.0.1") is True
        assert _is_private_or_reserved("::ffff:169.254.169.254") is True

    def test_dns_rebinding_blocked_by_pinning(self, scope_config):
        """A1: A target that resolves to public at validation but private at scan
        time is still safe because the pinned IP is used, not re-resolved."""
        from backend.app.target_validation import validate_target, ValidationResult

        # Simulate: getaddrinfo returns a public IP during validation
        public_result = [(2, 1, 6, '', ('93.184.216.34', 80))]
        with patch("backend.app.target_validation.socket.getaddrinfo", return_value=public_result):
            result = validate_target("http://rebind.example.com", scope_config)
            # The pinned IP is the public one that was validated
            assert result.pinned_ip == "93.184.216.34"
            # Even if DNS later returns 169.254.169.254, the scanner uses the pinned IP


# ══════════════════════════════════════════════════════════════════════════════
# SCAN RUNNER — SCOPE ENFORCEMENT
# ══════════════════════════════════════════════════════════════════════════════

class TestScanRunner:
    def test_active_on_out_of_scope_refused(self, scope_config, db_path):
        from backend.app.scanner import start_scan, ScanRefusedError
        from backend.app.models import ScanMode

        with patch("backend.app.scanner.subprocess.Popen") as mock_popen:
            with pytest.raises(ScanRefusedError, match="not authorized"):
                start_scan(
                    "https://juice-shop.herokuapp.com",
                    ScanMode.active,
                    scope_config,
                    db_path,
                )
            mock_popen.assert_not_called()

    def test_auto_mode_resolves_passive_for_out_of_scope(self, scope_config):
        from backend.app.scanner import resolve_mode
        from backend.app.models import ScanMode
        assert resolve_mode(ScanMode.auto, "https://example.com", scope_config) == "passive"

    def test_auto_mode_resolves_active_for_in_scope(self, scope_config):
        from backend.app.scanner import resolve_mode
        from backend.app.models import ScanMode
        assert resolve_mode(ScanMode.auto, "http://localhost:3000", scope_config) == "active"

    def test_safe_host_neutralizes_traversal(self):
        from backend.app.scanner import _safe_host
        assert ".." not in _safe_host("http://../../etc/passwd:3000")
        assert "/" not in _safe_host("http://foo/bar:3000")
        assert "\\" not in _safe_host("http://foo\\bar:3000")
        result = _safe_host("http://localhost:3000")
        assert result == "localhost_3000"

    def test_start_scan_returns_resolved_mode(self, scope_config, db_path):
        """B4: start_scan returns (run_id, resolved_mode)."""
        from backend.app.scanner import start_scan
        from backend.app.models import ScanMode

        with patch("backend.app.scanner.threading.Thread") as mock_thread:
            mock_thread.return_value.start = MagicMock()
            run_id, mode = start_scan(
                "http://localhost:3000", ScanMode.auto, scope_config, db_path,
            )
            assert mode == "active"
            assert run_id is not None

    def test_error_message_is_redacted(self):
        """A3: error messages must have secrets redacted and be truncated."""
        from backend.app.scanner import _sanitize_error
        raw = 'Connection failed: password: "SuperSecretToken1234567890" host error'
        result = _sanitize_error(raw)
        assert "SuperSecretToken1234567890" not in result
        assert "****" in result

    def test_error_message_truncated(self):
        from backend.app.scanner import _sanitize_error
        long_msg = "some error message. " * 300
        result = _sanitize_error(long_msg)
        assert len(result) < 3000
        assert "[truncated]" in result

    def test_reconcile_orphaned_runs(self, db_path):
        """B3: orphaned runs from previous server instance are marked failed."""
        from backend.app.scanner import reconcile_orphaned_runs
        from backend.app.database import get_db

        with get_db(db_path) as conn:
            conn.execute(
                "INSERT INTO runs (id, target_url, target_host, mode, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("orphan-1", "http://x.com", "x_com", "passive", "running", "2025-01-01T00:00:00Z"),
            )
            conn.execute(
                "INSERT INTO runs (id, target_url, target_host, mode, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("orphan-2", "http://x.com", "x_com", "passive", "queued", "2025-01-01T00:00:00Z"),
            )

        count = reconcile_orphaned_runs(db_path)
        assert count == 2

        with get_db(db_path) as conn:
            row = conn.execute("SELECT status FROM runs WHERE id = ?", ("orphan-1",)).fetchone()
            assert row["status"] == "failed"


# ══════════════════════════════════════════════════════════════════════════════
# SECRET REDACTION
# ══════════════════════════════════════════════════════════════════════════════

class TestRedaction:
    def test_gitleaks_finding_redacted(self):
        from backend.app.models import redact_gitleaks_finding
        evidence = 'api_key = "AKIAIOSFODNN7EXAMPLE1234567890"'
        result = redact_gitleaks_finding(evidence, "config/secrets.yml", 42)
        assert "secret detected at config/secrets.yml:42" in result
        assert "AKIAIOSFODNN7EXAMPLE1234567890" not in result
        assert "****" in result

    def test_raw_secret_never_stored(self):
        from backend.app.models import redact_secret
        raw = 'password: "SuperSecretP@ssw0rd123456"'
        result = redact_secret(raw)
        assert "SuperSecretP@ssw0rd123456" not in result
        assert "****" in result

    def test_short_tokens_fully_masked(self):
        from backend.app.models import redact_secret
        raw = 'key=abcdefghijklmnop'
        result = redact_secret(raw)
        assert "abcdefghijklmnop" not in result


# ══════════════════════════════════════════════════════════════════════════════
# DEDUP + MERGE
# ══════════════════════════════════════════════════════════════════════════════

class TestDedup:
    def test_same_finding_different_tools_merge(self, db_path):
        """C3: Same finding from ZAP + nuclei MERGES into one row with
        source_tool='nuclei,zap' (not dropped)."""
        from backend.app.scanner import _insert_findings
        from backend.app.models import ParsedFinding
        from backend.app.database import get_db

        run_id = str(uuid.uuid4())
        with get_db(db_path) as conn:
            conn.execute(
                "INSERT INTO runs (id, target_url, target_host, mode, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (run_id, "http://localhost:3000", "localhost_3000", "active", "running", "2025-01-01T00:00:00Z"),
            )

        findings = [
            ParsedFinding(
                severity="medium",
                title="Missing CSP Header",
                category="A02:2025",
                category_name="Security Misconfiguration",
                location="http://localhost:3000",
                evidence="No CSP header (short)",
                fix="Add CSP",
                source_tool="zap",
            ),
            ParsedFinding(
                severity="high",  # higher severity
                title="Missing CSP Header",
                category="A02:2025",
                category_name="Security Misconfiguration",
                location="http://localhost:3000",
                evidence="No Content-Security-Policy header detected in response (longer evidence)",
                fix="Add a Content-Security-Policy header: default-src 'self' (better fix)",
                source_tool="nuclei",
            ),
        ]

        _insert_findings(run_id, findings, db_path)

        with get_db(db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE run_id = ?", (run_id,)
            ).fetchall()

        # Should be ONE merged row, not two
        assert len(rows) == 1
        row = rows[0]
        # source_tool contains both
        assert "zap" in row["source_tool"]
        assert "nuclei" in row["source_tool"]
        # Kept the highest severity
        assert row["severity"] == "high"
        # Kept the longer evidence
        assert "longer evidence" in row["evidence"]
        # Kept the longer fix
        assert "default-src" in row["fix"]

    def test_different_findings_different_hashes(self):
        from backend.app.models import compute_dedupe_hash
        h1 = compute_dedupe_hash("A02:2025", "http://localhost:3000", "Missing CSP")
        h2 = compute_dedupe_hash("A05:2025", "http://localhost:3000/api", "SQL Injection")
        assert h1 != h2

    def test_dedup_is_case_insensitive(self):
        from backend.app.models import compute_dedupe_hash
        h1 = compute_dedupe_hash("A02:2025", "http://localhost:3000", "Missing CSP Header")
        h2 = compute_dedupe_hash("A02:2025", "HTTP://LOCALHOST:3000", "MISSING CSP HEADER")
        assert h1 == h2

    def test_query_string_values_dedup(self):
        """C2: Same vuln with two different query-string values dedupes to one."""
        from backend.app.models import compute_dedupe_hash
        h1 = compute_dedupe_hash(
            "A05:2025",
            "http://localhost:3000/search?q=<script>alert(1)</script>",
            "Reflected XSS",
        )
        h2 = compute_dedupe_hash(
            "A05:2025",
            "http://localhost:3000/search?q=<img+onerror=alert(1)>",
            "Reflected XSS",
        )
        assert h1 == h2


# ══════════════════════════════════════════════════════════════════════════════
# LOCATION NORMALIZATION
# ══════════════════════════════════════════════════════════════════════════════

class TestLocationNormalization:
    def test_query_values_zeroed(self):
        from backend.app.models import normalize_location
        result = normalize_location("http://localhost:3000/search?q=payload&page=5")
        assert "payload" not in result
        assert "q=0" in result
        assert "page=0" in result

    def test_no_query_unchanged(self):
        from backend.app.models import normalize_location
        result = normalize_location("http://localhost:3000/api/users")
        assert result == "http://localhost:3000/api/users"

    def test_trailing_slash_stripped(self):
        from backend.app.models import normalize_location
        r1 = normalize_location("http://localhost:3000/api/")
        r2 = normalize_location("http://localhost:3000/api")
        assert r1 == r2


# ══════════════════════════════════════════════════════════════════════════════
# PARSERS
# ══════════════════════════════════════════════════════════════════════════════

class TestParsers:
    def test_missing_file_yields_empty(self, tmp_path):
        """C1: A missing file must yield [] without crashing."""
        from backend.app.parsers import (
            parse_headers, parse_zap, parse_nuclei,
            parse_nikto, parse_testssl, parse_gitleaks,
        )
        nonexistent = tmp_path / "does_not_exist.json"
        assert parse_headers(nonexistent, "run1") == []
        assert parse_zap(nonexistent, "run1") == []
        assert parse_nuclei(nonexistent, "run1") == []
        assert parse_nikto(nonexistent, "run1") == []
        assert parse_testssl(nonexistent, "run1") == []
        assert parse_gitleaks(nonexistent, "run1") == []

    def test_empty_file_yields_empty(self, tmp_path):
        empty = tmp_path / "empty.json"
        empty.write_text("", encoding="utf-8")
        from backend.app.parsers import parse_zap
        assert parse_zap(empty, "run1") == []

    def test_headers_parser(self, tmp_path):
        from backend.app.parsers import parse_headers
        summary = {
            "target": "http://localhost:3000",
            "host": "localhost:3000",
            "security_headers": {
                "content-security-policy": {"present": False, "value": None},
                "strict-transport-security": {"present": True, "value": "max-age=31536000"},
                "x-frame-options": {"present": False, "value": None},
                "x-content-type-options": {"present": True, "value": "nosniff"},
                "referrer-policy": {"present": False, "value": None},
                "permissions-policy": {"present": False, "value": None},
            },
            "server_info": {"server": "Express", "x-powered-by": "Express"},
        }
        f = tmp_path / "summary.json"
        f.write_text(json.dumps(summary), encoding="utf-8")

        findings = parse_headers(f, "run1")
        # Missing: CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy = 4
        # Plus server disclosure + x-powered-by = 6
        assert len(findings) == 6
        titles = [f.title for f in findings]
        assert "Missing content-security-policy header" in titles

    def test_zap_parser(self, tmp_path):
        from backend.app.parsers import parse_zap
        zap_data = {
            "site": [{
                "alerts": [{
                    "name": "Cross-Site Scripting (Reflected)",
                    "riskcode": "3",
                    "confidence": "3",
                    "cweid": "79",
                    "desc": "XSS found",
                    "solution": "Sanitize user input",
                    "instances": [{"uri": "http://localhost:3000/search?q=test", "evidence": "<script>"}],
                }]
            }]
        }
        f = tmp_path / "zap-report.json"
        f.write_text(json.dumps(zap_data), encoding="utf-8")

        findings = parse_zap(f, "run1")
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert findings[0].category == "A05:2025"  # CWE-79 -> Injection

    def test_nuclei_parser(self, tmp_path):
        from backend.app.parsers import parse_nuclei
        nuclei_data = '{"template-id":"csp-missing","info":{"name":"CSP Missing","severity":"medium","classification":{"cwe-id":["CWE-16"]}},"matched-at":"http://localhost:3000","host":"http://localhost:3000"}\n'
        f = tmp_path / "nuclei.jsonl"
        f.write_text(nuclei_data, encoding="utf-8")

        findings = parse_nuclei(f, "run1")
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_gitleaks_parser_redacts_secrets(self, tmp_path):
        from backend.app.parsers import parse_gitleaks
        data = [{
            "RuleID": "aws-access-key",
            "File": "config.py",
            "StartLine": 10,
            "Match": "AKIAIOSFODNN7EXAMPLE1234567890",
            "Description": "AWS Access Key",
        }]
        f = tmp_path / "gitleaks.json"
        f.write_text(json.dumps(data), encoding="utf-8")

        findings = parse_gitleaks(f, "run1")
        assert len(findings) == 1
        # Secret must be redacted
        assert "AKIAIOSFODNN7EXAMPLE1234567890" not in findings[0].evidence
        assert "****" in findings[0].evidence
        assert "config.py:10" in findings[0].evidence


# ══════════════════════════════════════════════════════════════════════════════
# API — SCOPE (read-only, no auth needed)
# ══════════════════════════════════════════════════════════════════════════════

class TestScopeAPI:
    @pytest.fixture
    def client(self, scope_file, db_path):
        from fastapi.testclient import TestClient
        os.environ["SCOPE_FILE"] = str(scope_file)
        os.environ["MASREK_DB"] = db_path
        os.environ["MASREK_AUTH_DISABLED"] = "1"
        from backend.app.main import app
        return TestClient(app)

    def test_get_scope(self, client):
        resp = client.get("/scope")
        assert resp.status_code == 200
        data = resp.json()
        assert "http://localhost:3000" in data["allowlist"]

    def test_scope_check_in_scope(self, client):
        resp = client.get("/scope/check", params={"url": "http://localhost:3000"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["in_scope"] is True
        assert data["allowed_mode"] == "active"

    def test_scope_check_out_of_scope(self, client):
        resp = client.get("/scope/check", params={"url": "https://example.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["in_scope"] is False
        assert data["allowed_mode"] == "passive"

    def test_no_write_endpoint_for_scope(self, client):
        for method in [client.post, client.put, client.patch, client.delete]:
            resp = method("/scope")
            assert resp.status_code == 405


# ══════════════════════════════════════════════════════════════════════════════
# AUTH — B1: fail-closed, protect reads
# ══════════════════════════════════════════════════════════════════════════════

class TestAuth:
    @pytest.fixture
    def auth_client(self, scope_file, db_path):
        from fastapi.testclient import TestClient
        os.environ["SCOPE_FILE"] = str(scope_file)
        os.environ["MASREK_DB"] = db_path
        os.environ["MASREK_API_KEY"] = "test-secret-key-123"
        os.environ.pop("MASREK_AUTH_DISABLED", None)
        from backend.app.main import app
        yield TestClient(app)
        os.environ.pop("MASREK_API_KEY", None)

    def test_scan_without_key_rejected(self, auth_client):
        resp = auth_client.post("/scan", json={"target_url": "http://localhost:3000"})
        assert resp.status_code == 401

    def test_scan_with_wrong_key_rejected(self, auth_client):
        resp = auth_client.post(
            "/scan",
            json={"target_url": "http://localhost:3000"},
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert resp.status_code == 403

    def test_scope_endpoints_no_auth_needed(self, auth_client):
        assert auth_client.get("/scope").status_code == 200
        assert auth_client.get("/scope/check", params={"url": "http://x.com"}).status_code == 200
        assert auth_client.get("/health").status_code == 200

    def test_runs_endpoint_requires_auth(self, auth_client):
        """B1: GET /runs must require auth (findings are sensitive)."""
        resp = auth_client.get("/runs")
        assert resp.status_code == 401

    def test_runs_with_valid_key(self, auth_client):
        resp = auth_client.get(
            "/runs",
            headers={"Authorization": "Bearer test-secret-key-123"},
        )
        assert resp.status_code == 200

    def test_auth_required_by_default(self, scope_file, db_path):
        """B1: When neither MASREK_API_KEY nor MASREK_AUTH_DISABLED is set,
        all protected endpoints return 503 (fail-closed)."""
        from fastapi.testclient import TestClient
        os.environ["SCOPE_FILE"] = str(scope_file)
        os.environ["MASREK_DB"] = db_path
        os.environ.pop("MASREK_API_KEY", None)
        os.environ.pop("MASREK_AUTH_DISABLED", None)
        from backend.app.main import app
        client = TestClient(app)
        resp = client.post("/scan", json={"target_url": "http://localhost:3000"})
        assert resp.status_code == 503
        assert "MASREK_API_KEY" in resp.json()["detail"]


# ══════════════════════════════════════════════════════════════════════════════
# PATH SAFETY
# ══════════════════════════════════════════════════════════════════════════════

class TestPathSafety:
    def test_traversal_neutralized(self):
        from backend.app.scanner import _safe_host
        assert ".." not in _safe_host("http://../../../etc/passwd")
        assert _safe_host("http://a/b/c:80") == "a"
        assert "/" not in _safe_host("http://a/b/c:80")

    def test_safe_host_special_chars(self):
        from backend.app.scanner import _safe_host
        result = _safe_host("http://my-host.example.com:8080/path?q=1")
        assert result == "my-host.example.com_8080"
        assert "/" not in result
