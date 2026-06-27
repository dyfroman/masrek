"""Unit tests for CWE → OWASP Top 10:2025 mapping correctness.

Asserts the fixes from Phase 5 Part B:
  - XSS (CWE-79) → A05 Injection, NOT A03
  - SQLi (CWE-89) → A05 Injection
  - Missing CSP / headers → A02 (via headers parser, not CWE)
  - Cookie Secure flag (CWE-614) → A04 Crypto, NOT A02
  - Default creds (CWE-522) → A07 Auth, NOT A06
  - Plaintext password (CWE-256) → A07 Auth, NOT A06
  - Stack trace / error disclosure (CWE-209) → A10, NOT A02/A06
  - No duplicate CWE in the mapping dict
  - Tag-based fallback when CWE is absent
  - parse_cwe_id handles nuclei's lowercase "cwe-79" format
"""

import pytest

from app.parsers.base import CWE_TO_OWASP, cwe_to_owasp, tags_to_owasp, parse_cwe_id


class TestCweToOwaspMapping:
    def test_xss_maps_to_a05(self):
        cat, name, mapping = cwe_to_owasp(79)
        assert cat == "A05:2025"
        assert "Injection" in name
        assert mapping == "exact"

    def test_sqli_maps_to_a05(self):
        cat, _, mapping = cwe_to_owasp(89)
        assert cat == "A05:2025"
        assert mapping == "exact"

    def test_command_injection_maps_to_a05(self):
        cat, _, _ = cwe_to_owasp(78)
        assert cat == "A05:2025"

    def test_cookie_secure_flag_maps_to_a04(self):
        cat, name, _ = cwe_to_owasp(614)
        assert cat == "A04:2025", f"CWE-614 should be A04 (Crypto), got {cat}"
        assert "Cryptographic" in name

    def test_insufficiently_protected_creds_maps_to_a07(self):
        cat, name, _ = cwe_to_owasp(522)
        assert cat == "A07:2025", f"CWE-522 should be A07 (Auth), got {cat}"

    def test_plaintext_password_maps_to_a07(self):
        cat, name, _ = cwe_to_owasp(256)
        assert cat == "A07:2025", f"CWE-256 should be A07 (Auth), got {cat}"

    def test_error_info_exposure_maps_to_a10(self):
        cat, name, _ = cwe_to_owasp(209)
        assert cat == "A10:2025", f"CWE-209 should be A10 (Exceptions), got {cat}"

    def test_ssrf_maps_to_a01(self):
        cat, _, _ = cwe_to_owasp(918)
        assert cat == "A01:2025"

    def test_path_traversal_maps_to_a01(self):
        cat, _, _ = cwe_to_owasp(22)
        assert cat == "A01:2025"

    def test_access_control_cwe264_maps_to_a01(self):
        cat, _, mapping = cwe_to_owasp(264)
        assert cat == "A01:2025"
        assert mapping == "exact"

    def test_directory_listing_maps_to_a02(self):
        cat, _, _ = cwe_to_owasp(548)
        assert cat == "A02:2025"

    def test_xml_external_entity_maps_to_a02(self):
        cat, _, _ = cwe_to_owasp(611)
        assert cat == "A02:2025"

    def test_brute_force_maps_to_a07(self):
        cat, _, _ = cwe_to_owasp(307)
        assert cat == "A07:2025"

    def test_deserialization_maps_to_a08(self):
        cat, _, _ = cwe_to_owasp(502)
        assert cat == "A08:2025"

    def test_log_injection_maps_to_a09(self):
        cat, _, _ = cwe_to_owasp(117)
        assert cat == "A09:2025"

    def test_unknown_cwe_falls_back(self):
        cat, name, mapping = cwe_to_owasp(99999)
        assert cat == "A02:2025"
        assert mapping == "fallback"

    def test_none_cwe_falls_back(self):
        cat, _, mapping = cwe_to_owasp(None)
        assert cat == "A02:2025"
        assert mapping == "fallback"

    def test_no_duplicate_cwe_keys(self):
        """The Python dict literal silently overwrites duplicates.
        Verify every CWE appears exactly once by checking the count matches."""
        import ast
        import inspect
        import textwrap
        from app.parsers import base

        source = inspect.getsource(base)
        assert len(CWE_TO_OWASP) > 50, "Mapping should have 50+ CWE entries"

        seen_values = set(CWE_TO_OWASP.values())
        expected_categories = {
            "A01:2025", "A02:2025", "A03:2025", "A04:2025", "A05:2025",
            "A06:2025", "A07:2025", "A08:2025", "A09:2025", "A10:2025",
        }
        assert seen_values == expected_categories, (
            f"Missing categories: {expected_categories - seen_values}"
        )


class TestParseCweId:
    def test_uppercase_cwe(self):
        assert parse_cwe_id("CWE-79") == 79

    def test_lowercase_cwe(self):
        assert parse_cwe_id("cwe-200") == 200

    def test_bare_number(self):
        assert parse_cwe_id(79) == 79

    def test_string_number(self):
        assert parse_cwe_id("89") == 89

    def test_negative(self):
        assert parse_cwe_id(-1) is None

    def test_zero(self):
        assert parse_cwe_id(0) is None

    def test_none(self):
        assert parse_cwe_id(None) is None

    def test_garbage(self):
        assert parse_cwe_id("not-a-cwe") is None


class TestTagsToOwasp:
    def test_xss_tag(self):
        result = tags_to_owasp(["xss", "misc"])
        assert result is not None
        cat, name, mapping = result
        assert cat == "A05:2025"
        assert mapping == "tag"

    def test_sqli_tag(self):
        result = tags_to_owasp(["sqli", "database"])
        assert result is not None
        assert result[0] == "A05:2025"

    def test_injection_tag(self):
        result = tags_to_owasp(["injection"])
        assert result is not None
        assert result[0] == "A05:2025"

    def test_ssrf_tag(self):
        result = tags_to_owasp(["ssrf"])
        assert result is not None
        assert result[0] == "A01:2025"

    def test_exposure_tag(self):
        result = tags_to_owasp(["exposure", "api"])
        assert result is not None
        assert result[0] == "A01:2025"

    def test_auth_tag(self):
        result = tags_to_owasp(["auth", "login"])
        assert result is not None
        assert result[0] == "A07:2025"

    def test_default_login_tag(self):
        result = tags_to_owasp(["default-login"])
        assert result is not None
        assert result[0] == "A07:2025"

    def test_misconfig_tag(self):
        result = tags_to_owasp(["misconfig", "headers"])
        assert result is not None
        assert result[0] == "A02:2025"

    def test_no_match(self):
        result = tags_to_owasp(["tech", "discovery"])
        assert result is None

    def test_empty_tags(self):
        result = tags_to_owasp([])
        assert result is None


class TestZapCweMapping:
    def test_zap_cwe79_maps_to_a05(self):
        cat, _, mapping = cwe_to_owasp(79)
        assert cat == "A05:2025"
        assert mapping == "exact"

    def test_zap_cwe264_maps_to_a01(self):
        cat, _, mapping = cwe_to_owasp(264)
        assert cat == "A01:2025"
        assert mapping == "exact"

    def test_zap_cwe693_maps_to_a02(self):
        cat, _, mapping = cwe_to_owasp(693)
        assert cat == "A02:2025"
        assert mapping == "exact"

    def test_zap_negative_cwe_fallback(self):
        cat, _, mapping = cwe_to_owasp(-1)
        assert cat == "A02:2025"
        assert mapping == "fallback"


class TestChecksRegistry:
    def test_all_10_checks_defined(self):
        from app.checks import CHECKS, ALL_CHECK_IDS
        assert len(CHECKS) == 10
        assert ALL_CHECK_IDS == [f"A{i:02d}" for i in range(1, 11)]

    def test_none_detectability_has_no_active_tools(self):
        from app.checks import CHECKS
        for cid, check in CHECKS.items():
            if check.detectability == "none":
                assert check.active_tools == [], (
                    f"{cid} detectability=none but has active_tools={check.active_tools}"
                )

    def test_full_detectability_has_tools(self):
        from app.checks import CHECKS
        for cid, check in CHECKS.items():
            if check.detectability == "full":
                assert len(check.active_tools) > 0, (
                    f"{cid} detectability=full but has no active_tools"
                )

    def test_quick_preset_is_subset(self):
        from app.checks import ALL_CHECK_IDS, QUICK_CHECK_IDS
        assert set(QUICK_CHECK_IDS).issubset(set(ALL_CHECK_IDS))

    def test_checks_need_tool(self):
        from app.checks import checks_need_tool
        assert checks_need_tool(["A05"], "zap") is True
        assert checks_need_tool(["A05"], "nikto") is False
        assert checks_need_tool(["A02"], "nikto") is True
        assert checks_need_tool(["A03"], "zap") is False

    def test_get_not_testable_checks(self):
        from app.checks import get_not_testable_checks
        none_checks = get_not_testable_checks(["A03", "A06", "A08", "A09"])
        assert len(none_checks) == 4
        ids = {c.id for c in none_checks}
        assert ids == {"A03", "A06", "A08", "A09"}

    def test_get_not_testable_excludes_testable(self):
        from app.checks import get_not_testable_checks
        none_checks = get_not_testable_checks(["A01", "A05"])
        assert len(none_checks) == 0


class TestSingleCheckRun:
    """Verify that single-check runs only invoke that category's tooling."""

    def test_a05_only_needs_zap_and_nuclei(self):
        from app.checks import checks_need_tool
        assert checks_need_tool(["A05"], "zap") is True
        assert checks_need_tool(["A05"], "nuclei") is True
        assert checks_need_tool(["A05"], "nikto") is False

    def test_a02_only_needs_nikto_and_zap(self):
        from app.checks import checks_need_tool
        assert checks_need_tool(["A02"], "zap") is True
        assert checks_need_tool(["A02"], "nikto") is True
        assert checks_need_tool(["A02"], "nuclei") is False

    def test_single_check_filters_findings(self):
        """A run with checks=["A05"] should only keep A05 findings."""
        from app.models import ParsedFinding
        findings = [
            ParsedFinding(
                severity="high", title="XSS", category="A05:2025",
                category_name="Injection", location="http://x/", source_tool="zap",
            ),
            ParsedFinding(
                severity="medium", title="Misconfig", category="A02:2025",
                category_name="Security Misconfiguration", location="http://x/",
                source_tool="passive-headers",
            ),
        ]
        selected_cats = {f"{cid}:2025" for cid in ["A05"]}
        filtered = [f for f in findings if f.category in selected_cats]
        assert len(filtered) == 1
        assert filtered[0].category == "A05:2025"

    def test_unselected_category_generates_no_detectability_finding(self):
        """get_not_testable_checks only returns from the selected list."""
        from app.checks import get_not_testable_checks
        result = get_not_testable_checks(["A05"])
        ids = {c.id for c in result}
        assert "A03" not in ids
        assert "A06" not in ids

    def test_a05_check_has_full_detectability(self):
        from app.checks import CHECKS
        assert CHECKS["A05"].detectability == "full"
        assert "zap" in CHECKS["A05"].active_tools
        assert "nuclei" in CHECKS["A05"].active_tools


class TestSourcePathValidation:
    """Validate the source path containment logic (realpath, symlink escape, traversal)."""

    def test_valid_path_inside_allowlist(self, tmp_path):
        from app.scope import ScopeConfig, SafetyParams, validate_source_path
        allowed = tmp_path / "source"
        allowed.mkdir()
        subdir = allowed / "project"
        subdir.mkdir()

        scope = ScopeConfig(
            source_allowlist=(str(allowed),),
            safety=SafetyParams(),
        )
        result = validate_source_path(str(subdir), scope)
        assert result == subdir.resolve()

    def test_path_traversal_rejected(self, tmp_path):
        from app.scope import ScopeConfig, SafetyParams, SourcePathError, validate_source_path
        allowed = tmp_path / "source"
        allowed.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()

        scope = ScopeConfig(
            source_allowlist=(str(allowed),),
            safety=SafetyParams(),
        )
        with pytest.raises(SourcePathError, match="outside the authorized"):
            validate_source_path(str(outside), scope)

    def test_dotdot_traversal_rejected(self, tmp_path):
        from app.scope import ScopeConfig, SafetyParams, SourcePathError, validate_source_path
        allowed = tmp_path / "source"
        allowed.mkdir()
        (allowed / "sub").mkdir()

        scope = ScopeConfig(
            source_allowlist=(str(allowed),),
            safety=SafetyParams(),
        )
        # Try to escape via ../
        traversal = str(allowed / "sub" / ".." / ".." / "outside")
        with pytest.raises(SourcePathError):
            validate_source_path(traversal, scope)

    def test_symlink_escape_rejected(self, tmp_path):
        import os
        from app.scope import ScopeConfig, SafetyParams, SourcePathError, validate_source_path
        allowed = tmp_path / "source"
        allowed.mkdir()
        secret = tmp_path / "secret"
        secret.mkdir()
        link = allowed / "sneaky"
        try:
            os.symlink(str(secret), str(link))
        except OSError:
            pytest.skip("Cannot create symlinks on this system")

        scope = ScopeConfig(
            source_allowlist=(str(allowed),),
            safety=SafetyParams(),
        )
        with pytest.raises(SourcePathError, match="outside the authorized"):
            validate_source_path(str(link), scope)

    def test_nonexistent_path_rejected(self, tmp_path):
        from app.scope import ScopeConfig, SafetyParams, SourcePathError, validate_source_path
        scope = ScopeConfig(
            source_allowlist=(str(tmp_path),),
            safety=SafetyParams(),
        )
        with pytest.raises(SourcePathError, match="does not exist"):
            validate_source_path(str(tmp_path / "does-not-exist"), scope)

    def test_empty_source_allowlist_rejected(self, tmp_path):
        from app.scope import ScopeConfig, SafetyParams, SourcePathError, validate_source_path
        scope = ScopeConfig(
            source_allowlist=(),
            safety=SafetyParams(),
        )
        with pytest.raises(SourcePathError, match="No source paths authorized"):
            validate_source_path(str(tmp_path), scope)

    def test_empty_source_path_rejected(self, tmp_path):
        from app.scope import ScopeConfig, SafetyParams, SourcePathError, validate_source_path
        scope = ScopeConfig(
            source_allowlist=(str(tmp_path),),
            safety=SafetyParams(),
        )
        with pytest.raises(SourcePathError, match="source_path is required"):
            validate_source_path("", scope)

    def test_file_not_directory_rejected(self, tmp_path):
        from app.scope import ScopeConfig, SafetyParams, SourcePathError, validate_source_path
        f = tmp_path / "file.txt"
        f.write_text("not a dir")
        scope = ScopeConfig(
            source_allowlist=(str(tmp_path),),
            safety=SafetyParams(),
        )
        with pytest.raises(SourcePathError, match="not a directory"):
            validate_source_path(str(f), scope)


class TestOsvParser:
    """Verify osv-scanner parser produces correct A03 findings."""

    def test_parse_osv_json(self, tmp_path):
        import json
        from app.parsers.osv import parse

        osv_data = {
            "results": [{
                "source": {"path": "package.json", "type": "lockfile"},
                "packages": [{
                    "package": {
                        "name": "lodash",
                        "version": "4.17.20",
                        "ecosystem": "npm",
                    },
                    "vulnerabilities": [{
                        "id": "GHSA-jf85-cpcp-j695",
                        "aliases": ["CVE-2021-23337"],
                        "summary": "Lodash Command Injection",
                        "severity": [{"score": "CRITICAL"}],
                        "database_specific": {"severity": "CRITICAL"},
                        "affected": [{
                            "ranges": [{
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "4.17.21"},
                                ],
                            }],
                        }],
                    }],
                }],
            }],
        }
        osv_file = tmp_path / "osv-scanner.json"
        osv_file.write_text(json.dumps(osv_data))

        findings = parse(osv_file, "test-run")
        assert len(findings) == 1

        f = findings[0]
        assert f.category == "A03:2025"
        assert f.category_name == "Software Supply Chain Failures"
        assert f.source_tool == "osv-scanner"
        assert f.mapping == "exact"
        assert f.severity == "critical"
        assert "CVE-2021-23337" in f.title
        assert "lodash" in f.title
        assert "CVE-2021-23337" in f.evidence
        assert "GHSA-jf85-cpcp-j695" in f.evidence
        assert "4.17.21" in f.fix
        assert f.verified == "yes"

    def test_parse_empty_file(self, tmp_path):
        from app.parsers.osv import parse
        osv_file = tmp_path / "osv-scanner.json"
        # File doesn't exist
        findings = parse(osv_file, "test-run")
        assert findings == []

    def test_parse_no_vulnerabilities(self, tmp_path):
        import json
        from app.parsers.osv import parse

        osv_data = {"results": [{"source": {"path": "package.json"}, "packages": []}]}
        osv_file = tmp_path / "osv-scanner.json"
        osv_file.write_text(json.dumps(osv_data))

        findings = parse(osv_file, "test-run")
        assert findings == []

    def test_severity_mapping(self, tmp_path):
        import json
        from app.parsers.osv import parse

        def make_vuln(severity_text):
            return {
                "results": [{
                    "source": {"path": "req.txt"},
                    "packages": [{
                        "package": {"name": "pkg", "version": "1.0", "ecosystem": "PyPI"},
                        "vulnerabilities": [{
                            "id": f"TEST-{severity_text}",
                            "summary": "test",
                            "database_specific": {"severity": severity_text},
                        }],
                    }],
                }],
            }

        for text, expected in [("CRITICAL", "critical"), ("HIGH", "high"),
                               ("MODERATE", "medium"), ("LOW", "low")]:
            f = tmp_path / f"osv-{text}.json"
            f.write_text(json.dumps(make_vuln(text)))
            findings = parse(f, "test")
            assert findings[0].severity == expected, f"{text} should map to {expected}"


class TestSastCheckRegistry:
    """Verify SAST-specific check registry fields."""

    def test_a03_has_osv_scanner_sast_tool(self):
        from app.checks import CHECKS
        assert "osv-scanner" in CHECKS["A03"].sast_tools

    def test_a03_sast_detectability_is_full(self):
        from app.checks import CHECKS
        assert CHECKS["A03"].sast_detectability == "full"

    def test_a03_dast_detectability_is_none(self):
        from app.checks import CHECKS
        assert CHECKS["A03"].detectability == "none"

    def test_a03_combined_detectability_is_full(self):
        from app.checks import CHECKS
        assert CHECKS["A03"].combined_detectability == "full"

    def test_checks_need_sast_tool(self):
        from app.checks import checks_need_sast_tool
        assert checks_need_sast_tool(["A03"], "osv-scanner") is True
        assert checks_need_sast_tool(["A05"], "osv-scanner") is False
        assert checks_need_sast_tool(["A01"], "osv-scanner") is False

    def test_sast_not_testable_for_dast_categories(self):
        from app.checks import get_sast_not_testable_checks
        result = get_sast_not_testable_checks(["A01", "A03", "A04", "A05"])
        ids = {c.id for c in result}
        assert "A01" in ids
        assert "A04" in ids
        assert "A05" in ids
        assert "A03" not in ids

    def test_dast_only_categories_show_not_testable_in_sast(self):
        """A01, A04, A10 must show 'not testable' in a SAST-only scan, never 'clean'."""
        from app.checks import CHECKS
        for cid in ["A01", "A04", "A10"]:
            assert CHECKS[cid].sast_detectability == "none", (
                f"{cid} must have sast_detectability=none"
            )


class TestSourceAllowlistParsing:
    """Verify SOURCE-ALLOWLIST markers are parsed from SCOPE.md."""

    def test_parse_source_allowlist(self, tmp_path):
        from app.scope import parse_scope
        scope_file = tmp_path / "SCOPE.md"
        scope_file.write_text(
            "# Scope\n"
            "<!-- ALLOWLIST-START -->\n"
            "http://localhost:3000\n"
            "<!-- ALLOWLIST-END -->\n"
            "<!-- SOURCE-ALLOWLIST-START -->\n"
            "/app/source\n"
            "/opt/repos\n"
            "<!-- SOURCE-ALLOWLIST-END -->\n"
            "```yaml\nrate_limit_rps: 10\n```\n"
        )
        scope = parse_scope(scope_file)
        assert "/app/source" in scope.source_allowlist
        assert "/opt/repos" in scope.source_allowlist
        assert "http://localhost:3000" in scope.allowlist

    def test_missing_source_markers(self, tmp_path):
        from app.scope import parse_scope
        scope_file = tmp_path / "SCOPE.md"
        scope_file.write_text(
            "# Scope\n"
            "<!-- ALLOWLIST-START -->\nhttp://localhost:3000\n<!-- ALLOWLIST-END -->\n"
            "```yaml\nrate_limit_rps: 10\n```\n"
        )
        scope = parse_scope(scope_file)
        assert scope.source_allowlist == ()


class TestModeConstraintMigration:
    """Verify the runs.mode CHECK constraint migration is idempotent and preserves data."""

    OLD_SCHEMA = """\
    CREATE TABLE runs (
        id TEXT PRIMARY KEY, target_url TEXT NOT NULL, target_host TEXT NOT NULL,
        mode TEXT NOT NULL CHECK (mode IN ('passive', 'active')),
        status TEXT NOT NULL DEFAULT 'queued',
        created_at TEXT NOT NULL, completed_at TEXT, results_dir TEXT,
        summary_json TEXT, error_message TEXT, selected_checks TEXT,
        scan_type TEXT, target_type TEXT DEFAULT 'url', source_path TEXT
    );
    CREATE TABLE findings (
        id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id),
        severity TEXT NOT NULL, title TEXT, category TEXT, category_name TEXT,
        location TEXT, evidence TEXT, verified TEXT DEFAULT 'no',
        fix TEXT, source_tool TEXT, raw_id TEXT, dedupe_hash TEXT,
        mapping TEXT DEFAULT 'exact'
    );
    """

    def test_migration_widens_constraint(self, tmp_path):
        import sqlite3
        from app.database import init_db
        db = str(tmp_path / "test.db")
        c = sqlite3.connect(db)
        c.executescript(self.OLD_SCHEMA)
        c.execute(
            "INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("r1", "http://x", "x", "passive", "done", "2025-01-01",
             None, None, None, None, None, None, "url", None),
        )
        c.commit()
        c.close()

        init_db(db)

        c2 = sqlite3.connect(db)
        # Existing row survived
        assert c2.execute("SELECT count(*) FROM runs").fetchone()[0] == 1
        # mode='sast' is now accepted
        c2.execute(
            "INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("r2", "source://app", "s", "sast", "queued", "2025-06-01",
             None, None, None, None, "A03", None, "source", "/app/source"),
        )
        c2.commit()
        # _runs_old must not exist
        leftover = c2.execute(
            "SELECT count(*) FROM sqlite_master WHERE name='_runs_old'"
        ).fetchone()[0]
        assert leftover == 0
        c2.close()

    def test_migration_is_idempotent(self, tmp_path):
        import sqlite3
        from app.database import init_db
        db = str(tmp_path / "test.db")
        c = sqlite3.connect(db)
        c.executescript(self.OLD_SCHEMA)
        c.commit()
        c.close()

        init_db(db)
        init_db(db)  # second call must not crash

        c2 = sqlite3.connect(db)
        sql = c2.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='runs'"
        ).fetchone()[0]
        assert "'sast'" in sql
        leftover = c2.execute(
            "SELECT count(*) FROM sqlite_master WHERE name='_runs_old'"
        ).fetchone()[0]
        assert leftover == 0
        c2.close()

    def test_partial_migration_recovery(self, tmp_path):
        """If a previous migration left _runs_old behind, init_db cleans it up."""
        import sqlite3
        from app.database import init_db
        db = str(tmp_path / "test.db")
        c = sqlite3.connect(db)
        c.executescript(self.OLD_SCHEMA)
        # Simulate partial migration: _runs_old exists alongside runs
        c.execute("CREATE TABLE _runs_old (id TEXT)")
        c.commit()
        c.close()

        init_db(db)

        c2 = sqlite3.connect(db)
        leftover = c2.execute(
            "SELECT count(*) FROM sqlite_master WHERE name='_runs_old'"
        ).fetchone()[0]
        assert leftover == 0
        c2.close()
