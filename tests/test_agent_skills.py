"""
Unit tests for Milestone 9: Agent Skills Autonomous Lifecycle Integration.
Covers FiveAxisTriageEngine, Trust Boundary Scoring, STRIDE/OWASP metadata,
Verifier Conventional Commit scope synthesis & reproducer validation,
Git Manager scoped atomic branch creation, and prompt stop-the-line protocol.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
import pytest

from src.git_manager import GitManager
from src.static_scanner import FiveAxisTriageEngine, StaticScanner
from src.verifier import Verifier, ConventionalTitle


# =========================================================================
# 1. FiveAxisTriageEngine: 5-Axis Triage Ranking & Readability Filtering
# =========================================================================

def test_five_axis_weights_and_ordering():
    """Verify base weights: Correctness (100), Security (100), Performance (60), Architecture (40), Readability (0)."""
    engine = FiveAxisTriageEngine()

    assert engine.AXIS_WEIGHTS[engine.AXIS_CORRECTNESS] == 100
    assert engine.AXIS_WEIGHTS[engine.AXIS_SECURITY] == 100
    assert engine.AXIS_WEIGHTS[engine.AXIS_PERFORMANCE] == 60
    assert engine.AXIS_WEIGHTS[engine.AXIS_ARCHITECTURE] == 40
    assert engine.AXIS_WEIGHTS[engine.AXIS_READABILITY] == 0


def test_five_axis_triage_ranking_ordering():
    """Verify correct ordering: Correctness & Security outrank Performance & Architecture."""
    engine = FiveAxisTriageEngine()

    f_corr = {"rule_id": "F821", "severity": "WARNING", "file": "src/app.py", "message": "Undefined variable x"}
    f_sec = {"rule_id": "S101", "severity": "WARNING", "file": "src/app.py", "message": "Use of assert detected"}
    f_perf = {"rule_id": "PERF101", "severity": "WARNING", "file": "src/app.py", "message": "Unnecessary list cast"}
    f_arch = {"rule_id": "C901", "severity": "WARNING", "file": "src/app.py", "message": "Function is too complex"}

    t_corr = engine.evaluate_finding(f_corr)
    t_sec = engine.evaluate_finding(f_sec)
    t_perf = engine.evaluate_finding(f_perf)
    t_arch = engine.evaluate_finding(f_arch)

    assert t_corr["primary_axis"] == "correctness"
    assert t_sec["primary_axis"] == "security"
    assert t_perf["primary_axis"] == "performance"
    assert t_arch["primary_axis"] == "architecture"

    # Correctness and Security (100) > Performance (60) > Architecture (40)
    assert t_corr["composite_score"] == 100.0
    assert t_sec["composite_score"] == 100.0
    assert t_perf["composite_score"] == 60.0
    assert t_arch["composite_score"] == 40.0
    assert t_corr["composite_score"] > t_perf["composite_score"] > t_arch["composite_score"]


def test_severity_multipliers_preserve_hierarchical_order():
    """Verify Correctness/Security WARNING (100) > Performance ERROR (90) > Architecture ERROR (60)."""
    engine = FiveAxisTriageEngine()

    f_sec_warn = {"rule_id": "S101", "severity": "WARNING", "file": "src/app.py", "message": "Insecure call"}
    f_perf_err = {"rule_id": "PERF101", "severity": "ERROR", "file": "src/app.py", "message": "Slow loop"}
    f_arch_err = {"rule_id": "C901", "severity": "ERROR", "file": "src/app.py", "message": "Complex class"}

    t_sec_warn = engine.evaluate_finding(f_sec_warn)
    t_perf_err = engine.evaluate_finding(f_perf_err)
    t_arch_err = engine.evaluate_finding(f_arch_err)

    # 100 * 1.0 = 100; 60 * 1.5 = 90; 40 * 1.5 = 60
    assert t_sec_warn["composite_score"] == 100.0
    assert t_perf_err["composite_score"] == 90.0
    assert t_arch_err["composite_score"] == 60.0
    assert t_sec_warn["composite_score"] > t_perf_err["composite_score"] > t_arch_err["composite_score"]


def test_filtering_of_readability_noise(tmp_path: Path):
    """Verify that all cosmetic Readability findings (E501, docstrings, whitespace, formatting, import ordering, comments) are dropped."""
    scanner = StaticScanner(timeout_seconds=60, max_findings=10)
    repo = tmp_path / "repo_readability"
    repo.mkdir()

    cosmetic_findings = [
        {"tool": "ruff", "rule_id": "E501", "severity": "WARNING", "file": "src/a.py", "line": 1, "column": 1, "message": "Line too long (120 > 88)"},
        {"tool": "ruff", "rule_id": "D101", "severity": "WARNING", "file": "src/b.py", "line": 2, "column": 1, "message": "Missing docstring in public class"},
        {"tool": "ruff", "rule_id": "I001", "severity": "WARNING", "file": "src/c.py", "line": 3, "column": 1, "message": "Import block is unsorted or unformatted"},
        {"tool": "ruff", "rule_id": "W291", "severity": "WARNING", "file": "src/d.py", "line": 4, "column": 1, "message": "Trailing whitespace"},
        {"tool": "ruff", "rule_id": "Q000", "severity": "WARNING", "file": "src/e.py", "line": 5, "column": 1, "message": "Single quotes found but double quotes preferred"},
        {"tool": "ruff", "rule_id": "COM812", "severity": "WARNING", "file": "src/f.py", "line": 6, "column": 1, "message": "Missing trailing comma"},
        {"tool": "ruff", "rule_id": "N802", "severity": "WARNING", "file": "src/g.py", "line": 7, "column": 1, "message": "Function name MyFunc should be lowercase"},
        {"tool": "ruff", "rule_id": "ERA001", "severity": "WARNING", "file": "src/h.py", "line": 8, "column": 1, "message": "Found commented-out code"},
        # Only one real functional bug:
        {"tool": "ruff", "rule_id": "F821", "severity": "ERROR", "file": "src/real.py", "line": 9, "column": 1, "message": "Undefined variable foo"}
    ]

    out_file = scanner.run_static_prefilter(repo, skip_files=[], simulated_findings=cosmetic_findings)
    assert out_file.exists()
    findings = json.loads(out_file.read_text(encoding="utf-8"))

    # All 8 cosmetic findings must be dropped; only 1 genuine finding reaches OpenHands
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "F821"
    assert findings[0]["triage"]["primary_axis"] == "correctness"


# =========================================================================
# 2. Trust Boundary Scoring (+30 Elevation)
# =========================================================================

def test_trust_boundary_path_detection():
    """Verify detection of boundary paths: web_server.py, api/, routes/, cli.py, main.py."""
    engine = FiveAxisTriageEngine()

    assert engine.is_trust_boundary("src/web_server.py") is True
    assert engine.is_trust_boundary("web_server.py") is True
    assert engine.is_trust_boundary("src/api/v1/auth.py") is True
    assert engine.is_trust_boundary("api/endpoints.py") is True
    assert engine.is_trust_boundary("src/routes/users.py") is True
    assert engine.is_trust_boundary("routes/index.py") is True
    assert engine.is_trust_boundary("src/cli.py") is True
    assert engine.is_trust_boundary("cli.py") is True
    assert engine.is_trust_boundary("src/main.py") is True
    assert engine.is_trust_boundary("main.py") is True

    # Internal modules should NOT be trust boundaries
    assert engine.is_trust_boundary("src/database.py") is False
    assert engine.is_trust_boundary("src/logger.py") is False
    assert engine.is_trust_boundary("src/config.py") is False
    assert engine.is_trust_boundary("tests/test_server.py") is False


def test_trust_boundary_score_elevation(tmp_path: Path):
    """Verify that findings in trust boundary files receive a +30 score elevation."""
    scanner = StaticScanner(timeout_seconds=60, max_findings=10)
    repo = tmp_path / "repo_boundary"
    repo.mkdir()

    # Identical severity and rule, but one is in web_server.py and one is in internal database.py
    findings_input = [
        {"tool": "ruff", "rule_id": "B006", "severity": "WARNING", "file": "src/database.py", "line": 10, "column": 1, "message": "Mutable default argument"},
        {"tool": "ruff", "rule_id": "B006", "severity": "WARNING", "file": "src/web_server.py", "line": 10, "column": 1, "message": "Mutable default argument"},
    ]

    out_file = scanner.run_static_prefilter(repo, skip_files=[], simulated_findings=findings_input)
    results = json.loads(out_file.read_text(encoding="utf-8"))

    assert len(results) == 2
    # web_server.py finding must rank FIRST due to +30 boundary elevation
    assert results[0]["file"] == "src/web_server.py"
    assert results[0]["triage"]["is_boundary_exposed"] is True
    assert results[0]["triage"]["boundary_bonus"] == 30
    assert results[0]["triage"]["composite_score"] == 130.0  # 100 * 1.0 + 30

    assert results[1]["file"] == "src/database.py"
    assert results[1]["triage"]["is_boundary_exposed"] is False
    assert results[1]["triage"]["boundary_bonus"] == 0
    assert results[1]["triage"]["composite_score"] == 100.0  # 100 * 1.0 + 0


# =========================================================================
# 3. STRIDE & OWASP Metadata Enrichment
# =========================================================================

def test_stride_and_owasp_mapping():
    """Verify accurate STRIDE threat and OWASP Top 10 category assignment."""
    engine = FiveAxisTriageEngine()

    # 1. Path Traversal -> Elevation of Privilege & A01:Broken Access Control
    s1, o1 = engine.classify_stride_and_owasp("semgrep-path", "Path traversal vulnerability in open()")
    assert s1 == "Elevation of Privilege"
    assert o1 == "A01:2021-Broken Access Control"

    # 2. Injection -> Tampering & A03:Injection
    s2, o2 = engine.classify_stride_and_owasp("S608", "Possible SQL injection vector via string formatting")
    assert s2 == "Tampering"
    assert o2 == "A03:2021-Injection"

    # 3. Secrets / Token Leak -> Information Disclosure & A02:Cryptographic Failures
    s3, o3 = engine.classify_stride_and_owasp("S105", "Hardcoded password or secret token detected")
    assert s3 == "Information Disclosure"
    assert o3 == "A02:2021-Cryptographic Failures"

    # 4. Authentication / JWT -> Spoofing & A07:Identification and Authentication Failures
    s4, o4 = engine.classify_stride_and_owasp("sec-auth", "JWT token signature validation bypass")
    assert s4 == "Spoofing"
    assert o4 == "A07:2021-Identification and Authentication Failures"

    # 5. DoS / Regex -> Denial of Service & A05:Security Misconfiguration
    s5, o5 = engine.classify_stride_and_owasp("redos", "Unbounded regex leads to denial of service")
    assert s5 == "Denial of Service"
    assert o5 == "A05:2021-Security Misconfiguration"

    # 6. Deserialization -> Tampering & A08:Software and Data Integrity Failures
    s6, o6 = engine.classify_stride_and_owasp("S301", "Unsafe pickle deserialization")
    assert s6 == "Tampering"
    assert o6 == "A08:2021-Software and Data Integrity Failures"


def test_stride_and_owasp_enrichment_in_findings_file(tmp_path: Path):
    """Verify that .static_findings.json contains STRIDE and OWASP fields."""
    scanner = StaticScanner(timeout_seconds=60, max_findings=10)
    repo = tmp_path / "repo_stride"
    repo.mkdir()

    findings_input = [
        {"tool": "semgrep", "rule_id": "path-traversal", "severity": "ERROR", "file": "src/web_server.py", "line": 20, "column": 5, "message": "Unsanitized path directory traversal"}
    ]

    out_file = scanner.run_static_prefilter(repo, skip_files=[], simulated_findings=findings_input)
    results = json.loads(out_file.read_text(encoding="utf-8"))

    assert len(results) == 1
    f = results[0]
    assert f["stride_category"] == "Elevation of Privilege"
    assert f["owasp_category"] == "A01:2021-Broken Access Control"
    assert f["triage"]["stride_category"] == "Elevation of Privilege"
    assert f["triage"]["owasp_category"] == "A01:2021-Broken Access Control"


# =========================================================================
# 4. Snippet Context Extraction
# =========================================================================

def test_snippet_context_extraction(tmp_path: Path):
    """Verify snippet context extraction reads 2 lines before and 2 lines after target line."""
    engine = FiveAxisTriageEngine()
    source_file = tmp_path / "sample.py"
    content = "\n".join([f"line_{i}" for i in range(1, 11)])  # 10 lines: line_1 to line_10
    source_file.write_text(content, encoding="utf-8")

    # Target line 5: should capture line 3, line 4, line 5, line 6, line 7
    snippet = engine.extract_snippet_context(tmp_path, "sample.py", line_no=5, context_lines=2)
    expected = "\n".join(["line_3", "line_4", "line_5", "line_6", "line_7"])
    assert snippet == expected

    # Target line 1: should capture line 1, line 2, line 3
    snippet_start = engine.extract_snippet_context(tmp_path, "sample.py", line_no=1, context_lines=2)
    assert snippet_start == "\n".join(["line_1", "line_2", "line_3"])


# =========================================================================
# 5. Verifier: Conventional Commit Validation & Auto-Synthesis
# =========================================================================

def test_verifier_conventional_commit_validation():
    """Verify conventional commit validation for fix(<scope>): <description> format."""
    verifier = Verifier()

    # Valid format
    assert verifier.validate_conventional_commit("fix(database): fix connection leak") is True
    assert verifier.validate_conventional_commit("fix(web_server): sanitize path input") is True
    assert verifier.validate_conventional_commit("fix(api-v1): handle timeout") is True

    # Missing scope
    assert verifier.validate_conventional_commit("fix: fix connection leak") is False
    assert verifier.validate_conventional_commit("fix(): fix connection leak") is False

    # Invalid type or structure
    assert verifier.validate_conventional_commit("feat(database): add new table") is False
    assert verifier.validate_conventional_commit("chore: update deps") is False
    assert verifier.validate_conventional_commit("") is False


def test_verifier_scope_synthesis():
    """Verify auto-synthesis of scope from file_modified paths."""
    verifier = Verifier()

    assert verifier.synthesize_scope("src/database.py") == "database"
    assert verifier.synthesize_scope("src/web_server.py") == "web_server"
    assert verifier.synthesize_scope("src/api/auth.py") == "auth"
    assert verifier.synthesize_scope("cli.py") == "cli"
    assert verifier.synthesize_scope("main.py") == "main"
    assert verifier.synthesize_scope("") == "core"


def test_verifier_synthesize_conventional_title():
    """Verify synthesis of conventional title when scope is omitted."""
    verifier = Verifier()

    # When scope is already present, preserve it
    t1 = verifier.synthesize_conventional_title("fix(auth): handle token expiry", "src/database.py")
    assert t1 == "fix(auth): handle token expiry"

    # When scope is missing from "fix: <desc>", synthesize from file
    t2 = verifier.synthesize_conventional_title("fix: resolve connection leak", "src/database.py")
    assert t2 == "fix(database): resolve connection leak"

    # When title has no prefix, add fix(<scope>):
    t3 = verifier.synthesize_conventional_title("sanitize file path", "src/web_server.py")
    assert t3 == "fix(web_server): sanitize file path"

    # When title is empty, use default atomic patch description
    t4 = verifier.synthesize_conventional_title("", "src/database.py")
    assert t4 == "fix(database): automated atomic patch"


def test_verifier_verify_and_sanitize_conventional_commit(tmp_path: Path):
    """Verify verify_and_sanitize_fix populates conventional title and scope."""
    verifier = Verifier()
    diff = "--- a/src/database.py\n+++ b/src/database.py\n@@ -1,1 +1,2 @@\n-x = 1\n+x = 2\n"
    report = {
        "bug_found": True,
        "files_modified": ["src/database.py"],
        "pr_title": "fix: prevent connection leak",
        "pr_body": "Fixed leak"
    }

    res = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path,
        skip_files=[],
        simulated_report=report,
        custom_diff=diff
    )

    assert res.verified is True
    assert res.scope == "database"
    assert res.conventional_pr_title == "fix(database): prevent connection leak"
    # pr_title ConventionalTitle satisfies conventional commit pattern
    assert verifier.validate_conventional_commit(res.pr_title) is True


# =========================================================================
# 6. Verifier: Reproducer Fields Validation
# =========================================================================

def test_verifier_validate_reproducer_fields():
    """Verify validation of reproducer_test_path and reproducer_verified_red fields."""
    verifier = Verifier()

    # 1. Valid report: path provided and red verified -> PASS
    rep_valid = {
        "bug_found": True,
        "reproducer_test_path": "tests/test_repro_leak.py",
        "reproducer_verified_red": True
    }
    ok, err = verifier.validate_reproducer_fields(rep_valid)
    assert ok is True
    assert err is None

    # 2. Missing reproducer_test_path -> FAIL
    rep_no_path = {
        "bug_found": True,
        "reproducer_verified_red": True
    }
    ok, err = verifier.validate_reproducer_fields(rep_no_path)
    assert ok is False
    assert "reproducer test path missing" in err

    # 3. reproducer_verified_red is False -> FAIL
    rep_not_red = {
        "bug_found": True,
        "reproducer_test_path": "tests/test_repro_leak.py",
        "reproducer_verified_red": False
    }
    ok, err = verifier.validate_reproducer_fields(rep_not_red)
    assert ok is False
    assert "verified failing (RED)" in err

    # 4. Clean run (bug_found: False) -> PASS without reproducer
    rep_clean = {"bug_found": False}
    ok, err = verifier.validate_reproducer_fields(rep_clean)
    assert ok is True


def test_verifier_reproducer_enforcement_in_pipeline(tmp_path: Path):
    """Verify that verify_and_sanitize_fix enforces reproducer validation when required."""
    verifier = Verifier()
    diff = "--- a/src/app.py\n+++ b/src/app.py\n@@ -1,1 +1,2 @@\n-a = 1\n+a = 2\n"

    # Report with failing red verification must be rejected
    rep_fail = {
        "bug_found": True,
        "files_modified": ["src/app.py"],
        "reproducer_test_path": "tests/test_repro.py",
        "reproducer_verified_red": False
    }
    res_fail = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path,
        skip_files=[],
        simulated_report=rep_fail,
        custom_diff=diff
    )
    assert res_fail.verified is False
    assert "Stop-the-Line Violation" in res_fail.error_reason

    # Report with valid reproducer passes
    rep_pass = {
        "bug_found": True,
        "files_modified": ["src/app.py"],
        "reproducer_test_path": "tests/test_repro.py",
        "reproducer_verified_red": True
    }
    res_pass = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path,
        skip_files=[],
        simulated_report=rep_pass,
        custom_diff=diff
    )
    assert res_pass.verified is True


# =========================================================================
# 7. GitManager: Scoped Atomic Branch Generation
# =========================================================================

def test_git_manager_scoped_atomic_branch(tmp_path: Path):
    """Verify scoped atomic branch format fix/{prefix}-{scope}-{repo_short}-{hex6} and fallback."""
    gm = GitManager(workspace_dir=tmp_path)
    repo_path, _, _ = gm.sync_repository("owner/skills-repo", allow_init=True)

    # 1. When scope is given: fix/auto-database-<repo_short>-<hex6>
    branch_scoped = gm.create_atomic_branch(repo_path, prefix="auto", scope="database")
    assert branch_scoped.startswith("fix/auto-database-")
    # Repo short for repo_path is repo_path.name[:8]
    assert repo_path.name[:8] in branch_scoped

    # Verify branch is checked out
    p = subprocess.run(["git", "branch", "--show-current"], cwd=repo_path, capture_output=True, text=True, check=True)
    assert p.stdout.strip() == branch_scoped

    # 2. When scope is None: fix/auto-<repo_short>-<hex6>
    branch_unscoped = gm.create_atomic_branch(repo_path, prefix="auto", scope=None)
    assert branch_unscoped.startswith("fix/auto-")
    assert "database" not in branch_unscoped

    # 3. Special characters in scope are sanitized
    branch_sanitized = gm.create_atomic_branch(repo_path, prefix="auto", scope="web/server@api")
    assert branch_sanitized.startswith("fix/auto-webserverapi-")


# =========================================================================
# 8. Prompts: Stop-the-Line & Regression Reproducer Mandate
# =========================================================================

def test_task_prompt_stop_the_line_content():
    """Verify prompts/task_prompt.txt embeds Stop-the-Line protocol, conventional commits, and reproducer schema."""
    prompt_path = Path("prompts/task_prompt.txt")
    assert prompt_path.is_file()
    content = prompt_path.read_text(encoding="utf-8")

    # Stop-the-Line Protocol
    assert "STOP-THE-LINE PROTOCOL" in content
    assert "REPRODUCE (RED PHASE)" in content
    assert "reproducer_verified_red" in content
    assert "FIX ROOT CAUSE (GREEN PHASE)" in content
    assert "reproducer_verified_green" in content

    # Conventional commits and diff bounds
    assert "fix(<scope>): <description>" in content
    assert "3 files" in content
    assert "150 lines" in content
    assert "code-simplification" in content


# =========================================================================
# 9. Triage Hardening & Remediation Tests (Milestone 9 Iteration 2)
# =========================================================================

def test_cosmetic_comment_rules_dropped_from_triage(tmp_path: Path):
    """Verify FIX (flake8-fixme), PGH (pygrep-hooks), TD (flake8-todos), and message-based TODOs are filtered as Readability."""
    engine = FiveAxisTriageEngine()
    scanner = StaticScanner(timeout_seconds=30, max_findings=10)

    # 1. Direct classification assertions
    assert engine.classify_axis("FIX001", "Line contains FIXME") == "readability"
    assert engine.classify_axis("FIX002", "Line contains TODO") == "readability"
    assert engine.classify_axis("FIX003", "Line contains XXX") == "readability"
    assert engine.classify_axis("FIX004", "Line contains HACK") == "readability"
    assert engine.classify_axis("PGH001", "Noqa directive without rule code") == "readability"
    assert engine.classify_axis("TD002", "Missing author in TODO") == "readability"
    assert engine.classify_axis("CUSTOM_RULE", "Please fixme before commit") == "readability"

    # Pyflakes correctness must remain unaffected
    assert engine.classify_axis("F821", "Undefined name x") == "correctness"
    assert engine.classify_axis("F401", "Unused import sys") == "correctness"

    # 2. Scanner end-to-end filtering: 100% cosmetic comment noise dropped
    repo = tmp_path / "repo_comments"
    repo.mkdir()

    findings = [
        {"tool": "ruff", "rule_id": "FIX002", "severity": "WARNING", "file": "src/a.py", "line": 1, "message": "Line contains TODO"},
        {"tool": "ruff", "rule_id": "PGH001", "severity": "WARNING", "file": "src/b.py", "line": 2, "message": "Noqa without rule"},
        {"tool": "ruff", "rule_id": "TD002", "severity": "WARNING", "file": "src/c.py", "line": 3, "message": "Missing author in TODO"},
        {"tool": "ruff", "rule_id": "F821", "severity": "ERROR", "file": "src/d.py", "line": 4, "message": "Undefined variable foo"}
    ]

    out = scanner.run_static_prefilter(repo, skip_files=[], simulated_findings=findings)
    results = json.loads(out.read_text(encoding="utf-8"))

    # Only F821 should survive; all 3 comment rules must be dropped
    assert len(results) == 1
    assert results[0]["rule_id"] == "F821"
    assert results[0]["primary_axis"] == "correctness"


def test_trust_boundary_windows_casing_and_backslashes():
    """Verify trust boundary detection with Windows path casing and backslashes."""
    engine = FiveAxisTriageEngine()

    # Uppercase and mixed-case paths on Windows (Defect 3)
    assert engine.is_trust_boundary("src/API/routes.py") is True
    assert engine.is_trust_boundary("MAIN.PY") is True
    assert engine.is_trust_boundary("src/Web_Server.py") is True
    assert engine.is_trust_boundary("CLI.PY") is True
    assert engine.is_trust_boundary("src/ROUTES/auth.py") is True

    # Windows backslash paths
    assert engine.is_trust_boundary(r"src\web_server.py") is True
    assert engine.is_trust_boundary(r"src\api\v1\endpoints.py") is True
    assert engine.is_trust_boundary(r"C:\repo\src\api\routes.py") is True

    # Non-boundary preservation (no false positives)
    assert engine.is_trust_boundary("src/database.py") is False
    assert engine.is_trust_boundary("src/my_cli.py") is False
    assert engine.is_trust_boundary("src/submain.py") is False
    assert engine.is_trust_boundary("src/rapid_routes.py") is False

    # Safe null and type coercion
    assert engine.is_trust_boundary(None) is False
    assert engine.is_trust_boundary("") is False


def test_trust_boundary_score_elevation_with_casing(tmp_path: Path):
    """Verify that findings in uppercase/mixed-case trust boundary paths receive +30 elevation."""
    scanner = StaticScanner(timeout_seconds=60, max_findings=10)
    repo = tmp_path / "repo_boundary_casing"
    repo.mkdir()

    findings_input = [
        {"tool": "ruff", "rule_id": "B006", "severity": "WARNING", "file": "src/database.py", "line": 10, "column": 1, "message": "Mutable default argument"},
        {"tool": "ruff", "rule_id": "B006", "severity": "WARNING", "file": "src/API/routes.py", "line": 10, "column": 1, "message": "Mutable default argument"},
        {"tool": "ruff", "rule_id": "B006", "severity": "WARNING", "file": "MAIN.PY", "line": 5, "column": 1, "message": "Mutable default argument"},
    ]

    out_file = scanner.run_static_prefilter(repo, skip_files=[], simulated_findings=findings_input)
    results = json.loads(out_file.read_text(encoding="utf-8"))

    assert len(results) == 3
    # Top 2 findings must be the trust boundary files with +30 boundary elevation (130.0)
    assert results[0]["triage"]["boundary_bonus"] == 30
    assert results[0]["triage"]["composite_score"] == 130.0
    assert results[0]["triage"]["is_boundary_exposed"] is True

    assert results[1]["triage"]["boundary_bonus"] == 30
    assert results[1]["triage"]["composite_score"] == 130.0
    assert results[1]["triage"]["is_boundary_exposed"] is True

    # database.py finding must rank LAST (100.0)
    assert results[2]["file"] == "src/database.py"
    assert results[2]["triage"]["boundary_bonus"] == 0
    assert results[2]["triage"]["composite_score"] == 100.0

