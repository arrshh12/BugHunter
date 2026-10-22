"""
Unit tests for src/static_scanner.py: Ruff and Semgrep pre-filtering, skip filtering, and severity ranking.
"""

import json
from pathlib import Path
import pytest
from src.static_scanner import FiveAxisTriageEngine, StaticScanner


def test_static_scanner_simulated_findings(tmp_path: Path):
    """Verify static scanner compiles simulated findings into .static_findings.json."""
    scanner = StaticScanner(timeout_seconds=60, max_findings=10)
    repo = tmp_path / "repo1"
    repo.mkdir()

    simulated = [
        {"tool": "ruff", "rule_id": "F821", "severity": "ERROR", "file": "src/app.py", "line": 10, "column": 5, "message": "Undefined variable", "code_snippet": "x = y + 1"},
        {"tool": "semgrep", "rule_id": "sec-1", "severity": "WARNING", "file": "src/utils.py", "line": 20, "column": 8, "message": "Insecure hash", "code_snippet": "md5()"}
    ]

    out = scanner.run_static_prefilter(repo, skip_files=[], simulated_findings=simulated)
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data) == 2
    assert data[0]["severity"] == "ERROR"
    assert data[0]["rule_id"] == "F821"


def test_static_scanner_skip_files_filtering(tmp_path: Path):
    """Verify findings for files in skip_files are excluded."""
    scanner = StaticScanner(timeout_seconds=60, max_findings=10)
    repo = tmp_path / "repo2"
    repo.mkdir()

    simulated = [
        {"tool": "ruff", "rule_id": "F821", "severity": "ERROR", "file": "src/locked.py", "line": 10, "column": 1, "message": "Err in locked"},
        {"tool": "ruff", "rule_id": "F822", "severity": "ERROR", "file": "src/free.py", "line": 12, "column": 1, "message": "Err in free"}
    ]

    out = scanner.run_static_prefilter(repo, skip_files=["src/locked.py"], simulated_findings=simulated)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data) == 1
    assert data[0]["file"] == "src/free.py"


def test_static_scanner_style_suppression_and_ranking(tmp_path: Path):
    """Verify E501 line-length rules are suppressed and items are ranked ERROR > WARNING > INFO."""
    scanner = StaticScanner(timeout_seconds=60, max_findings=2)
    repo = tmp_path / "repo3"
    repo.mkdir()

    simulated = [
        {"tool": "ruff", "rule_id": "E501", "severity": "WARNING", "file": "src/a.py", "line": 1, "column": 1, "message": "Line too long"},
        {"tool": "ruff", "rule_id": "W101", "severity": "WARNING", "file": "src/b.py", "line": 2, "column": 1, "message": "Warning b"},
        {"tool": "ruff", "rule_id": "E999", "severity": "ERROR", "file": "src/c.py", "line": 3, "column": 1, "message": "Syntax error"},
        {"tool": "ruff", "rule_id": "I001", "severity": "INFO", "file": "src/d.py", "line": 4, "column": 1, "message": "Info d"}
    ]

    out = scanner.run_static_prefilter(repo, skip_files=[], simulated_findings=simulated)
    data = json.loads(out.read_text(encoding="utf-8"))
    # E501 excluded, capped at max_findings=2
    assert len(data) == 2
    assert data[0]["severity"] == "ERROR"
    assert data[1]["severity"] == "WARNING"


def test_five_axis_triage_hardening_r1():
    """Verify that Security and Correctness rules are prioritized and strict regexes prevent misclassification (R1)."""
    engine = FiveAxisTriageEngine()

    # Security rules must not be misclassified as Readability
    assert engine.classify_axis("INJECTION", "User input concatenated to query") == "security"
    assert engine.classify_axis("INSECURE_CIPHER", "DES cipher used") == "security"
    assert engine.classify_axis("INSECURE_COOKIE", "Cookie missing Secure flag") == "security"
    assert engine.classify_axis("COMMAND_INJECTION", "os.system call with unsanitized args") == "security"

    # Additional security keyword tests
    assert engine.classify_axis("CUSTOM_RULE", "Use of insecure communication channel") == "security"
    assert engine.classify_axis("CIPHER_01", "Weak cipher algorithm selected") == "security"
    assert engine.classify_axis("COOKIE_01", "Session cookie missing HttpOnly") == "security"
    assert engine.classify_axis("AUTH_FAIL", "Broken authentication mechanism") == "security"
    assert engine.classify_axis("CRYPTO_ERR", "Deprecated crypto primitive") == "security"

    # Correctness rules must not be misclassified as Readability
    assert engine.classify_axis("NULL_POINTER", "Possible null pointer dereference") == "correctness"
    assert engine.classify_axis("NULL_DEREF", "Object may be null") == "correctness"
    assert engine.classify_axis("DANGLING_POINTER", "Invalid memory address access") == "correctness"

    # Legitimate Flake8 cosmetic codes must continue to be classified as Readability
    assert engine.classify_axis("I001", "Import block is unsorted") == "readability"
    assert engine.classify_axis("N802", "Function name should be lowercase") == "readability"
    assert engine.classify_axis("COM812", "Missing trailing comma") == "readability"
    assert engine.classify_axis("D101", "Missing docstring") == "readability"
    assert engine.classify_axis("Q000", "Single quotes found") == "readability"

    # Non-3-digit Flake8-like rule names must NOT match Readability
    assert engine.classify_axis("I99", "Special rule", severity="ERROR") == "correctness"
    assert engine.classify_axis("INSPECTION", "Generic inspection failure", severity="ERROR") == "correctness"


def test_static_scanner_prefilter_retains_hardened_rules(tmp_path: Path):
    """Verify that end-to-end static scanner retains INJECTION, INSECURE_CIPHER, COMMAND_INJECTION, NULL_POINTER while dropping I001, COM812, N802, D101, Q000."""
    scanner = StaticScanner(timeout_seconds=60, max_findings=10)
    repo = tmp_path / "repo_hardening"
    repo.mkdir()

    findings = [
        {"tool": "semgrep", "rule_id": "INJECTION", "severity": "ERROR", "file": "src/db.py", "line": 1, "message": "SQL injection"},
        {"tool": "semgrep", "rule_id": "INSECURE_CIPHER", "severity": "WARNING", "file": "src/crypto.py", "line": 2, "message": "Weak cipher"},
        {"tool": "semgrep", "rule_id": "COMMAND_INJECTION", "severity": "ERROR", "file": "src/exec.py", "line": 3, "message": "Command injection"},
        {"tool": "semgrep", "rule_id": "NULL_POINTER", "severity": "ERROR", "file": "src/core.py", "line": 4, "message": "Null pointer access"},
        {"tool": "ruff", "rule_id": "I001", "severity": "INFO", "file": "src/style.py", "line": 5, "message": "Unsorted imports"},
        {"tool": "ruff", "rule_id": "COM812", "severity": "WARNING", "file": "src/style.py", "line": 6, "message": "Missing comma"},
        {"tool": "ruff", "rule_id": "N802", "severity": "WARNING", "file": "src/style.py", "line": 7, "message": "Bad naming"},
        {"tool": "ruff", "rule_id": "D101", "severity": "WARNING", "file": "src/style.py", "line": 8, "message": "Missing docstring"},
        {"tool": "ruff", "rule_id": "Q000", "severity": "WARNING", "file": "src/style.py", "line": 9, "message": "Bad quotes"},
    ]

    out = scanner.run_static_prefilter(repo, skip_files=[], simulated_findings=findings)
    results = json.loads(out.read_text(encoding="utf-8"))

    # I001, COM812, N802, D101, Q000 must be dropped; the 4 functional/security findings must survive
    assert len(results) == 4
    surviving_rules = {f["rule_id"] for f in results}
    assert surviving_rules == {"INJECTION", "INSECURE_CIPHER", "COMMAND_INJECTION", "NULL_POINTER"}

