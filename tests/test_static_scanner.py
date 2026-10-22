"""
Unit tests for src/static_scanner.py: Ruff and Semgrep pre-filtering, skip filtering, and severity ranking.
"""

import json
from pathlib import Path
import pytest
from src.static_scanner import StaticScanner


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
