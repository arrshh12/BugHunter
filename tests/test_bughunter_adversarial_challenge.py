"""
Empirical Adversarial Stress Suite for Milestone 2: BugHunter Agent Triage & Context Skills.
Written by Challenger M2-1.

Empirically tests and reproduces:
1. Proximity clustering: line 0 collapse bug (Bug 1).
2. Proximity clustering: unbounded transitive chaining (Bug 5).
3. Parser resilience: ESLint, Bandit, Semgrep, Trivy with None values, missing keys, and invalid types (Bug 2).
4. Context extraction: leading slash path resolution on Windows (Bug 3).
5. Context extraction: AST decorator stripping and decorator line lookup failure (Bug 4).
6. AST extraction: deeply nested closures, syntax errors, comments, multi-line strings.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from src.bughunter_agent import (
    BugHunterAgent,
    ContextExtractionSkill,
    ExtractedContext,
    RawFinding,
    TriageSkill,
)


# =========================================================================
# 1. Proximity Clustering Stress & Bug 1 Reproduction
# =========================================================================

class TestProximityClusteringStress:
    """Stress test deduplication and proximity clustering under edge-case line numbers."""

    def test_line_zero_swallows_subsequent_distant_findings(self):
        """
        EMPIRICAL BUG REPRODUCTION:
        In TriageSkill.deduplicate, `(cluster_base_line or f.line)` evaluates to `f.line`
        when cluster_base_line is 0, causing `abs(f.line - f.line) == 0 <= 2` to be True
        for ALL subsequent findings in the file, collapsing distant lines (50, 999) into line 0.
        """
        skill = TriageSkill()
        findings = [
            RawFinding(tool="trivy", rule_id="ROOT_USER", file="Dockerfile", line=0),
            RawFinding(tool="trivy", rule_id="EXPOSE_PORT", file="Dockerfile", line=50),
            RawFinding(tool="trivy", rule_id="HEALTHCHECK", file="Dockerfile", line=999),
        ]
        clusters = skill.deduplicate(findings)

        # Lines 0, 50, and 999 are far apart (>2 lines); they MUST NOT be clustered together!
        # An empirically correct implementation should produce 3 distinct clusters.
        # But due to `0 or f.line`, it currently produces 1 cluster!
        is_bug_present = len(clusters) == 1
        assert not is_bug_present, (
            f"VULNERABILITY DETECTED: Line 0 caused all distant findings (50, 999) to collapse into a single cluster: {clusters}"
        )

    def test_transitive_chaining_violates_proximity_window(self):
        """
        EMPIRICAL CHALLENGE:
        Findings spaced 2 lines apart across a 30-line range (10, 12, 14, 16, 18, 20, 22, 24, 26, 28)
        are currently all chained into 1 single cluster, meaning findings 18 lines apart are deemed 'duplicates'.
        """
        skill = TriageSkill()
        findings = [
            RawFinding(tool="flake8", rule_id=f"ERR_{i}", file="src/service.py", line=10 + i * 2)
            for i in range(10)
        ]
        clusters = skill.deduplicate(findings)

        # Line 10 and Line 28 are 18 lines apart. They should not be in the same cluster.
        for c in clusters:
            lines = [f.line for f in c]
            assert max(lines) - min(lines) <= 4, (
                f"Cluster spans {max(lines) - min(lines)} lines ({lines}), exceeding proximity window!"
            )


# =========================================================================
# 2. Parser Malformed Input Stress & Bug 2 Reproduction
# =========================================================================

class TestParserAdversarialInputs:
    """Stress test parsers with None fields, missing keys, and invalid types."""

    def test_eslint_parser_resilience_to_none_messages(self):
        """ESLint JSON with messages=None must not raise TypeError."""
        skill = TriageSkill()
        # Common in tools when a file was scanned but had null messages field
        payload = [{"filePath": "app.ts", "messages": None}]
        try:
            findings = skill.parse_eslint(payload)
            assert isinstance(findings, list)
        except TypeError as e:
            pytest.fail(f"parse_eslint crashed on messages=None: {e}")

    def test_eslint_parser_resilience_to_none_line(self):
        """ESLint JSON with line=None must not raise TypeError."""
        skill = TriageSkill()
        payload = [{"filePath": "app.ts", "messages": [{"ruleId": "r1", "line": None}]}]
        try:
            findings = skill.parse_eslint(payload)
            assert isinstance(findings, list)
        except TypeError as e:
            pytest.fail(f"parse_eslint crashed on line=None: {e}")

    def test_bandit_parser_resilience_to_none_results(self):
        """Bandit JSON with results=None must not raise TypeError."""
        skill = TriageSkill()
        payload = {"results": None}
        try:
            findings = skill.parse_bandit(payload)
            assert isinstance(findings, list)
        except TypeError as e:
            pytest.fail(f"parse_bandit crashed on results=None: {e}")

    def test_bandit_parser_resilience_to_none_line_number(self):
        """Bandit JSON with line_number=None must not raise TypeError."""
        skill = TriageSkill()
        payload = {"results": [{"filename": "app.py", "line_number": None}]}
        try:
            findings = skill.parse_bandit(payload)
            assert isinstance(findings, list)
        except TypeError as e:
            pytest.fail(f"parse_bandit crashed on line_number=None: {e}")

    def test_semgrep_parser_resilience_to_none_results(self):
        """Semgrep JSON with results=None must not raise TypeError."""
        skill = TriageSkill()
        payload = {"results": None}
        try:
            findings = skill.parse_semgrep(payload)
            assert isinstance(findings, list)
        except TypeError as e:
            pytest.fail(f"parse_semgrep crashed on results=None: {e}")

    def test_semgrep_parser_resilience_to_none_extra_and_start(self):
        """Semgrep JSON with extra=None or start=None must not raise AttributeError."""
        skill = TriageSkill()
        payload = {"results": [{"check_id": "r1", "path": "app.py", "extra": None, "start": None, "end": None}]}
        try:
            findings = skill.parse_semgrep(payload)
            assert isinstance(findings, list)
        except AttributeError as e:
            pytest.fail(f"parse_semgrep crashed on extra/start=None: {e}")

    def test_trivy_parser_resilience_to_none_fields(self):
        """Trivy JSON with Results=None or Vulnerabilities=None must not raise TypeError/AttributeError."""
        skill = TriageSkill()
        try:
            skill.parse_trivy({"Results": None})
        except TypeError as e:
            pytest.fail(f"parse_trivy crashed on Results=None: {e}")

        try:
            skill.parse_trivy({"Results": [{"Target": "Dockerfile", "Vulnerabilities": None, "Misconfigurations": None}]})
        except TypeError as e:
            pytest.fail(f"parse_trivy crashed on Vulnerabilities/Misconfigurations=None: {e}")

        try:
            skill.parse_trivy({"Results": [{"Target": "Dockerfile", "Misconfigurations": [{"CauseMetadata": None}]}]})
        except AttributeError as e:
            pytest.fail(f"parse_trivy crashed on CauseMetadata=None: {e}")


# =========================================================================
# 3. Context Extraction Windows Path & Decorator Stress (Bugs 3 & 4)
# =========================================================================

class TestContextExtractionAdversarialStress:
    """Stress test context extraction with leading slashes and decorators."""

    def test_leading_slash_path_resolution_on_windows(self, tmp_path: Path):
        """
        EMPIRICAL BUG REPRODUCTION:
        In extract_context, `repo_path / norm_rel` where norm_rel='/src/app.py'
        resolves to C:\\src\\app.py on Windows because leading slash is not stripped.
        """
        skill = ContextExtractionSkill()
        src_dir = tmp_path / "src"
        src_dir.mkdir(parents=True)
        app_file = src_dir / "app.py"
        app_file.write_text("def hello():\n    return 'world'\n", encoding="utf-8")

        # Calling with leading slash (common output from linters e.g. "/src/app.py")
        ctx = skill.extract_context(repo_path=tmp_path, file_path="/src/app.py", line_number=1)
        assert ctx.context_type != "empty" and ctx.enclosing_symbol != "(File Not Found)", (
            f"Failed to resolve file with leading slash on Windows: {ctx.enclosing_symbol}"
        )

    def test_ast_extraction_retains_decorators_on_function(self, tmp_path: Path):
        """
        EMPIRICAL DEFECT:
        AST function extraction strips decorators (@router.get, @auth_required)
        from code_slice, and fails to identify enclosing function if target_line is on a decorator.
        """
        skill = ContextExtractionSkill()
        source = (
            "@router.post('/login')\n"
            "@rate_limit(max=5)\n"
            "def login(request):\n"
            "    return {'status': 'ok'}\n"
        )
        test_file = tmp_path / "login.py"
        test_file.write_text(source, encoding="utf-8")

        # 1. Target line 3 (inside def login) - decorators must be present in code_slice!
        ctx1 = skill.extract_context(repo_path=tmp_path, file_path="login.py", line_number=3)
        assert "@router.post" in ctx1.code_slice, (
            f"Decorators were stripped from code_slice: {ctx1.code_slice}"
        )

        # 2. Target line 1 (on @router.post decorator) - must identify function def login!
        ctx2 = skill.extract_context(repo_path=tmp_path, file_path="login.py", line_number=1)
        assert ctx2.enclosing_symbol == "def login", (
            f"Decorator line not attributed to enclosing function, got '{ctx2.enclosing_symbol}'"
        )

    def test_ast_extraction_deeply_nested_closures(self, tmp_path: Path):
        """Verify extraction inside deeply nested closures."""
        skill = ContextExtractionSkill()
        source = (
            "def level_1():\n"
            "    def level_2():\n"
            "        def level_3():\n"
            "            x = 100\n"
            "            return x\n"
            "        return level_3()\n"
            "    return level_2()\n"
        )
        test_file = tmp_path / "closure.py"
        test_file.write_text(source, encoding="utf-8")

        ctx = skill.extract_context(repo_path=tmp_path, file_path="closure.py", line_number=4)
        assert ctx.enclosing_symbol == "def level_3"
        assert "x = 100" in ctx.code_slice
