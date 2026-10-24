"""
Comprehensive Unit Tests for Milestone 2: Modular BugHunter Agent with Skills (R1).

Verifies:
1. Data models: RawFinding, TriagedFinding, ExtractedContext, PatchPlan.
2. TriageSkill parsers: Flake8, ESLint, Bandit, Semgrep, Trivy.
3. Cross-tool deduplication and proximity clustering.
4. 5-axis triage, severity multipliers, trust boundary bonus, and graph blast radius ranking.
5. Filtering of cosmetic readability noise (E501, docstrings, imports, formatting).
6. ContextExtractionSkill: Python AST function/class slicing and imports collection without dumping full files.
7. Language-agnostic sliding text window fallback and syntax-error resilience.
8. PatchPlanningSkill: One Bug = One PR, <=150 lines diff ceiling, <=3 files, conventional commit PR title, aider prompt formatting.
9. BugHunterAgent coordinator end-to-end analyze_and_plan pipeline.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from src.bughunter_agent import (
    BugHunterAgent,
    ContextExtractionSkill,
    ExtractedContext,
    PatchPlan,
    PatchPlanningSkill,
    RawFinding,
    TriagedFinding,
    TriageSkill,
)
from src.code_graph import GraphEdge
from src.static_scanner import FiveAxisTriageEngine

# =========================================================================
# Mock Graph Engine Helper
# =========================================================================

@dataclass
class _MockGraphEngine:
    edges: list[GraphEdge]


# =========================================================================
# 1. Data Models Tests
# =========================================================================

class TestDataModels:
    """Verify data model construction and default invariant constraints."""

    def test_raw_finding_defaults(self):
        finding = RawFinding(
            tool="flake8",
            rule_id="F401",
            file="src/utils.py",
            line=10,
        )
        assert finding.tool == "flake8"
        assert finding.rule_id == "F401"
        assert finding.file == "src/utils.py"
        assert finding.line == 10
        assert finding.column == 1
        assert finding.end_line is None
        assert finding.end_column is None
        assert finding.message == ""
        assert finding.severity == "WARNING"
        assert finding.code_snippet == ""
        assert finding.raw_data == {}

    def test_triaged_finding_construction(self):
        triaged = TriagedFinding(
            id="src/auth.py:42:B602",
            primary_axis="security",
            severity="ERROR",
            composite_score=180.0,
            blast_radius_score=30.0,
            is_trust_boundary=True,
            inbound_dependents_count=2,
            tools_reporting=["bandit", "semgrep"],
            file="src/auth.py",
            line=42,
            column=5,
            rule_id="B602",
            message="subprocess with shell=True",
            code_snippet="subprocess.call(cmd, shell=True)",
            stride_category="Tampering",
            owasp_category="A03:2021-Injection",
        )
        assert triaged.id == "src/auth.py:42:B602"
        assert triaged.primary_axis == "security"
        assert triaged.severity == "ERROR"
        assert triaged.is_trust_boundary is True
        assert triaged.inbound_dependents_count == 2
        assert "bandit" in triaged.tools_reporting
        assert "semgrep" in triaged.tools_reporting

    def test_extracted_context_construction(self):
        ctx = ExtractedContext(
            file_path="src/login.py",
            target_line=25,
            enclosing_symbol="class Auth -> def verify",
            imports_slice="import hmac\nimport hashlib",
            code_slice="def verify(self):\n    return True",
            context_type="ast_python",
            total_lines=50,
            formatted_prompt_block="=== CONTEXT ===",
        )
        assert ctx.file_path == "src/login.py"
        assert ctx.target_line == 25
        assert ctx.context_type == "ast_python"
        assert ctx.total_lines == 50

    def test_patch_plan_diff_budget_ceilings(self):
        plan = PatchPlan(
            bug_id="src/api.py:10:SQLI",
            target_file="src/api.py",
            target_line=10,
            rule_id="SQLI",
            severity="ERROR",
            scope="api",
            pr_title="fix(api): resolve SQLI in api.py",
            pr_body="## Description",
            patch_instructions=["Fix query"],
            aider_prompt="Fix SQLI",
        )
        # Strictly verify diff ceiling constants
        assert plan.diff_ceiling_lines == 150
        assert plan.diff_ceiling_files == 3
        assert plan.pr_title == "fix(api): resolve SQLI in api.py"


# =========================================================================
# 2. TriageSkill Parsers Tests
# =========================================================================

class TestTriageSkillParsers:
    """Verify parsing accuracy for Flake8, ESLint, Bandit, Semgrep, and Trivy."""

    def test_parse_flake8_standard_and_windows_paths(self):
        skill = TriageSkill()
        output = (
            "src/auth.py:25:5: F401 'os' imported but unused\n"
            "src/parser.py:12: E999 SyntaxError: invalid syntax\n"
            "src/app.py:50:1: E302 expected 2 blank lines\n"
            "src/cmd.py:10:3: S602 subprocess call with shell=True\n"
            "src/style.py:80:1: W291 trailing whitespace\n"
            "C:\\project\\src\\db.py:14:3: B001 do not use bare except\n"
        )
        findings = skill.parse_flake8(output)
        assert len(findings) == 6

        # F401
        assert findings[0].tool == "flake8"
        assert findings[0].rule_id == "F401"
        assert findings[0].file == "src/auth.py"
        assert findings[0].line == 25
        assert findings[0].column == 5
        assert findings[0].severity == "ERROR"

        # E999
        assert findings[1].rule_id == "E999"
        assert findings[1].line == 12
        assert findings[1].column == 1
        assert findings[1].severity == "ERROR"

        # E302
        assert findings[2].rule_id == "E302"
        assert findings[2].severity == "WARNING"

        # S602 (Bandit rule in flake8)
        assert findings[3].rule_id == "S602"
        assert findings[3].severity == "ERROR"

        # W291
        assert findings[4].rule_id == "W291"
        assert findings[4].severity == "INFO"

        # Windows path
        assert findings[5].file.replace("\\", "/") == "C:/project/src/db.py"
        assert findings[5].rule_id == "B001"
        assert findings[5].severity == "WARNING"

    def test_parse_flake8_empty_or_invalid(self):
        skill = TriageSkill()
        assert skill.parse_flake8("") == []
        assert skill.parse_flake8("Random unformatted text without colons") == []

    def test_parse_eslint_json_array_and_dict(self):
        skill = TriageSkill()
        data = [
            {
                "filePath": "frontend/src/index.ts",
                "messages": [
                    {
                        "ruleId": "no-unused-vars",
                        "severity": 2,
                        "line": 15,
                        "column": 7,
                        "endLine": 15,
                        "endColumn": 8,
                        "message": "'x' is defined but never used.",
                    },
                    {
                        "ruleId": "prefer-const",
                        "severity": 1,
                        "line": 22,
                        "column": 5,
                        "message": "'y' is never reassigned.",
                    },
                ],
            }
        ]
        # Test as JSON string
        findings_json = skill.parse_eslint(json.dumps(data))
        assert len(findings_json) == 2
        assert findings_json[0].tool == "eslint"
        assert findings_json[0].rule_id == "no-unused-vars"
        assert findings_json[0].file == "frontend/src/index.ts"
        assert findings_json[0].line == 15
        assert findings_json[0].column == 7
        assert findings_json[0].end_line == 15
        assert findings_json[0].end_column == 8
        assert findings_json[0].severity == "ERROR"

        assert findings_json[1].rule_id == "prefer-const"
        assert findings_json[1].severity == "WARNING"

        # Test as dict with results
        dict_wrapper = {"results": data}
        findings_dict = skill.parse_eslint(dict_wrapper)
        assert len(findings_dict) == 2

    def test_parse_bandit_json(self):
        skill = TriageSkill()
        data = {
            "results": [
                {
                    "test_id": "B602",
                    "issue_severity": "HIGH",
                    "line_number": 42,
                    "col_offset": 5,
                    "filename": "src/exec.py",
                    "issue_text": "subprocess call with shell=True identified",
                    "code": "subprocess.Popen(cmd, shell=True)",
                },
                {
                    "test_id": "B105",
                    "issue_severity": "MEDIUM",
                    "line_number": 88,
                    "col_offset": 10,
                    "filename": "src/config.py",
                    "issue_text": "Hardcoded password string",
                    "code": "password = 'secret'",
                },
                {
                    "test_id": "B404",
                    "issue_severity": "LOW",
                    "line_number": 3,
                    "col_offset": 1,
                    "filename": "src/helper.py",
                    "issue_text": "Consider possible security implications with subprocess module",
                    "code": "import subprocess",
                },
            ]
        }
        findings = skill.parse_bandit(json.dumps(data))
        assert len(findings) == 3

        # B602 (HIGH -> ERROR)
        assert findings[0].tool == "bandit"
        assert findings[0].rule_id == "B602"
        assert findings[0].file == "src/exec.py"
        assert findings[0].line == 42
        assert findings[0].column == 5
        assert findings[0].severity == "ERROR"
        assert findings[0].code_snippet == "subprocess.Popen(cmd, shell=True)"

        # B105 (MEDIUM -> WARNING)
        assert findings[1].rule_id == "B105"
        assert findings[1].severity == "WARNING"

        # B404 (LOW -> INFO)
        assert findings[2].rule_id == "B404"
        assert findings[2].severity == "INFO"

    def test_parse_semgrep_json(self):
        skill = TriageSkill()
        data = {
            "results": [
                {
                    "check_id": "python.security.sql-injection",
                    "path": "src/database.py",
                    "start": {"line": 105, "col": 12},
                    "end": {"line": 106, "col": 30},
                    "extra": {
                        "severity": "ERROR",
                        "message": "Potential SQL injection vulnerability",
                        "lines": "cursor.execute(f'SELECT * FROM users WHERE id = {uid}')",
                    },
                },
                {
                    "check_id": "python.lang.best-practice.open-never-closed",
                    "path": "src/io_utils.py",
                    "start": {"line": 15, "col": 5},
                    "end": {"line": 15, "col": 20},
                    "extra": {
                        "severity": "WARNING",
                        "message": "Unclosed file resource",
                        "lines": "f = open('data.txt')",
                    },
                },
            ]
        }
        findings = skill.parse_semgrep(data)
        assert len(findings) == 2

        assert findings[0].tool == "semgrep"
        assert findings[0].rule_id == "python.security.sql-injection"
        assert findings[0].file == "src/database.py"
        assert findings[0].line == 105
        assert findings[0].column == 12
        assert findings[0].end_line == 106
        assert findings[0].end_column == 30
        assert findings[0].severity == "ERROR"
        assert "SELECT * FROM users" in findings[0].code_snippet

        assert findings[1].rule_id == "python.lang.best-practice.open-never-closed"
        assert findings[1].severity == "WARNING"

    def test_parse_trivy_json(self):
        skill = TriageSkill()
        data = {
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-9999",
                            "PkgName": "libssl3",
                            "Severity": "CRITICAL",
                            "Title": "Remote code execution in SSL library",
                        }
                    ],
                    "Misconfigurations": [
                        {
                            "ID": "AVD-DS-0002",
                            "Title": "Root user in Dockerfile",
                            "Message": "Specify at least one non-root user",
                            "Severity": "HIGH",
                            "CauseMetadata": {"StartLine": 12},
                        }
                    ],
                }
            ]
        }
        findings = skill.parse_trivy(json.dumps(data))
        assert len(findings) == 2

        # Vulnerability
        assert findings[0].tool == "trivy"
        assert findings[0].rule_id == "CVE-2024-9999"
        assert findings[0].file == "Dockerfile"
        assert findings[0].line == 1
        assert findings[0].severity == "CRITICAL"
        assert "libssl3" in findings[0].message

        # Misconfiguration
        assert findings[1].tool == "trivy"
        assert findings[1].rule_id == "AVD-DS-0002"
        assert findings[1].file == "Dockerfile"
        assert findings[1].line == 12
        assert findings[1].severity == "ERROR"
        assert "non-root user" in findings[1].message


# =========================================================================
# 3. Deduplication Tests
# =========================================================================

class TestDeduplication:
    """Verify proximity clustering and cross-tool duplicate resolution."""

    def test_proximity_clustering_same_file(self):
        skill = TriageSkill()
        findings = [
            # Cluster 1: lines 42 and 43 (within 2 lines)
            RawFinding(tool="bandit", rule_id="B602", file="src/utils.py", line=42, severity="ERROR"),
            RawFinding(tool="semgrep", rule_id="rules.command-injection", file="src/utils.py", line=42, severity="ERROR"),
            RawFinding(tool="flake8", rule_id="S602", file="src/utils.py", line=43, severity="ERROR"),
            # Cluster 2: line 100 (>2 lines away)
            RawFinding(tool="flake8", rule_id="F841", file="src/utils.py", line=100, severity="WARNING"),
            # Cluster 3: different file
            RawFinding(tool="eslint", rule_id="no-eval", file="frontend/app.js", line=42, severity="ERROR"),
        ]
        clusters = skill.deduplicate(findings)
        assert len(clusters) == 3

        # Check Cluster 1 contents
        c1 = next(c for c in clusters if any(f.file == "src/utils.py" and f.line == 42 for f in c))
        assert len(c1) == 3
        tools_in_c1 = {f.tool for f in c1}
        assert tools_in_c1 == {"bandit", "semgrep", "flake8"}

        # Check Cluster 2 contents
        c2 = next(c for c in clusters if any(f.line == 100 for f in c))
        assert len(c2) == 1
        assert c2[0].rule_id == "F841"

        # Check Cluster 3 contents
        c3 = next(c for c in clusters if any(f.file == "frontend/app.js" for f in c))
        assert len(c3) == 1
        assert c3[0].tool == "eslint"

    def test_empty_findings_deduplicate(self):
        skill = TriageSkill()
        assert skill.deduplicate([]) == []


# =========================================================================
# 4. Severity & Blast Radius Ranking Tests
# =========================================================================

class TestRankingAndTriage:
    """Verify composite scoring, trust boundary elevation, caller counting, and noise filtering."""

    def test_trust_boundary_elevation(self, tmp_path: Path):
        skill = TriageSkill()
        findings = [
            # Internal helper finding
            RawFinding(tool="flake8", rule_id="F821", file="src/internal_helper.py", line=20, severity="ERROR", message="undefined name 'x'"),
            # Trust boundary finding (web_server.py)
            RawFinding(tool="flake8", rule_id="F821", file="src/web_server.py", line=20, severity="ERROR", message="undefined name 'y'"),
        ]
        triaged = skill.triage_and_rank(findings, repo_path=tmp_path)
        assert len(triaged) == 2

        web_finding = next(t for t in triaged if t.file == "src/web_server.py")
        internal_finding = next(t for t in triaged if t.file == "src/internal_helper.py")

        assert web_finding.is_trust_boundary is True
        assert web_finding.blast_radius_score >= 30.0
        assert internal_finding.is_trust_boundary is False
        assert internal_finding.blast_radius_score == 0.0

        # Trust boundary finding must rank higher
        assert triaged[0].file == "src/web_server.py"
        assert web_finding.composite_score > internal_finding.composite_score

    def test_blast_radius_with_graph_engine_callers(self, tmp_path: Path):
        skill = TriageSkill()
        # Mock code graph engine with inbound IMPORTS edges targeting src/database.py
        mock_edges = [
            GraphEdge(source="src/web_server.py", target="src/database.py", edge_type="IMPORTS"),
            GraphEdge(source="src/orchestrator.py", target="src.database", edge_type="IMPORTS"),
            GraphEdge(source="src/api.py", target="database", edge_type="IMPORTS"),
            # Test file import should NOT count towards production caller count
            GraphEdge(source="tests/test_database.py", target="src/database.py", edge_type="IMPORTS"),
            # Other edge type should NOT count
            GraphEdge(source="src/web_server.py", target="src/database.py", edge_type="CALLS"),
        ]
        mock_graph = _MockGraphEngine(edges=mock_edges)

        finding = RawFinding(
            tool="bandit",
            rule_id="B608",
            file="src/database.py",
            line=50,
            severity="ERROR",
            message="Possible SQL injection vector",
        )

        blast_radius, inbound_count, is_boundary = skill.calculate_blast_radius(finding, graph_engine=mock_graph)
        assert inbound_count == 3
        assert is_boundary is False
        assert blast_radius == 30.0  # 3 callers * 10

        triaged = skill.triage_and_rank([finding], repo_path=tmp_path, graph_engine=mock_graph)
        assert len(triaged) == 1
        assert triaged[0].inbound_dependents_count == 3
        assert triaged[0].blast_radius_score == 30.0

    def test_filters_out_cosmetic_readability_noise(self, tmp_path: Path):
        skill = TriageSkill()
        findings = [
            # Cosmetic noise
            RawFinding(tool="flake8", rule_id="E501", file="src/service.py", line=10, message="line too long (88 > 79 characters)"),
            RawFinding(tool="flake8", rule_id="D101", file="src/service.py", line=20, message="Missing docstring in public class"),
            RawFinding(tool="flake8", rule_id="COM812", file="src/service.py", line=30, message="Trailing comma missing"),
            RawFinding(tool="flake8", rule_id="I001", file="src/service.py", line=1, message="Import block is unsorted"),
            RawFinding(tool="flake8", rule_id="W291", file="src/service.py", line=5, message="trailing whitespace"),
            # Real bug
            RawFinding(tool="flake8", rule_id="F821", file="src/service.py", line=55, severity="ERROR", message="undefined name 'client'"),
        ]
        triaged = skill.triage_and_rank(findings, repo_path=tmp_path)
        # Only the real functional bug must survive triage
        assert len(triaged) == 1
        assert triaged[0].rule_id == "F821"
        assert triaged[0].primary_axis == FiveAxisTriageEngine.AXIS_CORRECTNESS

    def test_skip_files_filtering(self, tmp_path: Path):
        skill = TriageSkill()
        findings = [
            RawFinding(tool="flake8", rule_id="F821", file="src/legacy.py", line=10, severity="ERROR", message="undefined name 'a'"),
            RawFinding(tool="flake8", rule_id="F821", file="src/active.py", line=10, severity="ERROR", message="undefined name 'b'"),
        ]
        triaged = skill.triage_and_rank(findings, repo_path=tmp_path, skip_files=["src/legacy.py"])
        assert len(triaged) == 1
        assert triaged[0].file == "src/active.py"


# =========================================================================
# 5. ContextExtractionSkill Tests
# =========================================================================

class TestContextExtractionSkill:
    """Verify surgical AST function/class extraction and text window fallback."""

    def test_ast_function_slicing_isolates_scope_without_full_file_dump(self, tmp_path: Path):
        skill = ContextExtractionSkill()
        source = (
            "import os\n"
            "from pathlib import Path\n"
            "\n"
            "def calculate_hash(data: bytes) -> str:\n"
            "    import hashlib\n"
            "    return hashlib.sha256(data).hexdigest()\n"
            "\n"
            "def target_function(x: int) -> int:\n"
            "    # Line 9: bug target\n"
            "    result = x * 2\n"
            "    return result\n"
            "\n"
            "def another_large_function():\n"
            + "\n".join(f"    # Line {i} filler" for i in range(14, 100))
            + "\n    return None\n"
        )
        test_file = tmp_path / "sample.py"
        test_file.write_text(source, encoding="utf-8")

        # Line 9 is inside target_function
        ctx = skill.extract_context(repo_path=tmp_path, file_path="sample.py", line_number=9)

        assert ctx.context_type == "ast_python"
        assert ctx.enclosing_symbol == "def target_function"
        assert "import os" in ctx.imports_slice
        assert "from pathlib import Path" in ctx.imports_slice

        # Sliced code must include target_function
        assert "def target_function(x: int) -> int:" in ctx.code_slice
        assert "result = x * 2" in ctx.code_slice

        # CRITICAL: Verify it does NOT dump the entire file
        assert "another_large_function" not in ctx.code_slice
        assert "Line 50 filler" not in ctx.code_slice
        assert ctx.total_lines > len(ctx.code_slice.splitlines())

        # Verify formatted prompt block has line annotations
        assert "=== SURGICAL CONTEXT:" in ctx.formatted_prompt_block
        assert "Line-Annotated" in ctx.formatted_prompt_block

    def test_ast_class_method_slicing(self, tmp_path: Path):
        skill = ContextExtractionSkill()
        source = (
            "import sys\n"
            "\n"
            "class UserManager:\n"
            "    def __init__(self, db):\n"
            "        self.db = db\n"
            "\n"
            "    def login(self, username, password):\n"
            "        # Line 8: bug\n"
            "        if not username:\n"
            "            return False\n"
            "        return True\n"
            "\n"
            "    def delete_account(self, uid):\n"
            + "\n".join(f"        # Line {i} delete logic" for i in range(14, 60))
            + "\n        return True\n"
        )
        test_file = tmp_path / "user_mgr.py"
        test_file.write_text(source, encoding="utf-8")

        # Line 8 is inside UserManager.login
        ctx = skill.extract_context(repo_path=tmp_path, file_path="user_mgr.py", line_number=8)

        assert ctx.context_type == "ast_python"
        assert ctx.enclosing_symbol == "class UserManager -> def login"
        assert "class UserManager:" in ctx.code_slice
        assert "def login(self, username, password):" in ctx.code_slice
        assert "delete_account" not in ctx.code_slice

    def test_ast_async_function_slicing(self, tmp_path: Path):
        skill = ContextExtractionSkill()
        source = (
            "import asyncio\n"
            "\n"
            "async def fetch_remote_data(url: str):\n"
            "    await asyncio.sleep(0.1)\n"
            "    return url\n"
        )
        test_file = tmp_path / "async_service.py"
        test_file.write_text(source, encoding="utf-8")

        ctx = skill.extract_context(repo_path=tmp_path, file_path="async_service.py", line_number=4)
        assert ctx.enclosing_symbol == "async def fetch_remote_data"
        assert "async def fetch_remote_data(url: str):" in ctx.code_slice

    def test_text_window_fallback_for_non_python(self, tmp_path: Path):
        skill = ContextExtractionSkill()
        source_lines = [
            "import { useState } from 'react';",
            "import axios from 'axios';",
            "",
        ] + [f"const line{i} = {i};" for i in range(4, 80)]
        source = "\n".join(source_lines)

        test_file = tmp_path / "App.tsx"
        test_file.write_text(source, encoding="utf-8")

        # Target line 40 with window=10 lines
        ctx = skill.extract_context(repo_path=tmp_path, file_path="App.tsx", line_number=40, context_window_lines=10)
        assert ctx.context_type == "text_window"
        assert "lines 30-50" in ctx.enclosing_symbol
        assert "import { useState } from 'react';" in ctx.imports_slice
        assert "const line40 = 40;" in ctx.code_slice
        assert "const line5 = 5;" not in ctx.code_slice

    def test_syntax_error_python_graceful_fallback(self, tmp_path: Path):
        skill = ContextExtractionSkill()
        # Invalid Python syntax
        source = (
            "import os\n"
            "def broken_syntax(:\n"
            "    return 42\n"
        )
        test_file = tmp_path / "broken.py"
        test_file.write_text(source, encoding="utf-8")

        ctx = skill.extract_context(repo_path=tmp_path, file_path="broken.py", line_number=2)
        # Must fall back gracefully to text_window without crashing
        assert ctx.context_type == "text_window"
        assert "def broken_syntax(:" in ctx.code_slice

    def test_missing_file_returns_empty_context(self, tmp_path: Path):
        skill = ContextExtractionSkill()
        ctx = skill.extract_context(repo_path=tmp_path, file_path="non_existent.py", line_number=10)
        assert ctx.context_type == "empty"
        assert ctx.enclosing_symbol == "(File Not Found)"
        assert ctx.total_lines == 0


# =========================================================================
# 6. PatchPlanningSkill Tests
# =========================================================================

class TestPatchPlanningSkill:
    """Verify One Bug = One PR, <=150 lines diff ceiling, and aider prompt formatting."""

    def test_formulate_plan_enforces_budget_and_conventional_title(self):
        planner = PatchPlanningSkill()
        finding = TriagedFinding(
            id="src/auth.py:42:B602",
            primary_axis="security",
            severity="ERROR",
            composite_score=150.0,
            blast_radius_score=30.0,
            is_trust_boundary=True,
            inbound_dependents_count=1,
            tools_reporting=["bandit", "semgrep"],
            file="src/auth.py",
            line=42,
            column=5,
            rule_id="B602",
            message="subprocess with shell=True identified",
            code_snippet="subprocess.call(cmd, shell=True)",
            stride_category="Tampering",
            owasp_category="A03:2021-Injection",
        )
        context = ExtractedContext(
            file_path="src/auth.py",
            target_line=42,
            enclosing_symbol="class AuthManager -> def execute_shell",
            imports_slice="import subprocess",
            code_slice="def execute_shell(cmd):\n    subprocess.call(cmd, shell=True)",
            context_type="ast_python",
            total_lines=60,
            formatted_prompt_block="=== CONTEXT ===",
        )

        plan = planner.formulate_plan(finding, context)

        # 1. Budget ceilings
        assert plan.diff_ceiling_lines == 150
        assert plan.diff_ceiling_files == 3

        # 2. Conventional commit PR title: fix(<scope>): resolve <rule_id> in <filename>
        assert plan.pr_title == "fix(auth): resolve B602 in auth.py"
        assert plan.scope == "auth"

        # 3. Patch instructions must mandate One Bug = One PR and diff bounds
        instructions_text = " ".join(plan.patch_instructions)
        assert "One Bug = One PR" in instructions_text
        assert "<= 150 lines" in instructions_text
        assert "3 files" in instructions_text

        # 4. Aider prompt must be formatted with message, instructions, and context
        assert "Fix bug `B602` in `src/auth.py` at line 42." in plan.aider_prompt
        assert "=== CONTEXT ===" in plan.aider_prompt
        assert "INSTRUCTIONS:" in plan.aider_prompt

        # 5. PR body must contain structured markdown
        assert "## Description" in plan.pr_body
        assert "## Root Cause" in plan.pr_body
        assert "## Remediation Instructions" in plan.pr_body
        assert "Tampering" in plan.pr_body
        assert "A03:2021-Injection" in plan.pr_body


# =========================================================================
# 7. BugHunterAgent Coordinator End-to-End Tests
# =========================================================================

class TestBugHunterAgentCoordinator:
    """Verify BugHunterAgent end-to-end triage -> context extraction -> patch planning pipeline."""

    def test_analyze_and_plan_end_to_end_success(self, tmp_path: Path):
        # Setup sample repo file
        src_dir = tmp_path / "src"
        src_dir.mkdir(parents=True)
        web_file = src_dir / "web_server.py"
        web_file.write_text(
            "import os\n"
            "from typing import Optional\n"
            "\n"
            "def handle_request(raw_path: str) -> str:\n"
            "    # Line 5: Path traversal vulnerability\n"
            "    target = os.path.join('/base', raw_path)\n"
            "    return open(target).read()\n",
            encoding="utf-8",
        )

        agent = BugHunterAgent()
        raw_findings = [
            # Cosmetic noise (should be ignored)
            RawFinding(tool="flake8", rule_id="E501", file="src/web_server.py", line=4, message="line too long"),
            # Real security vulnerability on trust boundary
            RawFinding(
                tool="semgrep",
                rule_id="python.security.path-traversal",
                file="src/web_server.py",
                line=5,
                severity="ERROR",
                message="Potential path traversal via untrusted raw_path parameter",
            ),
            RawFinding(
                tool="bandit",
                rule_id="B602",
                file="src/web_server.py",
                line=5,
                severity="ERROR",
                message="Path traversal in open()",
            ),
        ]

        plan = agent.analyze_and_plan(
            repo_path=tmp_path,
            raw_findings=raw_findings,
        )

        assert plan is not None
        assert plan.target_file == "src/web_server.py"
        assert plan.target_line == 5
        assert plan.pr_title == "fix(web_server): resolve python.security.path-traversal in web_server.py"
        assert plan.diff_ceiling_lines == 150
        assert plan.diff_ceiling_files == 3
        assert "def handle_request" in plan.aider_prompt
        assert "One Bug = One PR" in plan.aider_prompt

    def test_analyze_and_plan_returns_none_when_no_valid_findings(self, tmp_path: Path):
        agent = BugHunterAgent()
        # Only cosmetic findings
        raw_findings = [
            RawFinding(tool="flake8", rule_id="E501", file="src/service.py", line=10, message="line too long"),
            RawFinding(tool="flake8", rule_id="D101", file="src/service.py", line=20, message="missing docstring"),
        ]
        plan = agent.analyze_and_plan(repo_path=tmp_path, raw_findings=raw_findings)
        assert plan is None

    def test_analyze_and_plan_empty_input(self, tmp_path: Path):
        agent = BugHunterAgent()
        plan = agent.analyze_and_plan(repo_path=tmp_path, raw_findings=[])
        assert plan is None
