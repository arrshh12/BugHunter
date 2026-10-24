"""
Adversarial Stress Test Suite for Milestone 4: E2E Remediation Pipeline Boundaries.

Verifies:
1. Exact Diff Ceiling Boundaries:
   - 150 vs 151 lines (pure additions, pure deletions, mixed adds/deletes, hunk headers)
   - 0 lines / empty diff and whitespace-only diffs
2. File Bound Ceiling Boundaries:
   - 3 vs 4 modified files, 1 file, 0 files
   - Collision guards with skip lists and path variants
3. Credential Leak Patterns:
   - GitHub classic PATs (ghp_), Fine-grained PATs (github_pat_)
   - OpenAI keys (sk-), Google AI keys (AIza), PEM private keys (RSA, EC, OPENSSH)
   - Distinction between added credentials (leak) vs deleted credentials (safe remediation)
4. Multi-Scanner Ingestion & Proximity Deduplication:
   - Identical line findings across tools
   - Line distance boundaries (distance = 1, 2 clustered; distance = 3 separated)
   - Multi-file distribution and priority ranking
5. Deep AST Nesting & Context Extraction Resilience:
   - Quadruple-nested functions inside classes
   - Multiline stacked decorators and async function definitions
   - Non-Python / syntax error fallbacks and out-of-bound line numbers
6. Full Remediation Planning Invariants:
   - Conventional commit title synthesis and diff cap enforcement in Aider prompts
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.aider_runner import AiderRunner
from src.bughunter_agent import (
    BugHunterAgent,
    ContextExtractionSkill,
    PatchPlanningSkill,
    RawFinding,
    TriagedFinding,
)
from src.code_graph import GraphEdge
from src.verifier import Verifier

# =========================================================================
# Fixtures
# =========================================================================

@pytest.fixture
def mock_git_repo(tmp_path: Path) -> Path:
    """Create a minimal mock git repo structure."""
    repo = tmp_path / "adversarial_repo"
    repo.mkdir(parents=True, exist_ok=True)
    src_dir = repo / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "app.py").write_text("print('hello world')\n", encoding="utf-8")
    return repo


# =========================================================================
# 1. Exact Diff Ceiling Boundary Tests (150 vs 151 lines, mixed, empty)
# =========================================================================

class TestDiffCeilingBoundaries:
    """Stress-test exact 150 vs 151 line boundaries across diff variations."""

    def test_diff_exactly_150_additions_passes(self, mock_git_repo: Path) -> None:
        verifier = Verifier()
        diff = "--- a/src/app.py\n+++ b/src/app.py\n" + "".join(
            f"+x_{i} = {i}\n" for i in range(150)
        )
        res = verifier.verify_and_sanitize_fix(
            repo_path=mock_git_repo,
            skip_files=[],
            max_lines=150,
            custom_diff=diff,
            simulated_report={"bug_found": True, "file_modified": "src/app.py"},
        )
        assert res.verified is True
        assert res.diff_lines == 150
        assert res.error_reason is None

    def test_diff_exactly_151_additions_rejected(self, mock_git_repo: Path) -> None:
        verifier = Verifier()
        diff = "--- a/src/app.py\n+++ b/src/app.py\n" + "".join(
            f"+x_{i} = {i}\n" for i in range(151)
        )
        res = verifier.verify_and_sanitize_fix(
            repo_path=mock_git_repo,
            skip_files=[],
            max_lines=150,
            custom_diff=diff,
            simulated_report={"bug_found": True, "file_modified": "src/app.py"},
        )
        assert res.verified is False
        assert "Diff changed 151 lines, exceeding limit of 150" in (res.error_reason or "")

    def test_diff_exactly_150_deletions_passes(self, mock_git_repo: Path) -> None:
        verifier = Verifier()
        diff = "--- a/src/app.py\n+++ b/src/app.py\n" + "".join(
            f"-old_line_{i} = {i}\n" for i in range(150)
        )
        res = verifier.verify_and_sanitize_fix(
            repo_path=mock_git_repo,
            skip_files=[],
            max_lines=150,
            custom_diff=diff,
            simulated_report={"bug_found": True, "file_modified": "src/app.py"},
        )
        assert res.verified is True
        assert res.diff_lines == 150

    def test_diff_exactly_151_deletions_rejected(self, mock_git_repo: Path) -> None:
        verifier = Verifier()
        diff = "--- a/src/app.py\n+++ b/src/app.py\n" + "".join(
            f"-old_line_{i} = {i}\n" for i in range(151)
        )
        res = verifier.verify_and_sanitize_fix(
            repo_path=mock_git_repo,
            skip_files=[],
            max_lines=150,
            custom_diff=diff,
            simulated_report={"bug_found": True, "file_modified": "src/app.py"},
        )
        assert res.verified is False
        assert "Diff changed 151 lines, exceeding limit of 150" in (res.error_reason or "")

    def test_diff_mixed_75_additions_75_deletions_passes(self, mock_git_repo: Path) -> None:
        verifier = Verifier()
        adds = "".join(f"+new_{i} = {i}\n" for i in range(75))
        dels = "".join(f"-old_{i} = {i}\n" for i in range(75))
        diff = f"--- a/src/app.py\n+++ b/src/app.py\n{adds}{dels}"
        res = verifier.verify_and_sanitize_fix(
            repo_path=mock_git_repo,
            skip_files=[],
            max_lines=150,
            custom_diff=diff,
            simulated_report={"bug_found": True, "file_modified": "src/app.py"},
        )
        assert res.verified is True
        assert res.diff_lines == 150

    def test_diff_mixed_75_additions_76_deletions_rejected(self, mock_git_repo: Path) -> None:
        verifier = Verifier()
        adds = "".join(f"+new_{i} = {i}\n" for i in range(75))
        dels = "".join(f"-old_{i} = {i}\n" for i in range(76))
        diff = f"--- a/src/app.py\n+++ b/src/app.py\n{adds}{dels}"
        res = verifier.verify_and_sanitize_fix(
            repo_path=mock_git_repo,
            skip_files=[],
            max_lines=150,
            custom_diff=diff,
            simulated_report={"bug_found": True, "file_modified": "src/app.py"},
        )
        assert res.verified is False
        assert res.diff_lines == 151
        assert "Diff changed 151 lines, exceeding limit of 150" in (res.error_reason or "")

    def test_diff_with_multiple_hunk_headers_does_not_inflate_line_count(self, mock_git_repo: Path) -> None:
        """Verify @@ hunk headers and index lines are not counted as changed lines."""
        verifier = Verifier()
        # 10 hunks, each with 15 added lines = 150 added lines total
        hunks = []
        for h in range(10):
            hunks.append(f"@@ -{h*20},5 +{h*20},20 @@\n")
            for i in range(15):
                hunks.append(f"+line_{h}_{i} = True\n")

        diff = "--- a/src/app.py\n+++ b/src/app.py\n" + "".join(hunks)
        res = verifier.verify_and_sanitize_fix(
            repo_path=mock_git_repo,
            skip_files=[],
            max_lines=150,
            custom_diff=diff,
            simulated_report={"bug_found": True, "file_modified": "src/app.py"},
        )
        assert res.verified is True
        assert res.diff_lines == 150

    def test_empty_diff_rejected(self, mock_git_repo: Path) -> None:
        verifier = Verifier()
        res = verifier.verify_and_sanitize_fix(
            repo_path=mock_git_repo,
            skip_files=[],
            custom_diff="",
            simulated_report={"bug_found": True, "file_modified": "src/app.py"},
        )
        assert res.verified is False
        assert "Diff is completely empty" in (res.error_reason or "")


# =========================================================================
# 2. File Bound Ceiling Tests (3 vs 4 files, 1 vs 0 files)
# =========================================================================

class TestFileBoundCeilings:
    """Stress-test 3 vs 4 modified file limits, empty file lists, and skip guards."""

    def test_exactly_3_modified_files_passes(self, mock_git_repo: Path) -> None:
        verifier = Verifier()
        diff = (
            "--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +1 @@\n+a = 1\n"
            "--- a/src/b.py\n+++ b/src/b.py\n@@ -1 +1 @@\n+b = 2\n"
            "--- a/src/c.py\n+++ b/src/c.py\n@@ -1 +1 @@\n+c = 3\n"
        )
        res = verifier.verify_and_sanitize_fix(
            repo_path=mock_git_repo,
            skip_files=[],
            max_files=3,
            custom_diff=diff,
            simulated_report={
                "bug_found": True,
                "files_modified": ["src/a.py", "src/b.py", "src/c.py"],
            },
        )
        assert res.verified is True
        assert len(res.modified_files) == 3

    def test_exactly_4_modified_files_rejected(self, mock_git_repo: Path) -> None:
        verifier = Verifier()
        diff = "--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +1 @@\n+x = 1\n"
        res = verifier.verify_and_sanitize_fix(
            repo_path=mock_git_repo,
            skip_files=[],
            max_files=3,
            custom_diff=diff,
            simulated_report={
                "bug_found": True,
                "files_modified": ["src/a.py", "src/b.py", "src/c.py", "src/d.py"],
            },
        )
        assert res.verified is False
        assert "Modified 4 files, exceeding limit of 3" in (res.error_reason or "")

    def test_zero_modified_files_rejected(self, mock_git_repo: Path) -> None:
        verifier = Verifier()
        diff = "--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +1 @@\n+x = 1\n"
        res = verifier.verify_and_sanitize_fix(
            repo_path=mock_git_repo,
            skip_files=[],
            custom_diff=diff,
            simulated_report={
                "bug_found": True,
                "files_modified": [],
            },
        )
        assert res.verified is False
        assert "Zero modified files detected" in (res.error_reason or "")

    def test_collision_skip_guard_with_path_variations(self, mock_git_repo: Path) -> None:
        verifier = Verifier()
        diff = "--- a/src/blocked.py\n+++ b/src/blocked.py\n@@ -1 +1 @@\n+x = 1\n"

        # Direct name match in skip list
        res1 = verifier.verify_and_sanitize_fix(
            repo_path=mock_git_repo,
            skip_files=["blocked.py"],
            custom_diff=diff,
            simulated_report={"bug_found": True, "file_modified": "src/blocked.py"},
        )
        assert res1.verified is False
        assert "in collision skip list" in (res1.error_reason or "")

        # Windows backslash variant in skip list
        res2 = verifier.verify_and_sanitize_fix(
            repo_path=mock_git_repo,
            skip_files=["src\\blocked.py"],
            custom_diff=diff,
            simulated_report={"bug_found": True, "file_modified": "src/blocked.py"},
        )
        assert res2.verified is False
        assert "in collision skip list" in (res2.error_reason or "")


# =========================================================================
# 3. Credential Leak Patterns & Asymmetry Tests
# =========================================================================

class TestCredentialLeakRegexes:
    """Stress-test secret pattern regexes and added vs deleted lines asymmetry."""

    def test_github_classic_pat_detected(self, mock_git_repo: Path) -> None:
        verifier = Verifier()
        # Exactly 36 characters after ghp_
        token = "ghp_" + "A" * 36
        diff = f"--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n+TOKEN = '{token}'\n"
        res = verifier.verify_and_sanitize_fix(
            repo_path=mock_git_repo,
            skip_files=[],
            custom_diff=diff,
            simulated_report={"bug_found": True, "file_modified": "src/app.py"},
        )
        assert res.verified is False
        assert "Credential leak detected" in (res.error_reason or "")

    def test_github_fine_grained_pat_detected(self, mock_git_repo: Path) -> None:
        verifier = Verifier()
        # github_pat_ + 22 chars + _ + 50 chars
        token = "github_pat_" + ("X" * 22) + "_" + ("Y" * 50)
        diff = f"--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n+PAT = '{token}'\n"
        res = verifier.verify_and_sanitize_fix(
            repo_path=mock_git_repo,
            skip_files=[],
            custom_diff=diff,
            simulated_report={"bug_found": True, "file_modified": "src/app.py"},
        )
        assert res.verified is False
        assert "Credential leak detected" in (res.error_reason or "")

    def test_openai_api_key_detected(self, mock_git_repo: Path) -> None:
        verifier = Verifier()
        token = "sk-" + "a1B2c3D4e5F6g7H8i9J0k1"
        diff = f"--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n+OPENAI = '{token}'\n"
        res = verifier.verify_and_sanitize_fix(
            repo_path=mock_git_repo,
            skip_files=[],
            custom_diff=diff,
            simulated_report={"bug_found": True, "file_modified": "src/app.py"},
        )
        assert res.verified is False
        assert "Credential leak detected" in (res.error_reason or "")

    def test_google_aiza_key_detected(self, mock_git_repo: Path) -> None:
        verifier = Verifier()
        # AIza + 35 chars
        token = "AIza" + "Z" * 35
        diff = f"--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n+GOOGLE_KEY = '{token}'\n"
        res = verifier.verify_and_sanitize_fix(
            repo_path=mock_git_repo,
            skip_files=[],
            custom_diff=diff,
            simulated_report={"bug_found": True, "file_modified": "src/app.py"},
        )
        assert res.verified is False
        assert "Credential leak detected" in (res.error_reason or "")

    @pytest.mark.parametrize(
        "header",
        [
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
        ],
    )
    def test_pem_private_keys_detected(self, mock_git_repo: Path, header: str) -> None:
        verifier = Verifier()
        diff = f"--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n+{header}\n"
        res = verifier.verify_and_sanitize_fix(
            repo_path=mock_git_repo,
            skip_files=[],
            custom_diff=diff,
            simulated_report={"bug_found": True, "file_modified": "src/app.py"},
        )
        assert res.verified is False
        assert "Credential leak detected" in (res.error_reason or "")

    def test_deleted_secret_is_permitted_for_remediation(self, mock_git_repo: Path) -> None:
        """
        Crucial design property: If a diff REMOVES a leaked secret,
        it should NOT be blocked as a leak.
        """
        verifier = Verifier()
        diff = (
            "--- a/src/app.py\n+++ b/src/app.py\n@@ -1,2 +1,2 @@\n"
            "-GITHUB_PAT = 'ghp_123456789012345678901234567890123456'\n"
            "-OPENAI_KEY = 'sk-1234567890123456789012345'\n"
            "+GITHUB_PAT = os.environ.get('GITHUB_TOKEN')\n"
            "+OPENAI_KEY = os.environ.get('OPENAI_API_KEY')\n"
        )
        res = verifier.verify_and_sanitize_fix(
            repo_path=mock_git_repo,
            skip_files=[],
            custom_diff=diff,
            simulated_report={"bug_found": True, "file_modified": "src/app.py"},
        )
        assert res.verified is True
        assert res.diff_lines == 4
        assert res.error_reason is None


# =========================================================================
# 4. Multi-Scanner Ingestion & Proximity Deduplication Tests
# =========================================================================

class TestProximityDeduplicationAndTriage:
    """Stress-test finding clustering on exact line boundaries and proximity windows."""

    def test_simultaneous_findings_on_same_exact_line(self, tmp_path: Path) -> None:
        agent = BugHunterAgent()
        findings = [
            RawFinding(
                tool="flake8",
                rule_id="F821",
                file="src/core.py",
                line=42,
                column=5,
                message="undefined name 'client'",
            ),
            RawFinding(
                tool="bandit",
                rule_id="B602",
                file="src/core.py",
                line=42,
                column=5,
                message="subprocess call with shell=True",
                severity="CRITICAL",
            ),
            RawFinding(
                tool="semgrep",
                rule_id="python.security.injection",
                file="src/core.py",
                line=42,
                column=5,
                message="Dangerous command injection",
                severity="ERROR",
            ),
        ]

        clusters = agent.triage_skill.deduplicate(findings)
        assert len(clusters) == 1
        assert len(clusters[0]) == 3

        triaged = agent.triage_findings(raw_findings=findings, repo_path=tmp_path)
        assert len(triaged) == 1
        assert triaged[0].line == 42
        assert set(triaged[0].tools_reporting) == {"bandit", "flake8", "semgrep"}
        assert triaged[0].primary_axis == "security"

    def test_proximity_clustering_boundary_distance_2_vs_3(self, tmp_path: Path) -> None:
        """
        Verify that distance <= 2 is merged into 1 cluster, but distance == 3 creates 2 clusters.
        """
        agent = BugHunterAgent()

        # Distance 2: Line 10 and Line 12 -> 1 cluster
        findings_dist_2 = [
            RawFinding(tool="flake8", rule_id="F401", file="src/a.py", line=10, column=1),
            RawFinding(tool="bandit", rule_id="B101", file="src/a.py", line=12, column=1),
        ]
        clusters_2 = agent.triage_skill.deduplicate(findings_dist_2)
        assert len(clusters_2) == 1
        assert len(clusters_2[0]) == 2

        # Distance 3: Line 10 and Line 13 -> 2 separate clusters
        findings_dist_3 = [
            RawFinding(tool="flake8", rule_id="F401", file="src/a.py", line=10, column=1),
            RawFinding(tool="bandit", rule_id="B101", file="src/a.py", line=13, column=1),
        ]
        clusters_3 = agent.triage_skill.deduplicate(findings_dist_3)
        assert len(clusters_3) == 2
        assert len(clusters_3[0]) == 1
        assert len(clusters_3[1]) == 1

    def test_multi_file_triage_and_blast_radius_ranking(self, tmp_path: Path) -> None:
        """Verify multi-file findings are partitioned and ranked by trust boundary and composite score."""
        agent = BugHunterAgent()

        # Create mock repo files
        (tmp_path / "src").mkdir(parents=True, exist_ok=True)
        (tmp_path / "src" / "api").mkdir(parents=True, exist_ok=True)
        (tmp_path / "src" / "api" / "auth.py").write_text("def auth(): pass\n", encoding="utf-8")
        (tmp_path / "src" / "utils.py").write_text("def helper(): pass\n", encoding="utf-8")

        mock_graph = MagicMock()
        mock_graph.edges = [
            GraphEdge(source="src/main.py", target="src/api/auth.py", edge_type="IMPORTS"),
            GraphEdge(source="src/worker.py", target="src/api/auth.py", edge_type="IMPORTS"),
        ]

        findings = [
            # Low severity in non-boundary file
            RawFinding(
                tool="flake8",
                rule_id="B006",
                file="src/utils.py",
                line=1,
                message="mutable default argument",
                severity="WARNING",
            ),
            # Security finding in trust boundary file with inbound callers
            RawFinding(
                tool="bandit",
                rule_id="B602",
                file="src/api/auth.py",
                line=1,
                message="command injection",
                severity="CRITICAL",
            ),
        ]

        triaged = agent.triage_findings(
            raw_findings=findings,
            repo_path=tmp_path,
            graph_engine=mock_graph,
        )

        assert len(triaged) == 2
        top = triaged[0]
        assert top.file == "src/api/auth.py"
        assert top.primary_axis == "security"
        assert top.is_trust_boundary is True
        # Trust boundary (+30) + 2 inbound callers (+20) = 50.0 blast radius
        assert top.blast_radius_score == 50.0


# =========================================================================
# 5. Deep AST Nesting & Context Extraction Resilience Tests
# =========================================================================

class TestAstExtractionResilience:
    """Stress-test surgical AST extraction under deep nesting and edge conditions."""

    def test_deeply_nested_classes_and_functions(self, tmp_path: Path) -> None:
        """Verify extraction inside class Outer -> class Inner -> def method -> def sub_helper."""
        code = '''"""Deep nesting test."""

class OuterClass:
    class InnerClass:
        def outer_method(self):
            def deeply_nested_helper(x: int):
                # Vulnerability target at line 8
                return eval(str(x))
            return deeply_nested_helper(10)
'''
        file_path = tmp_path / "deep.py"
        file_path.write_text(code, encoding="utf-8")

        skill = ContextExtractionSkill()
        ctx = skill.extract_context(tmp_path, "deep.py", line_number=8)

        assert ctx.context_type == "ast_python"
        assert ctx.target_line == 8
        assert "deeply_nested_helper" in ctx.enclosing_symbol
        assert "class InnerClass" in ctx.enclosing_symbol
        assert "eval(str(x))" in ctx.code_slice

    def test_stacked_decorators_and_async_defs(self, tmp_path: Path) -> None:
        """Verify extraction preserves multiple decorators on async methods."""
        code = '''"""Async decorators test."""
from functools import lru_cache

def custom_dec(fn):
    return fn

class ServiceGateway:
    @custom_dec
    @lru_cache(maxsize=128)
    async def fetch_record(self, key: str) -> dict:
        # Target line 11
        res = f"result_{key}"
        return {"data": res}
'''
        file_path = tmp_path / "async_service.py"
        file_path.write_text(code, encoding="utf-8")

        skill = ContextExtractionSkill()
        ctx = skill.extract_context(tmp_path, "async_service.py", line_number=11)

        assert ctx.context_type == "ast_python"
        assert "@custom_dec" in ctx.code_slice
        assert "@lru_cache(maxsize=128)" in ctx.code_slice
        assert "async def fetch_record" in ctx.code_slice

    def test_syntax_error_in_python_file_falls_back_to_text_window(self, tmp_path: Path) -> None:
        """Ensure unparseable Python syntax does not raise SyntaxError."""
        bad_code = "def broken(\n  # Incomplete syntax error\nline_3 = 42\n"
        file_path = tmp_path / "bad.py"
        file_path.write_text(bad_code, encoding="utf-8")

        skill = ContextExtractionSkill()
        ctx = skill.extract_context(tmp_path, "bad.py", line_number=3)

        assert ctx.context_type == "text_window"
        assert "line_3 = 42" in ctx.code_slice

    def test_target_line_beyond_eof_handles_gracefully(self, tmp_path: Path) -> None:
        """Ensure line number exceeding file length does not raise IndexError."""
        code = "x = 1\ny = 2\n"
        file_path = tmp_path / "short.py"
        file_path.write_text(code, encoding="utf-8")

        skill = ContextExtractionSkill()
        ctx = skill.extract_context(tmp_path, "short.py", line_number=9999)

        assert ctx.context_type == "ast_python"
        assert ctx.enclosing_symbol == "module scope"


# =========================================================================
# 6. Patch Planning & AiderRunner Command Construction Invariants
# =========================================================================

class TestPatchPlanningAndRunnerInvariants:
    """Stress-test patch prompt generation, conventional titles, and CLI arg sanitation."""

    def test_patch_planning_prompt_invariants(self) -> None:
        skill = PatchPlanningSkill()
        finding = TriagedFinding(
            id="src/db.py:20:SQL01",
            primary_axis="security",
            severity="CRITICAL",
            composite_score=140.0,
            blast_radius_score=30.0,
            is_trust_boundary=True,
            inbound_dependents_count=1,
            tools_reporting=["bandit"],
            file="src/database/db.py",
            line=20,
            column=4,
            rule_id="SQL01",
            message="Possible SQL injection in query string",
            code_snippet="query = f'SELECT * FROM users WHERE id={user_id}'",
        )
        ctx = ContextExtractionSkill().extract_context(Path("."), "nonexistent.py", 20)

        plan = skill.formulate_plan(finding, ctx)
        assert plan.scope == "db"
        assert plan.pr_title == "fix(db): resolve SQL01 in db.py"
        assert plan.diff_ceiling_lines == 150
        assert plan.diff_ceiling_files == 3
        # Must enforce One Bug = One PR rule
        assert "One Bug = One PR" in plan.aider_prompt
        assert "<= 150 lines" in plan.aider_prompt

    def test_aider_runner_command_and_environment_invariants(self) -> None:
        runner = AiderRunner(
            default_model="openai/gpt-6-luna",
            default_api_base="https://api.scalemax.pro/v1",
        )

        cmd = runner.build_command(
            target_file="src\\auth\\tokens.py",  # Backslashes
            patch_instruction="Fix timing attack vulnerability",
            api_key="sk-scalemax-valid-key-9999",
        )

        # Target file normalized to POSIX
        assert cmd[-1] == "src/auth/tokens.py"
        assert cmd[cmd.index("--model") + 1] == "openai/gpt-6-luna"
        assert cmd[cmd.index("--openai-api-base") + 1] == "https://api.scalemax.pro/v1"
        assert cmd[cmd.index("--openai-api-key") + 1] == "sk-scalemax-valid-key-9999"

        # Host secret stripping
        env = runner.build_environment(
            api_key="sk-scalemax-valid-key-9999",
            base_env={
                "PATH": "C:\\Windows;C:\\Python",
                "GITHUB_TOKEN": "secret-gh-token",
                "AWS_SECRET_ACCESS_KEY": "secret-aws-key",
                "DASHBOARD_API_KEY": "secret-dashboard-key",
            },
        )
        assert env["OPENAI_API_BASE"] == "https://api.scalemax.pro/v1"
        assert env["OPENAI_API_KEY"] == "sk-scalemax-valid-key-9999"
        assert "GITHUB_TOKEN" not in env
        assert "AWS_SECRET_ACCESS_KEY" not in env
        assert "DASHBOARD_API_KEY" not in env
