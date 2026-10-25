"""
Comprehensive Automated Test Suite for Two-Agent "Bug-Hunter" Architecture.
Covers Milestone Requirements R1-R4:
- BugfindingAgent: Multi-scanner ingestion (Flake8, ESLint, Bandit, Semgrep, Trivy),
  proximity clustering (±2 lines), 5-axis ranking, and per-repo Bug-log.md generation across 5 repos.
- MainFixerAgent: Direct backlog consumption from Bug-log.md with ZERO static scanning,
  surgical AST context extraction, diff ceiling enforcement (<=150 lines, <=3 files),
  AiderRunner execution (openai/gpt-6-luna at https://api.scalemax.pro/v1),
  Bug-log.md mutation to DONE, and logs.md audit ledger append.
- End-to-End Integration: Complete multi-repo discovery -> remediation -> PR -> audit lifecycle.
- Zero Regressions across all existing tests in pytest.
"""

from __future__ import annotations

import json
import subprocess
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.aider_runner import AiderResult, AiderRunner
from src.bugfinding_agent import BugfindingAgent
from src.bughunter_agent import (
    TriagedFinding,
    TriageSkill,
)
from src.config import Config, KeyConfig
from src.database import Database
from src.fixer_agent import MainFixerAgent
from src.git_manager import GitManager
from src.key_manager import KeyManager
from src.logger import RingBufferLogger
from src.openhands_runner import OpenHandsRunner
from src.orchestrator import Orchestrator
from src.static_scanner import StaticScanner
from src.verifier import Verifier

# =========================================================================
# Shared Fixtures & Mock Factories
# =========================================================================

@pytest.fixture
def sample_config(tmp_path: Path) -> Config:
    """Provide a valid Config with 5 target repositories and ScaleMax LLM key."""
    k1 = KeyConfig(
        id="key-scalemax-1",
        provider="ScaleMax",
        base_url="https://api.scalemax.pro/v1",
        model="openai/gpt-6-luna",
        api_key="sk-scalemax-test-12345678",
        masked_key="sk-s...5678",
        priority=1,
    )
    return Config.load(overrides={
        "WORKSPACE_DIR": tmp_path,
        "workspace_dir": tmp_path,
        "TARGET_REPOS": [
            "owner/repo-alpha",
            "owner/repo-beta",
            "owner/repo-gamma",
            "owner/repo-delta",
            "owner/repo-epsilon",
        ],
        "target_repos": [
            "owner/repo-alpha",
            "owner/repo-beta",
            "owner/repo-gamma",
            "owner/repo-delta",
            "owner/repo-epsilon",
        ],
        "LLM_KEYS_POOL": [k1],
        "MAX_DIFF_LINES": 150,
        "MAX_FILES_PER_PR": 3,
    })


@pytest.fixture
def five_test_repos(tmp_path: Path) -> dict[str, Path]:
    """Initialize 5 genuine Git repositories in tmp_path with sample code."""
    repo_slugs = [
        "owner/repo-alpha",
        "owner/repo-beta",
        "owner/repo-gamma",
        "owner/repo-delta",
        "owner/repo-epsilon",
    ]
    repos = {}
    for slug in repo_slugs:
        repo_dir = tmp_path / "repos" / slug.replace("/", "__")
        repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "bot@autobughunter.local"], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "AutoBugHunter"], cwd=repo_dir, check=True, capture_output=True)

        src_dir = repo_dir / "src"
        src_dir.mkdir(parents=True, exist_ok=True)

        # Sample vulnerable file
        code = (
            "import os\n"
            "import subprocess\n\n"
            "def handle_request(command: str) -> None:\n"
            "    # Line 5: command injection\n"
            "    subprocess.call(command, shell=True)\n"
        )
        (src_dir / "app.py").write_text(code, encoding="utf-8")
        (repo_dir / "README.md").write_text(f"# {slug}\n", encoding="utf-8")

        subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_dir, check=True, capture_output=True)
        repos[slug] = repo_dir
    return repos


# =========================================================================
# 1. BugfindingAgent Tests
# =========================================================================

class TestBugfindingAgent:
    """Verify BugfindingAgent multi-scanner ingestion, proximity deduplication, and Bug-log.md generation."""

    def test_multi_scanner_ingestion_and_proximity_clustering(self, tmp_path: Path):
        """Verify ingestion from Flake8, ESLint, Bandit, Semgrep, Trivy and ±2 lines clustering."""
        agent = BugfindingAgent()

        raw_outputs = {
            "flake8": "src/app.py:5:1: S602 subprocess call with shell=True\nsrc/app.py:50:1: E501 line too long\n",
            "eslint": json.dumps([{"filePath": "frontend/index.js", "messages": [{"ruleId": "no-eval", "severity": 2, "line": 10, "column": 5, "message": "eval is evil"}]}]),
            "bandit": json.dumps({"results": [{"test_id": "B602", "filename": "src/app.py", "line_number": 5, "issue_severity": "HIGH", "issue_text": "subprocess call with shell=True"}]}),
            "semgrep": json.dumps({"results": [{"check_id": "rules.dangerous-exec", "path": "src/app.py", "start": {"line": 6, "col": 5}, "extra": {"severity": "ERROR", "message": "Dangerous shell execution"}}]}),
            "trivy": json.dumps({"Results": [{"Target": "Dockerfile", "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-0001", "Severity": "CRITICAL", "Title": "Remote code execution"}]}]}),
        }

        raw_findings = agent.ingest_scanner_outputs(raw_outputs)
        assert len(raw_findings) >= 5

        # Triage and deduplicate
        triaged = agent.triage_skill.triage_and_rank(raw_findings, repo_path=tmp_path)
        assert len(triaged) >= 3

        # src/app.py lines 5-6 must cluster into a single TriagedFinding
        app_bugs = [t for t in triaged if t.file == "src/app.py"]
        assert len(app_bugs) == 1
        top_app_bug = app_bugs[0]
        assert top_app_bug.line in (5, 6)
        assert "bandit" in top_app_bug.tools_reporting or "semgrep" in top_app_bug.tools_reporting

        # Cosmetic E501 must be completely dropped
        assert not any(t.rule_id == "E501" for t in triaged)

    def test_generate_bug_log_format(self, tmp_path: Path):
        """Verify Bug-log.md checkbox format: - [ ] **BUG-<ID>**: <file>:<line> - [<tool>:<rule>] <desc>."""
        agent = BugfindingAgent()
        findings = [
            TriagedFinding(
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
                message="subprocess call with shell=True identified",
                code_snippet="subprocess.call(cmd, shell=True)",
            )
        ]
        log_path = tmp_path / "Bug-log.md"
        result_path = agent.generate_bug_log(
            repo_slug="owner/repo-alpha",
            findings=findings,
            bug_log_path=log_path,
        )
        assert result_path.exists()
        content = result_path.read_text(encoding="utf-8")

        # Verify task checkbox format
        assert "- [ ] **BUG-001**: src/auth.py:42 - [bandit:B602] subprocess call with shell=True identified" in content
        assert "## Pending Bugs" in content
        assert "## Fixed Bugs" in content

    def test_bug_log_generation_across_five_repos(self, sample_config: Config, five_test_repos: dict[str, Path]):
        """Verify BugfindingAgent generates separate well-formatted Bug-log.md files across 5 repositories."""
        agent = BugfindingAgent(config=sample_config)
        tool_outputs = {}
        for idx, slug in enumerate(sample_config.target_repos):
            tool_outputs[slug] = {
                "flake8": f"src/app.py:5:1: S602 command injection in repo {idx+1}\n",
                "bandit": json.dumps({"results": [{"test_id": "B602", "filename": "src/app.py", "line_number": 5, "issue_severity": "HIGH", "issue_text": f"subprocess call in repo {idx+1}"}]}),
            }

        results = agent.scan_repositories(
            repo_slugs=sample_config.target_repos,
            repos_dir=sample_config.repos_dir,
            simulated_tool_outputs=tool_outputs,
        )
        assert len(results) == 5
        for slug in sample_config.target_repos:
            log_path = results[slug]
            assert log_path.exists()
            content = log_path.read_text(encoding="utf-8")
            assert "- [ ] **BUG-001**:" in content
            assert "src/app.py:5" in content

    def test_bugfinding_agent_fallback_to_static_findings_json(self, tmp_path: Path):
        """Verify BugfindingAgent falls back to .static_findings.json when simulated_tool_outputs is None."""
        repo_dir = tmp_path / "repos" / "owner__test-repo"
        repo_dir.mkdir(parents=True)
        (repo_dir / "src").mkdir()
        (repo_dir / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")

        findings_data = [
            {
                "tool": "semgrep",
                "rule_id": "python-sql-injection",
                "file": "src/app.py",
                "line": 1,
                "column": 1,
                "message": "Potential SQL injection",
                "severity": "ERROR",
                "code_snippet": "x = 1",
            }
        ]
        (repo_dir / ".static_findings.json").write_text(json.dumps(findings_data), encoding="utf-8")

        agent = BugfindingAgent()
        results = agent.scan_repositories(
            repo_slugs=["owner/test-repo"],
            repos_dir=tmp_path / "repos",
            simulated_tool_outputs=None,
        )

        assert "owner/test-repo" in results
        log_file = results["owner/test-repo"]
        assert log_file.exists()
        content = log_file.read_text(encoding="utf-8")
        assert "src/app.py:1" in content
        assert "python-sql-injection" in content

    def test_state_preservation_retains_done_entries_across_rescans(self, tmp_path: Path):
        """Verify that existing DONE entries are preserved across re-scans and not duplicated."""
        agent = BugfindingAgent()
        log_path = tmp_path / "Bug-log.md"

        # Pre-populate Bug-log.md with 1 DONE bug and 1 pending bug
        initial_content = (
            "# Bug Log — owner/repo-alpha\n\n"
            "## Pending Bugs\n"
            "- [ ] **BUG-002**: src/db.py:20 - [semgrep:sql-injection] SQL injection vector\n\n"
            "## Fixed Bugs\n"
            "- [x] **BUG-001**: src/auth.py:42 - [bandit:B602] subprocess with shell=True (DONE)\n"
        )
        log_path.write_text(initial_content, encoding="utf-8")

        # New scan finds the same auth.py bug (already DONE) plus a new bug in src/api.py
        new_findings = [
            TriagedFinding(
                id="src/auth.py:42:B602",
                primary_axis="security",
                severity="ERROR",
                composite_score=150.0,
                blast_radius_score=30.0,
                is_trust_boundary=True,
                inbound_dependents_count=1,
                tools_reporting=["bandit"],
                file="src/auth.py",
                line=42,
                column=5,
                rule_id="B602",
                message="subprocess with shell=True",
                code_snippet="",
            ),
            TriagedFinding(
                id="src/api.py:15:B101",
                primary_axis="correctness",
                severity="WARNING",
                composite_score=80.0,
                blast_radius_score=0.0,
                is_trust_boundary=False,
                inbound_dependents_count=0,
                tools_reporting=["flake8"],
                file="src/api.py",
                line=15,
                column=1,
                rule_id="B101",
                message="Assert detected in production",
                code_snippet="",
            ),
        ]

        agent.generate_bug_log("owner/repo-alpha", new_findings, bug_log_path=log_path)
        updated_content = log_path.read_text(encoding="utf-8")

        # 1. Fixed BUG-001 MUST remain checked under Fixed Bugs
        assert "- [x] **BUG-001**: src/auth.py:42 - [bandit:B602]" in updated_content
        # 2. Fixed BUG-001 must NOT be duplicated under Pending Bugs
        assert "- [ ] **BUG-001**" not in updated_content
        # 3. Existing pending BUG-002 must be preserved
        assert "BUG-002" in updated_content
        # 4. New bug must receive a distinct ID and be pending
        assert "src/api.py:15" in updated_content


# =========================================================================
# 2. MainFixerAgent Backlog Consumption & Zero Static Scanning Tests
# =========================================================================

class TestMainFixerAgentBacklogConsumption:
    """Verify MainFixerAgent parses Bug-log.md directly and strictly adheres to Zero Static Scanning."""

    def test_parse_pending_bugs_from_bug_log(self, tmp_path: Path):
        """Verify parsing pending checkboxes and skipping done entries."""
        fixer = MainFixerAgent()
        log_path = tmp_path / "Bug-log.md"
        log_path.write_text(
            "# Bug Log\n\n"
            "## Pending Bugs\n"
            "- [ ] **BUG-001**: src/auth.py:42 - [bandit:B602] Command injection in execute()\n"
            "- [ ] **BUG-002**: src/db.py:100 - [semgrep:sqli] Unescaped query parameter\n\n"
            "## Fixed Bugs\n"
            "- [x] **BUG-000**: src/init.py:5 - [flake8:F401] Unused import (DONE)\n",
            encoding="utf-8",
        )

        pending = fixer.parse_pending_bugs(log_path)
        assert len(pending) == 2
        assert pending[0]["bug_id"] == "BUG-001"
        assert pending[0]["file"] == "src/auth.py"
        assert pending[0]["line"] == 42
        assert pending[0]["tool"] == "bandit"
        assert pending[0]["rule_id"] == "B602"

        assert pending[1]["bug_id"] == "BUG-002"
        assert pending[1]["file"] == "src/db.py"
        assert pending[1]["line"] == 100

    def test_zero_static_scanning_invariant(self, tmp_path: Path):
        """STRICT ARCHITECTURAL INVARIANT:

        Verify that during fix operations, MainFixerAgent does NOT invoke any static scanners.
        """
        mock_scanner = MagicMock(spec=StaticScanner)
        mock_triage = MagicMock(spec=TriageSkill)

        repo_dir = tmp_path / "test_repo"
        repo_dir.mkdir(parents=True)
        (repo_dir / "src").mkdir()
        (repo_dir / "src" / "calc.py").write_text("def div(a, b): return a / b\n", encoding="utf-8")

        log_path = repo_dir / "Bug-log.md"
        log_path.write_text(
            "- [ ] **BUG-001**: src/calc.py:1 - [flake8:B001] Missing zero check\n",
            encoding="utf-8",
        )

        mock_aider = MagicMock(spec=AiderRunner)
        mock_aider.run_aider.return_value = AiderResult(
            exit_code=0,
            status="SUCCESS",
            diff_output="--- a/src/calc.py\n+++ b/src/calc.py\n@@ -1 +1 @@\n-def div(a, b): return a / b\n+def div(a, b): return a / b if b != 0 else 0\n",
            target_file="src/calc.py",
        )

        fixer = MainFixerAgent(aider_runner=mock_aider)

        with patch("src.static_scanner.StaticScanner.run_static_prefilter", mock_scanner.run_static_prefilter), \
             patch("src.bughunter_agent.TriageSkill.parse_flake8", mock_triage.parse_flake8), \
             patch("src.bughunter_agent.TriageSkill.parse_bandit", mock_triage.parse_bandit), \
             patch("src.bughunter_agent.TriageSkill.parse_semgrep", mock_triage.parse_semgrep), \
             patch("src.bughunter_agent.TriageSkill.parse_eslint", mock_triage.parse_eslint), \
             patch("src.bughunter_agent.TriageSkill.parse_trivy", mock_triage.parse_trivy):
            result = fixer.fix_next_bug(
                repo_slug="owner/repo-test",
                repo_path=repo_dir,
                bug_log_path=log_path,
            )

        assert result.success is True
        assert result.bug_id == "BUG-001"

        # VERIFY ZERO STATIC SCANNING CALLS
        assert mock_scanner.run_static_prefilter.call_count == 0
        assert mock_triage.parse_flake8.call_count == 0
        assert mock_triage.parse_bandit.call_count == 0
        assert mock_triage.parse_semgrep.call_count == 0
        assert mock_triage.parse_eslint.call_count == 0
        assert mock_triage.parse_trivy.call_count == 0


# =========================================================================
# 3. MainFixerAgent Execution, Mutation & Audit Ledger Tests
# =========================================================================

class TestMainFixerAgentExecutionAndMutation:
    """Verify Aider execution, Bug-log.md in-place mutation to DONE, and logs.md audit appending."""

    def test_mark_bug_done_mutates_bug_log_in_place(self, tmp_path: Path):
        """Verify mark_bug_done updates target bug to - [x] ... (DONE) and preserves other items."""
        fixer = MainFixerAgent()
        log_path = tmp_path / "Bug-log.md"
        log_path.write_text(
            "# Bug Log\n\n"
            "## Pending Bugs\n"
            "- [ ] **BUG-001**: src/auth.py:42 - [bandit:B602] Command injection\n"
            "- [ ] **BUG-002**: src/db.py:10 - [semgrep:sqli] SQL injection\n",
            encoding="utf-8",
        )

        updated = fixer.mark_bug_done(log_path, "BUG-001")
        assert updated is True
        content = log_path.read_text(encoding="utf-8")

        # BUG-001 must be checked and marked DONE
        assert "- [x] **BUG-001**: src/auth.py:42 - [bandit:B602] Command injection (DONE)" in content
        # BUG-002 must remain unchecked
        assert "- [ ] **BUG-002**: src/db.py:10 - [semgrep:sqli] SQL injection" in content

    def test_append_audit_log_schema(self, tmp_path: Path):
        """Verify logs.md is appended with valid table header and structured row."""
        fixer = MainFixerAgent()
        logs_path = tmp_path / "logs.md"

        fixer.append_audit_log(
            logs_path=logs_path,
            repo_slug="owner/repo-alpha",
            bug_id="BUG-001",
            target_file="src/auth.py",
            diff_lines=12,
            commit_or_branch="fix/auto-auth-bug-001",
            pr_status="PR_CREATED",
        )

        assert logs_path.exists()
        content = logs_path.read_text(encoding="utf-8")
        assert "| Timestamp (UTC) | Repository | Bug ID | Target File | Diff Lines | Commit / Branch | PR Status |" in content
        assert "| owner/repo-alpha | BUG-001 | src/auth.py | 12 | fix/auto-auth-bug-001 | PR_CREATED |" in content

        # Append second entry
        fixer.append_audit_log(
            logs_path=logs_path,
            repo_slug="owner/repo-beta",
            bug_id="BUG-002",
            target_file="src/db.py",
            diff_lines=8,
            commit_or_branch="fix/auto-db-bug-002",
            pr_status="PR_CREATED",
        )
        lines = [line for line in logs_path.read_text(encoding="utf-8").splitlines() if line.startswith("| 20")]
        assert len(lines) == 2

    def test_resolve_default_branch(self, tmp_path: Path):
        """Verify resolve_default_branch identifies master or main correctly."""
        fixer = MainFixerAgent()

        # 1. Non-git dir returns main
        assert fixer.resolve_default_branch(tmp_path / "non_git") == "main"

        # 2. Master repo returns master
        repo_master = tmp_path / "repo_master"
        repo_master.mkdir()
        subprocess.run(["git", "init", "-b", "master"], cwd=repo_master, check=True, capture_output=True)
        (repo_master / "README.md").write_text("master", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=repo_master, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init master"], cwd=repo_master, check=True, capture_output=True)
        assert fixer.resolve_default_branch(repo_master) == "master"

        # 3. Main repo returns main
        repo_main = tmp_path / "repo_main"
        repo_main.mkdir()
        subprocess.run(["git", "init", "-b", "main"], cwd=repo_main, check=True, capture_output=True)
        (repo_main / "README.md").write_text("main", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=repo_main, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init main"], cwd=repo_main, check=True, capture_output=True)
        assert fixer.resolve_default_branch(repo_main) == "main"

    def test_arrshh12_bot_identity_and_head_spec_construction(self, tmp_path: Path):
        """Verify arrshh12 dedicated bot identity and PR head-spec construction (arrshh12:<branch>)."""
        fixer = MainFixerAgent()
        assert fixer.get_bot_user() == "arrshh12"

        head_spec_airllm = fixer.construct_head_spec("bitxwolf/Airllm-tui", "fix/auto-terminal-bug-001")
        assert head_spec_airllm == "arrshh12:fix/auto-terminal-bug-001"

        mock_gm = MagicMock()
        mock_gm.get_authenticated_user.return_value = "arrshh12"
        fixer_with_gm = MainFixerAgent(git_manager=mock_gm)
        assert fixer_with_gm.get_bot_user() == "arrshh12"
        head_spec_orb = fixer_with_gm.construct_head_spec("bitxwolf/orb", "fix/auto-core-bug-002")
        assert head_spec_orb == "arrshh12:fix/auto-core-bug-002"

        repo_dir = tmp_path / "repo"
        repo_dir.mkdir(parents=True)
        (repo_dir / "src").mkdir()
        (repo_dir / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
        log_path = repo_dir / "Bug-log.md"
        log_path.write_text("- [ ] **BUG-001**: src/app.py:1 - [tool:rule] Fix bug\n", encoding="utf-8")

        mock_aider = MagicMock(spec=AiderRunner)
        mock_aider.run_aider.return_value = AiderResult(
            exit_code=0,
            status="SUCCESS",
            diff_output="--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n",
            target_file="src/app.py",
        )
        fixer_run = MainFixerAgent(aider_runner=mock_aider, git_manager=mock_gm)
        res = fixer_run.fix_next_bug("bitxwolf/Airllm-tui", repo_dir, bug_log_path=log_path)
        assert res.success is True
        assert res.head_spec == f"arrshh12:{res.branch_name}"


# =========================================================================
# 4. Diff Ceiling and Verification Boundary Tests
# =========================================================================

class TestTwoAgentDiffCeilingAndErrorHandling:
    """Verify enforcement of <=150 diff lines, <=3 files, and upstream error recovery."""

    def test_rejects_diff_exceeding_150_lines(self, tmp_path: Path):
        """Verify that patches with >150 lines diff are rejected, leaving Bug-log.md pending."""
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir(parents=True)
        (repo_dir / "src").mkdir()
        (repo_dir / "src" / "big.py").write_text("# initial\n", encoding="utf-8")

        log_path = repo_dir / "Bug-log.md"
        log_path.write_text("- [ ] **BUG-001**: src/big.py:1 - [flake8:B001] Large fix needed\n", encoding="utf-8")

        huge_diff = "--- a/src/big.py\n+++ b/src/big.py\n" + "".join(f"+line_{i} = {i}\n" for i in range(151))
        mock_aider = MagicMock(spec=AiderRunner)
        mock_aider.run_aider.return_value = AiderResult(
            exit_code=0,
            status="SUCCESS",
            diff_output=huge_diff,
            target_file="src/big.py",
        )

        fixer = MainFixerAgent(aider_runner=mock_aider)
        res = fixer.fix_next_bug(
            repo_slug="owner/repo-big",
            repo_path=repo_dir,
            bug_log_path=log_path,
        )

        assert res.success is False
        assert res.status == "VERIFICATION_FAILED"
        assert "exceeding limit of 150" in (res.error_message or "")

        # Bug-log.md must remain unchecked
        assert "- [ ] **BUG-001**" in log_path.read_text(encoding="utf-8")

    def test_rejects_diff_exceeding_3_files(self, tmp_path: Path):
        """Verify that patches modifying >3 files are rejected by Verifier."""
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir(parents=True)
        (repo_dir / "src").mkdir()
        (repo_dir / "src" / "mod.py").write_text("# initial\n", encoding="utf-8")

        log_path = repo_dir / "Bug-log.md"
        log_path.write_text("- [ ] **BUG-001**: src/mod.py:1 - [flake8:B001] Spread fix\n", encoding="utf-8")

        mock_verifier = MagicMock(spec=Verifier)
        mock_verifier.verify_and_sanitize_fix.return_value = MagicMock(
            verified=False,
            error_reason="Modified 4 files, exceeding limit of 3",
            diff_lines=20,
        )

        mock_aider = MagicMock(spec=AiderRunner)
        mock_aider.run_aider.return_value = AiderResult(exit_code=0, status="SUCCESS", diff_output="+fix\n", target_file="src/mod.py")

        fixer = MainFixerAgent(aider_runner=mock_aider, verifier=mock_verifier)
        res = fixer.fix_next_bug("owner/repo", repo_dir, bug_log_path=log_path)

        assert res.success is False
        assert "exceeding limit of 3" in (res.error_message or "")
        assert "- [ ] **BUG-001**" in log_path.read_text(encoding="utf-8")

    def test_handles_aider_rate_limit_429(self, tmp_path: Path):
        """Verify rate limit 429 from Aider returns RATE_LIMIT_429 status without corrupting Bug-log.md."""
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir(parents=True)
        (repo_dir / "src").mkdir()
        (repo_dir / "src" / "app.py").write_text("# code\n", encoding="utf-8")
        log_path = repo_dir / "Bug-log.md"
        log_path.write_text("- [ ] **BUG-001**: src/app.py:1 - [flake8:B001] Test\n", encoding="utf-8")

        mock_aider = MagicMock(spec=AiderRunner)
        mock_aider.run_aider.return_value = AiderResult(
            exit_code=1,
            diff_output="",
            status="RATE_LIMIT_429",
            error_message="HTTP 429 RateLimitError",
            target_file="src/app.py",
        )

        fixer = MainFixerAgent(aider_runner=mock_aider)
        res = fixer.fix_next_bug("owner/repo", repo_dir, bug_log_path=log_path)

        assert res.success is False
        assert res.status == "RATE_LIMIT_429"
        assert "- [ ] **BUG-001**" in log_path.read_text(encoding="utf-8")


# =========================================================================
# 5. Thread Safety and Concurrency Tests
# =========================================================================

class TestThreadSafetyAndConcurrency:
    """Verify thread-safe atomic updates to Bug-log.md and logs.md under concurrent access."""

    def test_concurrent_bug_log_mutation(self, tmp_path: Path):
        """Verify concurrent mark_bug_done calls do not drop updates or corrupt Bug-log.md."""
        log_path = tmp_path / "Bug-log.md"
        total_bugs = 20
        lines = ["# Bug Log\n\n## Pending Bugs"]
        for i in range(1, total_bugs + 1):
            lines.append(f"- [ ] **BUG-{i:03d}**: src/file_{i}.py:10 - [tool:rule] Fix bug {i}")
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        fixer = MainFixerAgent()

        def worker(bug_num: int):
            fixer.mark_bug_done(log_path, f"BUG-{bug_num:03d}")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(1, total_bugs + 1)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        final_content = log_path.read_text(encoding="utf-8")
        # Every single item must be checked (- [x])
        assert final_content.count("- [x]") == total_bugs
        assert final_content.count("- [ ]") == 0


# =========================================================================
# 6. End-to-End Two-Agent Integration Lifecycle Test
# =========================================================================

class TestTwoAgentEndToEndIntegration:
    """Complete end-to-end multi-repo lifecycle from bug discovery to fix, PR, and audit."""

    def test_complete_two_agent_lifecycle_across_repos(
        self, sample_config: Config, five_test_repos: dict[str, Path], tmp_path: Path
    ):
        """Verify the complete lifecycle across 5 target repositories:

        1. BugfindingAgent scans 5 repositories with multi-scanner inputs.
        2. 5 separate Bug-log.md files are populated with task checkboxes.
        3. MainFixerAgent directly consumes pending bugs from Bug-log.md (Zero Static Scanning).
        4. Aider executes atomic patch within diff budget (<=150 lines, <=3 files).
        5. Verifier approves fix, simulated PR is created.
        6. Bug-log.md is mutated in-place to DONE.
        7. logs.md audit ledger is appended with ISO 8601 timestamp and commit/PR status.
        8. Re-scan confirms fixed bugs remain DONE across subsequent discovery waves.
        """
        # Step 1: BugfindingAgent scans 5 repositories
        finder = BugfindingAgent(config=sample_config)
        tool_outputs = {}
        for slug in sample_config.target_repos:
            tool_outputs[slug] = {
                "bandit": json.dumps({"results": [{"test_id": "B602", "filename": "src/app.py", "line_number": 5, "issue_severity": "HIGH", "issue_text": "subprocess with shell=True"}]}),
                "semgrep": json.dumps({"results": [{"check_id": "dangerous-subprocess", "path": "src/app.py", "start": {"line": 5, "col": 5}, "extra": {"severity": "ERROR", "message": "Dangerous subprocess"}}]}),
            }

        scan_results = finder.scan_repositories(
            repo_slugs=sample_config.target_repos,
            repos_dir=sample_config.repos_dir,
            simulated_tool_outputs=tool_outputs,
        )
        assert len(scan_results) == 5

        # Step 2: Verify Bug-log.md exists in each repo with pending BUG-001
        for slug in sample_config.target_repos:
            log_path = scan_results[slug]
            assert log_path.exists()
            assert "- [ ] **BUG-001**: src/app.py:5" in log_path.read_text(encoding="utf-8")

        # Step 3: MainFixerAgent remediates repo-alpha
        target_slug = "owner/repo-alpha"
        target_repo_dir = five_test_repos[target_slug]
        target_log_path = scan_results[target_slug]
        audit_logs_path = tmp_path / "logs.md"

        # Mock AiderRunner to return compliant atomic patch
        compliant_diff = (
            "--- a/src/app.py\n"
            "+++ b/src/app.py\n"
            "@@ -5,1 +5,1 @@\n"
            "-    subprocess.call(command, shell=True)\n"
            "+    subprocess.run([command], shell=False, check=True)\n"
        )
        mock_aider = MagicMock(spec=AiderRunner)
        mock_aider.run_aider.return_value = AiderResult(
            exit_code=0,
            status="SUCCESS",
            diff_output=compliant_diff,
            target_file="src/app.py",
        )

        fixer = MainFixerAgent(
            config=sample_config,
            aider_runner=mock_aider,
        )

        fix_res = fixer.fix_next_bug(
            repo_slug=target_slug,
            repo_path=target_repo_dir,
            bug_log_path=target_log_path,
            logs_path=audit_logs_path,
        )

        # Step 4: Verify Fixer Result
        assert fix_res.success is True
        assert fix_res.bug_id == "BUG-001"
        assert fix_res.target_file == "src/app.py"
        assert fix_res.head_spec == fix_res.branch_name

        # Step 5: Verify Bug-log.md mutated in-place to DONE
        updated_log_content = target_log_path.read_text(encoding="utf-8")
        assert "- [x] **BUG-001**: src/app.py:5 - [bandit:B602] subprocess with shell=True (DONE)" in updated_log_content
        assert "- [ ] **BUG-001**" not in updated_log_content

        # Step 6: Verify logs.md audit entry appended
        assert audit_logs_path.exists()
        audit_content = audit_logs_path.read_text(encoding="utf-8")
        assert target_slug in audit_content
        assert "BUG-001" in audit_content
        assert "src/app.py" in audit_content

        # Step 7: Re-scan confirms fixed bugs remain DONE
        re_scan_results = finder.scan_repositories(
            repo_slugs=[target_slug],
            repos_dir=sample_config.repos_dir,
            simulated_tool_outputs=tool_outputs,
        )
        re_scanned_content = re_scan_results[target_slug].read_text(encoding="utf-8")
        assert "- [x] **BUG-001**" in re_scanned_content
        assert "- [ ] **BUG-001**" not in re_scanned_content

        # Step 8: Next fixer run on repo-alpha reports NO_PENDING_BUGS
        next_fix_res = fixer.fix_next_bug(
            repo_slug=target_slug,
            repo_path=target_repo_dir,
            bug_log_path=target_log_path,
        )
        assert next_fix_res.success is False
        assert next_fix_res.status == "NO_PENDING_BUGS"

    def test_orchestrator_two_agent_cycle_integration(
        self, sample_config: Config, five_test_repos: dict[str, Path], tmp_path: Path
    ):
        """Verify Orchestrator.run_two_agent_cycle executes discovery then fixer with arrshh12 identity."""
        db = Database(tmp_path / "two_agent_orch.sqlite")
        km = KeyManager(sample_config, db)
        km.preflight_check = MagicMock(return_value=True)
        gm = GitManager(tmp_path, github_token="ghp_mock_arrshh12_test_token_abcdef123456", max_open_prs=5)
        ss = StaticScanner()
        oh = OpenHandsRunner()
        vf = Verifier()
        rl = RingBufferLogger()

        mock_aider = MagicMock(spec=AiderRunner)
        mock_aider.run_aider.return_value = AiderResult(
            exit_code=0,
            status="SUCCESS",
            diff_output="--- a/src/app.py\n+++ b/src/app.py\n@@ -5,1 +5,1 @@\n-    subprocess.call(command, shell=True)\n+    subprocess.run([command], shell=False, check=True)\n",
            target_file="src/app.py",
        )

        orch = Orchestrator(sample_config, db, km, gm, ss, oh, vf, rl)
        orch.fixer_agent.aider_runner = mock_aider

        tool_outputs = {}
        for slug in sample_config.target_repos:
            tool_outputs[slug] = {
                "bandit": json.dumps({"results": [{"test_id": "B602", "filename": "src/app.py", "line_number": 5, "issue_severity": "HIGH", "issue_text": "subprocess with shell=True"}]}),
            }

        cycle_res = orch.run_two_agent_cycle(
            repo_slugs=sample_config.target_repos,
            simulated_tool_outputs=tool_outputs,
        )

        assert "bug_logs" in cycle_res
        assert len(cycle_res["bug_logs"]) == 5
        assert "fix_results" in cycle_res
        assert len(cycle_res["fix_results"]) == 5

        for fix in cycle_res["fix_results"]:
            assert fix["outcome"] == "PR_CREATED"
            assert fix["success"] is True
            assert fix["head_spec"] == fix["branch_name"]

    def test_fixer_push_failure_leaves_bug_pending_and_rolls_back(self, sample_config: Config, tmp_path: Path):
        """Verify that when Git push fails, the bug is NOT marked DONE in Bug-log.md and rollback is called."""
        repo_dir = tmp_path / "repo_push_fail"
        repo_dir.mkdir(parents=True)
        subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
        (repo_dir / "src").mkdir()
        (repo_dir / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo_dir, check=True, capture_output=True)

        log_path = repo_dir / "Bug-log.md"
        log_path.write_text("- [ ] **BUG-999**: src/app.py:1 - [tool:rule] Fix bug\n", encoding="utf-8")

        mock_gm = MagicMock(spec=GitManager)
        mock_gm.get_authenticated_user.return_value = "arrshh12"
        mock_gm.push_atomic_branch.side_effect = RuntimeError("Push rejected: network unreachable")

        mock_aider = MagicMock(spec=AiderRunner)
        from src.aider_runner import AiderResult
        mock_aider.run_aider.return_value = AiderResult(
            exit_code=0,
            status="SUCCESS",
            diff_output="--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n",
            target_file="src/app.py",
        )

        fixer = MainFixerAgent(config=sample_config, git_manager=mock_gm, aider_runner=mock_aider)
        res = fixer.fix_next_bug("owner/repo", repo_dir, bug_log_path=log_path)

        assert res.success is False
        assert res.status == "PUSH_FAILED"
        mock_gm.rollback_working_tree.assert_called_once()

        # Bug must still be pending in Bug-log.md!
        content = log_path.read_text(encoding="utf-8")
        assert "- [ ] **BUG-999**" in content
        assert "- [x]" not in content


