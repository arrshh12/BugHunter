"""
Comprehensive End-to-End Integration and Remediation Test Suite (Milestone 4 / R1-R4).

Verifies:
1. Full Remediation Pipeline Integration:
   - Multi-scanner finding ingestion (Flake8, ESLint, Bandit, Semgrep, Trivy)
   - 5-axis triage ranking, proximity deduplication (+/- 2 lines), trust boundary elevation
   - Surgical AST context extraction, decorator retention, POSIX path normalization
   - Patch planning adhering strictly to One Bug = One PR and <= 150 lines diff ceiling
   - Headless AiderRunner CLI argument construction, environment sanitization, process isolation, and diff extraction
   - Verifier diff bounds (<= 3 files, <= 150 lines), secret sanitization, collision guard, and conventional commit PR formatting
2. End-to-End Resilience & Failure Recovery:
   - Rate limit 429 detection triggering circuit breaker failover to next healthy key
   - Quota exhaustion 402 / insufficient_quota tripping 24-hour key lockout
   - Subprocess timeout watchdog terminating hung process trees cleanly
   - Missing binary handling returning status="NOT_FOUND" without unhandled crashes
3. Global System Audits:
   - Zero "longcat" / "longcat-preview" references across operational codebase
   - py_compile compilation integrity across all src/*.py and main.py
   - ScaleMax configuration defaults and invariants (https://api.scalemax.pro/v1, openai/gpt-6-luna)
"""

from __future__ import annotations

import json
import os
import py_compile
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.aider_runner import AiderRunner
from src.bughunter_agent import (
    BugHunterAgent,
    PatchPlan,
    TriagedFinding,
)
from src.code_graph import GraphEdge
from src.config import Config, KeyConfig
from src.database import Database
from src.key_manager import KeyManager
from src.verifier import ConventionalTitle, Verifier

# =========================================================================
# Fixtures & Test Helpers
# =========================================================================


@dataclass
class _MockGraphEngine:
    edges: list[GraphEdge]


@pytest.fixture
def test_git_repo(tmp_path: Path) -> Path:
    """Initialize a genuine git repository with standard commits and structure."""
    repo = tmp_path / "target_repo"
    repo.mkdir(parents=True, exist_ok=True)

    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "bughunter@example.com"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "AutoBugHunter Agent"],
        cwd=repo,
        check=True,
        capture_output=True,
    )

    # Create initial files
    api_dir = repo / "src" / "api"
    api_dir.mkdir(parents=True, exist_ok=True)

    auth_code = '''"""Authentication and token handling module."""
import os
import sys
import hashlib
import subprocess

def log_event(event_name: str) -> None:
    """Internal event logger."""
    print(f"Event: {event_name}")

@classmethod
def setup_auth_gate():
    """Setup gate hook."""
    return True

def authenticate_user(username: str, secret_token: str) -> bool:
    """Validate user credentials against system registry."""
    if not username:
        return False
    # Vulnerable command execution
    cmd = f"check_auth.sh {username}"
    subprocess.call(cmd, shell=True)
    return True

def auxiliary_cleanup() -> None:
    """Helper routine."""
    pass
'''
    (api_dir / "auth.py").write_text(auth_code, encoding="utf-8")
    (repo / "README.md").write_text("# Target Repo\n", encoding="utf-8")

    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "Initial commit for target repository"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    return repo


@pytest.fixture
def mock_graph_engine() -> _MockGraphEngine:
    """Provide a mock dependency graph with inbound non-test callers."""
    return _MockGraphEngine(
        edges=[
            GraphEdge(
                source="src/web_server.py",
                target="src/api/auth.py",
                edge_type="IMPORTS",
            ),
            GraphEdge(
                source="src/orchestrator.py",
                target="src/api/auth.py",
                edge_type="IMPORTS",
            ),
            GraphEdge(
                source="tests/test_auth.py",
                target="src/api/auth.py",
                edge_type="IMPORTS",
            ),
        ]
    )


# =========================================================================
# 1. Full Remediation Pipeline Integration Tests
# =========================================================================


class TestFullRemediationPipeline:
    """
    End-to-End verification of the complete remediation pipeline:
    Scanner Ingestion -> Triage & Proximity Clustering -> Surgical AST Extraction
    -> Patch Planning (<=150 lines, <=3 files) -> AiderRunner Execution & Diff -> Verifier Gate.
    """

    def test_e2e_remediation_pipeline_all_scanners_to_verifier(
        self, test_git_repo: Path, mock_graph_engine: _MockGraphEngine
    ) -> None:
        """
        Verify the complete pipeline across all 5 scanners:
        Flake8, ESLint, Bandit, Semgrep, Trivy -> Triage -> AST -> Plan -> Aider -> Verifier.
        """
        agent = BugHunterAgent()
        triage_skill = agent.triage_skill

        # 1. Multi-scanner finding ingestion
        flake8_output = (
            "src/api/auth.py:21:5: F821 undefined name 'cmd'\n"
            "src/api/auth.py:50:1: E501 line too long (95 > 79 characters)\n"  # Cosmetic noise, should be dropped
        )
        flake8_findings = triage_skill.parse_flake8(flake8_output)
        assert len(flake8_findings) == 2

        eslint_json = json.dumps([
            {
                "filePath": "src/client.js",
                "messages": [
                    {
                        "ruleId": "no-eval",
                        "severity": 2,
                        "message": "eval can be harmful.",
                        "line": 15,
                        "column": 5,
                    }
                ],
            }
        ])
        eslint_findings = triage_skill.parse_eslint(eslint_json)
        assert len(eslint_findings) == 1
        assert eslint_findings[0].tool == "eslint"

        bandit_json = json.dumps({
            "results": [
                {
                    "code": "subprocess.call(cmd, shell=True)",
                    "filename": "src/api/auth.py",
                    "issue_confidence": "HIGH",
                    "issue_severity": "CRITICAL",
                    "issue_text": "subprocess call with shell=True identified, critical command injection.",
                    "line_number": 22,
                    "test_id": "B602",
                }
            ]
        })
        bandit_findings = triage_skill.parse_bandit(bandit_json)
        assert len(bandit_findings) == 1
        assert bandit_findings[0].tool == "bandit"

        semgrep_json = json.dumps({
            "results": [
                {
                    "check_id": "python.lang.security.dangerous-subprocess.dangerous-subprocess",
                    "path": "src/api/auth.py",
                    "start": {"line": 21, "col": 5},
                    "extra": {
                        "message": "Dangerous subprocess execution with untrusted input.",
                        "severity": "ERROR",
                        "lines": "subprocess.call(cmd, shell=True)",
                    },
                }
            ]
        })
        semgrep_findings = triage_skill.parse_semgrep(semgrep_json)
        assert len(semgrep_findings) == 1
        assert semgrep_findings[0].tool == "semgrep"

        trivy_json = json.dumps({
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Class": "lang-pkgs",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-9999",
                            "PkgName": "cryptography",
                            "Severity": "HIGH",
                            "Title": "Buffer overflow vulnerability in cryptography",
                        }
                    ],
                }
            ]
        })
        trivy_findings = triage_skill.parse_trivy(trivy_json)
        assert len(trivy_findings) == 1
        assert trivy_findings[0].tool == "trivy"

        # Combine all findings
        all_raw_findings = (
            flake8_findings
            + eslint_findings
            + bandit_findings
            + semgrep_findings
            + trivy_findings
        )
        assert len(all_raw_findings) == 6

        # 2. Triage & Ranking with Proximity Deduplication & Trust Boundary Elevation
        triaged = agent.triage_findings(
            raw_findings=all_raw_findings,
            repo_path=test_git_repo,
            graph_engine=mock_graph_engine,
            skip_files=["src/client.js"],  # Skip file collision guard
        )
        assert len(triaged) >= 1

        # The cluster in src/api/auth.py lines 21-22 should deduplicate Flake8, Bandit, Semgrep into one bug
        top_bug = triaged[0]
        assert top_bug.file == "src/api/auth.py"
        assert top_bug.primary_axis == "security"
        assert top_bug.is_trust_boundary is True
        assert top_bug.blast_radius_score >= 30.0  # Trust boundary (+30) + inbound callers
        # Reporting tools list should combine reporting tools
        assert "bandit" in top_bug.tools_reporting
        assert "semgrep" in top_bug.tools_reporting

        # Verify agent.analyze_and_plan produces identical top plan
        pipeline_plan = agent.analyze_and_plan(
            repo_path=test_git_repo,
            raw_findings=all_raw_findings,
            skip_files=["src/client.js"],
            graph_engine=mock_graph_engine,
        )
        assert pipeline_plan is not None
        assert pipeline_plan.target_file == "src/api/auth.py"

        # 3. Surgical AST Context Extraction
        context = agent.extract_context(test_git_repo, top_bug)
        assert context.context_type == "ast_python"
        assert context.target_line in (21, 22)
        assert "authenticate_user" in context.enclosing_symbol
        assert "import subprocess" in context.imports_slice
        assert "subprocess.call(cmd, shell=True)" in context.code_slice
        # Full file was NOT dumped
        assert "log_event" not in context.code_slice
        assert "setup_auth_gate" not in context.code_slice
        assert "=== SURGICAL CONTEXT:" in context.formatted_prompt_block

        # 4. Patch Planning (One Bug = One PR, <= 150 line ceiling)
        plan = agent.create_patch_plan(top_bug, context)
        assert isinstance(plan, PatchPlan)
        assert plan.scope == "auth"
        assert plan.pr_title.startswith("fix(auth):")
        assert plan.diff_ceiling_lines == 150
        assert plan.diff_ceiling_files == 3
        assert "One Bug = One PR" in plan.aider_prompt
        assert "<= 150 lines" in plan.aider_prompt
        assert plan.target_file == "src/api/auth.py"

        # 5. Headless AiderRunner CLI Command Construction & Execution
        runner = AiderRunner(
            timeout_seconds=60,
            default_model="openai/gpt-6-luna",
            default_api_base="https://api.scalemax.pro/v1",
        )
        cmd = runner.build_command(
            target_file=plan.target_file,
            patch_instruction=plan.aider_prompt,
            api_key="sk-test-scalemax-key-12345678",
        )
        assert cmd[0] == "aider"
        assert cmd[cmd.index("--model") + 1] == "openai/gpt-6-luna"
        assert cmd[cmd.index("--openai-api-base") + 1] == "https://api.scalemax.pro/v1"
        assert "--yes" in cmd
        assert "--no-auto-commits" in cmd
        assert "--edit-format" in cmd
        assert cmd[cmd.index("--edit-format") + 1] == "diff"
        assert cmd[-1] == "src/api/auth.py"

        env = runner.build_environment(
            api_key="sk-test-scalemax-key-12345678",
            base_env={"PATH": os.environ.get("PATH", ""), "GITHUB_TOKEN": "secret-token-to-strip"},
        )
        assert env["OPENAI_API_BASE"] == "https://api.scalemax.pro/v1"
        assert env["OPENAI_BASE_URL"] == "https://api.scalemax.pro/v1"
        assert env["OPENAI_API_KEY"] == "sk-test-scalemax-key-12345678"
        assert "GITHUB_TOKEN" not in env

        # Execute remediation edit in the real repository
        auth_file = test_git_repo / "src" / "api" / "auth.py"
        raw_auth = auth_file.read_text(encoding="utf-8")
        patched_code = re.sub(
            r'cmd\s*=\s*f"check_auth\.sh \{username\}"\s*subprocess\.call\(cmd,\s*shell=True\)',
            'subprocess.run(["check_auth.sh", username], shell=False, check=True)',
            raw_auth,
        )
        assert patched_code != raw_auth, "Failed to apply patch replacement to auth.py"
        auth_file.write_text(patched_code, encoding="utf-8")

        # Mock the subprocess.Popen to return success while using real git diff and stdout fallback
        diff_snippet = (
            "```diff\n"
            "--- a/src/api/auth.py\n"
            "+++ b/src/api/auth.py\n"
            "@@ -21,2 +21,1 @@\n"
            "-    cmd = f\"check_auth.sh {username}\"\n"
            "-    subprocess.call(cmd, shell=True)\n"
            "+    subprocess.run([\"check_auth.sh\", username], shell=False, check=True)\n"
            "```\n"
        )
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = iter([
            "Aider v0.70.0 started with openai/gpt-6-luna\n",
            diff_snippet,
            "Applied 1 diff hunk to src/api/auth.py\n",
        ])
        mock_proc.wait.return_value = 0

        with patch("subprocess.Popen", return_value=mock_proc):
            aider_res = runner.run_aider(
                repo_path=test_git_repo,
                target_file=plan.target_file,
                patch_instruction=plan.aider_prompt,
                api_key="sk-test-scalemax-key-12345678",
            )

        assert aider_res.exit_code == 0
        assert aider_res.status == "SUCCESS"
        assert "subprocess.run" in aider_res.diff_output
        assert "shell=False" in aider_res.diff_output

        # 6. Verifier Gate & Secret Sanitization
        verifier = Verifier()
        verification = verifier.verify_and_sanitize_fix(
            repo_path=test_git_repo,
            skip_files=["src/skip_me.py"],
            max_files=plan.diff_ceiling_files,
            max_lines=plan.diff_ceiling_lines,
            simulated_report={
                "bug_found": True,
                "file_modified": plan.target_file,
                "pr_title": plan.pr_title,
                "pr_body": plan.pr_body,
            },
        )

        assert verification.verified is True
        assert verification.error_reason is None
        assert "src/api/auth.py" in verification.modified_files
        assert 1 <= verification.diff_lines <= 150
        assert len(verification.modified_files) <= 3
        assert verification.scope == "auth"
        assert verification.conventional_pr_title == plan.pr_title
        assert isinstance(verification.pr_title, ConventionalTitle)

    def test_e2e_pipeline_ast_decorator_retention_and_posix_paths(
        self, test_git_repo: Path
    ) -> None:
        """
        Verify that AST context extraction preserves function decorators and normalizes
        Windows-style backslashes to standard POSIX relative paths.
        """
        agent = BugHunterAgent()
        code_file = test_git_repo / "src" / "decorated.py"
        decorated_content = '''"""Decorated handlers."""
from functools import wraps

def custom_guard(fn):
    return fn

@classmethod
@custom_guard
def secured_endpoint(user_id: int) -> dict:
    """Handle secured endpoint."""
    if user_id <= 0:
        raise ValueError("Invalid user ID")
    return {"status": "ok", "user": user_id}
'''
        code_file.write_text(decorated_content, encoding="utf-8")

        finding = TriagedFinding(
            id="src/decorated.py:11:SEC01",
            primary_axis="security",
            severity="ERROR",
            composite_score=150.0,
            blast_radius_score=30.0,
            is_trust_boundary=True,
            inbound_dependents_count=1,
            tools_reporting=["bandit"],
            file="src\\decorated.py",  # Windows-style backslash
            line=11,
            column=1,
            rule_id="SEC01",
            message="Input validation check required",
            code_snippet="if user_id <= 0:",
        )

        context = agent.extract_context(test_git_repo, finding)
        assert context.context_type == "ast_python"
        assert context.file_path == "src/decorated.py"  # POSIX normalized
        assert "@classmethod" in context.code_slice
        assert "@custom_guard" in context.code_slice
        assert "def secured_endpoint" in context.code_slice

        # Formulate patch plan
        plan = agent.create_patch_plan(finding, context)
        assert plan.target_file == "src\\decorated.py"
        assert plan.scope == "decorated"
        assert plan.pr_title == "fix(decorated): resolve SEC01 in decorated.py"

    def test_e2e_pipeline_diff_ceiling_and_atomic_boundary_enforcement(
        self, test_git_repo: Path
    ) -> None:
        """
        Verify that Verifier strictly enforces diff line limits (<=150) and file bounds (<=3).
        """
        verifier = Verifier()

        # 1. Reject > 150 diff lines
        huge_diff = "--- a/src/core.py\n+++ b/src/core.py\n" + "".join(
            f"+line_{i} = {i}\n" for i in range(151)
        )
        res_lines = verifier.verify_and_sanitize_fix(
            repo_path=test_git_repo,
            skip_files=[],
            max_lines=150,
            custom_diff=huge_diff,
            simulated_report={"bug_found": True, "file_modified": "src/core.py"},
        )
        assert res_lines.verified is False
        assert "exceeding limit of 150" in res_lines.error_reason

        # 2. Reject > 3 modified files
        res_files = verifier.verify_and_sanitize_fix(
            repo_path=test_git_repo,
            skip_files=[],
            max_files=3,
            custom_diff="--- a/f1.py\n+++ b/f1.py\n@@ -1 +1 @@\n+x=1\n",
            simulated_report={
                "bug_found": True,
                "files_modified": ["f1.py", "f2.py", "f3.py", "f4.py"],
            },
        )
        assert res_files.verified is False
        assert "Modified 4 files, exceeding limit of 3" in res_files.error_reason

    def test_e2e_pipeline_secret_leak_interception(self, test_git_repo: Path) -> None:
        """Verify Verifier intercepts simulated GitHub tokens and OpenAI keys."""
        verifier = Verifier()

        # Leak 1: GitHub PAT
        leaked_diff_pat = (
            "--- a/src/auth.py\n+++ b/src/auth.py\n@@ -10,1 +10,1 @@\n"
            "+GITHUB_PAT = 'ghp_123456789012345678901234567890123456'\n"
        )
        res_pat = verifier.verify_and_sanitize_fix(
            repo_path=test_git_repo,
            skip_files=[],
            custom_diff=leaked_diff_pat,
            simulated_report={"bug_found": True, "file_modified": "src/auth.py"},
        )
        assert res_pat.verified is False
        assert "Credential leak detected" in res_pat.error_reason

        # Leak 2: OpenAI API Key
        leaked_diff_openai = (
            "--- a/src/auth.py\n+++ b/src/auth.py\n@@ -10,1 +10,1 @@\n"
            "+OPENAI_KEY = 'sk-1234567890123456789012345'\n"
        )
        res_openai = verifier.verify_and_sanitize_fix(
            repo_path=test_git_repo,
            skip_files=[],
            custom_diff=leaked_diff_openai,
            simulated_report={"bug_found": True, "file_modified": "src/auth.py"},
        )
        assert res_openai.verified is False
        assert "Credential leak detected" in res_openai.error_reason

    def test_e2e_pipeline_whitespace_only_rejection(self, test_git_repo: Path) -> None:
        """Verify that whitespace-only modifications are caught and rejected."""
        verifier = Verifier()
        # Modifying only whitespace in src/api/auth.py
        auth_file = test_git_repo / "src" / "api" / "auth.py"
        current_content = auth_file.read_text(encoding="utf-8")
        auth_file.write_text(current_content.replace("    pass\n", "    pass   \n"), encoding="utf-8")

        res = verifier.verify_and_sanitize_fix(
            repo_path=test_git_repo,
            skip_files=[],
            simulated_report={"bug_found": True, "file_modified": "src/api/auth.py"},
        )
        assert res.verified is False
        assert "Whitespace-only changes rejected" in res.error_reason


# =========================================================================
# 2. End-to-End Resilience & Failure Recovery Tests
# =========================================================================


class TestEndToEndResilience:
    """
    Verify end-to-end resilience against upstream failure modes:
    HTTP 429 rate limits, HTTP 402 quota exhaustion, process timeouts, and missing binaries.
    """

    def test_e2e_rate_limit_429_failover(self, tmp_path: Path, test_git_repo: Path) -> None:
        """
        Verify rate limit 429 encountered during Aider execution trips circuit breaker
        into COOLDOWN and successfully fails over to the next healthy key in the pool.
        """
        db_file = tmp_path / "test_keys_429.sqlite"
        db = Database(db_file)

        k1 = KeyConfig(
            id="key-primary",
            provider="ScaleMax",
            base_url="https://api.scalemax.pro/v1",
            model="openai/gpt-6-luna",
            api_key="sk-primary-key-11111111",
            masked_key="sk-p...1111",
            priority=1,
        )
        k2 = KeyConfig(
            id="key-backup",
            provider="ScaleMax",
            base_url="https://api.scalemax.pro/v1",
            model="openai/gpt-6-luna",
            api_key="sk-backup-key-22222222",
            masked_key="sk-b...2222",
            priority=2,
        )

        config = Config.load(overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": [k1, k2],
        })
        key_manager = KeyManager(config, db)

        # Confirm primary key is initially active
        initial_key = key_manager.get_next_healthy_key()
        assert initial_key is not None
        assert initial_key.id == "key-primary"

        runner = AiderRunner()

        # Simulate Aider returning HTTP 429 RateLimitError on primary key
        mock_proc_429 = MagicMock()
        mock_proc_429.returncode = 1
        mock_proc_429.stdout = iter([
            "Aider v0.70.0 initializing...\n",
            "RateLimitError: HTTP 429 Too Many Requests: Rate limit exceeded\n",
        ])
        mock_proc_429.wait.return_value = 1

        with patch("subprocess.Popen", return_value=mock_proc_429):
            result_1 = runner.run_aider(
                repo_path=test_git_repo,
                target_file="src/api/auth.py",
                patch_instruction="Fix vulnerability",
                key_entry=initial_key,
            )

        assert result_1.status == "RATE_LIMIT_429"
        assert result_1.error_message is not None

        # Coordinator reports failure to KeyManager
        key_manager.report_key_failure(
            key_id=initial_key.id,
            error_message=result_1.error_message,
            status_code=429,
        )

        # Verify key-primary is now in COOLDOWN
        with db.get_connection() as conn:
            row = conn.execute(
                "SELECT state, consecutive_failures FROM api_key_status WHERE key_id='key-primary'"
            ).fetchone()
            assert row["state"] == "COOLDOWN"
            assert row["consecutive_failures"] == 1

        # KeyManager automatically promotes/fails over to key-backup
        failover_key = key_manager.get_next_healthy_key()
        assert failover_key is not None
        assert failover_key.id == "key-backup"

        # Second execution with backup key succeeds
        mock_proc_ok = MagicMock()
        mock_proc_ok.returncode = 0
        mock_proc_ok.stdout = iter([
            "Aider v0.70.0 initializing with backup key...\n",
            "Fix successfully applied to src/api/auth.py\n",
        ])
        mock_proc_ok.wait.return_value = 0

        with patch("subprocess.Popen", return_value=mock_proc_ok), \
             patch.object(runner, "extract_diff", return_value="--- a/src/api/auth.py\n+++ b/src/api/auth.py\n@@ -1 +1 @@\n-old\n+new\n"):
            result_2 = runner.run_aider(
                repo_path=test_git_repo,
                target_file="src/api/auth.py",
                patch_instruction="Fix vulnerability",
                key_entry=failover_key,
            )

        assert result_2.status == "SUCCESS"
        assert result_2.diff_output != ""
        key_manager.report_key_success(failover_key.id)

    def test_e2e_quota_exhaustion_402_trip(self, tmp_path: Path, test_git_repo: Path) -> None:
        """
        Verify quota exhaustion 402 / insufficient_quota trips the key to EXHAUSTED
        for 24 hours, preventing re-selection.
        """
        db_file = tmp_path / "test_keys_402.sqlite"
        db = Database(db_file)

        k1 = KeyConfig(
            id="key-exhaust",
            provider="ScaleMax",
            base_url="https://api.scalemax.pro/v1",
            model="openai/gpt-6-luna",
            api_key="sk-exhaust-key-11111111",
            masked_key="sk-e...1111",
            priority=1,
        )
        k2 = KeyConfig(
            id="key-standby",
            provider="ScaleMax",
            base_url="https://api.scalemax.pro/v1",
            model="openai/gpt-6-luna",
            api_key="sk-standby-key-22222222",
            masked_key="sk-s...2222",
            priority=2,
        )

        config = Config.load(overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": [k1, k2],
        })
        key_manager = KeyManager(config, db)

        runner = AiderRunner()

        # Simulate Aider returning HTTP 402 insufficient_quota
        mock_proc_402 = MagicMock()
        mock_proc_402.returncode = 1
        mock_proc_402.stdout = iter([
            "API error: insufficient_quota (402 Payment Required)\n",
        ])
        mock_proc_402.wait.return_value = 1

        with patch("subprocess.Popen", return_value=mock_proc_402):
            result = runner.run_aider(
                repo_path=test_git_repo,
                target_file="src/api/auth.py",
                patch_instruction="Patch",
                key_entry=k1,
            )

        assert result.status == "QUOTA_EXHAUSTED_402"

        # Coordinator trips key in KeyManager
        key_manager.report_key_failure(
            key_id=k1.id,
            error_message="insufficient_quota (402 Payment Required)",
            status_code=402,
        )

        with db.get_connection() as conn:
            row = conn.execute(
                "SELECT state, cooldown_until FROM api_key_status WHERE key_id='key-exhaust'"
            ).fetchone()
            assert row["state"] == "EXHAUSTED"
            assert row["cooldown_until"] is not None

        # Next key selected must be standby key
        next_key = key_manager.get_next_healthy_key()
        assert next_key is not None
        assert next_key.id == "key-standby"

    def test_e2e_timeout_watchdog_process_cleanup(self, test_git_repo: Path) -> None:
        """
        Verify that when an Aider subprocess exceeds the timeout threshold,
        the watchdog aborts execution, terminates the process tree, and returns status="TIMEOUT".
        """
        # Runner configured with a tiny 0.2s timeout
        runner = AiderRunner(timeout_seconds=0.2)

        # Hanging command that sleeps longer than timeout
        hang_cmd = [sys.executable, "-c", "import time; time.sleep(5)"]

        with patch.object(runner, "build_command", return_value=hang_cmd):
            start = time.time()
            res = runner.run_aider(
                repo_path=test_git_repo,
                target_file="src/api/auth.py",
                patch_instruction="Fix",
            )
            elapsed = time.time() - start

        assert res.status == "TIMEOUT"
        assert res.exit_code != 0
        assert "timed out" in (res.error_message or "").lower()
        # Execution terminated close to the 0.2s watchdog threshold
        assert elapsed < 3.0

    def test_e2e_missing_binary_graceful_handling(self, test_git_repo: Path) -> None:
        """
        Verify that if the Aider binary is not found, AiderRunner cleanly returns
        status="NOT_FOUND" without unhandled crashes.
        """
        runner = AiderRunner(aider_binary="non_existent_aider_bin_xyz_99")
        res = runner.run_aider(
            repo_path=test_git_repo,
            target_file="src/api/auth.py",
            patch_instruction="Fix",
        )
        assert res.status == "NOT_FOUND"
        assert res.exit_code == -1
        assert "not found" in (res.error_message or "").lower()


# =========================================================================
# 3. Global System Audits
# =========================================================================


class TestGlobalSystemAudits:
    """
    Global system invariants across configuration, codebase compilation,
    and eradication of legacy model identifiers.
    """

    def test_zero_longcat_references_across_codebase(self) -> None:
        """
        Assert that 'longcat' and 'longcat-preview' do NOT appear in any src/ file,
        main.py, .env.example, Dockerfile, or docker-compose.yml.
        """
        root_dir = Path(__file__).resolve().parent.parent

        target_files: list[Path] = []

        # All python files in src/
        src_dir = root_dir / "src"
        if src_dir.exists():
            target_files.extend(src_dir.rglob("*.py"))

        # Explicit root files
        for extra in ["main.py", ".env.example", "Dockerfile", "docker-compose.yml"]:
            extra_path = root_dir / extra
            if extra_path.exists():
                target_files.append(extra_path)

        assert len(target_files) >= 5, f"Expected at least 5 target files, found {len(target_files)}"

        violations: list[str] = []
        for file_path in target_files:
            try:
                content = file_path.read_text(encoding="utf-8")
                # Look for longcat case-insensitively
                matches = re.findall(r"(?i)\blongcat(?:-preview)?\b", content)
                if matches:
                    violations.append(f"{file_path.relative_to(root_dir)}: {matches}")
            except Exception as e:
                violations.append(f"{file_path}: read error {e}")

        assert not violations, "Found legacy longcat references in codebase:\n" + "\n".join(violations)

    def test_all_src_files_compile(self) -> None:
        """
        Verify that all src/*.py files and main.py compile cleanly with py_compile.
        """
        root_dir = Path(__file__).resolve().parent.parent
        src_dir = root_dir / "src"

        files_to_compile: list[Path] = list(src_dir.rglob("*.py"))
        main_file = root_dir / "main.py"
        if main_file.exists():
            files_to_compile.append(main_file)

        assert len(files_to_compile) >= 10

        compilation_failures: list[str] = []
        for py_file in files_to_compile:
            try:
                py_compile.compile(str(py_file), doraise=True)
            except py_compile.PyCompileError as exc:
                compilation_failures.append(f"{py_file.name}: {exc}")

        assert not compilation_failures, (
            "py_compile failed on the following files:\n" + "\n".join(compilation_failures)
        )

    def test_scalemax_configuration_invariants(self) -> None:
        """
        Verify that Config.load() defaults to ScaleMax endpoint and gpt-6-luna model,
        and AiderRunner defaults match ScaleMax invariants.
        """
        # Test Config defaults in isolation
        with patch.dict(os.environ, {}, clear=True):
            config = Config.load(env_file=Path("nonexistent_env_file_for_test"))
            assert config.openai_api_base == "https://api.scalemax.pro/v1"
            assert config.llm_model == "openai/gpt-6-luna"

        # Test AiderRunner default constants
        runner = AiderRunner()
        assert runner.default_api_base == "https://api.scalemax.pro/v1"
        assert runner.default_model == "openai/gpt-6-luna"

        # Verify environment builder propagates ScaleMax endpoints
        env = runner.build_environment(api_key="sk-test-scalemax-key")
        assert env.get("OPENAI_API_BASE") == "https://api.scalemax.pro/v1"
        assert env.get("OPENAI_BASE_URL") == "https://api.scalemax.pro/v1"
