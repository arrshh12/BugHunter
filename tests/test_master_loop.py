"""
Unit and integration tests for Orchestrator Master Loop:
Dual-Layer Hybrid Memory (Layer 1 Episodic Memory, Layer 2 Structural Graph),
Scoped Branch Creation, and Bug Memory Outcome Feedback.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from src.config import Config, KeyConfig
from src.database import Database
from src.git_manager import GitManager
from src.key_manager import KeyManager
from src.logger import RingBufferLogger
from src.openhands_runner import OpenHandsRunner, SessionResult
from src.orchestrator import Orchestrator
from src.static_scanner import StaticScanner
from src.verifier import Verifier


@pytest.fixture
def master_loop_setup(tmp_path: Path):
    """Fixture providing Orchestrator with an isolated SQLite WAL database and git workspace."""
    db = Database(tmp_path / "test_master_loop.sqlite")
    k1 = KeyConfig(
        id="k1",
        provider="ScaleMax",
        base_url="https://api.sm.ai/v1",
        model="claude-haiku-5.5",
        api_key="sk-12345678",
        masked_key="sk-1...5678",
        priority=1,
    )
    config = Config.load(overrides={
        "workspace_dir": tmp_path,
        "LLM_KEYS_POOL": [k1],
        "target_repos": ["owner/master-loop-repo"],
        "MAX_OPEN_PRS_PER_REPO": 3,
    })
    km = KeyManager(config, db)
    gm = GitManager(tmp_path, max_open_prs=3)
    ss = StaticScanner()
    oh = OpenHandsRunner()
    vf = Verifier()
    rl = RingBufferLogger()

    orch = Orchestrator(config, db, km, gm, ss, oh, vf, rl)
    return orch, db, gm, tmp_path


# =========================================================================
# TEST 1: Layer 1 Episodic Memory Pre-Filter Skips Finding and Concludes Cleanly
# =========================================================================
def test_layer1_memory_prefilter_skips_finding_and_concludes_cleanly(master_loop_setup, monkeypatch):
    """
    Test 1: Layer 1 Episodic Memory pre-filter skips recurring false positive finding
    (similarity > 0.88) without running OpenHands, purges artifacts, and concludes cleanly.
    """
    orch, db, gm, tmp_path = master_loop_setup
    repo_slug = "owner/fp-skip-repo"
    repo_path = gm.repos_dir / "owner__fp-skip-repo"
    repo_path.mkdir(parents=True, exist_ok=True)

    # 1. Record a known false positive finding in Layer 1 episodic memory
    fp_snippet = "def insecure_function(user_data, items=[]): pass"
    db.record_bug_memory(
        repo_slug=repo_slug,
        commit_sha="dummy_head_sha",
        rule_id="B006",
        file_path="src/handlers.py",
        code_snippet=fp_snippet,
        patch_outcome="false_positive",
        rejection_reason="Mutable default argument is intentional fixture pattern",
        stride_category="Denial of Service",
        owasp_category="A06:Vulnerable and Outdated Components",
    )

    # 2. Populate .static_findings.json with finding identical or > 0.88 similarity
    static_finding = [{
        "tool": "ruff",
        "rule_id": "B006",
        "severity": "WARNING",
        "file": "src/handlers.py",
        "line": 1,
        "column": 1,
        "message": "Do not use mutable default arguments",
        "code_snippet": fp_snippet,
        "stride_category": "Denial of Service",
        "owasp_category": "A06:Vulnerable and Outdated Components",
    }]
    (repo_path / ".static_findings.json").write_text(json.dumps(static_finding), encoding="utf-8")

    # 3. Spy on OpenHandsRunner to ensure it is NOT called
    mock_run_openhands = MagicMock()
    monkeypatch.setattr(orch.openhands, "run_openhands_session", mock_run_openhands)

    # 4. Execute scan
    res = orch.scan_single_repo(repo_slug)

    # 5. Invariant Assertions
    mock_run_openhands.assert_not_called()
    assert res["outcome"] in ("CLEAN_EXHAUSTED", "SKIPPED_MEMORY")
    assert db.get_stats()["repositories"][0]["fully_exhausted"] == 1
    assert not (repo_path / ".task_prompt.txt").exists()


# =========================================================================
# TEST 2: Layer 2 Code Graph Prompt Injection and Cleanup
# =========================================================================
def test_layer2_code_graph_prompt_injection_and_cleanup(master_loop_setup, monkeypatch):
    """
    Test 2: Layer 2 Structural Graph context is generated and injected into OpenHands prompt,
    and ephemeral prompt file is unlinked in finally cleanup.
    """
    orch, db, gm, tmp_path = master_loop_setup
    repo_slug = "owner/graph-injection-repo"
    repo_path = gm.repos_dir / "owner__graph-injection-repo"
    repo_path.mkdir(parents=True, exist_ok=True)
    src_dir = repo_path / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    tests_dir = repo_path / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)

    # Create target module and corresponding test module
    (src_dir / "auth.py").write_text(
        "class TokenManager:\n"
        "    def verify_token(self, token: str) -> bool:\n"
        "        return token == 'valid'\n",
        encoding="utf-8"
    )
    (tests_dir / "test_auth.py").write_text(
        "from src.auth import TokenManager\n"
        "def test_token():\n"
        "    assert TokenManager().verify_token('valid') is True\n",
        encoding="utf-8"
    )

    # Commit the source and test files so git_manager.sync_repository's git reset/clean doesn't wipe them
    subprocess.run(["git", "init", "-b", "main"], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "tester@test.local"], cwd=repo_path, check=True, capture_output=True)
    (repo_path / "README.md").write_text("# Graph Injection Repo\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_path, check=True, capture_output=True)

    # Create static finding pointing to src/auth.py
    static_finding = [{
        "tool": "ruff",
        "rule_id": "S101",
        "severity": "WARNING",
        "file": "src/auth.py",
        "line": 2,
        "column": 5,
        "message": "Use of assert detected",
        "code_snippet": "def verify_token(self, token: str) -> bool:",
        "stride_category": "Information Disclosure",
        "owasp_category": "A02:Cryptographic Failures",
    }]
    (repo_path / ".static_findings.json").write_text(json.dumps(static_finding), encoding="utf-8")

    captured_prompt_blocks: list[str] = []

    def mock_openhands_capture(repo_path, key_entry, task_prompt_path, log_callback, simulated_outcome=None):
        if task_prompt_path.exists():
            captured_prompt_blocks.append(task_prompt_path.read_text(encoding="utf-8"))
        return SessionResult(success=True, bug_found=False, duration_seconds=0.5)

    monkeypatch.setattr(orch.openhands, "run_openhands_session", mock_openhands_capture)

    res = orch.scan_single_repo(repo_slug)

    # Invariant Assertions
    assert len(captured_prompt_blocks) == 1
    prompt_text = captured_prompt_blocks[0]
    assert "LAYER 2 STRUCTURAL CODEBASE MEMORY" in prompt_text
    assert "Target File: src/auth.py" in prompt_text
    assert "TokenManager" in prompt_text
    assert "verify_token" in prompt_text
    # Mapped test suite must be identified
    assert "test_auth.py" in prompt_text
    # Ephemeral prompt file must be removed after execution
    assert not (repo_path / ".task_prompt.txt").exists()


# =========================================================================
# TEST 3: Verified Patch Outcome Recorded in bug_memory
# =========================================================================
def test_orchestrator_records_bug_memory_on_verified_pr(master_loop_setup):
    """
    Test 3: Verified patch outcome is recorded into bug_memory with STRIDE/OWASP metadata and verified status.
    """
    orch, db, gm, tmp_path = master_loop_setup
    repo_slug = "owner/verified-patch-repo"
    repo_path = gm.repos_dir / "owner__verified-patch-repo"
    repo_path.mkdir(parents=True, exist_ok=True)

    static_finding = [{
        "tool": "semgrep",
        "rule_id": "OWASP-A02-KEY",
        "severity": "ERROR",
        "file": "src/crypto.py",
        "line": 10,
        "column": 1,
        "message": "Hardcoded encryption key detected",
        "code_snippet": "KEY = 'secret_key_12345'",
        "stride_category": "Information Disclosure",
        "owasp_category": "A02:Cryptographic Failures",
    }]
    (repo_path / ".static_findings.json").write_text(json.dumps(static_finding), encoding="utf-8")

    custom_diff = """--- a/src/crypto.py
+++ b/src/crypto.py
@@ -1,1 +1,2 @@
-KEY = 'secret_key_12345'
+import os
+KEY = os.environ.get('KEY', '')
"""
    res = orch.scan_single_repo(
        repo_slug,
        simulated_agent_outcome="SUCCESS",
        custom_diff=custom_diff
    )

    # Invariant Assertions
    assert res["outcome"] == "PR_CREATED"
    assert "pr_url" in res

    # Check bug_memory table
    with db.get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM bug_memory WHERE repo_slug = ? AND patch_outcome = 'verified'",
            (repo_slug,)
        ).fetchone()
        assert row is not None
        assert row["patch_outcome"] == "verified"
        assert row["rule_id"] == "OWASP-A02-KEY"
        assert row["stride_category"] == "Information Disclosure"
        assert row["owasp_category"] == "A02:Cryptographic Failures"
        assert "KEY" in row["code_snippet"]


# =========================================================================
# TEST 4: Rejected Patch Outcome Recorded in bug_memory
# =========================================================================
def test_orchestrator_records_bug_memory_on_rejected_verification(master_loop_setup):
    """
    Test 4: Rejected patch outcome is recorded into bug_memory with rejection reason.
    """
    orch, db, gm, tmp_path = master_loop_setup
    repo_slug = "owner/rejected-patch-repo"
    repo_path = gm.repos_dir / "owner__rejected-patch-repo"
    repo_path.mkdir(parents=True, exist_ok=True)

    static_finding = [{
        "tool": "ruff",
        "rule_id": "E501",
        "severity": "INFO",
        "file": "src/utils.py",
        "line": 5,
        "column": 80,
        "message": "Line too long",
        "code_snippet": "long_line_of_code = True",
        "stride_category": "Tampering",
        "owasp_category": "A05:Security Misconfiguration",
    }]
    (repo_path / ".static_findings.json").write_text(json.dumps(static_finding), encoding="utf-8")

    # Empty diff causes verification gate rejection
    res = orch.scan_single_repo(
        repo_slug,
        simulated_agent_outcome="SUCCESS",
        custom_diff="",
    )

    # Invariant Assertions
    assert res["outcome"] == "VERIFICATION_FAILED"

    with db.get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM bug_memory WHERE repo_slug = ? AND patch_outcome = 'rejected'",
            (repo_slug,)
        ).fetchone()
        assert row is not None
        assert row["patch_outcome"] == "rejected"
        assert row["rejection_reason"] is not None
        assert "empty" in row["rejection_reason"].lower()
        assert row["rule_id"] == "E501"


# =========================================================================
# TEST 5: Scoped Atomic Branch Created Using Synthesized Scope
# =========================================================================
def test_orchestrator_creates_scoped_atomic_branch(master_loop_setup):
    """
    Test 5: Scoped atomic branch fix/auto-<scope>-... is created using the synthesized scope.
    """
    orch, db, gm, tmp_path = master_loop_setup
    repo_slug = "owner/scoped-branch-repo"
    repo_path = gm.repos_dir / "owner__scoped-branch-repo"
    repo_path.mkdir(parents=True, exist_ok=True)
    src_dir = repo_path / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "database.py").write_text("# db code\n", encoding="utf-8")

    custom_diff = """--- a/src/database.py
+++ b/src/database.py
@@ -1,1 +1,2 @@
 # db code
+fix: prevent connection leak
"""
    res = orch.scan_single_repo(
        repo_slug,
        simulated_agent_outcome="SUCCESS",
        custom_diff=custom_diff,
    )

    # Invariant Assertions
    assert res["outcome"] == "PR_CREATED"
    branch_name = res["branch_name"]
    # Branch must include conventional scope 'database' synthesized from 'src/database.py'
    assert branch_name.startswith("fix/auto-database-")


# =========================================================================
# TEST 6: Mock Robustness: MagicMock and Legacy GitManager
# =========================================================================
def test_mock_robustness_magicmock_and_legacy_git_manager(master_loop_setup, monkeypatch):
    """
    Test 6: Verify orchestrator gracefully handles MagicMock db, mock git_manager without scope kwarg,
    and missing methods without crashing.
    """
    orch, db, gm, tmp_path = master_loop_setup
    repo_slug = "owner/mock-compat-repo"

    # Test 1: Mock DB lacking should_skip_finding or record_bug_memory
    mock_db = MagicMock()
    orch.db = mock_db

    # Test 2: GitManager create_atomic_branch without 'scope' kwarg
    class LegacyGitManager:
        def __init__(self, original):
            self.orig = original
        def __getattr__(self, name):
            return getattr(self.orig, name)
        def create_atomic_branch(self, repo_path, prefix="auto"):
            # Lacks scope parameter on purpose
            branch_name = f"fix/{prefix}-legacy-branch"
            subprocess.run(["git", "checkout", "-b", branch_name], cwd=repo_path, check=True, capture_output=True)
            return branch_name

    orch.git_manager = LegacyGitManager(gm)

    # Execution should not raise TypeError or UnpackError
    res = orch.scan_single_repo(
        repo_slug,
        simulated_agent_outcome="SUCCESS",
        custom_diff="--- a/README.md\n+++ b/README.md\n@@ -1,1 +1,2 @@\n-a\n+b\n",
    )
    assert res["outcome"] == "PR_CREATED"
    assert res["branch_name"] == "fix/auto-legacy-branch"
