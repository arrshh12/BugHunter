"""
Unit tests for src/orchestrator.py: Master scanning cycle, PR dispatcher, collision guards, and exhaustion marks.
"""

from pathlib import Path
from unittest.mock import MagicMock
import pytest
from src.config import Config, KeyConfig
from src.database import Database
from src.git_manager import GitManager
from src.key_manager import KeyManager
from src.logger import RingBufferLogger
from src.openhands_runner import OpenHandsRunner
from src.orchestrator import Orchestrator
from src.static_scanner import StaticScanner
from src.verifier import Verifier


@pytest.fixture
def orchestrator_setup(tmp_path: Path):
    db = Database(tmp_path / "orch.sqlite")
    k1 = KeyConfig("k1", "ScaleMax", "https://api.sm.ai/v1", "claude-haiku-5.5", "sk-12345678", "sk-1...5678", 1)
    config = Config.load(overrides={
        "workspace_dir": tmp_path,
        "LLM_KEYS_POOL": [k1],
        "target_repos": ["owner/repo1"],
        "MAX_OPEN_PRS_PER_REPO": 3
    })
    km = KeyManager(config, db)
    gm = GitManager(tmp_path, max_open_prs=3)
    ss = StaticScanner()
    oh = OpenHandsRunner()
    vf = Verifier()
    rl = RingBufferLogger()

    orch = Orchestrator(config, db, km, gm, ss, oh, vf, rl)
    return orch, db, gm, tmp_path


def test_orchestrator_pause_toggle(orchestrator_setup):
    """Verify pausing halts scanning and toggles state."""
    orch, _, _, _ = orchestrator_setup
    assert orch.paused is False
    orch.toggle_pause()
    assert orch.paused is True

    res = orch.scan_single_repo("owner/repo1")
    assert res["outcome"] == "PAUSED"


def test_orchestrator_max_open_prs_guard(orchestrator_setup):
    """Verify repo is skipped when open PR count reaches ceiling and artifacts purged."""
    orch, db, gm, _ = orchestrator_setup
    sim_prs = [
        {"number": 1, "headRefName": "fix/1", "files": ["f1.py"]},
        {"number": 2, "headRefName": "fix/2", "files": ["f2.py"]},
        {"number": 3, "headRefName": "fix/3", "files": ["f3.py"]},
    ]

    res = orch.scan_single_repo("owner/repo1", simulated_open_prs=sim_prs)
    assert res["outcome"] == "SKIPPED_MAX_PRS"
    assert db.get_stats()["repositories"][0]["status"] == "PAUSED_MAX_PRS"
    repo_path = gm.repos_dir / "owner__repo1"
    assert not (repo_path / ".skip_files.txt").exists()


def test_orchestrator_clean_no_bug_exhausts_repo(orchestrator_setup):
    """Verify clean audit marks fully_exhausted = 1 and sets status to IDLE."""
    orch, db, _, _ = orchestrator_setup
    res = orch.scan_single_repo("owner/clean-repo", simulated_agent_outcome="CLEAN_NO_BUG")

    assert res["outcome"] == "CLEAN_EXHAUSTED"
    repo = db.get_stats()["repositories"][0]
    assert repo["fully_exhausted"] == 1

    # Second scan on same clean commit is skipped
    res2 = orch.scan_single_repo("owner/clean-repo")
    assert res2["outcome"] == "SKIPPED_EXHAUSTED"


def test_orchestrator_successful_pr_dispatch(orchestrator_setup):
    """Verify successful bug fix flows through verification, PR creation, and DB recording."""
    orch, db, _, _ = orchestrator_setup
    custom_diff = """--- a/README.md
+++ b/README.md
@@ -1,1 +1,2 @@
 # repo
+fix: resolve crash
"""
    res = orch.scan_single_repo(
        "owner/success-repo",
        simulated_agent_outcome="SUCCESS",
        custom_diff=custom_diff
    )

    assert res["outcome"] == "PR_CREATED"
    assert "pr_url" in res
    stats = db.get_stats()
    assert stats["kpis"]["total_prs_created"] == 1
    assert len(stats["recent_prs"]) == 1


def test_orchestrator_verification_failure_rollback(orchestrator_setup):
    """Verify invalid fix triggers rollback and marks VERIFICATION_FAILED."""
    orch, db, _, _ = orchestrator_setup
    # Empty diff triggers verification failure
    res = orch.scan_single_repo(
        "owner/fail-repo",
        simulated_agent_outcome="SUCCESS",
        custom_diff=""
    )
    assert res["outcome"] == "VERIFICATION_FAILED"
    stats = db.get_stats()
    assert stats["repositories"][0]["status"] == "ERROR"


def test_orchestrator_force_scan_queue(orchestrator_setup):
    """Verify force scan queue prioritizes repository even if exhausted."""
    orch, db, _, _ = orchestrator_setup
    orch.scan_single_repo("owner/force-repo", simulated_agent_outcome="CLEAN_NO_BUG")
    assert db.get_stats()["repositories"][0]["fully_exhausted"] == 1

    orch.queue_force_scan("owner/force-repo")
    custom_diff = """--- a/README.md
+++ b/README.md
@@ -1,1 +1,2 @@
 # repo
+fix: priority fix
"""
    results = orch.run_cycle()
    # First result was the forced scan
    assert len(results) >= 1
    assert results[0]["repo_slug"] == "owner/force-repo"


def test_orchestrator_key_exhaustion_purges_temporary_artifacts(orchestrator_setup):
    """Verify temporary orchestration artifacts are purged if all API keys are exhausted."""
    orch, db, gm, _ = orchestrator_setup

    # Put all keys in key manager into EXHAUSTED state
    for k in orch.config.llm_keys:
        orch.key_manager.report_key_failure(k.id, "Simulated quota exhaustion", status_code=402)

    assert orch.key_manager.get_next_healthy_key() is None

    repo_slug = "owner/exhaustion-purge-repo"
    repo_path = gm.repos_dir / "owner__exhaustion-purge-repo"
    repo_path.mkdir(parents=True, exist_ok=True)
    # Pre-populate stale artifacts
    (repo_path / ".skip_files.txt").write_text("src/core.py\n", encoding="utf-8")
    (repo_path / ".static_findings.json").write_text('{"findings": []}', encoding="utf-8")
    (repo_path / ".bug_fix_report.json").write_text('{"bug_found": true}', encoding="utf-8")

    res = orch.scan_single_repo(repo_slug)

    assert res["outcome"] == "NO_HEALTHY_KEYS"
    assert db.get_stats()["repositories"][0]["status"] == "ERROR"

    # Verify none of the temporary artifacts remain on disk
    assert not (repo_path / ".skip_files.txt").exists()
    assert not (repo_path / ".static_findings.json").exists()
    assert not (repo_path / ".bug_fix_report.json").exists()

