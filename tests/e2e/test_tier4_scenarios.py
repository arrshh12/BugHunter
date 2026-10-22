"""
Tier 4: Realistic End-to-End Bug Hunting Workflow Simulation Scenarios.
Simulates autonomous 24/7 cycles across the complete lifecycle of AutoBugHunter.
"""

from pathlib import Path
import pytest
from starlette.testclient import TestClient

from tests.e2e.conftest import (
    Config,
    ContractDatabase,
    ContractGitManager,
    ContractKeyManager,
    ContractOpenHandsRunner,
    ContractOrchestrator,
    ContractRingBufferLogger,
    ContractStaticScanner,
    ContractVerifier,
    create_contract_web_app,
)


def test_scenario_full_golden_path_autonomous_fix(orchestrator: ContractOrchestrator):
    """Scenario 1: Full Golden Path (Sync -> Pre-filter -> Fix -> Verify -> Branch -> Push -> PR -> Telemetry)."""
    repo_slug = "acme/web-service"

    # Step 1: Execute single scan cycle on buggy repo
    result = orchestrator.scan_single_repo(
        repo_slug=repo_slug,
        simulated_agent_outcome="SUCCESS",
        simulated_open_prs=[],
        custom_diff="+def auth_token(t):\n+    if not t: return None\n+    return t.strip()\n"
    )

    # Step 2: Validate orchestration outcome
    assert result["outcome"] == "PR_CREATED"
    assert "pr_url" in result
    assert "fix/auto-" in result["branch_name"]

    # Step 3: Validate database state
    stats = orchestrator.db.get_stats()
    assert stats["kpis"]["total_prs_created"] >= 1
    recent_pr = stats["recent_prs"][0]
    assert recent_pr["repo_slug"] == repo_slug
    assert recent_pr["file_modified"] == "src/auth.py"
    assert recent_pr["llm_key_id"] == "key-1"

    # Step 4: Validate audit scan_logs
    with orchestrator.db._conn() as conn:
        log_row = conn.execute(
            "SELECT outcome, details FROM scan_logs WHERE repo_slug = ? ORDER BY id DESC",
            (repo_slug,)
        ).fetchone()
        assert log_row["outcome"] == "PR_CREATED"
        assert result["pr_url"] in log_row["details"]

    # Step 5: Validate ring buffer telemetry
    logs = orchestrator.logger.get_recent_logs(20)
    assert any("[PR CREATED]" in l for l in logs)


def test_scenario_clean_repository_zero_bugs_exhaustion(orchestrator: ContractOrchestrator):
    """Scenario 2: Clean Repository Audit (Sync -> No Bugs -> Mark fully_exhausted = 1 -> Skip next cycle)."""
    repo_slug = "acme/clean-service"

    # Cycle 1: Audit finds 0 bugs
    res1 = orchestrator.scan_single_repo(
        repo_slug=repo_slug,
        simulated_agent_outcome="CLEAN_NO_BUG"
    )
    assert res1["outcome"] == "CLEAN_EXHAUSTED"

    # Validate database has marked fully_exhausted = 1
    with orchestrator.db._conn() as conn:
        repo_row = conn.execute(
            "SELECT fully_exhausted, last_scanned_sha FROM repositories WHERE repo_slug = ?",
            (repo_slug,)
        ).fetchone()
        assert repo_row["fully_exhausted"] == 1
        assert repo_row["last_scanned_sha"] is not None

    # Stats reflect exhausted repo
    stats = orchestrator.db.get_stats()
    assert stats["kpis"]["exhausted_repos"] >= 1


def test_scenario_open_pr_ceiling_collision_skipping(orchestrator: ContractOrchestrator):
    """Scenario 3: PR Ceiling Reached (5 open bot PRs -> collision guard skips repo -> $0 tokens)."""
    repo_slug = "acme/busy-repo"
    simulated_5_prs = [
        {"number": 101, "files": ["src/a.py"]},
        {"number": 102, "files": ["src/b.py"]},
        {"number": 103, "files": ["src/c.py"]},
        {"number": 104, "files": ["src/d.py"]},
        {"number": 105, "files": ["src/e.py"]},
    ]

    res = orchestrator.scan_single_repo(
        repo_slug=repo_slug,
        simulated_open_prs=simulated_5_prs
    )
    assert res["outcome"] == "SKIPPED_MAX_PRS"

    # Status must be PAUSED_MAX_PRS in database
    with orchestrator.db._conn() as conn:
        repo_row = conn.execute(
            "SELECT status, open_pr_count FROM repositories WHERE repo_slug = ?",
            (repo_slug,)
        ).fetchone()
        assert repo_row["status"] == "PAUSED_MAX_PRS"
        assert repo_row["open_pr_count"] == 5

    # Telemetry logged warning
    logs = orchestrator.logger.get_recent_logs(10)
    assert any("[WARN]" in l and "Skipping" in l for l in logs)


def test_scenario_rate_limit_failover_recovery(orchestrator: ContractOrchestrator):
    """Scenario 4: Rate-Limit Recovery (Key 1 hits 429 -> Key 1 cooled down -> Key 2 takes over -> PR created)."""
    repo_slug = "acme/api-gateway"

    # Phase 1: Attempt scan, key 1 hits 429
    res_fail = orchestrator.scan_single_repo(
        repo_slug=repo_slug,
        simulated_agent_outcome="RATE_LIMIT_429"
    )
    assert res_fail["outcome"] == "RATE_LIMIT_429"

    # Key 1 is now in COOLDOWN
    with orchestrator.db._conn() as conn:
        k1_status = conn.execute("SELECT state FROM api_key_status WHERE key_id = 'key-1'").fetchone()
        assert k1_status["state"] == "COOLDOWN"

    # Phase 2: Retry scan with backup key-2
    res_retry = orchestrator.scan_single_repo(
        repo_slug=repo_slug,
        simulated_agent_outcome="SUCCESS"
    )
    assert res_retry["outcome"] == "PR_CREATED"

    # PR recorded with key-2
    with orchestrator.db._conn() as conn:
        pr_row = conn.execute(
            "SELECT llm_key_id FROM pull_requests WHERE repo_slug = ? ORDER BY id DESC",
            (repo_slug,)
        ).fetchone()
        assert pr_row["llm_key_id"] == "key-2"


def test_scenario_untrusted_agent_remediation_intercepted(orchestrator: ContractOrchestrator):
    """Scenario 5: Untrusted Agent Interception (4 modified files + secret leak -> verifier rejects -> rollback)."""
    repo_slug = "acme/vulnerable-repo"

    malicious_diff = "+SECRET = 'sk-proj-123456789012345678901234567890'\n"
    res = orchestrator.scan_single_repo(
        repo_slug=repo_slug,
        simulated_agent_outcome="SUCCESS",
        custom_diff=malicious_diff
    )
    assert res["outcome"] == "VERIFICATION_FAILED"
    assert "credential leak" in res["error"].lower()

    # Zero PRs created
    with orchestrator.db._conn() as conn:
        pr_count = conn.execute(
            "SELECT COUNT(*) FROM pull_requests WHERE repo_slug = ?",
            (repo_slug,)
        ).fetchone()[0]
        assert pr_count == 0

    # Repo working tree rolled back cleanly
    repo_path = orchestrator.git_manager.repos_dir / "acme__vulnerable-repo"
    assert not (repo_path / ".skip_files.txt").exists()
    assert not (repo_path / ".bug_fix_report.json").exists()


def test_scenario_mission_control_operator_intervention(orchestrator: ContractOrchestrator):
    """Scenario 6: Mission Control Interactivity (Pause -> Reset Cache -> Priority Scan -> Unpause)."""
    app = create_contract_web_app(orchestrator)
    client = TestClient(app)

    # 1. Check state snapshot
    r_state = client.get("/api/state")
    assert r_state.status_code == 200
    assert r_state.json()["daemon"]["paused"] is False

    # 2. Operator pauses the daemon
    r_pause = client.post("/api/control/toggle-pause")
    assert r_pause.json()["paused"] is True

    # 3. Mark a repo as exhausted, then operator resets cache
    orchestrator.db.record_scan_result("acme/hotfix-repo", "sha-initial", fully_exhausted=1)
    r_reset = client.post("/api/control/reset-exhausted")
    assert r_reset.status_code == 200
    assert r_reset.json()["reset_count"] >= 1

    # 4. Operator triggers high-priority Scan Now for hotfix repo
    # First unpause so scan can proceed
    client.post("/api/control/toggle-pause")
    r_scan = client.post("/api/control/scan-now/acme/hotfix-repo")
    assert r_scan.status_code == 200
    scan_data = r_scan.json()
    assert scan_data["repo"] == "acme/hotfix-repo"
    assert scan_data["scan_result"]["outcome"] in ("PR_CREATED", "CLEAN_EXHAUSTED")
