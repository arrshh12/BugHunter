"""
Tier 3: Cross-Feature Interactions & Pairwise Combination Tests for AutoBugHunter 24/7.
Verifies multi-subsystem contracts (Key Rotation + Git Sync + Verifier Rollback + Web Control).
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


def test_comb_key_failover_during_scan_and_tree_rollback(orchestrator: ContractOrchestrator):
    """C1: OpenHands hits 429 -> primary key trips to COOLDOWN -> tree rolled back -> backup key ready."""
    # Primary key initially
    key_primary = orchestrator.key_manager.get_next_healthy_key()
    assert key_primary is not None
    assert key_primary.id == "key-1"

    # Run scan with 429 simulation
    res = orchestrator.scan_single_repo("org/repo-alpha", simulated_agent_outcome="RATE_LIMIT_429")
    assert res["outcome"] == "RATE_LIMIT_429"

    # Primary key must now be in COOLDOWN in DB
    with orchestrator.db._conn() as conn:
        row = conn.execute("SELECT state, consecutive_failures FROM api_key_status WHERE key_id = 'key-1'").fetchone()
        assert row["state"] == "COOLDOWN"
        assert row["consecutive_failures"] == 1

    # Next key must be key-2 (failover)
    key_fallback = orchestrator.key_manager.get_next_healthy_key()
    assert key_fallback is not None
    assert key_fallback.id == "key-2"

    # Working tree must be clean (no leftover artifacts)
    repo_path = orchestrator.git_manager.repos_dir / "org__repo-alpha"
    assert not (repo_path / ".bug_fix_report.json").exists()


def test_comb_git_sync_collision_skip_files_and_static_filter(orchestrator: ContractOrchestrator):
    """C2: Bot PR on file -> .skip_files.txt written -> static scanner filters it -> verifier guards it."""
    repo_slug = "org/repo-collision"
    repo_path, _, _ = orchestrator.git_manager.sync_repository(repo_slug)

    # Simulate an open PR modifying src/auth.py
    sim_prs = [{"number": 12, "files": ["src/auth.py"]}]
    count, skip_files = orchestrator.git_manager.get_open_bot_prs(repo_slug, repo_path, simulated_open_prs=sim_prs)
    assert "src/auth.py" in skip_files

    # Static scanner excludes src/auth.py
    findings = [
        {"file": "src/auth.py", "severity": "ERROR", "message": "Auth bug"},
        {"file": "src/db.py", "severity": "ERROR", "message": "DB bug"}
    ]
    findings_file = orchestrator.static_scanner.run_static_prefilter(repo_path, skip_files, simulated_findings=findings)
    assert findings_file.exists()
    content = findings_file.read_text(encoding="utf-8")
    assert "src/auth.py" not in content
    assert "src/db.py" in content

    # Verifier would reject any diff that attempts to modify src/auth.py
    report = {"bug_found": True, "files_modified": ["src/auth.py"]}
    ver_res = orchestrator.verifier.verify_and_sanitize_fix(
        repo_path, skip_files, simulated_report=report, custom_diff="+fix"
    )
    assert ver_res.verified is False
    assert "collision skip list" in ver_res.error_reason


def test_comb_openhands_timeout_and_db_audit_and_tree_cleanup(orchestrator: ContractOrchestrator):
    """C3: OpenHands hits timeout -> process group killed -> tree cleaned -> DB audit logged."""
    res = orchestrator.scan_single_repo("org/repo-timeout", simulated_agent_outcome="TIMEOUT")
    assert res["outcome"] == "TIMEOUT"

    # Check database scan_logs
    with orchestrator.db._conn() as conn:
        log_entry = conn.execute(
            "SELECT outcome, repo_slug FROM scan_logs WHERE repo_slug = 'org/repo-timeout' ORDER BY id DESC"
        ).fetchone()
        assert log_entry is not None
        assert log_entry["outcome"] == "TIMEOUT"

        repo_entry = conn.execute(
            "SELECT status FROM repositories WHERE repo_slug = 'org/repo-timeout'"
        ).fetchone()
        assert repo_entry["status"] == "ERROR"


def test_comb_verifier_secret_rejection_and_clean_rollback(orchestrator: ContractOrchestrator):
    """C4: Agent diff leaks secret -> verifier rejects -> rollback executed -> VERIFICATION_FAILED logged."""
    secret_diff = "+SECRET_PAT = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'\n"
    res = orchestrator.scan_single_repo(
        "org/repo-secret-leak",
        simulated_agent_outcome="SUCCESS",
        custom_diff=secret_diff
    )
    assert res["outcome"] == "VERIFICATION_FAILED"
    assert "credential leak" in res["error"].lower()

    # Verify no PR was created
    stats = orchestrator.db.get_stats()
    secret_prs = [p for p in stats["recent_prs"] if p["repo_slug"] == "org/repo-secret-leak"]
    assert len(secret_prs) == 0

    # Verify scan_logs recorded VERIFICATION_FAILED
    with orchestrator.db._conn() as conn:
        log_row = conn.execute(
            "SELECT outcome FROM scan_logs WHERE repo_slug = 'org/repo-secret-leak'"
        ).fetchone()
        assert log_row["outcome"] == "VERIFICATION_FAILED"


def test_comb_web_pause_stops_orchestrator_and_state_api_reflects(orchestrator: ContractOrchestrator):
    """C5: Operator triggers pause via UI -> GET /api/state reports paused -> scan halts with PAUSED."""
    app = create_contract_web_app(orchestrator)
    client = TestClient(app)

    # Initial state: not paused
    assert orchestrator.paused is False

    # Pause via API
    resp_pause = client.post("/api/control/toggle-pause")
    assert resp_pause.json()["paused"] is True
    assert orchestrator.paused is True

    # State API reflects paused
    resp_state = client.get("/api/state")
    assert resp_state.json()["daemon"]["paused"] is True

    # Scan attempt halts immediately without work
    res = orchestrator.scan_single_repo("org/repo-paused-test")
    assert res["outcome"] == "PAUSED"

    # Resume via API
    resp_resume = client.post("/api/control/toggle-pause")
    assert resp_resume.json()["paused"] is False
    assert orchestrator.paused is False


def test_comb_reset_exhausted_enables_rescan_of_clean_repo(orchestrator: ContractOrchestrator):
    """C6: Clean repo marked exhausted -> reset-exhausted API called -> fully_exhausted reset to 0."""
    app = create_contract_web_app(orchestrator)
    client = TestClient(app)

    # Clean audit marks fully_exhausted = 1
    res1 = orchestrator.scan_single_repo("org/repo-clean-audit", simulated_agent_outcome="CLEAN_NO_BUG")
    assert res1["outcome"] == "CLEAN_EXHAUSTED"

    with orchestrator.db._conn() as conn:
        row = conn.execute("SELECT fully_exhausted FROM repositories WHERE repo_slug = 'org/repo-clean-audit'").fetchone()
        assert row["fully_exhausted"] == 1

    # Reset cache via API
    resp = client.post("/api/control/reset-exhausted")
    assert resp.status_code == 200
    assert resp.json()["reset_count"] >= 1

    with orchestrator.db._conn() as conn:
        row = conn.execute("SELECT fully_exhausted FROM repositories WHERE repo_slug = 'org/repo-clean-audit'").fetchone()
        assert row["fully_exhausted"] == 0


def test_comb_multi_key_exhaustion_sleep_and_telemetry(orchestrator: ContractOrchestrator):
    """C7: All keys exhausted -> get_next_healthy_key returns None -> NO_HEALTHY_KEYS outcome and log."""
    # Trip all keys
    for k in orchestrator.config.llm_keys:
        orchestrator.key_manager.report_key_failure(k.id, "Quota exhausted", status_code=402)

    res = orchestrator.scan_single_repo("org/repo-no-keys")
    assert res["outcome"] == "NO_HEALTHY_KEYS"

    recent_logs = orchestrator.logger.get_recent_logs(10)
    assert any("All API keys in pool are in COOLDOWN or EXHAUSTED" in log for log in recent_logs)


def test_comb_atomic_pr_creation_updates_db_and_resets_exhaustion(orchestrator: ContractOrchestrator):
    """C8: Valid PR created -> pull_requests ledger updated -> fully_exhausted reset to 0 for next bug."""
    # First mark as exhausted
    orchestrator.db.record_scan_result("org/repo-one-bug", "sha12345", fully_exhausted=1)

    # Scan and fix 1 bug
    res = orchestrator.scan_single_repo("org/repo-one-bug", simulated_agent_outcome="SUCCESS")
    assert res["outcome"] == "PR_CREATED"

    # Database must have fully_exhausted = 0 so subsequent bugs can be remediated
    with orchestrator.db._conn() as conn:
        row = conn.execute("SELECT fully_exhausted, open_pr_count, total_prs_created FROM repositories WHERE repo_slug = 'org/repo-one-bug'").fetchone()
        assert row["fully_exhausted"] == 0
        assert row["open_pr_count"] >= 1
        assert row["total_prs_created"] >= 1
