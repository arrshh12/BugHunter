"""
Tier 1: Comprehensive Feature Verification Tests for AutoBugHunter 24/7.
Covers core functional requirements R1 through R5 and PRD requirements FR-01 through FR-08.
Threshold: >= 5 test cases per feature category.
"""

import json
import re
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

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
    KeyConfig,
    create_contract_web_app,
)


# ===========================================================================
# Category 1: R1 Open-Source Component Leverage & Tooling Contracts
# ===========================================================================

def test_r1_openhands_headless_contract(temp_workspace: Path):
    """R1.1: Verify OpenHands runner contract adheres to headless mode and process runtime."""
    runner = ContractOpenHandsRunner(timeout_seconds=1200)
    assert runner.timeout_seconds == 1200

    repo = temp_workspace / "test_repo"
    repo.mkdir(parents=True)
    key = KeyConfig("k1", "ScaleMax", "https://api.scalemax.ai/v1", "openai/claude-haiku-5.5", "sk-12345678", "sk-1...5678", 1)

    logs = []
    res = runner.run_openhands_session(
        repo_path=repo,
        key_entry=key,
        task_prompt_path=Path("prompts/task_prompt.txt"),
        log_callback=logs.append,
        simulated_outcome="SUCCESS"
    )
    assert res.success is True
    assert res.bug_found is True
    assert any("[OPENHANDS]" in line for line in logs)
    assert (repo / ".bug_fix_report.json").exists()


def test_r1_static_scanner_tooling_integration(temp_workspace: Path):
    """R1.2: Verify static pre-scanner compiles findings from Ruff and Semgrep abstractions."""
    scanner = ContractStaticScanner(timeout_seconds=90, max_findings=10)
    repo = temp_workspace / "scanner_repo"
    repo.mkdir(parents=True)

    findings_file = scanner.run_static_prefilter(
        repo_path=repo,
        skip_files=[],
        simulated_findings=[
            {"file": "main.py", "line": 12, "severity": "ERROR", "message": "SyntaxError: invalid syntax"},
            {"file": "sec.py", "line": 40, "severity": "ERROR", "message": "Semgrep: hardcoded credentials"}
        ]
    )
    assert findings_file.exists()
    data = json.loads(findings_file.read_text(encoding="utf-8"))
    assert len(data) == 2
    assert all(item["severity"] == "ERROR" for item in data)


def test_r1_llm_rotator_openai_compatible_contract(sample_config: Config, mock_db: ContractDatabase):
    """R1.3: Verify LLM rotator contract parses OpenAI-compatible ScaleMax model routing."""
    km = ContractKeyManager(sample_config, mock_db)
    key = km.get_next_healthy_key()
    assert key is not None
    assert key.provider == "ScaleMax"
    assert "scalemax" in key.base_url
    assert "claude-haiku-5.5" in key.model
    assert key.api_key.startswith("sk-")


def test_r1_github_cli_pr_guard_contract(temp_workspace: Path, git_manager: ContractGitManager):
    """R1.4: Verify GitHub CLI integration schema parses open PRs and file paths."""
    repo = temp_workspace / "gh_repo"
    repo.mkdir(parents=True)
    simulated_prs = [
        {"number": 1, "headRefName": "fix/auto-auth-1a2b3c", "files": [{"path": "src/auth.py"}]},
        {"number": 2, "headRefName": "fix/auto-db-4d5e6f", "files": [{"path": "src/database.py"}]}
    ]
    count, skip_files = git_manager.get_open_bot_prs("owner/gh_repo", repo, simulated_open_prs=simulated_prs)
    assert count == 2
    assert "src/auth.py" in skip_files
    assert "src/database.py" in skip_files
    assert (repo / ".skip_files.txt").read_text(encoding="utf-8").splitlines() == ["src/auth.py", "src/database.py"]


def test_r1_fastapi_mission_control_routes(orchestrator: ContractOrchestrator):
    """R1.5: Verify FastAPI mission control application exposes required endpoints."""
    app = create_contract_web_app(orchestrator)
    client = TestClient(app)

    # Root HTML
    r_root = client.get("/")
    assert r_root.status_code == 200
    assert "AutoBugHunter" in r_root.text

    # JSON State
    r_state = client.get("/api/state")
    assert r_state.status_code == 200
    data = r_state.json()
    assert "daemon" in data
    assert "kpis" in data


# ===========================================================================
# Category 2: R2 Core Persistence & Resilient Key Routing (Phases 1 & 2)
# ===========================================================================

def test_r2_config_typed_settings_and_paths(temp_workspace: Path):
    """R2.1: Verify Config loader parses environment variables and creates directories."""
    cfg = Config.load(overrides={
        "workspace_dir": temp_workspace,
        "MAX_OPEN_PRS_PER_REPO": "7",
        "MAX_FILES_PER_PR": "2",
        "MAX_DIFF_LINES": "100",
        "LLM_KEYS_POOL": "https://api.scalemax.ai/v1|openai/claude-haiku-5.5|sk-test-12345678"
    })
    assert cfg.max_open_prs_per_repo == 7
    assert cfg.max_files_per_pr == 2
    assert cfg.max_diff_lines == 100
    assert cfg.repos_dir.exists()
    assert cfg.state_dir.exists()
    assert len(cfg.llm_keys) == 1
    assert cfg.llm_keys[0].masked_key == "sk-t...5678"


def test_r2_sqlite_wal_engine_and_schema(temp_workspace: Path):
    """R2.2: Verify SQLite WAL engine initializes 4 core tables and WAL mode."""
    db_file = temp_workspace / "state" / "bughunter.sqlite"
    db = ContractDatabase(db_file)

    with db._conn() as conn:
        journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert journal_mode.upper() == "WAL"

        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert "repositories" in tables
        assert "pull_requests" in tables
        assert "api_key_status" in tables
        assert "scan_logs" in tables


def test_r2_database_crud_and_kpi_stats(mock_db: ContractDatabase):
    """R2.3: Verify CRUD operations, PR audit ledger, and KPI aggregations."""
    mock_db.upsert_repository("owner/repo1", default_branch="main", status="IDLE", open_pr_count=1)
    mock_db.upsert_repository("owner/repo2", default_branch="main", status="SCANNING", open_pr_count=2)

    # Record PR
    pr_id = mock_db.record_pull_request(
        repo_slug="owner/repo1",
        pr_number=42,
        pr_url="https://github.com/owner/repo1/pull/42",
        branch_name="fix/auto-repo1-1a2b3c",
        commit_sha="c0ffee1",
        file_modified="src/app.py",
        pr_title="fix: resolve NPE",
        bug_summary="Null pointer dereference fixed",
        llm_key_id="key-1"
    )
    assert pr_id > 0

    stats = mock_db.get_stats()
    kpis = stats["kpis"]
    assert kpis["total_repos"] == 2
    assert kpis["total_prs_created"] == 1
    assert len(stats["repositories"]) == 2
    assert len(stats["recent_prs"]) == 1


def test_r2_ring_buffer_logger_capacity(temp_workspace: Path):
    """R2.4: Verify ring buffer logger retains latest 500 items and drops oldest."""
    log_file = temp_workspace / "test.log"
    logger = ContractRingBufferLogger(capacity=500, log_file=log_file)

    for i in range(550):
        logger.log("INFO", f"Log line number {i}")

    recent = logger.get_recent_logs(500)
    assert len(recent) == 500
    assert "Log line number 50" in recent[0]
    assert "Log line number 549" in recent[-1]
    assert log_file.exists()


def test_r2_key_manager_priority_selection(sample_config: Config, mock_db: ContractDatabase):
    """R2.5: Verify KeyManager selects highest-priority healthy key."""
    km = ContractKeyManager(sample_config, mock_db)
    k = km.get_next_healthy_key()
    assert k is not None
    assert k.id == "key-1"
    assert k.priority == 1


def test_r2_key_manager_preflight_ping(sample_config: Config, mock_db: ContractDatabase):
    """R2.6: Verify KeyManager preflight check trips circuit breaker on 429."""
    km = ContractKeyManager(sample_config, mock_db)
    key1 = km.get_next_healthy_key()
    assert key1 is not None

    # Simulate 429 rate limit
    ok = km.preflight_check(key1, simulated_response_code=429)
    assert ok is False

    # Key1 should now be in COOLDOWN, next healthy key should be key2
    key2 = km.get_next_healthy_key()
    assert key2 is not None
    assert key2.id == "key-2"


# ===========================================================================
# Category 3: R3 Git Workspace, Pre-Filter & OpenHands Runner (Phases 3 & 4)
# ===========================================================================

def test_r3_git_sync_and_default_branch(git_manager: ContractGitManager):
    """R3.1: Verify git sync initializes or resets working tree and retrieves HEAD SHA."""
    repo_path, branch, sha = git_manager.sync_repository("test-org/sync-test")
    assert repo_path.exists()
    assert (repo_path / ".git").exists()
    assert branch == "main"
    assert len(sha) == 40 or len(sha) > 0


def test_r3_open_pr_collision_guard_skip_files(temp_workspace: Path, git_manager: ContractGitManager):
    """R3.2: Verify open PR collision guard writes .skip_files.txt correctly."""
    repo_path = temp_workspace / "collision_repo"
    repo_path.mkdir(parents=True)

    sim_prs = [
        {"number": 10, "headRefName": "fix/auto-1", "files": ["src/login.py", "src/auth.py"]},
        {"number": 11, "headRefName": "fix/auto-2", "files": ["config/settings.yaml"]}
    ]
    count, skip_list = git_manager.get_open_bot_prs("org/repo", repo_path, simulated_open_prs=sim_prs)
    assert count == 2
    assert "src/login.py" in skip_list
    assert "src/auth.py" in skip_list
    assert "config/settings.yaml" in skip_list

    content = (repo_path / ".skip_files.txt").read_text(encoding="utf-8")
    assert "src/login.py" in content


def test_r3_atomic_branch_creation_format(temp_workspace: Path, git_manager: ContractGitManager):
    """R3.3: Verify branch name format strictly satisfies RULE-GIT-01: fix/auto-<repo_short>-<hex6>."""
    repo_path, _, _ = git_manager.sync_repository("test-org/atomic-branch-test")
    branch = git_manager.create_atomic_branch(repo_path, prefix="auto")

    assert branch.startswith("fix/auto-")
    parts = branch.split("-")
    assert len(parts) >= 3
    hex_suffix = parts[-1]
    assert re.match(r"^[0-9a-f]{6}$", hex_suffix)


def test_r3_static_scanner_severity_ranking(temp_workspace: Path, static_scanner: ContractStaticScanner):
    """R3.4: Verify static scanner ranks findings ERROR > WARNING > INFO."""
    repo = temp_workspace / "rank_repo"
    repo.mkdir(parents=True)
    findings = [
        {"file": "a.py", "severity": "INFO", "message": "Style check"},
        {"file": "b.py", "severity": "ERROR", "message": "Syntax error"},
        {"file": "c.py", "severity": "WARNING", "message": "Unused import"},
    ]
    out = static_scanner.run_static_prefilter(repo, skip_files=[], simulated_findings=findings)
    res = json.loads(out.read_text(encoding="utf-8"))
    assert len(res) == 3
    assert res[0]["severity"] == "ERROR"
    assert res[1]["severity"] == "WARNING"
    assert res[2]["severity"] == "INFO"


def test_r3_static_scanner_skip_filter(temp_workspace: Path, static_scanner: ContractStaticScanner):
    """R3.5: Verify static scanner excludes files present in skip_files list."""
    repo = temp_workspace / "skip_repo"
    repo.mkdir(parents=True)
    findings = [
        {"file": "src/skipped.py", "severity": "ERROR", "message": "Error 1"},
        {"file": "src/target.py", "severity": "ERROR", "message": "Error 2"},
    ]
    out = static_scanner.run_static_prefilter(repo, skip_files=["src/skipped.py"], simulated_findings=findings)
    res = json.loads(out.read_text(encoding="utf-8"))
    assert len(res) == 1
    assert res[0]["file"] == "src/target.py"


def test_r3_openhands_runner_execution_and_report(temp_workspace: Path, openhands_runner: ContractOpenHandsRunner):
    """R3.6: Verify OpenHands runner produces structured .bug_fix_report.json."""
    repo = temp_workspace / "oh_repo"
    repo.mkdir(parents=True)
    key = KeyConfig("k1", "ScaleMax", "https://api.scalemax.ai/v1", "openai/claude-haiku-5.5", "sk-12345678", "sk-1...5678", 1)

    res = openhands_runner.run_openhands_session(
        repo_path=repo,
        key_entry=key,
        task_prompt_path=Path("prompts/task_prompt.txt"),
        log_callback=lambda x: None,
        simulated_outcome="SUCCESS"
    )
    assert res.success is True
    assert res.bug_found is True
    report = json.loads((repo / ".bug_fix_report.json").read_text(encoding="utf-8"))
    assert report["bug_found"] is True
    assert "files_modified" in report
    assert "pr_title" in report


# ===========================================================================
# Category 4: R4 Verification Gate & PR Dispatcher (Phase 5)
# ===========================================================================

def test_r4_verifier_accepts_valid_atomic_diff(temp_workspace: Path, verifier: ContractVerifier):
    """R4.1: Verify verifier gate accepts valid diff <= 3 files, <= 150 lines, non-empty."""
    repo = temp_workspace / "ver_repo"
    repo.mkdir(parents=True)
    report = {
        "bug_found": True,
        "files_modified": ["src/fix.py"],
        "pr_title": "fix: correct off-by-one error",
        "pr_body": "Corrects index calculation"
    }
    diff = "+def calculate(i):\n+    return i + 1\n"
    res = verifier.verify_and_sanitize_fix(repo, skip_files=[], simulated_report=report, custom_diff=diff)
    assert res.verified is True
    assert res.pr_title == "fix: correct off-by-one error"


def test_r4_verifier_rejects_empty_diff(temp_workspace: Path, verifier: ContractVerifier):
    """R4.2: Verify verifier rejects empty diff."""
    repo = temp_workspace / "empty_repo"
    repo.mkdir(parents=True)
    report = {"bug_found": True, "files_modified": ["src/fix.py"]}
    res = verifier.verify_and_sanitize_fix(repo, skip_files=[], simulated_report=report, custom_diff="")
    assert res.verified is False
    assert "empty" in res.error_reason.lower()


def test_r4_verifier_rejects_whitespace_only_diff(temp_workspace: Path, verifier: ContractVerifier):
    """R4.3: Verify verifier rejects whitespace-only diffs (RULE-GIT-04)."""
    repo = temp_workspace / "ws_repo"
    repo.mkdir(parents=True)
    report = {"bug_found": True, "files_modified": ["src/fix.py"]}
    res = verifier.verify_and_sanitize_fix(repo, skip_files=[], simulated_report=report, custom_diff="   \n\t\n")
    assert res.verified is False
    assert "whitespace" in res.error_reason.lower() or "empty" in res.error_reason.lower()


def test_r4_verifier_purges_temporary_artifacts(temp_workspace: Path, verifier: ContractVerifier):
    """R4.4: Verify verifier purges temporary artifacts (.skip_files.txt, .static_findings.json, etc.)."""
    repo = temp_workspace / "purge_repo"
    repo.mkdir(parents=True)
    (repo / ".skip_files.txt").write_text("skip.py", encoding="utf-8")
    (repo / ".static_findings.json").write_text("[]", encoding="utf-8")
    (repo / ".bug_fix_report.json").write_text('{"bug_found": true}', encoding="utf-8")

    purged = verifier.purge_temp_artifacts(repo)
    assert ".skip_files.txt" in purged
    assert ".static_findings.json" in purged
    assert ".bug_fix_report.json" in purged
    assert not (repo / ".skip_files.txt").exists()


def test_r4_orchestrator_pr_dispatch_and_audit(orchestrator: ContractOrchestrator):
    """R4.5: Verify orchestrator master loop creates PR, updates audit ledger and DB."""
    res = orchestrator.scan_single_repo("org/repo-alpha", simulated_agent_outcome="SUCCESS")
    assert res["outcome"] == "PR_CREATED"
    assert "pr_url" in res
    assert "github.com/org/repo-alpha/pull/" in res["pr_url"]

    stats = orchestrator.db.get_stats()
    assert stats["kpis"]["total_prs_created"] >= 1
    assert len(stats["recent_prs"]) >= 1


def test_r4_clean_scan_marks_fully_exhausted(orchestrator: ContractOrchestrator):
    """R4.6: Verify clean audit (0 bugs found) marks repository fully_exhausted = 1."""
    res = orchestrator.scan_single_repo("org/repo-beta", simulated_agent_outcome="CLEAN_NO_BUG")
    assert res["outcome"] == "CLEAN_EXHAUSTED"

    with orchestrator.db._conn() as conn:
        row = conn.execute("SELECT fully_exhausted FROM repositories WHERE repo_slug = 'org/repo-beta'").fetchone()
        assert row["fully_exhausted"] == 1


# ===========================================================================
# Category 5: R5 Mission Control UI & Deployment (Phases 6 & 7)
# ===========================================================================

def test_r5_web_server_dashboard_html_render(web_app):
    """R5.1: Verify GET / serves Mission Control HTML containing cyber-ops styling."""
    client = TestClient(web_app)
    resp = client.get("/")
    assert resp.status_code == 200
    assert "AutoBugHunter" in resp.text
    assert "#090D16" in resp.text  # Deep Obsidian canvas color


def test_r5_web_server_api_state_schema(web_app):
    """R5.2: Verify GET /api/state satisfies complete JSON schema."""
    client = TestClient(web_app)
    resp = client.get("/api/state")
    assert resp.status_code == 200
    data = resp.json()
    assert "daemon" in data
    assert "kpis" in data
    assert "repositories" in data
    assert "keys" in data
    assert "recent_prs" in data
    assert "total_repos" in data["kpis"]


def test_r5_web_server_pause_control(web_app):
    """R5.3: Verify POST /api/control/toggle-pause toggles scanning state."""
    client = TestClient(web_app)
    resp = client.post("/api/control/toggle-pause")
    assert resp.status_code == 200
    assert resp.json()["paused"] is True

    # Unpause
    resp2 = client.post("/api/control/toggle-pause")
    assert resp2.status_code == 200
    assert resp2.json()["paused"] is False


def test_r5_web_server_reset_exhausted_control(orchestrator: ContractOrchestrator, web_app):
    """R5.4: Verify POST /api/control/reset-exhausted resets fully_exhausted = 0."""
    # Mark repo as exhausted
    orchestrator.db.record_scan_result("org/repo-gamma", "sha12345", fully_exhausted=1)

    client = TestClient(web_app)
    resp = client.post("/api/control/reset-exhausted")
    assert resp.status_code == 200
    assert resp.json()["reset_count"] >= 1

    with orchestrator.db._conn() as conn:
        row = conn.execute("SELECT fully_exhausted FROM repositories WHERE repo_slug = 'org/repo-gamma'").fetchone()
        assert row["fully_exhausted"] == 0


def test_r5_web_server_websocket_log_stream(orchestrator: ContractOrchestrator, web_app):
    """R5.5: Verify WebSocket /ws/logs replays recent log lines."""
    orchestrator.logger.log("AGENT", "Simulated WebSocket telemetry event")
    client = TestClient(web_app)
    with client.websocket_connect("/ws/logs") as ws:
        msg = ws.receive_text()
        assert "Simulated WebSocket telemetry event" in msg
