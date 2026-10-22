"""
Tier 2: Boundary, Capacity Limits, Rate Limits, and Adversarial Secret Tests.
Covers edge cases, mathematical limits, rate limit spikes, and security invariants.
Threshold: >= 5 test cases per boundary domain (25 total tests).
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

from tests.e2e.conftest import (
    Config,
    ContractDatabase,
    ContractGitManager,
    ContractKeyManager,
    ContractOpenHandsRunner,
    ContractRingBufferLogger,
    ContractStaticScanner,
    ContractVerifier,
    KeyConfig,
)


# ===========================================================================
# Domain 1: Empty Inputs, Zero States & Nil Boundaries
# ===========================================================================

def test_boundary_empty_key_pool(temp_workspace: Path, mock_db: ContractDatabase):
    """B1.1: Verify Config and KeyManager handle empty or whitespace key pool safely."""
    cfg = Config.load(overrides={"workspace_dir": temp_workspace, "LLM_KEYS_POOL": ""})
    assert len(cfg.llm_keys) == 0

    km = ContractKeyManager(cfg, mock_db)
    assert km.get_next_healthy_key() is None


def test_boundary_zero_open_prs_behavior(temp_workspace: Path, git_manager: ContractGitManager):
    """B1.2: Verify repository with 0 open bot PRs creates empty .skip_files.txt without error."""
    repo = temp_workspace / "zero_pr_repo"
    repo.mkdir(parents=True)

    count, skip_files = git_manager.get_open_bot_prs("org/repo", repo, simulated_open_prs=[])
    assert count == 0
    assert skip_files == []
    assert (repo / ".skip_files.txt").exists()
    assert (repo / ".skip_files.txt").read_text(encoding="utf-8") == ""


def test_boundary_empty_static_findings(temp_workspace: Path, static_scanner: ContractStaticScanner):
    """B1.3: Verify static scanner generates valid empty JSON array when no issues exist."""
    repo = temp_workspace / "clean_static_repo"
    repo.mkdir(parents=True)

    out = static_scanner.run_static_prefilter(repo, skip_files=[], simulated_findings=[])
    assert out.exists()
    assert out.read_text(encoding="utf-8").strip() == "[]"


def test_boundary_empty_target_repos(temp_workspace: Path):
    """B1.4: Verify Config parses empty TARGET_REPOS gracefully."""
    cfg = Config.load(overrides={"workspace_dir": temp_workspace, "TARGET_REPOS": ""})
    assert cfg.target_repos == []


def test_boundary_zero_modified_files_in_report(temp_workspace: Path, verifier: ContractVerifier):
    """B1.5: Verify verifier rejects fix when report claims bug_found but modifies 0 files."""
    repo = temp_workspace / "zero_mod_repo"
    repo.mkdir(parents=True)
    report = {"bug_found": True, "files_modified": []}
    diff = "+# comment with no modified files"
    res = verifier.verify_and_sanitize_fix(repo, skip_files=[], simulated_report=report, custom_diff=diff)
    assert res.verified is False
    assert "zero" in res.error_reason.lower() or "0" in res.error_reason.lower()


# ===========================================================================
# Domain 2: Maximum Bounds, Diff Limits & Threshold Enforcements
# ===========================================================================

def test_boundary_exact_max_files_limit_three_vs_four(temp_workspace: Path, verifier: ContractVerifier):
    """B2.1: Verify verifier accepts exactly 3 files and rejects 4 files (MAX_FILES_PER_PR=3)."""
    repo = temp_workspace / "max_files_repo"
    repo.mkdir(parents=True)
    diff = "+content\n"

    # Exactly 3 files -> Allowed
    rep_3 = {"bug_found": True, "files_modified": ["a.py", "b.py", "c.py"]}
    res_3 = verifier.verify_and_sanitize_fix(repo, skip_files=[], max_files=3, simulated_report=rep_3, custom_diff=diff)
    assert res_3.verified is True

    # 4 files -> Rejected
    rep_4 = {"bug_found": True, "files_modified": ["a.py", "b.py", "c.py", "d.py"]}
    res_4 = verifier.verify_and_sanitize_fix(repo, skip_files=[], max_files=3, simulated_report=rep_4, custom_diff=diff)
    assert res_4.verified is False
    assert "exceeding limit of 3" in res_4.error_reason


def test_boundary_exact_max_lines_limit_150_vs_151(temp_workspace: Path, verifier: ContractVerifier):
    """B2.2: Verify verifier accepts exactly 150 lines and rejects 151 lines (MAX_DIFF_LINES=150)."""
    repo = temp_workspace / "max_lines_repo"
    repo.mkdir(parents=True)
    report = {"bug_found": True, "files_modified": ["src/fix.py"]}

    # 150 lines -> Allowed
    diff_150 = "\n".join([f"+line {i}" for i in range(150)])
    res_150 = verifier.verify_and_sanitize_fix(repo, skip_files=[], max_lines=150, simulated_report=report, custom_diff=diff_150)
    assert res_150.verified is True

    # 151 lines -> Rejected
    diff_151 = "\n".join([f"+line {i}" for i in range(151)])
    res_151 = verifier.verify_and_sanitize_fix(repo, skip_files=[], max_lines=150, simulated_report=report, custom_diff=diff_151)
    assert res_151.verified is False
    assert "exceeding limit of 150" in res_151.error_reason


def test_boundary_open_pr_ceiling_boundary_4_vs_5_vs_6(temp_workspace: Path, git_manager: ContractGitManager):
    """B2.3: Verify open bot PR ceiling boundary: 4 allowed, 5 and 6 trigger collision guard."""
    repo = temp_workspace / "ceiling_repo"
    repo.mkdir(parents=True)

    make_prs = lambda n: [{"number": i, "files": [f"f{i}.py"]} for i in range(n)]

    c4, _ = git_manager.get_open_bot_prs("org/repo", repo, simulated_open_prs=make_prs(4))
    assert c4 < git_manager.max_open_prs  # 4 < 5

    c5, _ = git_manager.get_open_bot_prs("org/repo", repo, simulated_open_prs=make_prs(5))
    assert c5 >= git_manager.max_open_prs  # 5 >= 5 (ceiling hit)

    c6, _ = git_manager.get_open_bot_prs("org/repo", repo, simulated_open_prs=make_prs(6))
    assert c6 >= git_manager.max_open_prs  # 6 >= 5 (ceiling exceeded)


def test_boundary_static_scanner_top_10_cap(temp_workspace: Path, static_scanner: ContractStaticScanner):
    """B2.4: Verify static scanner strictly caps output to top 10 items when 25 findings exist."""
    repo = temp_workspace / "cap_repo"
    repo.mkdir(parents=True)
    findings = [{"file": f"f{i}.py", "severity": "ERROR", "message": f"Err {i}"} for i in range(25)]

    out = static_scanner.run_static_prefilter(repo, skip_files=[], simulated_findings=findings)
    res = json.loads(out.read_text(encoding="utf-8"))
    assert len(res) == 10  # Capped to 10


def test_boundary_ring_buffer_exact_500_overflow(temp_workspace: Path):
    """B2.5: Verify ring buffer with capacity 500 maintains boundary when 501 items logged."""
    logger = ContractRingBufferLogger(capacity=500, log_file=temp_workspace / "buf.log")
    for i in range(500):
        logger.log("INFO", f"Item-{i}")
    assert len(logger.buffer) == 500
    assert "Item-0" in logger.buffer[0]

    # Add 501st item
    logger.log("INFO", "Item-500")
    assert len(logger.buffer) == 500
    assert "Item-1" in logger.buffer[0]
    assert "Item-500" in logger.buffer[-1]


# ===========================================================================
# Domain 3: Rate Limits, Cooldown Spikes & Backoff Mathematics
# ===========================================================================

def test_boundary_exponential_cooldown_formula_derivation(sample_config: Config, mock_db: ContractDatabase):
    """B3.1: Mathematically verify T = min(3600, 60 * 2^(F-1)) for F = 1..10."""
    km = ContractKeyManager(sample_config, mock_db)
    expected_cooldowns = {
        1: 60,      # 60 * 2^0
        2: 120,     # 60 * 2^1
        3: 240,     # 60 * 2^2
        4: 480,     # 60 * 2^3
        5: 960,     # 60 * 2^4
        6: 1920,    # 60 * 2^5
        7: 3600,    # 60 * 2^6 = 3840 -> capped at 3600
        8: 3600,
        10: 3600,
    }
    for failures, expected_secs in expected_cooldowns.items():
        computed = km.calculate_cooldown_seconds(failures)
        assert computed == expected_secs, f"Failed at F={failures}: expected {expected_secs}, got {computed}"


def test_boundary_http_402_triggers_exact_24h_exhaustion(sample_config: Config, mock_db: ContractDatabase):
    """B3.2: Verify HTTP 402 / insufficient_quota triggers EXHAUSTED state for 24 hours (86400s)."""
    km = ContractKeyManager(sample_config, mock_db)
    key = km.get_next_healthy_key()
    assert key is not None

    km.report_key_failure(key.id, "insufficient_quota: payment required", status_code=402)

    with mock_db._conn() as conn:
        row = conn.execute("SELECT state, cooldown_until FROM api_key_status WHERE key_id = ?", (key.id,)).fetchone()
        assert row["state"] == "EXHAUSTED"
        cd_time = datetime.fromisoformat(row["cooldown_until"])
        now = datetime.now(timezone.utc)
        diff_hours = (cd_time - now).total_seconds() / 3600
        assert 23.9 <= diff_hours <= 24.1


def test_boundary_consecutive_failure_reset_on_success(sample_config: Config, mock_db: ContractDatabase):
    """B3.3: Verify successful usage resets consecutive_failures to 0 and clears cooldown."""
    km = ContractKeyManager(sample_config, mock_db)
    key = km.get_next_healthy_key()
    assert key is not None

    # Trip 3 failures
    for _ in range(3):
        km.report_key_failure(key.id, "HTTP 429", status_code=429)

    with mock_db._conn() as conn:
        row = conn.execute("SELECT consecutive_failures, state FROM api_key_status WHERE key_id = ?", (key.id,)).fetchone()
        assert row["consecutive_failures"] == 3
        assert row["state"] == "COOLDOWN"

    # Report success
    km.report_key_success(key.id)

    with mock_db._conn() as conn:
        row = conn.execute("SELECT consecutive_failures, state, cooldown_until FROM api_key_status WHERE key_id = ?", (key.id,)).fetchone()
        assert row["consecutive_failures"] == 0
        assert row["state"] == "HEALTHY"
        assert row["cooldown_until"] is None


def test_boundary_all_keys_in_cooldown_returns_none(sample_config: Config, mock_db: ContractDatabase):
    """B3.4: Verify get_next_healthy_key returns None when all keys in pool are in cooldown."""
    km = ContractKeyManager(sample_config, mock_db)
    for k in sample_config.llm_keys:
        km.report_key_failure(k.id, "HTTP 429", status_code=429)

    healthy = km.get_next_healthy_key()
    assert healthy is None


def test_boundary_expired_cooldown_automatic_recovery(sample_config: Config, mock_db: ContractDatabase):
    """B3.5: Verify key with cooldown timestamp in the past automatically recovers to HEALTHY."""
    km = ContractKeyManager(sample_config, mock_db)
    key = sample_config.llm_keys[0]

    # Set cooldown in the past
    past_iso = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    mock_db.update_api_key_status(key.id, "COOLDOWN", consecutive_failures=1, cooldown_until=past_iso)

    # Next call should promote it and return it
    retrieved = km.get_next_healthy_key()
    assert retrieved is not None
    assert retrieved.id == key.id

    with mock_db._conn() as conn:
        row = conn.execute("SELECT state, cooldown_until FROM api_key_status WHERE key_id = ?", (key.id,)).fetchone()
        assert row["state"] == "HEALTHY"
        assert row["cooldown_until"] is None


# ===========================================================================
# Domain 4: Secret Leaks, Regex Adversarial Patterns & Sanitization
# ===========================================================================

def test_boundary_secret_leak_github_pat_classic(temp_workspace: Path, verifier: ContractVerifier):
    """B4.1: Verify verifier detects and blocks classic GitHub PAT (ghp_...)."""
    repo = temp_workspace / "pat_repo"
    repo.mkdir(parents=True)
    report = {"bug_found": True, "files_modified": ["src/client.py"]}
    diff = "+TOKEN = 'ghp_123456789012345678901234567890123456'\n"

    res = verifier.verify_and_sanitize_fix(repo, skip_files=[], simulated_report=report, custom_diff=diff)
    assert res.verified is False
    assert "credential leak" in res.error_reason.lower()


def test_boundary_secret_leak_github_fine_grained_pat(temp_workspace: Path, verifier: ContractVerifier):
    """B4.2: Verify verifier detects and blocks fine-grained GitHub PAT (github_pat_...)."""
    repo = temp_workspace / "pat_fg_repo"
    repo.mkdir(parents=True)
    report = {"bug_found": True, "files_modified": ["src/client.py"]}
    diff = "+PAT = 'github_pat_11AAAAAAA0012345678901_12345678901234567890123456789012345678901234567890'\n"

    res = verifier.verify_and_sanitize_fix(repo, skip_files=[], simulated_report=report, custom_diff=diff)
    assert res.verified is False
    assert "credential leak" in res.error_reason.lower()


def test_boundary_secret_leak_openai_api_key(temp_workspace: Path, verifier: ContractVerifier):
    """B4.3: Verify verifier detects and blocks OpenAI-style API keys (sk-...)."""
    repo = temp_workspace / "openai_key_repo"
    repo.mkdir(parents=True)
    report = {"bug_found": True, "files_modified": ["src/client.py"]}
    diff = "+API_KEY = 'sk-proj-123456789012345678901234567890'\n"

    res = verifier.verify_and_sanitize_fix(repo, skip_files=[], simulated_report=report, custom_diff=diff)
    assert res.verified is False
    assert "credential leak" in res.error_reason.lower()


def test_boundary_secret_leak_rsa_private_key(temp_workspace: Path, verifier: ContractVerifier):
    """B4.4: Verify verifier detects and blocks RSA private key headers."""
    repo = temp_workspace / "rsa_repo"
    repo.mkdir(parents=True)
    report = {"bug_found": True, "files_modified": ["src/auth.py"]}
    diff = "+PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA0...\\n-----END RSA PRIVATE KEY-----'\n"

    res = verifier.verify_and_sanitize_fix(repo, skip_files=[], simulated_report=report, custom_diff=diff)
    assert res.verified is False
    assert "credential leak" in res.error_reason.lower()


def test_boundary_secret_sanitizer_preserves_legitimate_code(temp_workspace: Path, verifier: ContractVerifier):
    """B4.5: Verify legitimate code mentioning tokens or keys without secrets is accepted."""
    repo = temp_workspace / "clean_code_repo"
    repo.mkdir(parents=True)
    report = {"bug_found": True, "files_modified": ["src/auth.py"]}
    diff = "+def is_valid_token(token_str: str) -> bool:\n+    return len(token_str) > 0\n"

    res = verifier.verify_and_sanitize_fix(repo, skip_files=[], simulated_report=report, custom_diff=diff)
    assert res.verified is True


# ===========================================================================
# Domain 5: Process Limits, Git Safety & Timeout Invariants
# ===========================================================================

def test_boundary_git_force_push_strictly_prevented(temp_workspace: Path, git_manager: ContractGitManager):
    """B5.1: Verify push_atomic_branch strictly raises exception on force=True (RULE-GIT-02)."""
    repo = temp_workspace / "push_repo"
    repo.mkdir(parents=True)
    branch = "fix/auto-test-123456"

    with pytest.raises(ValueError, match="Force pushing is strictly prohibited"):
        git_manager.push_atomic_branch(repo, branch, force=True)


def test_boundary_git_rollback_cleans_dirty_tree(git_manager: ContractGitManager):
    """B5.2: Verify rollback_working_tree cleans untracked and modified files (RULE-GIT-05)."""
    repo_path, default_branch, _ = git_manager.sync_repository("test-org/rollback-test")

    # Create dirty uncommitted file
    dirty_file = repo_path / "dirty.txt"
    dirty_file.write_text("untracked dirty text", encoding="utf-8")
    assert dirty_file.exists()

    git_manager.rollback_working_tree(repo_path, default_branch)
    assert not dirty_file.exists()


def test_boundary_key_masking_short_and_edge_inputs():
    """B5.3: Verify ContractKeyManager.mask_key handles varied string lengths safely."""
    # Standard key
    assert ContractKeyManager.mask_key("sk-scalemax-1234-5678") == "sk-s...5678"
    # Exact 8 chars
    assert ContractKeyManager.mask_key("12345678") == "****"
    # Short string
    assert ContractKeyManager.mask_key("short") == "****"
    # Empty string
    assert ContractKeyManager.mask_key("") == "****"


def test_boundary_openhands_process_timeout_outcome(temp_workspace: Path, openhands_runner: ContractOpenHandsRunner):
    """B5.4: Verify OpenHands runner correctly captures process timeout outcome."""
    repo = temp_workspace / "to_repo"
    repo.mkdir(parents=True)
    key = KeyConfig("k1", "ScaleMax", "https://api.scalemax.ai/v1", "openai/claude-haiku-5.5", "sk-12345678", "sk-1...5678", 1)

    res = openhands_runner.run_openhands_session(
        repo_path=repo,
        key_entry=key,
        task_prompt_path=Path("prompts/task_prompt.txt"),
        log_callback=lambda x: None,
        simulated_outcome="TIMEOUT"
    )
    assert res.success is False
    assert res.error_type == "TIMEOUT"


def test_boundary_static_scan_skip_files_collision(temp_workspace: Path, static_scanner: ContractStaticScanner):
    """B5.5: Verify static scanner excludes multiple skip files across nested directories."""
    repo = temp_workspace / "skip_multi_repo"
    repo.mkdir(parents=True)
    findings = [
        {"file": "src/auth/token.py", "severity": "ERROR", "message": "Error A"},
        {"file": "src/db/models.py", "severity": "ERROR", "message": "Error B"},
        {"file": "src/allowed.py", "severity": "ERROR", "message": "Error C"},
    ]
    skip = ["src/auth/token.py", "src/db/models.py"]
    out = static_scanner.run_static_prefilter(repo, skip_files=skip, simulated_findings=findings)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data) == 1
    assert data[0]["file"] == "src/allowed.py"
