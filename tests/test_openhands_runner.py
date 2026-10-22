"""
Unit tests for src/openhands_runner.py: Headless execution, rate limits, timeouts, and report parsing.
"""

from pathlib import Path
import pytest
from src.config import KeyConfig
from src.openhands_runner import OpenHandsRunner


@pytest.fixture
def sample_key():
    return KeyConfig("k1", "ScaleMax", "https://api.sm.ai/v1", "claude-haiku-5.5", "sk-12345678", "sk-1...5678", 1)


def test_runner_simulated_success(tmp_path: Path, sample_key):
    """Verify simulated success session produces valid SessionResult and report."""
    runner = OpenHandsRunner(timeout_seconds=1200)
    logs = []
    res = runner.run_openhands_session(
        repo_path=tmp_path,
        key_entry=sample_key,
        task_prompt_path=Path("prompts/task_prompt.txt"),
        log_callback=logs.append,
        simulated_outcome="SUCCESS"
    )
    assert res.success is True
    assert res.bug_found is True
    assert any("[OPENHANDS]" in l for l in logs)
    assert (tmp_path / ".bug_fix_report.json").exists()


def test_runner_simulated_rate_limit(tmp_path: Path, sample_key):
    """Verify rate limit 429 returns error_type RATE_LIMIT_429."""
    runner = OpenHandsRunner(timeout_seconds=1200)
    logs = []
    res = runner.run_openhands_session(
        repo_path=tmp_path,
        key_entry=sample_key,
        task_prompt_path=Path("prompts/task_prompt.txt"),
        log_callback=logs.append,
        simulated_outcome="RATE_LIMIT_429"
    )
    assert res.success is False
    assert res.error_type == "RATE_LIMIT_429"


def test_runner_simulated_quota_402(tmp_path: Path, sample_key):
    """Verify quota exhaustion returns error_type QUOTA_EXHAUSTED_402."""
    runner = OpenHandsRunner(timeout_seconds=1200)
    logs = []
    res = runner.run_openhands_session(
        repo_path=tmp_path,
        key_entry=sample_key,
        task_prompt_path=Path("prompts/task_prompt.txt"),
        log_callback=logs.append,
        simulated_outcome="QUOTA_EXHAUSTED_402"
    )
    assert res.success is False
    assert res.error_type == "QUOTA_EXHAUSTED_402"


def test_runner_simulated_clean_no_bug(tmp_path: Path, sample_key):
    """Verify clean audit returns success=True with bug_found=False."""
    runner = OpenHandsRunner(timeout_seconds=1200)
    logs = []
    res = runner.run_openhands_session(
        repo_path=tmp_path,
        key_entry=sample_key,
        task_prompt_path=Path("prompts/task_prompt.txt"),
        log_callback=logs.append,
        simulated_outcome="CLEAN_NO_BUG"
    )
    assert res.success is True
    assert res.bug_found is False


def test_terminate_process_tree():
    """Verify _terminate_process_tree terminates process and handles exceptions cleanly."""
    import subprocess
    import sys
    runner = OpenHandsRunner()
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    try:
        assert proc.poll() is None
        runner._terminate_process_tree(proc)
        proc.wait(timeout=2)
        assert proc.poll() is not None
    finally:
        try:
            proc.kill()
        except Exception:
            pass


def test_runner_timeout_watchdog_kills_hanging_process(tmp_path: Path, sample_key, monkeypatch):
    """Verify that a process producing zero stdout and hanging is terminated by timeout watchdog."""
    import subprocess
    import sys
    runner = OpenHandsRunner(timeout_seconds=1)
    logs = []

    orig_popen = subprocess.Popen

    def mock_popen(cmd, **kwargs):
        return orig_popen([sys.executable, "-c", "import time; time.sleep(10)"], **kwargs)

    monkeypatch.setattr(subprocess, "Popen", mock_popen)

    res = runner.run_openhands_session(
        repo_path=tmp_path,
        key_entry=sample_key,
        task_prompt_path=Path("prompts/task_prompt.txt"),
        log_callback=logs.append,
    )
    assert res.success is False
    assert res.error_type == "TIMEOUT"


