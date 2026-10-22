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


def test_rate_limit_detection_precision_avoids_spurious_aborts():
    """Verify word-boundary matching prevents spurious aborts on line numbers, ports, commit hashes (R2)."""
    runner = OpenHandsRunner()

    false_positive_lines = [
        "tests/test_parser.py:4290: AssertionError",
        "File 'main.py', line 4290, in run",
        "[main a429ef12] fix: handle edge case",
        "commit 429abcdef0123456789",
        "Listening on port 4290",
        "server at 127.0.0.1:4290",
        "Processed 14290 tokens successfully",
        "PID 24298 running",
        "Line 4290",
        "commit a429ef",
        "port 4290",
    ]

    for line in false_positive_lines:
        assert runner._is_rate_limit_line(line) == (False, ""), f"False positive triggered for: {line}"

    genuine_rate_limit_lines = [
        ("HTTP 429: RateLimitError: Requests rate limit exceeded", r"\b429\b"),
        ("openai.RateLimitError: Error code: 429", r"\b429\b"),
        ("429 Too Many Requests", r"\b429\b"),
        ("Client error: 429", r"\b429\b"),
        ("Status code: 429", r"\b429\b"),
        ("RateLimitError: model overloaded", "RateLimitError"),
        ("insufficient_quota: limit reached", "insufficient_quota"),
        ("402 Payment Required: billing expired", "402 Payment Required"),
        ("502 Bad Gateway: upstream error", "502 Bad Gateway"),
        ("503 Service Unavailable", "503 Service Unavailable"),
        ("504 Gateway Timeout", "504 Gateway Timeout"),
    ]

    for line, expected_sig in genuine_rate_limit_lines:
        hit, reason = runner._is_rate_limit_line(line)
        assert hit is True, f"Failed to detect rate limit for: {line}"
        assert reason == expected_sig, f"Expected signature {expected_sig}, got {reason}"


def test_runner_live_stdout_scanning_with_false_positive_lines(tmp_path: Path, sample_key, monkeypatch):
    """Verify that a live process outputting lines with 429 in larger numbers does not abort with RATE_LIMIT_429."""
    import subprocess
    import sys
    runner = OpenHandsRunner(timeout_seconds=5)
    logs = []

    report_file = tmp_path / ".bug_fix_report.json"
    script = (
        "import sys, json, pathlib\n"
        "print('Starting audit at line 4290')\n"
        "print('Checking commit a429ef12')\n"
        "print('Binding port 4290')\n"
        "print('Processed 14290 tokens')\n"
        "sys.stdout.flush()\n"
        f"p = pathlib.Path(r'{report_file}')\n"
        "p.write_text(json.dumps({'bug_found': False, 'tests_passed': True}))\n"
    )

    orig_popen = subprocess.Popen

    def mock_popen(cmd, **kwargs):
        return orig_popen([sys.executable, "-c", script], **kwargs)

    monkeypatch.setattr(subprocess, "Popen", mock_popen)

    res = runner.run_openhands_session(
        repo_path=tmp_path,
        key_entry=sample_key,
        task_prompt_path=Path("prompts/task_prompt.txt"),
        log_callback=logs.append,
    )
    assert res.success is True
    assert res.error_type is None
    assert res.bug_found is False


def test_runner_live_stdout_scanning_with_genuine_rate_limit(tmp_path: Path, sample_key, monkeypatch):
    """Verify that a live process outputting word-bounded 429 aborts with RATE_LIMIT_429."""
    import subprocess
    import sys
    runner = OpenHandsRunner(timeout_seconds=5)
    logs = []

    script = (
        "import sys, time\n"
        "print('Connecting to API...')\n"
        "print('Error: HTTP 429 Too Many Requests')\n"
        "sys.stdout.flush()\n"
        "time.sleep(5)\n"
    )

    orig_popen = subprocess.Popen

    def mock_popen(cmd, **kwargs):
        return orig_popen([sys.executable, "-c", script], **kwargs)

    monkeypatch.setattr(subprocess, "Popen", mock_popen)

    res = runner.run_openhands_session(
        repo_path=tmp_path,
        key_entry=sample_key,
        task_prompt_path=Path("prompts/task_prompt.txt"),
        log_callback=logs.append,
    )
    assert res.success is False
    assert res.error_type == "RATE_LIMIT_429"


def test_runner_live_stdout_scanning_with_genuine_402_quota(tmp_path: Path, sample_key, monkeypatch):
    """Verify that a live process outputting 402 aborts with QUOTA_EXHAUSTED_402."""
    import subprocess
    import sys
    runner = OpenHandsRunner(timeout_seconds=5)
    logs = []

    script = (
        "import sys, time\n"
        "print('Error: 402 Payment Required: insufficient balance')\n"
        "sys.stdout.flush()\n"
        "time.sleep(5)\n"
    )

    orig_popen = subprocess.Popen

    def mock_popen(cmd, **kwargs):
        return orig_popen([sys.executable, "-c", script], **kwargs)

    monkeypatch.setattr(subprocess, "Popen", mock_popen)

    res = runner.run_openhands_session(
        repo_path=tmp_path,
        key_entry=sample_key,
        task_prompt_path=Path("prompts/task_prompt.txt"),
        log_callback=logs.append,
    )
    assert res.success is False
    assert res.error_type == "QUOTA_EXHAUSTED_402"



