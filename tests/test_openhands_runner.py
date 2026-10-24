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
        "port 4290",
        "Processed 429 records successfully",
        "Found 429 warnings in scan",
        "Catalog contains 429 active repositories",
    ]

    for line in false_positive_lines:
        assert runner._is_rate_limit_line(line) == (False, ""), f"False positive triggered for: {line}"

    genuine_rate_limit_lines = [
        ("HTTP 429: RateLimitError: Requests rate limit exceeded", OpenHandsRunner.SIG_429),
        ("openai.RateLimitError: Error code: 429", OpenHandsRunner.SIG_429),
        ("429 Too Many Requests", "429 Too Many Requests"),
        ("Client error: 429", OpenHandsRunner.SIG_429),
        ("Status code: 429", OpenHandsRunner.SIG_429),
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


def test_direct_llm_agent_prevents_file_truncation_on_large_file(tmp_path: Path, sample_key, monkeypatch):
    """Verify _run_direct_llm_agent does not drop file tail and aborts on truncated LLM response."""
    import json
    import time
    from unittest.mock import MagicMock

    runner = OpenHandsRunner(timeout_seconds=5)
    # Create a 600-line file
    large_file = tmp_path / "large_app.py"
    original_lines = [f"# line {i}" for i in range(1, 601)]
    large_file.write_text("\n".join(original_lines), encoding="utf-8")

    # Mock requests.post to return a truncated 200-line response
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    truncated_content = "\n".join([f"# line {i}" for i in range(1, 201)])
    mock_resp.json.return_value = {
        "choices": [{
            "message": {
                "content": json.dumps({
                    "bug_found": True,
                    "bug_summary": "Attempted truncation",
                    "updated_full_file": truncated_content,
                })
            }
        }]
    }

    import requests
    monkeypatch.setattr(requests, "post", lambda *a, **kw: mock_resp)

    logs = []
    res = runner._run_direct_llm_agent(
        repo_path=tmp_path,
        key_entry=sample_key,
        task_prompt_path=tmp_path / "task.txt",
        log_callback=logs.append,
        start_time=time.time(),
    )

    # Verification: Truncation was prevented, file tail on disk was not wiped out
    assert res.success is False
    assert res.error_type == "FILE_TRUNCATION_PREVENTED"
    assert len(large_file.read_text(encoding="utf-8").splitlines()) == 600




