"""
Empirical Adversarial Challenge Test Suite for src/aider_runner.py (Milestone 3 / R2 & R4).
Written by Challenger M3-2 (challenger_m3_2).

Stress-tests:
1. False Positive Rate Limit Immunity (line numbers like :429:, ports 4290, commit 402a8f, stack traces, genuine rate limits).
2. Subprocess Timeout Watchdog & Process Tree Termination (hung child processes, process trees, infinite output).
3. Diff Extraction Stress (untracked files, deleted files, binary diffs, multi-file diffs, stdout fallback with multiple blocks or trailing prose).
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import psutil
import pytest

from src.aider_runner import AiderResult, AiderRunner


# =========================================================================
# Fixtures
# =========================================================================


@pytest.fixture
def runner() -> AiderRunner:
    return AiderRunner(
        timeout_seconds=30,
        default_model="openai/gpt-6-luna",
        default_api_base="https://api.scalemax.pro/v1",
        aider_binary="aider",
    )


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """Initialize a real Git repository with initial commit."""
    repo = tmp_path / "test_repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=repo,
        check=True,
        capture_output=True,
    )

    # Initial commit
    init_file = repo / "README.md"
    init_file.write_text("# Test Repo\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "Initial commit"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    return repo


# =========================================================================
# 1. Rate Limit False Positive & Immunity Stress Tests
# =========================================================================


class TestRateLimitImmunityAndPrecision:
    """
    Stress-tests rate limit signature matching.
    Ensures compiler/linter line numbers (:429:), ports, commit hashes,
    and stack traces do NOT trigger false positives, while genuine rate
    limit strings are accurately caught.
    """

    @pytest.mark.parametrize(
        "log_line",
        [
            "tests/test_foo.py:429: error: Incompatible types in assignment",
            "src/utils.py:429:1: E501 line too long (88 > 79 characters)",
            "server.py:502: RuntimeWarning: coroutine was never awaited",
            "File \"foo.py\", line 429, in <module>",
            "tests/test_calc.py:429: AssertionError: Expected 429 but got 200",
            "Listening on http://127.0.0.1:4290",
            "commit 402a8f4c51b72e903a45c364e2",
            "commit 429df83",
            "Merged PR #429: Fix authentication timeout",
            "Issue #402 resolved in release v1.4",
            "Processed 4290 tokens successfully in 1.2s",
            "PID 4290 terminated",
            "Elapsed time: 429ms",
        ],
    )
    def test_benign_logs_must_not_trigger_rate_limit(
        self, runner: AiderRunner, log_line: str
    ) -> None:
        """
        Adversarial challenge: Verify non-rate-limit console lines (compiler outputs,
        line numbers, ports, commit hashes, PR numbers) do NOT trigger rate limit detection.
        """
        hit, sig = runner._is_rate_limit_line(log_line)
        assert not hit, (
            f"FALSE POSITIVE DETECTED! Line '{log_line}' was incorrectly flagged "
            f"as rate limit by signature '{sig}'"
        )

    @pytest.mark.parametrize(
        "log_line,expected_status",
        [
            ("HTTP 429 Too Many Requests", "RATE_LIMIT_429"),
            ("429 Too Many Requests: Rate limit exceeded", "RATE_LIMIT_429"),
            ("openai.error.RateLimitError: Rate limit reached for model", "RATE_LIMIT_429"),
            ("status_code: 429, message: rate limit exceeded", "RATE_LIMIT_429"),
            ("402 Payment Required: Please add funds", "QUOTA_EXHAUSTED_402"),
            ("insufficient_quota: You have exceeded your current quota", "QUOTA_EXHAUSTED_402"),
            ("HTTP 502 Bad Gateway from upstream proxy", "RATE_LIMIT_429"),
            ("503 Service Unavailable: High load", "RATE_LIMIT_429"),
            ("504 Gateway Timeout: Upstream response timed out", "RATE_LIMIT_429"),
        ],
    )
    def test_genuine_rate_limits_must_trigger(
        self, runner: AiderRunner, log_line: str, expected_status: str
    ) -> None:
        """
        Verify genuine rate limit and quota exhaustion signatures ARE caught
        and properly classified.
        """
        hit, sig = runner._is_rate_limit_line(log_line)
        assert hit, f"Genuine rate limit line '{log_line}' was NOT detected!"
        classification = runner._classify_rate_limit(sig)
        assert classification == expected_status, (
            f"Expected classification '{expected_status}' but got '{classification}'"
        )


# =========================================================================
# 2. Subprocess Timeout Watchdog & Process Tree Termination Stress Tests
# =========================================================================


class TestSubprocessTimeoutAndTermination:
    """
    Stress-tests subprocess execution with real processes:
    - Hung child processes timing out
    - Process tree / grandchild termination
    - Infinite output streams
    """

    @staticmethod
    def _create_mock_aider(tmp_path: Path, python_body: str) -> str:
        """Create an executable wrapper script that accepts arbitrary arguments and executes python_body."""
        script_path = tmp_path / "action.py"
        script_path.write_text(python_body, encoding="utf-8")
        if sys.platform == "win32":
            cmd_path = tmp_path / "mock_aider.cmd"
            cmd_path.write_text(f'@echo off\r\n"{sys.executable}" "{script_path}"\r\n', encoding="utf-8")
            return str(cmd_path)
        else:
            sh_path = tmp_path / "mock_aider.sh"
            sh_path.write_text(f'#!/bin/sh\n"{sys.executable}" "{script_path}"\n', encoding="utf-8")
            sh_path.chmod(0o755)
            return str(sh_path)

    def test_real_hung_process_timeout_aborts(self, tmp_path: Path) -> None:
        """
        Launch a real process that hangs in time.sleep(100).
        With timeout_seconds=1, verify it aborts within ~2s and returns status='TIMEOUT'.
        """
        binary = self._create_mock_aider(tmp_path, "import time\ntime.sleep(100)\n")

        runner = AiderRunner(timeout_seconds=1, aider_binary=binary)
        t0 = time.time()
        result = runner.run_aider(
            repo_path=tmp_path,
            target_file="hung.py",
            patch_instruction="fix",
            api_key="test",
        )
        elapsed = time.time() - t0

        assert result.status == "TIMEOUT", f"Expected TIMEOUT but got {result.status}"
        assert elapsed < 5.0, f"Hung process took {elapsed}s to terminate, expected < 5s"
        assert "timed out" in (result.error_message or "").lower()

    def test_real_process_tree_termination(self, tmp_path: Path) -> None:
        """
        Launch a parent process that spawns a grandchild process sleeping for 100s.
        Verify that when timeout expires, BOTH parent and grandchild processes are terminated.
        """
        pid_file = tmp_path / "grandchild.pid"
        body = (
            "import subprocess, sys, time\n"
            f'code = f"""import os, time\\nwith open({repr(str(pid_file))}, "w") as f:\\n    f.write(str(os.getpid()))\\ntime.sleep(100)\\n"""\n'
            "p = subprocess.Popen([sys.executable, '-c', code])\n"
            "time.sleep(100)\n"
        )
        binary = self._create_mock_aider(tmp_path, body)

        runner = AiderRunner(timeout_seconds=2, aider_binary=binary)
        result = runner.run_aider(
            repo_path=tmp_path,
            target_file="tree_parent.py",
            patch_instruction="fix",
            api_key="test",
        )

        assert result.status == "TIMEOUT"

        # Check if grandchild PID was recorded and if it's still running
        if pid_file.exists():
            grandchild_pid = int(pid_file.read_text().strip())
            time.sleep(0.5)  # grace period for OS signal propagation
            assert not psutil.pid_exists(grandchild_pid), (
                f"Grandchild process PID {grandchild_pid} was leaked and is still running!"
            )

    def test_real_infinite_output_timeout(self, tmp_path: Path) -> None:
        """
        Launch a process that outputs lines continuously in an infinite loop.
        Verify timeout watchdog still trips and terminates the process.
        """
        body = (
            "import sys, time\n"
            "while True:\n"
            "    sys.stdout.write('generating rapid logs\\n')\n"
            "    sys.stdout.flush()\n"
            "    time.sleep(0.01)\n"
        )
        binary = self._create_mock_aider(tmp_path, body)

        runner = AiderRunner(timeout_seconds=1, aider_binary=binary)
        t0 = time.time()
        result = runner.run_aider(
            repo_path=tmp_path,
            target_file="spam.py",
            patch_instruction="fix",
            api_key="test",
        )
        elapsed = time.time() - t0

        assert result.status == "TIMEOUT"
        assert elapsed < 5.0
        assert len(result.raw_output) > 0


# =========================================================================
# 3. Diff Extraction Stress Tests
# =========================================================================


class TestDiffExtractionStress:
    """
    Stress-tests diff extraction with real Git repositories and stdout fallbacks:
    - Untracked new files
    - Modified files
    - Deleted files
    - Binary files
    - Multi-file changes in working tree
    - Fallback stdout parsing with multiple codeblocks or trailing prose
    """

    def test_extract_diff_untracked_new_file(
        self, runner: AiderRunner, git_repo: Path
    ) -> None:
        """
        Verify extract_diff accurately captures newly created, untracked files
        via intent-to-add (git add -N).
        """
        new_file = git_repo / "src" / "new_module.py"
        new_file.parent.mkdir(parents=True, exist_ok=True)
        new_file.write_text("def new_func():\n    return 42\n", encoding="utf-8")

        diff = runner.extract_diff(git_repo, "src/new_module.py")
        assert "+def new_func():" in diff
        assert "+    return 42" in diff

    def test_extract_diff_modified_file(
        self, runner: AiderRunner, git_repo: Path
    ) -> None:
        """Verify extract_diff captures modifications to committed files."""
        existing = git_repo / "README.md"
        existing.write_text("# Test Repo\nUpdated line\n", encoding="utf-8")

        diff = runner.extract_diff(git_repo, "README.md")
        assert "-# Test Repo" not in diff or "+Updated line" in diff
        assert "+Updated line" in diff

    def test_extract_diff_deleted_file(
        self, runner: AiderRunner, git_repo: Path
    ) -> None:
        """
        Verify extract_diff handles deleted files in the working tree.
        """
        del_file = git_repo / "to_delete.py"
        del_file.write_text("def dead(): pass\n", encoding="utf-8")
        subprocess.run(["git", "add", "to_delete.py"], cwd=git_repo, check=True)
        subprocess.run(["git", "commit", "-m", "add to_delete"], cwd=git_repo, check=True)

        # Now delete file
        del_file.unlink()

        diff = runner.extract_diff(git_repo, "to_delete.py")
        assert "-def dead(): pass" in diff

    def test_extract_diff_binary_file(
        self, runner: AiderRunner, git_repo: Path
    ) -> None:
        """
        Verify extract_diff handles binary file modifications gracefully.
        """
        bin_file = git_repo / "data.bin"
        bin_file.write_bytes(b"\x00\x01\x02\x03\xff")
        subprocess.run(["git", "add", "data.bin"], cwd=git_repo, check=True)
        subprocess.run(["git", "commit", "-m", "add data.bin"], cwd=git_repo, check=True)

        # Modify binary file
        bin_file.write_bytes(b"\x00\x01\x02\x03\xfe\xaa\xbb")

        diff = runner.extract_diff(git_repo, "data.bin")
        # Git diff outputs "Binary files a/data.bin and b/data.bin differ"
        assert "differ" in diff or "Binary files" in diff

    def test_extract_diff_multi_file_isolation(
        self, runner: AiderRunner, git_repo: Path
    ) -> None:
        """
        Verify that when multiple files are modified in working tree,
        extract_diff for target_file ONLY returns changes for target_file.
        """
        file_a = git_repo / "file_a.py"
        file_b = git_repo / "file_b.py"
        file_a.write_text("print('A original')\n", encoding="utf-8")
        file_b.write_text("print('B original')\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=git_repo, check=True)
        subprocess.run(["git", "commit", "-m", "commit two files"], cwd=git_repo, check=True)

        # Modify both files
        file_a.write_text("print('A MODIFIED')\n", encoding="utf-8")
        file_b.write_text("print('B MODIFIED')\n", encoding="utf-8")

        diff_a = runner.extract_diff(git_repo, "file_a.py")
        assert "A MODIFIED" in diff_a
        assert "B MODIFIED" not in diff_a

    def test_extract_diff_fallback_multiple_markdown_codeblocks(
        self, runner: AiderRunner, tmp_path: Path
    ) -> None:
        """
        Adversarial challenge: When raw stdout contains multiple diff codeblocks
        (e.g. Aider edited multiple hunks or presented multi-file changes),
        does fallback parsing capture all diff blocks or silently truncate?
        """
        raw_output = (
            "Here is the diff for file 1:\n"
            "```diff\n"
            "--- a/src/part1.py\n"
            "+++ b/src/part1.py\n"
            "@@ -1,1 +1,1 @@\n"
            "-old_part1\n"
            "+new_part1\n"
            "```\n"
            "And here is the diff for file 2:\n"
            "```diff\n"
            "--- a/src/part2.py\n"
            "+++ b/src/part2.py\n"
            "@@ -1,1 +1,1 @@\n"
            "-old_part2\n"
            "+new_part2\n"
            "```\n"
        )
        with patch("subprocess.run", side_effect=Exception("No git")):
            diff = runner.extract_diff(tmp_path, "src/part1.py", raw_output=raw_output)
            # If multi-block parsing is supported, both or the relevant block should be present
            assert "new_part1" in diff

    def test_extract_diff_fallback_unified_diff_trailing_prose(
        self, runner: AiderRunner, tmp_path: Path
    ) -> None:
        """
        Adversarial challenge: When unified diff in stdout is followed by conversational text,
        verify non-diff trailing prose is NOT included in the returned diff output.
        """
        raw_output = (
            "--- a/src/app.py\n"
            "+++ b/src/app.py\n"
            "@@ -1,2 +1,2 @@\n"
            "-def foo(): pass\n"
            "+def foo(): return 1\n"
            "\n"
            "I have completed the patch. Let me know if you need more help!\n"
        )
        with patch("subprocess.run", side_effect=Exception("No git")):
            diff = runner.extract_diff(tmp_path, "src/app.py", raw_output=raw_output)
            assert "+def foo(): return 1" in diff
            assert "I have completed the patch" not in diff, (
                "TRAILING PROSE LEAKED! Conversational text was included in the extracted diff"
            )
