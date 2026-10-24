"""
Comprehensive automated unit test suite for src/aider_runner.py (Milestone 3 / R2 & R4).
Hermetic, fast, and fully covers CLI building, environment sanitization,
process lifecycle, rate limit detection, timeout watchdog, and diff extraction.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.aider_runner import (
    DENIED_ENV_VARS,
    DENIED_PREFIXES,
    SAFE_SYSTEM_ENV_VARS,
    AiderResult,
    AiderRunner,
)
from src.config import KeyConfig

# =========================================================================
# Fixtures & Helpers
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
def sample_key_config() -> KeyConfig:
    return KeyConfig(
        id="key-scalemax-1",
        provider="openai",
        base_url="https://api.scalemax.pro/v1",
        model="openai/gpt-6-luna",
        api_key="sk-test-scalemax-key-12345678",
        masked_key="sk-t...5678",
        priority=1,
    )


# =========================================================================
# 1. Data Model & Initialization Tests
# =========================================================================


def test_aider_result_dataclass() -> None:
    """Verify AiderResult dataclass initialization, attributes, and default values."""
    res = AiderResult(
        exit_code=0,
        diff_output="--- a/foo.py\n+++ b/foo.py\n",
        status="SUCCESS",
        target_file="src/foo.py",
    )
    assert res.exit_code == 0
    assert res.diff_output == "--- a/foo.py\n+++ b/foo.py\n"
    assert res.status == "SUCCESS"
    assert res.target_file == "src/foo.py"
    assert res.duration_seconds == 0.0
    assert res.error_message is None
    assert res.raw_output == ""

    # Test explicit non-defaults
    res_explicit = AiderResult(
        exit_code=1,
        diff_output="",
        status="FAILED",
        target_file="src/bar.py",
        duration_seconds=12.5,
        error_message="SyntaxError on line 12",
        raw_output="Traceback...",
    )
    assert res_explicit.duration_seconds == 12.5
    assert res_explicit.error_message == "SyntaxError on line 12"
    assert res_explicit.raw_output == "Traceback..."


def test_aider_runner_defaults() -> None:
    """Verify AiderRunner default configuration values."""
    runner = AiderRunner()
    assert runner.timeout_seconds == 300
    assert runner.default_model == "openai/gpt-6-luna"
    assert runner.default_api_base == "https://api.scalemax.pro/v1"
    assert runner.aider_binary == "aider"


def test_aider_runner_custom_init() -> None:
    """Verify AiderRunner accepts custom initialization arguments."""
    runner = AiderRunner(
        timeout_seconds=60,
        default_model="openai/gpt-4o",
        default_api_base="https://custom.llm.endpoint/v1",
        aider_binary="/usr/local/bin/aider",
    )
    assert runner.timeout_seconds == 60
    assert runner.default_model == "openai/gpt-4o"
    assert runner.default_api_base == "https://custom.llm.endpoint/v1"
    assert runner.aider_binary == "/usr/local/bin/aider"


# =========================================================================
# 2. CLI Command Construction Tests
# =========================================================================


def test_build_command_exact_matching(runner: AiderRunner) -> None:
    """
    Verify build_command constructs the exact required arguments matching:
    aider --model openai/gpt-6-luna --openai-api-base https://api.scalemax.pro/v1
          --openai-api-key "$ACTIVE_KEY" --yes --no-auto-commits --edit-format diff
          --message "$PATCH_INSTRUCTION" path/to/target_file.py
    """
    cmd = runner.build_command(
        target_file="path/to/target_file.py",
        patch_instruction="Fix null pointer exception in handle_request",
        api_key="$ACTIVE_KEY",
    )

    expected = [
        "aider",
        "--model",
        "openai/gpt-6-luna",
        "--openai-api-base",
        "https://api.scalemax.pro/v1",
        "--openai-api-key",
        "$ACTIVE_KEY",
        "--yes",
        "--no-auto-commits",
        "--edit-format",
        "diff",
        "--message",
        "Fix null pointer exception in handle_request",
        "path/to/target_file.py",
    ]
    assert cmd == expected


def test_build_command_with_key_config(
    runner: AiderRunner, sample_key_config: KeyConfig
) -> None:
    """Verify build_command extracts model, base_url, and api_key from KeyConfig."""
    cmd = runner.build_command(
        target_file=Path("src/auth.py"),
        patch_instruction="Validate bearer token expiration",
        key_entry=sample_key_config,
    )

    assert "--model" in cmd
    assert cmd[cmd.index("--model") + 1] == "openai/gpt-6-luna"
    assert "--openai-api-base" in cmd
    assert cmd[cmd.index("--openai-api-base") + 1] == "https://api.scalemax.pro/v1"
    assert "--openai-api-key" in cmd
    assert cmd[cmd.index("--openai-api-key") + 1] == "sk-test-scalemax-key-12345678"
    assert cmd[-1] == "src/auth.py"


def test_build_command_overrides_key_config(
    runner: AiderRunner, sample_key_config: KeyConfig
) -> None:
    """Verify explicit parameters override values in KeyConfig and defaults."""
    cmd = runner.build_command(
        target_file="src/utils.py",
        patch_instruction="Optimize regex compilation",
        key_entry=sample_key_config,
        api_key="sk-override-key",
        api_base="https://override.api/v1",
        model="openai/gpt-6-luna-turbo",
    )

    assert cmd[cmd.index("--model") + 1] == "openai/gpt-6-luna-turbo"
    assert cmd[cmd.index("--openai-api-base") + 1] == "https://override.api/v1"
    assert cmd[cmd.index("--openai-api-key") + 1] == "sk-override-key"


def test_build_command_path_normalization(runner: AiderRunner) -> None:
    """Verify target_file Path objects with OS backslashes are normalized to posix."""
    windows_path = Path("src") / "nested" / "module.py"
    cmd = runner.build_command(
        target_file=windows_path,
        patch_instruction="Refactor helper",
        api_key="sk-key",
    )
    assert cmd[-1] == "src/nested/module.py"
    assert "\\" not in cmd[-1]


def test_build_command_without_api_key_omits_flag(runner: AiderRunner) -> None:
    """Verify --openai-api-key is omitted if no key is supplied and env var is empty."""
    with patch.dict(os.environ, {}, clear=True):
        cmd = runner.build_command(
            target_file="src/app.py",
            patch_instruction="Fix typo",
        )
        assert "--openai-api-key" not in cmd


def test_build_command_picks_up_openai_api_key_env(runner: AiderRunner) -> None:
    """Verify OPENAI_API_KEY from environment is used when no key parameter is given."""
    with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-env-key-999"}, clear=True):
        cmd = runner.build_command(
            target_file="src/app.py",
            patch_instruction="Fix typo",
        )
        assert "--openai-api-key" in cmd
        assert cmd[cmd.index("--openai-api-key") + 1] == "sk-env-key-999"


# =========================================================================
# 3. Subprocess Environment & Credential Sanitization Tests
# =========================================================================


def test_build_environment_sanitization(
    runner: AiderRunner, sample_key_config: KeyConfig
) -> None:
    """
    Verify build_environment:
    1. Retains safe system variables.
    2. Explicitly strips sensitive credentials (GITHUB_*, AWS_*, etc.).
    3. Injects OPENAI_API_BASE and OPENAI_API_KEY.
    """
    dirty_env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "SYSTEMROOT": "C:\\Windows",
        "WINDIR": "C:\\Windows",
        "TEMP": "/tmp",
        "USERPROFILE": "C:\\Users\\alice",
        "HOME": "/home/alice",
        "LANG": "en_US.UTF-8",
        "PYTHONPATH": "/app/src",
        # Sensitive variables that MUST be stripped:
        "GITHUB_TOKEN": "ghp_super_secret_token_12345",
        "GH_TOKEN": "gho_another_secret_token_67890",
        "GITHUB_PAT": "github_pat_sensitive_token",
        "DASHBOARD_API_KEY": "dash_sec_abc123",
        "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
        "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "AZURE_CLIENT_SECRET": "azure_secret_val",
        "OCI_KEY": "oci_key_val",
        "GCP_PRIVATE_KEY": "gcp_key_val",
        # Unwhitelisted system var:
        "UNWHITELISTED_INTERNAL_VAR": "secret_internal_value",
    }

    env = runner.build_environment(
        key_entry=sample_key_config,
        base_env=dirty_env,
    )

    # 1. Retained safe system vars
    assert env["PATH"] == "/usr/local/bin:/usr/bin:/bin"
    assert env["SYSTEMROOT"] == "C:\\Windows"
    assert env["WINDIR"] == "C:\\Windows"
    assert env["TEMP"] == "/tmp"
    assert env["USERPROFILE"] == "C:\\Users\\alice"
    assert env["HOME"] == "/home/alice"
    assert env["LANG"] == "en_US.UTF-8"
    assert env["PYTHONPATH"] == "/app/src"

    # 2. Stripped sensitive vars
    assert "GITHUB_TOKEN" not in env
    assert "GH_TOKEN" not in env
    assert "GITHUB_PAT" not in env
    assert "DASHBOARD_API_KEY" not in env
    assert "AWS_ACCESS_KEY_ID" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "AZURE_CLIENT_SECRET" not in env
    assert "OCI_KEY" not in env
    assert "GCP_PRIVATE_KEY" not in env
    assert "UNWHITELISTED_INTERNAL_VAR" not in env

    # 3. Propagated OpenAI variables
    assert env["OPENAI_API_BASE"] == "https://api.scalemax.pro/v1"
    assert env["OPENAI_BASE_URL"] == "https://api.scalemax.pro/v1"
    assert env["OPENAI_API_KEY"] == "sk-test-scalemax-key-12345678"


def test_build_environment_explicit_overrides(runner: AiderRunner) -> None:
    """Verify api_key and api_base overrides in build_environment."""
    base_env = {"PATH": "/bin"}
    env = runner.build_environment(
        api_key="sk-direct-key",
        api_base="https://direct.base.url/v1",
        base_env=base_env,
    )
    assert env["OPENAI_API_BASE"] == "https://direct.base.url/v1"
    assert env["OPENAI_BASE_URL"] == "https://direct.base.url/v1"
    assert env["OPENAI_API_KEY"] == "sk-direct-key"


def test_environment_constants_completeness() -> None:
    """Verify denied and safe lists conform to security requirements."""
    for required_safe in ("PATH", "SYSTEMROOT", "TEMP", "USERPROFILE", "HOME", "LANG", "PYTHONPATH"):
        assert required_safe in SAFE_SYSTEM_ENV_VARS
    for required_denied in ("GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PAT", "DASHBOARD_API_KEY"):
        assert required_denied in DENIED_ENV_VARS
    for required_prefix in ("GITHUB_", "GH_", "DASHBOARD_", "AWS_", "AZURE_", "OCI_", "GCP_"):
        assert required_prefix in DENIED_PREFIXES


# =========================================================================
# 4. Process Execution & Subprocess Lifecycle Tests (Hermetic)
# =========================================================================


def test_run_aider_success_status(runner: AiderRunner, tmp_path: Path) -> None:
    """Verify exit code 0 maps to SUCCESS and extracts diff."""
    mock_stdout_lines = [
        "Aider v0.50.0\n",
        "Applied edit to src/calc.py\n",
        "Commit suppressed (--no-auto-commits)\n",
    ]

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = iter(mock_stdout_lines)
    mock_proc.wait.return_value = 0

    expected_diff = (
        "--- a/src/calc.py\n"
        "+++ b/src/calc.py\n"
        "@@ -10,3 +10,3 @@\n"
        "-    return a / b\n"
        "+    return a / b if b != 0 else 0\n"
    )

    with patch("subprocess.Popen", return_value=mock_proc) as mock_popen, \
         patch.object(runner, "extract_diff", return_value=expected_diff) as mock_diff:

        result = runner.run_aider(
            repo_path=tmp_path,
            target_file="src/calc.py",
            patch_instruction="Handle division by zero",
            api_key="sk-test",
        )

        assert mock_popen.called
        assert mock_diff.called
        assert result.status == "SUCCESS"
        assert result.exit_code == 0
        assert result.diff_output == expected_diff
        assert result.target_file == "src/calc.py"
        assert result.error_message is None
        assert "Applied edit to src/calc.py" in result.raw_output


def test_run_aider_failure_exit_code(runner: AiderRunner, tmp_path: Path) -> None:
    """Verify non-zero exit code maps to FAILED."""
    mock_stdout_lines = [
        "Model rejected the requested edits.\n",
        "Error: Invalid syntax in suggested patch.\n",
    ]

    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stdout = iter(mock_stdout_lines)
    mock_proc.wait.return_value = 1

    with patch("subprocess.Popen", return_value=mock_proc):
        result = runner.run_aider(
            repo_path=tmp_path,
            target_file="src/calc.py",
            patch_instruction="Fix bug",
            api_key="sk-test",
        )

        assert result.status == "FAILED"
        assert result.exit_code == 1
        assert result.diff_output == ""
        assert "Aider process failed with return code 1" in (result.error_message or "")


def test_run_aider_rate_limit_429(runner: AiderRunner, tmp_path: Path) -> None:
    """Verify rate limit 429 signature aborts process and maps to RATE_LIMIT_429."""
    mock_stdout_lines = [
        "Connecting to openai/gpt-6-luna...\n",
        "HTTP 429: RateLimitError: Requests rate limit exceeded for model\n",
        "Retrying in 5 seconds...\n",
    ]

    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stdout = iter(mock_stdout_lines)
    mock_proc.wait.return_value = 1

    with patch("subprocess.Popen", return_value=mock_proc), \
         patch.object(runner, "_terminate_process_tree") as mock_terminate:

        result = runner.run_aider(
            repo_path=tmp_path,
            target_file="src/calc.py",
            patch_instruction="Fix bug",
            api_key="sk-test",
        )

        assert mock_terminate.called
        assert result.status == "RATE_LIMIT_429"
        assert result.exit_code == 1
        assert result.diff_output == ""
        assert "Rate limit" in (result.error_message or "")


def test_run_aider_quota_exhausted_402(runner: AiderRunner, tmp_path: Path) -> None:
    """Verify 402 payment required / insufficient_quota maps to QUOTA_EXHAUSTED_402."""
    mock_stdout_lines = [
        "Connecting to https://api.scalemax.pro/v1...\n",
        "openai.error.RateLimitError: 402 Payment Required: insufficient_quota credits\n",
    ]

    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stdout = iter(mock_stdout_lines)
    mock_proc.wait.return_value = 1

    with patch("subprocess.Popen", return_value=mock_proc), \
         patch.object(runner, "_terminate_process_tree") as mock_terminate:

        result = runner.run_aider(
            repo_path=tmp_path,
            target_file="src/calc.py",
            patch_instruction="Fix bug",
            api_key="sk-test",
        )

        assert mock_terminate.called
        assert result.status == "QUOTA_EXHAUSTED_402"
        assert result.exit_code == 1
        assert result.diff_output == ""


def test_run_aider_rate_limit_gateway_errors(runner: AiderRunner, tmp_path: Path) -> None:
    """Verify 502, 503, 504 gateway signatures map to RATE_LIMIT_429."""
    for sig in ("502 Bad Gateway", "503 Service Unavailable", "504 Gateway Timeout"):
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = iter([f"Error: {sig}\n"])
        mock_proc.wait.return_value = 1

        with patch("subprocess.Popen", return_value=mock_proc), \
             patch.object(runner, "_terminate_process_tree"):

            result = runner.run_aider(
                repo_path=tmp_path,
                target_file="src/calc.py",
                patch_instruction="Fix",
                api_key="sk-test",
            )
            assert result.status == "RATE_LIMIT_429"


def test_run_aider_timeout_aborts_process(runner: AiderRunner, tmp_path: Path) -> None:
    """Verify timeout watchdog terminates hung process tree and maps to TIMEOUT."""
    mock_proc = MagicMock()
    mock_proc.returncode = -15
    mock_proc.stdout = iter(["Thinking...\n", "Still thinking...\n"])
    mock_proc.wait.side_effect = subprocess.TimeoutExpired(cmd="aider", timeout=0.1)

    with patch("subprocess.Popen", return_value=mock_proc), \
         patch.object(runner, "_terminate_process_tree") as mock_term:

        result = runner.run_aider(
            repo_path=tmp_path,
            target_file="src/calc.py",
            patch_instruction="Fix slow loop",
            api_key="sk-test",
        )

        assert mock_term.called
        assert result.status == "TIMEOUT"
        assert result.diff_output == ""
        assert "timed out" in (result.error_message or "").lower()


def test_run_aider_missing_binary(runner: AiderRunner, tmp_path: Path) -> None:
    """Verify FileNotFoundError when launching aider returns NOT_FOUND cleanly."""
    with patch("subprocess.Popen", side_effect=FileNotFoundError("No such file or directory: 'aider'")):
        result = runner.run_aider(
            repo_path=tmp_path,
            target_file="src/calc.py",
            patch_instruction="Fix bug",
            api_key="sk-test",
        )

        assert result.status == "NOT_FOUND"
        assert result.exit_code == -1
        assert result.diff_output == ""
        assert "not found in PATH" in (result.error_message or "")


def test_run_aider_handles_absolute_target_file(
    runner: AiderRunner, tmp_path: Path
) -> None:
    """Verify absolute target file path inside repo_path is converted to relative posix."""
    target_abs = tmp_path / "sub" / "file.py"

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = iter([])
    mock_proc.wait.return_value = 0

    with patch("subprocess.Popen", return_value=mock_proc) as mock_popen, \
         patch.object(runner, "extract_diff", return_value=""):

        result = runner.run_aider(
            repo_path=tmp_path,
            target_file=target_abs,
            patch_instruction="Fix",
            api_key="sk-test",
        )

        assert result.target_file == "sub/file.py"
        called_cmd = mock_popen.call_args[0][0]
        assert called_cmd[-1] == "sub/file.py"


def test_run_aider_invokes_log_callback(runner: AiderRunner, tmp_path: Path) -> None:
    """Verify log_callback receives streamed lines and masked command."""
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = iter(["Starting Aider...\n", "Editing complete.\n"])
    mock_proc.wait.return_value = 0

    captured_logs: list[str] = []

    with patch("subprocess.Popen", return_value=mock_proc), \
         patch.object(runner, "extract_diff", return_value=""):

        runner.run_aider(
            repo_path=tmp_path,
            target_file="src/foo.py",
            patch_instruction="Fix",
            api_key="sk-secret-long-key-12345",
            log_callback=captured_logs.append,
        )

    # First log is masked command invocation
    assert any("[AIDER] Executing:" in line for line in captured_logs)
    # Ensure raw secret is not present in logged command
    assert "sk-secret-long-key-12345" not in "".join(captured_logs)
    assert "Starting Aider..." in captured_logs
    assert "Editing complete." in captured_logs


# =========================================================================
# 5. Diff Extraction Tests
# =========================================================================


def test_extract_diff_git_head_success(runner: AiderRunner, tmp_path: Path) -> None:
    """Verify extract_diff returns git diff HEAD output when git succeeds."""
    expected = "--- a/src/target.py\n+++ b/src/target.py\n@@ -1 +1 @@\n-old\n+new\n"

    def mock_subprocess_run(cmd: list[str], **kwargs: object) -> MagicMock:
        res = MagicMock()
        if "diff" in cmd and "HEAD" in cmd:
            res.returncode = 0
            res.stdout = expected
        else:
            res.returncode = 0
            res.stdout = ""
        return res

    with patch("subprocess.run", side_effect=mock_subprocess_run):
        diff = runner.extract_diff(tmp_path, "src/target.py")
        assert diff == expected


def test_extract_diff_git_working_tree_fallback(
    runner: AiderRunner, tmp_path: Path
) -> None:
    """Verify extract_diff falls back to git diff (working tree) if HEAD diff is empty."""
    expected = "--- a/src/target.py\n+++ b/src/target.py\n@@ -1 +1 @@\n-old\n+new\n"

    def mock_subprocess_run(cmd: list[str], **kwargs: object) -> MagicMock:
        res = MagicMock()
        if "diff" in cmd and "HEAD" in cmd:
            res.returncode = 0
            res.stdout = ""
        elif "diff" in cmd and "--" in cmd:
            res.returncode = 0
            res.stdout = expected
        else:
            res.returncode = 0
            res.stdout = ""
        return res

    with patch("subprocess.run", side_effect=mock_subprocess_run):
        diff = runner.extract_diff(tmp_path, "src/target.py")
        assert diff == expected


def test_extract_diff_from_markdown_block_fallback(
    runner: AiderRunner, tmp_path: Path
) -> None:
    """Verify extract_diff parses markdown diff block from stdout if git is unavailable."""
    raw_output = (
        "Here is the diff of the changes:\n"
        "```diff\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -5,3 +5,3 @@\n"
        "-print('hello')\n"
        "+print('world')\n"
        "```\n"
        "Done!"
    )

    with patch("subprocess.run", side_effect=FileNotFoundError("git not found")):
        diff = runner.extract_diff(tmp_path, "src/app.py", raw_output=raw_output)
        assert "--- a/src/app.py" in diff
        assert "+print('world')" in diff


def test_extract_diff_from_unified_diff_fallback(
    runner: AiderRunner, tmp_path: Path
) -> None:
    """Verify extract_diff parses unified diff text from stdout without markdown backticks."""
    raw_output = (
        "Diff:\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -1 +1 @@\n"
        "-a\n"
        "+b\n"
    )

    with patch("subprocess.run", side_effect=Exception("git error")):
        diff = runner.extract_diff(tmp_path, "src/app.py", raw_output=raw_output)
        assert diff.startswith("--- a/src/app.py")
        assert "+b" in diff


def test_extract_diff_empty_when_no_changes(
    runner: AiderRunner, tmp_path: Path
) -> None:
    """Verify extract_diff returns empty string when neither git nor stdout contains diff."""
    with patch("subprocess.run", side_effect=Exception("no git")):
        diff = runner.extract_diff(tmp_path, "src/app.py", raw_output="All clean, no edits.")
        assert diff == ""


# =========================================================================
# 6. Process Tree Termination Tests
# =========================================================================


def test_terminate_process_tree_with_psutil(runner: AiderRunner) -> None:
    """Verify _terminate_process_tree kills all child processes and parent."""
    mock_proc = MagicMock()
    mock_proc.pid = 4321

    mock_child1 = MagicMock()
    mock_child2 = MagicMock()
    mock_parent = MagicMock()
    mock_parent.children.return_value = [mock_child1, mock_child2]

    with patch("psutil.Process", return_value=mock_parent):
        runner._terminate_process_tree(mock_proc)

        mock_child1.kill.assert_called_once()
        mock_child2.kill.assert_called_once()
        mock_parent.kill.assert_called_once()


def test_terminate_process_tree_fallback_posix(runner: AiderRunner) -> None:
    """Verify fallback to os.killpg on POSIX when psutil fails."""
    mock_proc = MagicMock()
    mock_proc.pid = 1234

    with patch("psutil.Process", side_effect=Exception("psutil failure")), \
         patch("sys.platform", "linux"), \
         patch("os.getpgid", create=True, return_value=1234), \
         patch("os.killpg", create=True) as mock_killpg:

        runner._terminate_process_tree(mock_proc)
        mock_killpg.assert_called_once_with(1234, 9)


def test_terminate_process_tree_fallback_windows(runner: AiderRunner) -> None:
    """Verify fallback to taskkill /F /T /PID and proc.kill on Windows when psutil fails."""
    mock_proc = MagicMock()
    mock_proc.pid = 5678

    with patch("psutil.Process", side_effect=Exception("psutil failure")), \
         patch("sys.platform", "win32"), \
         patch("subprocess.run") as mock_run:

        runner._terminate_process_tree(mock_proc)
        mock_run.assert_called_once_with(
            ["taskkill", "/F", "/T", "/PID", "5678"],
            check=False,
            capture_output=True,
        )
        mock_proc.kill.assert_called_once()


def test_run_aider_sets_stdin_devnull(runner: AiderRunner, tmp_path: Path) -> None:
    """Verify run_aider passes stdin=subprocess.DEVNULL to prevent interactive hangs."""
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = iter([])
    mock_proc.wait.return_value = 0

    with patch("subprocess.Popen", return_value=mock_proc) as mock_popen, \
         patch.object(runner, "extract_diff", return_value=""):
        runner.run_aider(
            repo_path=tmp_path,
            target_file="src/target.py",
            patch_instruction="Fix",
            api_key="sk-test",
        )
        kwargs = mock_popen.call_args[1]
        assert kwargs.get("stdin") == subprocess.DEVNULL


def test_extract_diff_bounded_hunk_and_multiple_blocks(
    runner: AiderRunner, tmp_path: Path
) -> None:
    """Verify fallback diff extraction selects matching target block and excludes trailing prose."""
    raw_output = (
        "Here is diff for other.py:\n"
        "```diff\n"
        "--- a/src/other.py\n"
        "+++ b/src/other.py\n"
        "@@ -1,1 +1,1 @@\n"
        "-other_old\n"
        "+other_new\n"
        "```\n"
        "Here is diff for app.py:\n"
        "```diff\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -1,2 +1,2 @@\n"
        "-def old(): pass\n"
        "+def new(): pass\n"
        "\n"
        "This patch was generated by Aider. Have a nice day!\n"
        "```\n"
    )
    with patch("subprocess.run", side_effect=Exception("no git")):
        diff = runner.extract_diff(tmp_path, "src/app.py", raw_output=raw_output)
        assert "+def new(): pass" in diff
        assert "other_new" not in diff
        assert "Have a nice day!" not in diff


# =========================================================================
# 7. Rate Limit Regex Detection Tests
# =========================================================================


@pytest.mark.parametrize(
    "line,expected_hit,expected_type",
    [
        ("HTTP 429: Too Many Requests", True, "RATE_LIMIT_429"),
        ("Error 429 Too Many Requests", True, "RATE_LIMIT_429"),
        ("status code 429", True, "RATE_LIMIT_429"),
        ("HTTP 429", True, "RATE_LIMIT_429"),
        ("[429]", True, "RATE_LIMIT_429"),
        ("\"code\": 429", True, "RATE_LIMIT_429"),
        ("\"status\": 429", True, "RATE_LIMIT_429"),
        ("tests/test_foo.py:429: error: Incompatible types in assignment", False, ""),
        ("src/utils.py:429:1: E501 line too long", False, ""),
        ("server.py:502: RuntimeWarning: coroutine was never awaited", False, ""),
        ("File \"foo.py\", line 429, in <module>", False, ""),
        ("tests/test_calc.py:429: AssertionError: Expected 429 but got 200", False, ""),
        ("Merged PR #429: Fix authentication timeout", False, ""),
        ("http://localhost:429/v1", False, ""),
        ("Line 4290: def foo():", False, ""),  # Not word-bounded status
        ("Commit a429ef failed", False, ""),  # Not word-bounded status
        ("server at 127.0.0.1:4290", False, ""),  # Port number substring
        ("Processed 14290 tokens successfully", False, ""),  # Substring in token count
        ("PID 24298 running", False, ""),  # Substring in PID
        ("RateLimitError: Rate limit reached for organization", True, "RATE_LIMIT_429"),
        ("insufficient_quota: Current quota exceeded", True, "QUOTA_EXHAUSTED_402"),
        ("402 Payment Required: Please add credits", True, "QUOTA_EXHAUSTED_402"),
        ("HTTP 402: Payment Required", True, "QUOTA_EXHAUSTED_402"),
        ("502 Bad Gateway", True, "RATE_LIMIT_429"),
        ("503 Service Unavailable", True, "RATE_LIMIT_429"),
        ("504 Gateway Timeout", True, "RATE_LIMIT_429"),
        ("Normal execution log output", False, ""),
    ],
)
def test_rate_limit_detection_precision(
    runner: AiderRunner, line: str, expected_hit: bool, expected_type: str
) -> None:
    """Verify word-bounded regex precision and classification for rate limit signatures."""
    hit, sig = runner._is_rate_limit_line(line)
    assert hit is expected_hit
    if expected_hit:
        classification = runner._classify_rate_limit(sig)
        assert classification == expected_type

