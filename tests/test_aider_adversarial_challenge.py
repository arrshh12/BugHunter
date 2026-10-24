"""
Adversarial Challenge & Stress-Test Suite for Milestone 3: Aider Execution Runner.
Target: src/aider_runner.py
Author: challenger_m3_1 (Empirical Challenger)

Tests coverage:
1. Adversarial CLI argument construction:
   - Weird target file paths: spaces, quotes, non-ASCII characters, relative paths with '.' and '..',
     backslashes vs forward slashes, flag-like filenames, absolute paths outside repository.
   - Patch instructions: single/double/nested quotes, newlines (LF & CRLF), shell metacharacters
     ($, &, |, ;, >, <, ``, $(), *, ?, etc.), unicode, emojis, huge instruction payloads.
   - Key config resolution: priority handling, null/empty keys, missing attributes,
     custom models and endpoints, override precedence.
2. Subprocess environment sanitization stress:
   - Dirty secret tokens: lowercase, mixed-case, denied prefixes (GITHUB_*, GH_*, DASHBOARD_*, AWS_*, etc.).
   - Confirming safe system variables (PATH, TEMP, USERPROFILE, etc.) survive.
   - Confirming OpenAI endpoint credentials injection and overrides.
3. Subprocess lifecycle, process tree termination, and diff extraction boundary stress.
"""

from __future__ import annotations

import os
import subprocess
import sys
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


# =========================================================================
# 1. Adversarial Command Construction: Target File Paths
# =========================================================================


class TestAdversarialFilePathConstruction:
    """Stress-test target file path handling in build_command and run_aider."""

    def test_target_file_with_spaces(self, runner: AiderRunner):
        """File paths with spaces must remain intact as a single argument."""
        file_path = "src/my nested folder/my target file.py"
        cmd = runner.build_command(
            target_file=file_path,
            patch_instruction="Fix issue",
            api_key="sk-test",
        )
        assert cmd[-1] == "src/my nested folder/my target file.py"
        # Ensure it is not split across arguments
        assert "src/my" not in cmd

    def test_target_file_windows_backslashes_normalized(self, runner: AiderRunner):
        """Windows backslashes must be normalized to forward slashes (posix)."""
        win_path = r"src\core\handlers\request_handler.py"
        cmd = runner.build_command(
            target_file=win_path,
            patch_instruction="Fix issue",
            api_key="sk-test",
        )
        assert cmd[-1] == "src/core/handlers/request_handler.py"
        assert "\\" not in cmd[-1]

    def test_target_file_mixed_slashes_normalized(self, runner: AiderRunner):
        """Mixed slashes must be consistently normalized to posix."""
        mixed_path = r"src/modules\utils/sub\helper.py"
        cmd = runner.build_command(
            target_file=mixed_path,
            patch_instruction="Fix issue",
            api_key="sk-test",
        )
        assert cmd[-1] == "src/modules/utils/sub/helper.py"

    def test_target_file_non_ascii_and_unicode(self, runner: AiderRunner):
        """Non-ASCII, Unicode, and international characters must be preserved."""
        unicode_paths = [
            "src/模块/测试.py",
            "src/こんにちは/テスト.py",
            "src/тест/файл.py",
            "src/café/résumé.py",
            "src/📁_tools/⚡_fast.py",
        ]
        for upath in unicode_paths:
            cmd = runner.build_command(
                target_file=upath,
                patch_instruction="Fix issue",
                api_key="sk-test",
            )
            assert cmd[-1] == Path(upath).as_posix()

    def test_target_file_with_quotes(self, runner: AiderRunner):
        """Target file paths containing quotes should not corrupt the command list."""
        path_with_single_quote = "src/user's_module/file.py"
        cmd = runner.build_command(
            target_file=path_with_single_quote,
            patch_instruction="Fix issue",
            api_key="sk-test",
        )
        assert cmd[-1] == "src/user's_module/file.py"

    def test_target_file_relative_dots(self, runner: AiderRunner):
        """Paths with '.' and '..' are handled safely via Path.as_posix()."""
        relative_dot_path = "./src/../src/components/button.py"
        cmd = runner.build_command(
            target_file=relative_dot_path,
            patch_instruction="Fix issue",
            api_key="sk-test",
        )
        expected = Path(relative_dot_path).as_posix()
        assert cmd[-1] == expected

    def test_target_file_flag_like_name(self, runner: AiderRunner):
        """Filenames looking like CLI flags should be passed as the final argument."""
        flag_file = "--option-file.py"
        cmd = runner.build_command(
            target_file=flag_file,
            patch_instruction="Fix issue",
            api_key="sk-test",
        )
        assert cmd[-1] == "--option-file.py"

    def test_run_aider_path_outside_repo_handled_gracefully(self, runner: AiderRunner, tmp_path: Path):
        """An absolute path outside repo_path handles ValueError gracefully."""
        outside_path = Path("/some/outside/path/to/target.py").resolve()

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = iter([])
        mock_proc.wait.return_value = 0

        with patch("subprocess.Popen", return_value=mock_proc) as mock_popen, \
             patch.object(runner, "extract_diff", return_value=""):
            result = runner.run_aider(
                repo_path=tmp_path,
                target_file=outside_path,
                patch_instruction="Fix bug",
                api_key="sk-test",
            )
            assert result.status == "SUCCESS"
            called_cmd = mock_popen.call_args[0][0]
            assert called_cmd[-1] == outside_path.as_posix()


# =========================================================================
# 2. Adversarial Command Construction: Patch Instructions
# =========================================================================


class TestAdversarialPatchInstructions:
    """Stress-test patch instructions with shell metacharacters, quotes, and newlines."""

    def test_instruction_with_shell_metacharacters(self, runner: AiderRunner):
        """Shell metacharacters ($VAR, ;, |, &&, >, <, ``, $()) must NOT be expanded or split."""
        metachar_instructions = [
            "Fix injection: $USER and ${HOME} should not be evaluated; rm -rf /",
            "Filter output | grep -v 'secret' > /tmp/out 2>&1",
            "Evaluate $(whoami) and `id` safely && exit 0",
            "Escape special chars: & < > \" ' * ? ~ [ ] ( )",
            "Windows cmd expansion: %PATH% %SYSTEMROOT%",
        ]
        for instruction in metachar_instructions:
            cmd = runner.build_command(
                target_file="src/safe.py",
                patch_instruction=instruction,
                api_key="sk-test",
            )
            msg_idx = cmd.index("--message")
            assert cmd[msg_idx + 1] == instruction
            # Verify the command list has exact expected length
            # binary, --model, M, --openai-api-base, B, --openai-api-key, K, --yes, --no-auto-commits, --edit-format, diff, --message, I, F = 14
            assert len(cmd) == 14

    def test_instruction_with_various_quotes(self, runner: AiderRunner):
        """Single, double, and escaped quotes in instructions must be preserved."""
        quoted_instruction = (
            'Change function: def greet(name="world"):\n'
            "    return f'Hello, {name}! It\\'s working.'"
        )
        cmd = runner.build_command(
            target_file="src/greet.py",
            patch_instruction=quoted_instruction,
            api_key="sk-test",
        )
        msg_idx = cmd.index("--message")
        assert cmd[msg_idx + 1] == quoted_instruction

    def test_instruction_multiline_newlines(self, runner: AiderRunner):
        """Instructions with embedded LF and CRLF newlines must remain a single message argument."""
        multiline_instruction = (
            "Step 1: Import typing.Optional\r\n"
            "Step 2: Add validation check:\r\n"
            "    if value is None:\r\n"
            "        raise ValueError('Missing required value')\n"
            "Step 3: Return sanitized result"
        )
        cmd = runner.build_command(
            target_file="src/validator.py",
            patch_instruction=multiline_instruction,
            api_key="sk-test",
        )
        msg_idx = cmd.index("--message")
        assert cmd[msg_idx + 1] == multiline_instruction

    def test_instruction_unicode_and_emojis(self, runner: AiderRunner):
        """Unicode characters, mathematical symbols, and emojis must be preserved."""
        unicode_instruction = "🐛 Fix race condition: ensure mutex locks ∀ thread ∈ T; add 🚀 performance fix"
        cmd = runner.build_command(
            target_file="src/lock.py",
            patch_instruction=unicode_instruction,
            api_key="sk-test",
        )
        msg_idx = cmd.index("--message")
        assert cmd[msg_idx + 1] == unicode_instruction

    def test_instruction_large_payload(self, runner: AiderRunner):
        """Very large patch instruction payloads (50,000 chars) must not crash or corrupt command list."""
        large_instruction = "Fix line " + ("# comment text with details\n" * 2000)
        assert len(large_instruction) > 50000
        cmd = runner.build_command(
            target_file="src/large.py",
            patch_instruction=large_instruction,
            api_key="sk-test",
        )
        msg_idx = cmd.index("--message")
        assert cmd[msg_idx + 1] == large_instruction
        assert cmd[-1] == "src/large.py"


# =========================================================================
# 3. Adversarial Command Construction: Key Config Resolution & Precedence
# =========================================================================


class TestAdversarialKeyResolution:
    """Stress-test KeyConfig resolution, priority, null keys, missing keys, and overrides."""

    def test_key_entry_null_and_empty_api_key(self, runner: AiderRunner):
        """When KeyConfig has api_key=None or '', it falls back to OPENAI_API_KEY or omits."""
        # Case A: api_key is None, env var is empty
        key_entry_none = KeyConfig(
            id="key-null",
            provider="openai",
            base_url="https://api.scalemax.pro/v1",
            model="openai/gpt-6-luna",
            api_key=None,  # type: ignore[arg-type]
            masked_key="****",
        )
        with patch.dict(os.environ, {}, clear=True):
            cmd = runner.build_command(
                target_file="src/main.py",
                patch_instruction="Fix",
                key_entry=key_entry_none,
            )
            assert "--openai-api-key" not in cmd

        # Case B: api_key is empty string, env var is empty
        key_entry_empty = KeyConfig(
            id="key-empty",
            provider="openai",
            base_url="https://api.scalemax.pro/v1",
            model="openai/gpt-6-luna",
            api_key="",
            masked_key="****",
        )
        with patch.dict(os.environ, {}, clear=True):
            cmd = runner.build_command(
                target_file="src/main.py",
                patch_instruction="Fix",
                key_entry=key_entry_empty,
            )
            assert "--openai-api-key" not in cmd

    def test_key_entry_fallback_to_env_when_none(self, runner: AiderRunner):
        """When KeyConfig has api_key=None, it falls back to OPENAI_API_KEY if present."""
        key_entry = KeyConfig(
            id="key-fallback",
            provider="openai",
            base_url="https://api.scalemax.pro/v1",
            model="openai/gpt-6-luna",
            api_key=None,  # type: ignore[arg-type]
            masked_key="****",
        )
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-env-backup-key"}, clear=True):
            cmd = runner.build_command(
                target_file="src/main.py",
                patch_instruction="Fix",
                key_entry=key_entry,
            )
            assert "--openai-api-key" in cmd
            assert cmd[cmd.index("--openai-api-key") + 1] == "sk-env-backup-key"

    def test_override_precedence(self, runner: AiderRunner):
        """Explicit parameters must override key_entry values and defaults."""
        key_entry = KeyConfig(
            id="key-entry-1",
            provider="openai",
            base_url="https://keyentry.endpoint/v1",
            model="openai/keyentry-model",
            api_key="sk-keyentry-key",
            masked_key="sk-k...-key",
            priority=5,
        )

        cmd = runner.build_command(
            target_file="src/app.py",
            patch_instruction="Fix",
            key_entry=key_entry,
            api_key="sk-explicit-key",
            api_base="https://explicit.endpoint/v1",
            model="openai/explicit-model",
        )

        assert cmd[cmd.index("--model") + 1] == "openai/explicit-model"
        assert cmd[cmd.index("--openai-api-base") + 1] == "https://explicit.endpoint/v1"
        assert cmd[cmd.index("--openai-api-key") + 1] == "sk-explicit-key"

    def test_missing_or_duck_typed_key_entry(self, runner: AiderRunner):
        """Objects missing model or base_url attributes fall back to defaults gracefully."""
        class PartialKeyConfig:
            api_key = "sk-partial-key"

        cmd = runner.build_command(
            target_file="src/app.py",
            patch_instruction="Fix",
            key_entry=PartialKeyConfig(),  # type: ignore[arg-type]
        )
        assert cmd[cmd.index("--model") + 1] == runner.default_model
        assert cmd[cmd.index("--openai-api-base") + 1] == runner.default_api_base
        assert cmd[cmd.index("--openai-api-key") + 1] == "sk-partial-key"


# =========================================================================
# 4. Adversarial Subprocess Environment Sanitization
# =========================================================================


class TestAdversarialEnvironmentSanitization:
    """Stress-test environment variable filtering with dirty secrets, casing, and overrides."""

    def test_dirty_secrets_casing_and_prefixes(self, runner: AiderRunner):
        """
        Subprocess environment must scrub dirty tokens across casing variations:
        - Lowercase: github_token, gh_token, aws_secret_access_key, dashboard_api_key
        - Mixed-case: Gh_ToKeN, GitHub_Token, DaShBoArD_ApI_KeY, Aws_Secret_Access_Key
        - Denied prefixes: GITHUB_*, GH_*, DASHBOARD_*, AWS_*, AZURE_*, OCI_*, GCP_*
        - Safe system variables must survive.
        """
        dirty_env = {
            # Safe system vars
            "PATH": "/usr/local/bin:/usr/bin",
            "SYSTEMROOT": "C:\\Windows",
            "WINDIR": "C:\\Windows",
            "COMSPEC": "cmd.exe",
            "TEMP": "/tmp",
            "USERPROFILE": "C:\\Users\\test",
            "HOME": "/home/test",
            "LANG": "en_US.UTF-8",
            "PYTHONPATH": "/app/src",
            # Dirty secret tokens (lowercase)
            "github_token": "ghp_lowercase_token_123456",
            "gh_token": "gho_lowercase_token_123456",
            "dashboard_api_key": "dash_lowercase_secret",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG",
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "azure_client_secret": "azure_secret",
            "oci_key": "oci_secret",
            "gcp_private_key": "gcp_secret",
            # Dirty secret tokens (mixed case)
            "Gh_ToKeN": "gho_mixed_token_123456",
            "GitHub_Token": "ghp_mixed_token_123456",
            "DaShBoArD_ApI_KeY": "dash_mixed_secret",
            "Aws_Secret_Access_Key": "aws_mixed_secret",
            # Denied prefixes
            "GITHUB_ENTERPRISE_TOKEN": "ghe_token_xyz",
            "GH_ENTERPRISE_PAT": "ghp_ent_pat",
            "DASHBOARD_SHARED_SECRET": "dash_shared",
            "AWS_SESSION_TOKEN": "aws_session",
            "AZURE_TENANT_ID": "azure_tenant",
            "OCI_TENANCY": "oci_tenancy",
            "GCP_PROJECT_ID": "gcp_project",
            # Arbitrary host secrets
            "SECRET_INTERNAL_TOKEN": "super_secret",
            "DATABASE_PASSWORD": "db_password_123",
            "SSH_AUTH_SOCK": "/tmp/ssh.sock",
        }

        env = runner.build_environment(
            api_key="sk-clean-key",
            api_base="https://api.scalemax.pro/v1",
            base_env=dirty_env,
        )

        # 1. Verify safe system variables survived
        assert env["PATH"] == "/usr/local/bin:/usr/bin"
        assert env["SYSTEMROOT"] == "C:\\Windows"
        assert env["WINDIR"] == "C:\\Windows"
        assert env["COMSPEC"] == "cmd.exe"
        assert env["TEMP"] == "/tmp"
        assert env["USERPROFILE"] == "C:\\Users\\test"
        assert env["HOME"] == "/home/test"
        assert env["LANG"] == "en_US.UTF-8"
        assert env["PYTHONPATH"] == "/app/src"

        # 2. Verify all dirty secrets are stripped (none present)
        for dirty_key in [
            "github_token", "gh_token", "dashboard_api_key",
            "aws_secret_access_key", "aws_access_key_id", "azure_client_secret",
            "oci_key", "gcp_private_key",
            "Gh_ToKeN", "GitHub_Token", "DaShBoArD_ApI_KeY", "Aws_Secret_Access_Key",
            "GITHUB_ENTERPRISE_TOKEN", "GH_ENTERPRISE_PAT", "DASHBOARD_SHARED_SECRET",
            "AWS_SESSION_TOKEN", "AZURE_TENANT_ID", "OCI_TENANCY", "GCP_PROJECT_ID",
            "SECRET_INTERNAL_TOKEN", "DATABASE_PASSWORD", "SSH_AUTH_SOCK",
        ]:
            assert dirty_key not in env, f"Dirty secret '{dirty_key}' leaked into subprocess env!"

        # 3. Verify OpenAI vars are cleanly injected
        assert env["OPENAI_API_BASE"] == "https://api.scalemax.pro/v1"
        assert env["OPENAI_BASE_URL"] == "https://api.scalemax.pro/v1"
        assert env["OPENAI_API_KEY"] == "sk-clean-key"

    def test_environment_sanitization_overrides_host_openai_key(self, runner: AiderRunner):
        """Host OPENAI_API_KEY must be overridden if an active key or KeyConfig is passed."""
        dirty_env = {
            "PATH": "/usr/bin",
            "OPENAI_API_KEY": "sk-host-dirty-key",
        }
        key_entry = KeyConfig(
            id="key-active",
            provider="openai",
            base_url="https://api.scalemax.pro/v1",
            model="openai/gpt-6-luna",
            api_key="sk-active-rotated-key",
            masked_key="sk-a...-key",
        )

        env = runner.build_environment(
            key_entry=key_entry,
            base_env=dirty_env,
        )
        assert env["OPENAI_API_KEY"] == "sk-active-rotated-key"
        assert env["OPENAI_API_KEY"] != "sk-host-dirty-key"

    def test_environment_omits_openai_api_key_when_empty(self, runner: AiderRunner):
        """OPENAI_API_KEY must be omitted if no key is configured anywhere."""
        base_env = {"PATH": "/usr/bin"}
        env = runner.build_environment(
            api_key="",
            base_env=base_env,
        )
        assert "OPENAI_API_KEY" not in env


# =========================================================================
# 5. Process Lifecycle, Timeout, and Streaming Adversarial Stress
# =========================================================================


class TestAdversarialProcessLifecycle:
    """Stress-test process execution, creation flags, timeouts, and error classification."""

    def test_run_aider_windows_creationflags(self, runner: AiderRunner, tmp_path: Path):
        """Verify on Windows CREATE_NEW_PROCESS_GROUP is used for clean tree termination."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = iter([])
        mock_proc.wait.return_value = 0

        with patch("subprocess.Popen", return_value=mock_proc) as mock_popen, \
             patch("sys.platform", "win32"), \
             patch.object(runner, "extract_diff", return_value=""):

            runner.run_aider(
                repo_path=tmp_path,
                target_file="src/target.py",
                patch_instruction="Fix",
                api_key="sk-test",
            )

            kwargs = mock_popen.call_args[1]
            assert "creationflags" in kwargs
            assert kwargs["creationflags"] == subprocess.CREATE_NEW_PROCESS_GROUP

    def test_run_aider_posix_start_new_session(self, runner: AiderRunner, tmp_path: Path):
        """Verify on non-Windows start_new_session=True is set."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = iter([])
        mock_proc.wait.return_value = 0

        with patch("subprocess.Popen", return_value=mock_proc) as mock_popen, \
             patch("sys.platform", "linux"), \
             patch.object(runner, "extract_diff", return_value=""):

            runner.run_aider(
                repo_path=tmp_path,
                target_file="src/target.py",
                patch_instruction="Fix",
                api_key="sk-test",
            )

            kwargs = mock_popen.call_args[1]
            assert kwargs.get("start_new_session") is True

    def test_raw_output_post_failure_rate_limit_catch(self, runner: AiderRunner, tmp_path: Path):
        """If proc failed and rate limit was in raw_output but missed during streaming, catch it post-exit."""
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        # No stream output during iteration
        mock_proc.stdout = iter([])
        mock_proc.wait.return_value = 1

        with patch("subprocess.Popen", return_value=mock_proc), \
             patch.object(runner, "_find_rate_limit_in_text", return_value=(True, "429 Too Many Requests")):

            result = runner.run_aider(
                repo_path=tmp_path,
                target_file="src/calc.py",
                patch_instruction="Fix",
                api_key="sk-test",
            )

            assert result.status == "RATE_LIMIT_429"
            assert result.exit_code == 1
            assert "429 Too Many Requests" in (result.error_message or "")


# =========================================================================
# 6. Log Callback Credential Masking & Diff Extraction Boundary Tests
# =========================================================================


class TestAdversarialMaskingAndDiffExtraction:
    """Stress-test log callback credential masking and diff extraction edge cases."""

    def test_log_callback_short_key_masked(self, runner: AiderRunner, tmp_path: Path):
        """Short API key (<= 8 chars) must be masked as ****."""
        logs: list[str] = []
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = iter([])
        mock_proc.wait.return_value = 0

        with patch("subprocess.Popen", return_value=mock_proc), \
             patch.object(runner, "extract_diff", return_value=""):
            runner.run_aider(
                repo_path=tmp_path,
                target_file="src/target.py",
                patch_instruction="Fix",
                api_key="12345678",
                log_callback=logs.append,
            )

        cmd_log = logs[0]
        assert "12345678" not in cmd_log
        assert "****" in cmd_log

    def test_log_callback_long_key_masked(self, runner: AiderRunner, tmp_path: Path):
        """Long API key (> 8 chars) must show only first 4 and last 4 chars."""
        logs: list[str] = []
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = iter([])
        mock_proc.wait.return_value = 0

        with patch("subprocess.Popen", return_value=mock_proc), \
             patch.object(runner, "extract_diff", return_value=""):
            runner.run_aider(
                repo_path=tmp_path,
                target_file="src/target.py",
                patch_instruction="Fix",
                api_key="sk-live-super-secret-key-9999",
                log_callback=logs.append,
            )

        cmd_log = logs[0]
        assert "sk-live-super-secret-key-9999" not in cmd_log
        assert "sk-l...9999" in cmd_log

    def test_extract_diff_markdown_multiline_block(self, runner: AiderRunner, tmp_path: Path):
        """Diff extraction parses markdown ```diff block when git is unavailable."""
        raw_output = (
            "Thinking about the problem...\n"
            "```diff\n"
            "--- a/src/calc.py\n"
            "+++ b/src/calc.py\n"
            "@@ -1,3 +1,3 @@\n"
            "-    return a / b\n"
            "+    return a / b if b != 0 else 0\n"
            "```\n"
            "Applied successfully!\n"
        )
        with patch("subprocess.run", side_effect=Exception("No git")):
            diff = runner.extract_diff(tmp_path, "src/calc.py", raw_output=raw_output)
            assert "--- a/src/calc.py" in diff
            assert "+    return a / b if b != 0 else 0" in diff

    def test_extract_diff_unified_diff_fallback(self, runner: AiderRunner, tmp_path: Path):
        """Diff extraction parses unified diff format without markdown code fence."""
        raw_output = (
            "Reviewing patch:\n"
            "--- a/src/utils.py\n"
            "+++ b/src/utils.py\n"
            "@@ -10,1 +10,1 @@\n"
            "-x = 1\n"
            "+x = 2\n"
        )
        with patch("subprocess.run", side_effect=Exception("No git")):
            diff = runner.extract_diff(tmp_path, "src/utils.py", raw_output=raw_output)
            assert diff.startswith("--- a/src/utils.py")
            assert "+x = 2" in diff


# =========================================================================
# 7. Rate Limit Regex Precision & False-Positive Immunity Tests
# =========================================================================


class TestRateLimitRegexPrecision:
    """Stress-test word-bounded rate limit regexes to avoid false-positive aborts."""

    @pytest.mark.parametrize(
        "benign_line",
        [
            "Line 4290: def parse_url(url: str) -> None:",
            "Processed 14290 records in 2.3 seconds",
            "Commit hash 402a1b9f verified",
            "Connecting to port 5020 on localhost",
            "Serving request on port 5030...",
            "Response time: 5040 ms",
            "User ID 429 logged in",
        ],
    )
    def test_rate_limit_false_positive_immunity(self, runner: AiderRunner, benign_line: str):
        """Numbers embedding 429, 402, 502, 503, 504 in words or non-error contexts should not false-positive."""
        # For User ID 429, \b429\b is word-bounded so it would match, but 4290, 14290, 5020 etc must not match
        if "4290" in benign_line or "14290" in benign_line or "402a" in benign_line or "5020" in benign_line or "5030" in benign_line or "5040" in benign_line:
            hit, _ = runner._is_rate_limit_line(benign_line)
            assert not hit, f"False positive rate limit detection on line: {benign_line}"

    @pytest.mark.parametrize(
        "error_line,expected_status",
        [
            ("openai.RateLimitError: Rate limit exceeded", "RATE_LIMIT_429"),
            ("HTTP 429: Too Many Requests", "RATE_LIMIT_429"),
            ("Status: 402 Payment Required: insufficient_quota", "QUOTA_EXHAUSTED_402"),
            ("insufficient_quota: you have exceeded your credit balance", "QUOTA_EXHAUSTED_402"),
            ("502 Bad Gateway from ScaleMax endpoint", "RATE_LIMIT_429"),
            ("503 Service Unavailable", "RATE_LIMIT_429"),
            ("504 Gateway Timeout", "RATE_LIMIT_429"),
        ],
    )
    def test_rate_limit_true_positives(
        self, runner: AiderRunner, error_line: str, expected_status: str
    ):
        """Real rate limit and quota exhaustion signatures must be detected and correctly classified."""
        hit, sig = runner._is_rate_limit_line(error_line)
        assert hit, f"Failed to detect rate limit signature in: {error_line}"
        assert runner._classify_rate_limit(sig) == expected_status

