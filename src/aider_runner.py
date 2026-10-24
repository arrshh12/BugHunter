"""
Headless Aider Execution Runner for AutoBugHunter 24/7 (R2 & R4).
Handles CLI command construction, subprocess lifecycle management,
environment sanitization, real-time rate limit detection, and diff extraction.
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.config import KeyConfig

# =========================================================================
# Data Models
# =========================================================================


@dataclass
class AiderResult:
    """Result of an Aider execution run."""

    exit_code: int
    diff_output: str
    status: str  # "SUCCESS", "FAILED", "TIMEOUT", "RATE_LIMIT_429", "QUOTA_EXHAUSTED_402", "NOT_FOUND"
    target_file: str
    duration_seconds: float = 0.0
    error_message: str | None = None
    raw_output: str = ""


# =========================================================================
# Constants & Environment Whitelists
# =========================================================================

RATE_LIMIT_SIGNATURES: list[str] = [
    # 402 Quota Exhaustion signatures (prioritized over 429)
    "insufficient_quota",
    "402 Payment Required",
    r"(?i)\b(?:HTTP(?:/\d(?:\.\d)?)?|status(?:_code)?|error|code)[\s:_\"']*(?:code\s*[:=]?\s*)?(?:is\s*)?402\b",
    r"(?i)\b402\s+payment required",
    r"(?:\[402\]|\(402\)|(?:\"|')code(?:\"|')\s*:\s*402|(?:\"|')status(?:\"|')\s*:\s*402)",
    # 429 Rate Limit, Gateway & Server error signatures
    "RateLimitError",
    "429 Too Many Requests",
    "502 Bad Gateway",
    "503 Service Unavailable",
    "504 Gateway Timeout",
    r"(?i)\b(?:HTTP(?:/\d(?:\.\d)?)?|status(?:_code)?|error|code|client error|response)[\s:_\"']*(?:code\s*[:=]?\s*)?(?:is\s*)?429\b",
    r"(?i)\b429\s+(?:too many requests|rate limit)",
    r"(?:\[429\]|\(429\)|(?:\"|')code(?:\"|')\s*:\s*429|(?:\"|')status(?:\"|')\s*:\s*429)",
    r"(?i)\b(?:HTTP(?:/\d(?:\.\d)?)?|status(?:_code)?|error|code)[\s:_\"']*(?:code\s*[:=]?\s*)?(?:is\s*)?502\b",
    r"(?i)\b(?:HTTP(?:/\d(?:\.\d)?)?|status(?:_code)?|error|code)[\s:_\"']*(?:code\s*[:=]?\s*)?(?:is\s*)?503\b",
    r"(?i)\b(?:HTTP(?:/\d(?:\.\d)?)?|status(?:_code)?|error|code)[\s:_\"']*(?:code\s*[:=]?\s*)?(?:is\s*)?504\b",
    r"(?i)\b502\s+bad gateway",
    r"(?i)\b503\s+service unavailable",
    r"(?i)\b504\s+gateway timeout",
]


SAFE_SYSTEM_ENV_VARS: set[str] = {
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "USERPROFILE",
    "HOMEPATH",
    "HOMEDRIVE",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "VIRTUAL_ENV",
    "PYTHONPATH",
    "PYTHONHOME",
}

DENIED_ENV_VARS: set[str] = {
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITHUB_PAT",
    "DASHBOARD_API_KEY",
}

DENIED_PREFIXES: tuple[str, ...] = (
    "GITHUB_",
    "GH_",
    "DASHBOARD_",
    "AWS_",
    "AZURE_",
    "OCI_",
    "GCP_",
)


# =========================================================================
# Aider Runner Class
# =========================================================================


class AiderRunner:
    """Headless Aider CLI runner for surgical code patching."""

    def __init__(
        self,
        timeout_seconds: int = 300,
        default_model: str = "openai/gpt-6-luna",
        default_api_base: str = "https://api.scalemax.pro/v1",
        aider_binary: str = "aider",
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.default_model = default_model
        self.default_api_base = default_api_base
        self.aider_binary = aider_binary

    def build_command(
        self,
        target_file: Path | str,
        patch_instruction: str,
        key_entry: KeyConfig | None = None,
        api_key: str | None = None,
        api_base: str | None = None,
        model: str | None = None,
    ) -> list[str]:
        """
        Construct CLI arguments for headless aider invocation matching:
        aider --model <model> --openai-api-base <api_base> [--openai-api-key <key>]
              --yes --no-auto-commits --edit-format diff --message <patch_instruction> <target_file>
        """
        # Resolve model
        resolved_model = model
        if not resolved_model and key_entry is not None:
            resolved_model = getattr(key_entry, "model", None)
        if not resolved_model:
            resolved_model = self.default_model

        # Resolve api_base
        resolved_api_base = api_base
        if not resolved_api_base and key_entry is not None:
            resolved_api_base = getattr(key_entry, "base_url", None)
        if not resolved_api_base:
            resolved_api_base = self.default_api_base

        # Resolve api_key
        resolved_api_key = api_key
        if resolved_api_key is None and key_entry is not None:
            resolved_api_key = getattr(key_entry, "api_key", None)
        if resolved_api_key is None:
            resolved_api_key = os.getenv("OPENAI_API_KEY", "")

        target_str = Path(target_file).as_posix()

        cmd = [
            self.aider_binary,
            "--model",
            resolved_model,
            "--openai-api-base",
            resolved_api_base,
        ]
        if resolved_api_key:
            cmd.extend(["--openai-api-key", resolved_api_key])

        cmd.extend([
            "--yes",
            "--no-auto-commits",
            "--edit-format",
            "diff",
            "--message",
            patch_instruction,
            target_str,
        ])
        return cmd

    def build_environment(
        self,
        key_entry: KeyConfig | None = None,
        api_key: str | None = None,
        api_base: str | None = None,
        base_env: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """
        Construct sanitized subprocess environment retaining safe system variables
        while stripping sensitive host secrets and injecting OpenAI endpoint credentials.
        """
        source = os.environ if base_env is None else base_env
        env: dict[str, str] = {}

        for var in SAFE_SYSTEM_ENV_VARS:
            if var in source:
                env[var] = source[var]

        for denied in DENIED_ENV_VARS:
            env.pop(denied, None)

        for k in list(env.keys()):
            upper_k = k.upper()
            if any(upper_k.startswith(p) for p in DENIED_PREFIXES):
                env.pop(k, None)

        resolved_api_base = api_base
        if not resolved_api_base and key_entry is not None:
            resolved_api_base = getattr(key_entry, "base_url", None)
        if not resolved_api_base:
            resolved_api_base = self.default_api_base

        resolved_api_key = api_key
        if resolved_api_key is None and key_entry is not None:
            resolved_api_key = getattr(key_entry, "api_key", None)
        if resolved_api_key is None:
            resolved_api_key = source.get("OPENAI_API_KEY", "")

        env["OPENAI_API_BASE"] = resolved_api_base
        env["OPENAI_BASE_URL"] = resolved_api_base
        if resolved_api_key:
            env["OPENAI_API_KEY"] = resolved_api_key

        return env

    @staticmethod
    def _sanitize_log_line(line: str) -> str:
        """Strip non-rate-limit syntax patterns (file paths, line numbers, PRs, URLs) before checking."""
        # 1. URLs (including those with port numbers, e.g. http://localhost:429/v1)
        s = re.sub(r"https?://[^\s]+", " ", line)
        # 2. File paths with line/col numbers, e.g. foo.py:429: or utils.py:429:1:
        s = re.sub(r":\d+(?::\d+)?(?=[\s:]|$)", " ", s)
        # 3. Python traceback / compiler line numbers, e.g. 'line 429'
        s = re.sub(r"(?i)\bline\s+\d+\b", " ", s)
        # 4. PR and Issue numbers, e.g. '#429', '#402'
        s = re.sub(r"[#＃]\d+\b", " ", s)
        # 5. Git commit hashes and refs, e.g. 'commit 402a8f...' or hex sequences (min 7 chars)
        s = re.sub(r"(?i)\bcommit\s+[0-9a-fA-F]+\b", " ", s)
        s = re.sub(r"\b[0-9a-fA-F]{7,40}\b", " ", s)
        # 6. Test assertion comparisons, e.g. 'AssertionError: Expected 429 but got 200'
        s = re.sub(r"(?i)\bAssertionError\s*:.*", " ", s)
        s = re.sub(r"(?i)\bExpected\s+\d+\s+but\s+got\s+\d+\b", " ", s)
        # 7. Metrics and duration units, e.g. '429ms', '4290 tokens'
        s = re.sub(r"(?i)\b\d+\s*(?:ms|s|tokens?|records?|characters?)\b", " ", s)
        # 8. Process IDs, User IDs, Ports, e.g. 'PID 4290', 'User ID 429', 'port 5020'
        s = re.sub(r"(?i)\b(?:PID|User ID|User|Port)\s+\d+\b", " ", s)
        return s

    def _is_rate_limit_line(self, line: str) -> tuple[bool, str]:
        """Check if a log line matches any rate limit or quota exhaustion signature."""
        if not line:
            return False, ""
        cleaned = self._sanitize_log_line(line)
        for sig in RATE_LIMIT_SIGNATURES:
            if r"\b" in sig or "\\" in sig or "[" in sig or "(" in sig or "?" in sig:
                if re.search(sig, cleaned, re.IGNORECASE):
                    return True, sig
            elif sig.lower() in cleaned.lower():
                return True, sig
        return False, ""

    def _find_rate_limit_in_text(self, text: str) -> tuple[bool, str]:
        """Scan text buffer line-by-line for rate limit or quota signatures."""
        if not text:
            return False, ""
        for line in text.splitlines():
            hit, sig = self._is_rate_limit_line(line.strip())
            if hit:
                return True, sig
        return False, ""

    def _classify_rate_limit(self, sig: str) -> str:
        """Classify signature into QUOTA_EXHAUSTED_402 or RATE_LIMIT_429."""
        sig_lower = sig.lower()
        if "402" in sig_lower or "insufficient_quota" in sig_lower:
            return "QUOTA_EXHAUSTED_402"
        return "RATE_LIMIT_429"

    def _terminate_process_tree(self, proc: subprocess.Popen) -> None:
        """Cross-platform process tree termination using psutil with OS fallbacks."""
        try:
            import psutil

            parent = psutil.Process(proc.pid)
            children = parent.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                except Exception:
                    pass
            parent.kill()
        except Exception:
            try:
                if sys.platform != "win32":
                    killpg = getattr(os, "killpg", None)
                    getpgid = getattr(os, "getpgid", None)
                    sigkill = getattr(signal, "SIGKILL", 9)
                    if killpg is not None and getpgid is not None:
                        killpg(getpgid(proc.pid), sigkill)
                    else:
                        proc.kill()
                else:
                    try:
                        subprocess.run(
                            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                            check=False,
                            capture_output=True,
                        )
                    except Exception:
                        pass
                    proc.kill()
            except Exception:
                pass

    def _extract_diff_hunks(self, raw_diff: str) -> str:
        """
        Extract only genuine unified diff lines (headers and hunks) from text,
        truncating before any trailing conversational prose or comments.
        """
        if not raw_diff:
            return ""

        lines = raw_diff.splitlines()
        diff_lines: list[str] = []
        in_hunk = False

        for i, line in enumerate(lines):
            # Headers before the first hunk
            if not in_hunk:
                if line.startswith((
                    "diff --git",
                    "index ",
                    "--- ",
                    "+++ ",
                    "new file mode",
                    "deleted file mode",
                    "similarity index",
                    "rename from",
                    "rename to",
                    "old mode",
                    "new mode",
                    "Binary files",
                )):
                    diff_lines.append(line)
                    continue
                elif line.startswith("@@"):
                    in_hunk = True
                    diff_lines.append(line)
                    continue
                else:
                    # Non-diff line before any hunk
                    has_minus = any(dl.startswith("--- ") for dl in diff_lines)
                    has_plus = any(dl.startswith("+++ ") for dl in diff_lines)
                    if has_minus and has_plus:
                        break
                    continue

            # In hunk
            if line.startswith(("@@", "+", "-", " ", "\\")):
                diff_lines.append(line)
            elif line == "":
                # Check if future lines contain more hunk content
                remaining = lines[i + 1:]
                has_future = any(
                    fl.startswith(("@@", "+", "-", " "))
                    for fl in remaining
                    if fl.strip() != ""
                )
                if has_future:
                    diff_lines.append(line)
                else:
                    break
            else:
                # Conversational prose, code fence, or explanation -> stop
                break

        # Trim any trailing empty lines
        while diff_lines and diff_lines[-1] == "":
            diff_lines.pop()

        return "\n".join(diff_lines)

    def extract_diff(
        self,
        repo_path: Path,
        target_file: Path | str,
        raw_output: str = "",
    ) -> str:
        """
        Extract diff of changes made to target_file via git diff HEAD
        or fallback to diff blocks in stdout.
        """
        target_str = Path(target_file).as_posix()
        try:
            # Stage intent-to-add for untracked files
            subprocess.run(
                ["git", "add", "-N", "--", target_str],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=False,
            )
            res = subprocess.run(
                ["git", "diff", "HEAD", "--", target_str],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout

            res_working = subprocess.run(
                ["git", "diff", "--", target_str],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=False,
            )
            if res_working.returncode == 0 and res_working.stdout.strip():
                return res_working.stdout
        except Exception:
            pass

        # Fallback to diff blocks in raw stdout
        if raw_output:
            target_name = Path(target_file).name

            # 1. Search for markdown code blocks (```diff ... ``` or ``` ... ```)
            blocks = re.findall(r"```(?:diff)?\s*\n([\s\S]*?)```", raw_output)
            valid_diff_blocks: list[str] = []
            matching_blocks: list[str] = []

            for block in blocks:
                cleaned = self._extract_diff_hunks(block.strip())
                if cleaned and any(marker in cleaned for marker in ("---", "+++", "@@")):
                    valid_diff_blocks.append(cleaned)
                    if target_name in block or target_str in block:
                        matching_blocks.append(cleaned)

            if matching_blocks:
                return "\n".join(matching_blocks).strip()
            if valid_diff_blocks:
                return valid_diff_blocks[0].strip()

            # 2. Unified diff block without markdown backticks
            diff_match = re.search(r"(?:^|\n)(--- [^\n]+\n\+\+\+ [^\n]+[\s\S]*)", raw_output)
            if diff_match:
                cleaned = self._extract_diff_hunks(diff_match.group(1).strip())
                if cleaned:
                    return cleaned

        return ""


    def run_aider(
        self,
        repo_path: Path,
        target_file: Path | str,
        patch_instruction: str,
        key_entry: KeyConfig | None = None,
        api_key: str | None = None,
        api_base: str | None = None,
        model: str | None = None,
        log_callback: Callable[[str], None] | None = None,
    ) -> AiderResult:
        """
        Execute headless Aider on target_file with patch_instruction.
        Monitors output for rate limits, enforces timeout, terminates process tree,
        and returns structured AiderResult.
        """
        start_time = time.time()
        repo_path = Path(repo_path).resolve()

        # Compute relative target path if target_file is within repo_path
        target_path = Path(target_file)
        if target_path.is_absolute():
            try:
                rel_target = target_path.resolve().relative_to(repo_path)
            except ValueError:
                rel_target = target_path
        else:
            rel_target = target_path
        target_file_str = rel_target.as_posix()

        cmd = self.build_command(
            target_file=target_file_str,
            patch_instruction=patch_instruction,
            key_entry=key_entry,
            api_key=api_key,
            api_base=api_base,
            model=model,
        )
        env = self.build_environment(
            key_entry=key_entry,
            api_key=api_key,
            api_base=api_base,
        )

        if log_callback:
            display_cmd = list(cmd)
            for i, arg in enumerate(display_cmd):
                if arg == "--openai-api-key" and i + 1 < len(display_cmd):
                    k = display_cmd[i + 1]
                    display_cmd[i + 1] = f"{k[:4]}...{k[-4:]}" if len(k) > 8 else "****"
            log_callback(f"[AIDER] Executing: {' '.join(display_cmd)}")

        kwargs: dict[str, Any] = {
            "cwd": repo_path,
            "env": env,
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
            "text": True,
            "bufsize": 1,
        }
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True

        try:
            proc = subprocess.Popen(cmd, **kwargs)
        except FileNotFoundError as exc:
            duration = time.time() - start_time
            err_msg = f"Aider executable '{self.aider_binary}' not found in PATH: {exc}"
            if log_callback:
                log_callback(f"[ERROR] {err_msg}")
            return AiderResult(
                exit_code=-1,
                diff_output="",
                status="NOT_FOUND",
                target_file=target_file_str,
                duration_seconds=duration,
                error_message=err_msg,
                raw_output="",
            )

        rate_limit_hit = False
        rate_limit_sig = ""
        timed_out = False
        output_lines: list[str] = []

        timer = threading.Timer(
            self.timeout_seconds,
            lambda: self._terminate_process_tree(proc),
        )
        timer.daemon = True
        timer.start()

        try:
            if proc.stdout:
                for line in proc.stdout:
                    output_lines.append(line)
                    clean_line = line.strip()
                    if log_callback:
                        log_callback(clean_line)

                    # Watchdog timeout check during stream
                    if (time.time() - start_time) > self.timeout_seconds:
                        timed_out = True
                        self._terminate_process_tree(proc)
                        break

                    # Real-time rate limit / quota detection
                    hit, sig = self._is_rate_limit_line(clean_line)
                    if hit:
                        rate_limit_hit = True
                        rate_limit_sig = sig
                        self._terminate_process_tree(proc)
                        break

            if not timed_out and (time.time() - start_time) > self.timeout_seconds:
                timed_out = True
                self._terminate_process_tree(proc)

            remaining_timeout = max(0.1, self.timeout_seconds - (time.time() - start_time))
            proc.wait(timeout=remaining_timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._terminate_process_tree(proc)
        finally:
            timer.cancel()

        duration = time.time() - start_time
        raw_output = "".join(output_lines)

        # Status resolution
        if timed_out:
            status = "TIMEOUT"
            err_msg = f"Aider execution timed out after {self.timeout_seconds} seconds"
            exit_code = proc.returncode if proc.returncode is not None else -1
            diff_output = ""
        elif rate_limit_hit:
            status = self._classify_rate_limit(rate_limit_sig)
            err_msg = f"Rate limit / quota error detected: {rate_limit_sig}"
            exit_code = proc.returncode if proc.returncode is not None else 1
            diff_output = ""
        else:
            # Check raw_output if returncode non-zero for any missed signatures
            if proc.returncode != 0:
                hit, sig = self._find_rate_limit_in_text(raw_output)
                if hit:
                    status = self._classify_rate_limit(sig)
                    err_msg = f"Rate limit / quota error in output: {sig}"
                    return AiderResult(
                        exit_code=proc.returncode,
                        diff_output="",
                        status=status,
                        target_file=target_file_str,
                        duration_seconds=duration,
                        error_message=err_msg,
                        raw_output=raw_output,
                    )
                status = "FAILED"
                err_msg = f"Aider process failed with return code {proc.returncode}"
                diff_output = ""
                exit_code = proc.returncode
            else:
                status = "SUCCESS"
                err_msg = None
                exit_code = 0
                diff_output = self.extract_diff(repo_path, target_file_str, raw_output)

        return AiderResult(
            exit_code=exit_code,
            diff_output=diff_output,
            status=status,
            target_file=target_file_str,
            duration_seconds=duration,
            error_message=err_msg,
            raw_output=raw_output,
        )
