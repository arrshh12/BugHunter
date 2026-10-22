"""
Headless OpenHands CLI Runner for AutoBugHunter 24/7: Process isolation, live streaming, and rate limit detection.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from src.config import KeyConfig


@dataclass
class SessionResult:
    success: bool
    bug_found: bool
    error_type: Optional[str] = None
    report_path: Optional[Path] = None
    duration_seconds: float = 0.0
    report_data: Optional[dict[str, Any]] = None


class OpenHandsRunner:
    """Headless OpenHands execution harness with rate-limit and timeout detection."""

    RATE_LIMIT_SIGNATURES = [
        "429",
        "RateLimitError",
        "insufficient_quota",
        "402 Payment Required",
        "502 Bad Gateway",
        "503 Service Unavailable",
        "504 Gateway Timeout",
    ]

    def __init__(self, timeout_seconds: int = 1200, runtime: Optional[str] = None):
        self.timeout_seconds = timeout_seconds
        self.runtime = runtime or os.getenv("OPENHANDS_RUNTIME", "docker" if shutil.which("docker") else "process")

    def _terminate_process_tree(self, proc: subprocess.Popen) -> None:
        """Cross-platform process tree termination using psutil."""
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
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                else:
                    proc.kill()
            except Exception:
                pass

    SAFE_SYSTEM_ENV_VARS = {
        "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC",
        "TEMP", "TMP", "TMPDIR",
        "HOME", "USERPROFILE", "HOMEPATH", "HOMEDRIVE",
        "LANG", "LC_ALL", "LC_CTYPE", "TERM",
        "VIRTUAL_ENV", "PYTHONPATH", "PYTHONHOME",
    }
    DENIED_ENV_VARS = {
        "GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PAT", "DASHBOARD_API_KEY",
    }

    def _build_subprocess_env(self, repo_path: Path, key_entry: KeyConfig) -> dict[str, str]:
        """Construct sanitized environment for OpenHands subprocess omitting host secrets."""
        env: dict[str, str] = {}
        for var in self.SAFE_SYSTEM_ENV_VARS:
            if var in os.environ:
                env[var] = os.environ[var]

        for denied in self.DENIED_ENV_VARS:
            env.pop(denied, None)

        for k in list(env.keys()):
            upper_k = k.upper()
            if any(upper_k.startswith(p) for p in ("GITHUB_", "GH_", "DASHBOARD_", "AWS_", "AZURE_", "OCI_", "GCP_")):
                env.pop(k, None)

        env["LLM_BASE_URL"] = key_entry.base_url
        env["LLM_MODEL"] = key_entry.model
        env["LLM_API_KEY"] = key_entry.api_key
        env["RUNTIME"] = self.runtime
        env["WORKSPACE_BASE"] = str(repo_path)
        return env

    def run_openhands_session(
        self,
        repo_path: Path,
        key_entry: KeyConfig,
        task_prompt_path: Path,
        log_callback: Callable[[str], None],
        simulated_outcome: Optional[str] = None,
    ) -> SessionResult:
        """Launch headless OpenHands CLI session, stream logs, detect rate limits, and parse report."""
        start_time = time.time()
        log_callback(f"[OPENHANDS] Initiating session on {repo_path.name} using key {key_entry.masked_key}")

        # Simulated outcome mode for testing
        if simulated_outcome is not None:
            if simulated_outcome == "RATE_LIMIT_429":
                log_callback("[ERROR] HTTP 429: RateLimitError: Requests rate limit exceeded")
                return SessionResult(
                    success=False,
                    bug_found=False,
                    error_type="RATE_LIMIT_429",
                    duration_seconds=time.time() - start_time
                )
            elif simulated_outcome == "QUOTA_EXHAUSTED_402":
                log_callback("[ERROR] HTTP 402: insufficient_quota: credit balance is zero")
                return SessionResult(
                    success=False,
                    bug_found=False,
                    error_type="QUOTA_EXHAUSTED_402",
                    duration_seconds=time.time() - start_time
                )
            elif simulated_outcome == "TIMEOUT":
                log_callback(f"[ERROR] Process group timed out after {self.timeout_seconds}s")
                return SessionResult(
                    success=False,
                    bug_found=False,
                    error_type="TIMEOUT",
                    duration_seconds=time.time() - start_time
                )
            elif simulated_outcome == "CLEAN_NO_BUG":
                report = {
                    "bug_found": False,
                    "bug_summary": "Full repository audit completed. Zero bugs identified.",
                    "file_modified": "",
                    "pr_title": "",
                    "pr_body": "",
                    "test_command_run": "pytest",
                    "tests_passed": True
                }
                report_file = repo_path / ".bug_fix_report.json"
                report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
                return SessionResult(
                    success=True,
                    bug_found=False,
                    report_path=report_file,
                    duration_seconds=time.time() - start_time,
                    report_data=report
                )
            else:  # SUCCESS
                report = {
                    "bug_found": True,
                    "bug_summary": "Fixed NullPointerException on user auth payload",
                    "file_modified": "src/auth.py",
                    "pr_title": "fix: resolve null check on user auth payload",
                    "pr_body": "## Description\nFixed NoneType dereference.",
                    "test_command_run": "pytest tests/test_auth.py",
                    "tests_passed": True
                }
                report_file = repo_path / ".bug_fix_report.json"
                report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
                return SessionResult(
                    success=True,
                    bug_found=True,
                    report_path=report_file,
                    duration_seconds=time.time() - start_time,
                    report_data=report
                )

        # Real execution mode
        env = self._build_subprocess_env(repo_path, key_entry)

        cmd = [
            "openhands",
            "--headless",
            "--override-with-envs",
            "-f", str(task_prompt_path)
        ]

        kwargs: dict[str, Any] = {
            "cwd": repo_path,
            "env": env,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
            "text": True,
            "bufsize": 1,
        }

        if sys.platform != "win32":
            kwargs["start_new_session"] = True
        else:
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        try:
            proc = subprocess.Popen(cmd, **kwargs)
        except FileNotFoundError:
            # openhands executable not installed in environment
            log_callback("[WARN] openhands executable not found in PATH")
            return SessionResult(
                success=False,
                bug_found=False,
                error_type="OPENHANDS_NOT_FOUND",
                duration_seconds=time.time() - start_time
            )

        rate_limit_hit = False
        rate_limit_reason = ""
        timed_out = False

        timer = threading.Timer(self.timeout_seconds, lambda: self._terminate_process_tree(proc))
        timer.daemon = True
        timer.start()

        try:
            if proc.stdout:
                for line in proc.stdout:
                    clean_line = line.strip()
                    log_callback(clean_line)

                    # Check elapsed time against timeout_seconds
                    if (time.time() - start_time) > self.timeout_seconds:
                        timed_out = True
                        self._terminate_process_tree(proc)
                        break

                    # Scan for rate-limit signatures
                    for sig in self.RATE_LIMIT_SIGNATURES:
                        if sig.lower() in clean_line.lower():
                            rate_limit_hit = True
                            rate_limit_reason = sig
                            break

                    if rate_limit_hit:
                        self._terminate_process_tree(proc)
                        break

            if timed_out or (time.time() - start_time) > self.timeout_seconds:
                log_callback(f"[ERROR] OpenHands session timed out after {self.timeout_seconds}s")
                return SessionResult(
                    success=False,
                    bug_found=False,
                    error_type="TIMEOUT",
                    duration_seconds=time.time() - start_time
                )

            remaining_timeout = max(0.1, self.timeout_seconds - (time.time() - start_time))
            proc.wait(timeout=remaining_timeout)
        except subprocess.TimeoutExpired:
            self._terminate_process_tree(proc)
            log_callback(f"[ERROR] OpenHands session timed out after {self.timeout_seconds}s")
            return SessionResult(
                success=False,
                bug_found=False,
                error_type="TIMEOUT",
                duration_seconds=time.time() - start_time
            )
        finally:
            timer.cancel()

        duration = time.time() - start_time

        if rate_limit_hit:
            err_type = "QUOTA_EXHAUSTED_402" if ("402" in rate_limit_reason or "insufficient_quota" in rate_limit_reason) else "RATE_LIMIT_429"
            return SessionResult(
                success=False,
                bug_found=False,
                error_type=err_type,
                duration_seconds=duration
            )

        report_file = repo_path / ".bug_fix_report.json"
        if report_file.exists():
            try:
                data = json.loads(report_file.read_text(encoding="utf-8"))
                return SessionResult(
                    success=True,
                    bug_found=data.get("bug_found", False),
                    report_path=report_file,
                    duration_seconds=duration,
                    report_data=data
                )
            except Exception:
                pass

        return SessionResult(
            success=(proc.returncode == 0),
            bug_found=False,
            duration_seconds=duration
        )
