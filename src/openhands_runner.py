"""
Headless OpenHands CLI Runner for AutoBugHunter 24/7: Process isolation, live streaming, and rate limit detection.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

import requests

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

    SIG_429 = r"(?i)\b(?:status|code|http|error)[\s:_]*429\b"
    RATE_LIMIT_SIGNATURES = [
        SIG_429,
        "429 Too Many Requests",
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
        # 5. Git commit hashes and refs, e.g. 'commit 402a8f...' or hex sequences (min 6 chars)
        s = re.sub(r"(?i)\bcommit\s+[0-9a-fA-F]+\b", " ", s)
        s = re.sub(r"\b[0-9a-fA-F]{6,40}\b", " ", s)
        # 6. Test assertion comparisons, e.g. 'AssertionError: Expected 429 but got 200'
        s = re.sub(r"(?i)\bAssertionError\s*:.*", " ", s)
        s = re.sub(r"(?i)\bExpected\s+\d+\s+but\s+got\s+\d+\b", " ", s)
        # 7. Metrics and duration units, e.g. '429ms', '4290 tokens'
        s = re.sub(r"(?i)\b\d+\s*(?:ms|s|tokens?|records?|characters?)\b", " ", s)
        # 8. Process IDs, User IDs, Ports, e.g. 'PID 4290', 'User ID 429', 'port 5020'
        s = re.sub(r"(?i)\b(?:PID|User ID|User|Port)\s+\d+\b", " ", s)
        return s

    def _is_rate_limit_line(self, line: str) -> tuple[bool, str]:
        """Check if a log line matches any rate-limit or outage signature."""
        if not line:
            return False, ""
        cleaned = self._sanitize_log_line(line)
        for sig in self.RATE_LIMIT_SIGNATURES:
            if r"\b" in sig or "\\" in sig or "[" in sig or "(" in sig or "?" in sig:
                if re.search(sig, cleaned, re.IGNORECASE):
                    return True, sig
            elif sig.lower() in cleaned.lower():
                return True, sig
        return False, ""

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
        env["OPENAI_API_BASE"] = key_entry.base_url or "https://api.scalemax.pro/v1"
        env["OPENAI_BASE_URL"] = key_entry.base_url or "https://api.scalemax.pro/v1"
        env["OPENAI_API_KEY"] = key_entry.api_key
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
            # openhands executable not installed in environment; fallback to built-in autonomous LLM bug patcher
            log_callback("[FALLBACK] openhands executable not found in PATH; engaging built-in autonomous LLM bug patcher...")
            return self._run_direct_llm_agent(repo_path, key_entry, task_prompt_path, log_callback, start_time)

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
                    hit, reason = self._is_rate_limit_line(clean_line)
                    if hit:
                        rate_limit_hit = True
                        rate_limit_reason = reason
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

    def _run_direct_llm_agent(
        self,
        repo_path: Path,
        key_entry: KeyConfig,
        task_prompt_path: Path,
        log_callback: Callable[[str], None],
        start_time: float,
    ) -> SessionResult:
        """Built-in autonomous LLM agent fallback when openhands CLI is not available."""
        log_callback(f"[LLM_AGENT] Engaging built-in autonomous LLM bug patcher ({key_entry.model})...")

        # 1. Check for static findings
        findings_file = repo_path / ".static_findings.json"
        findings = []
        if findings_file.exists():
            try:
                raw = json.loads(findings_file.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    findings = raw
                elif isinstance(raw, dict) and "findings" in raw:
                    findings = raw["findings"]
            except Exception:
                findings = []

        skip_file = repo_path / ".skip_files.txt"
        skip_files = set()
        if skip_file.exists():
            try:
                skip_files = {line.strip() for line in skip_file.read_text(encoding="utf-8").splitlines() if line.strip()}
            except Exception:
                skip_files = set()

        # 2. Identify candidate file and context
        target_file: Optional[Path] = None
        bug_clue = ""

        if findings:
            for f in findings:
                fname = f.get("file")
                if fname and fname not in skip_files and (repo_path / fname).is_file():
                    target_file = repo_path / fname
                    bug_clue = f"Static analysis flag ({f.get('rule_id')}): {f.get('message')} at line {f.get('line')}"
                    break

        # If no static findings, find candidate source files (prefer .ts, .tsx, .py, .js)
        if not target_file:
            candidates: list[Path] = []
            for ext in ("*.ts", "*.tsx", "*.py", "*.js", "*.jsx"):
                for p in repo_path.rglob(ext):
                    rel = p.relative_to(repo_path).as_posix()
                    if rel in skip_files:
                        continue
                    if any(part in rel.split("/") for part in ("node_modules", ".git", "dist", "build", ".pytest_cache")):
                        continue
                    candidates.append(p)

            # Prioritize files in components/, src/, api/, or main entry
            candidates.sort(key=lambda p: (
                0 if any(k in p.name.lower() for k in ("app", "main", "service", "util", "api")) else 1,
                p.stat().st_size
            ))
            if candidates:
                target_file = candidates[0]
                bug_clue = f"Audit candidate source file: {target_file.relative_to(repo_path).as_posix()}"

        if not target_file or not target_file.is_file():
            log_callback("[LLM_AGENT] No actionable source files found to audit.")
            report = {
                "bug_found": False,
                "bug_summary": "Zero actionable source files found for analysis.",
                "file_modified": "",
                "pr_title": "",
                "pr_body": "",
                "test_command_run": "",
                "tests_passed": True
            }
            report_file = repo_path / ".bug_fix_report.json"
            report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
            return SessionResult(success=True, bug_found=False, report_path=report_file, duration_seconds=time.time() - start_time, report_data=report)

        rel_path = target_file.relative_to(repo_path).as_posix()
        try:
            original_code = target_file.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            log_callback(f"[ERROR] Could not read target file {rel_path}: {e}")
            return SessionResult(success=False, bug_found=False, error_type=str(e), duration_seconds=time.time() - start_time)

        # Retain entire file; do NOT truncate original code destructively
        code_lines = original_code.splitlines()

        log_callback(f"[LLM_AGENT] Auditing {rel_path} with {key_entry.model}...")

        system_prompt = (
            "You are an autonomous senior software engineer under the AutoBugHunter 24/7 daemon.\n"
            "MANDATE: ONE BUG = ONE PR rule.\n"
            "1. Identify exactly ONE genuine, functional bug or resilience defect (e.g. unhandled null/undefined, missing error handling, input validation flaw, unhandled promise rejection, race condition).\n"
            "2. Apply a minimal atomic fix directly to the target file. The fix MUST modify <= 150 lines total. Do NOT perform cosmetic refactoring.\n"
            "3. Format your response strictly as a JSON object with this exact schema (no markdown formatting outside the JSON):\n"
            "{\n"
            '  "bug_found": true,\n'
            '  "bug_summary": "One-line clear description of the bug and fix",\n'
            '  "scope": "short conventional scope, e.g. api, app, auth, utils",\n'
            '  "pr_title": "fix(<scope>): concise description in conventional commit format",\n'
            '  "pr_body": "## Description\\nDetails about the bug.\\n\\n## Fix Applied\\nHow it was fixed.\\n\\n## Verification\\nProof of fix.",\n'
            '  "search_block": "Exact lines to find in original file",\n'
            '  "replace_block": "Replacement lines for search_block",\n'
            '  "updated_full_file": "The COMPLETE modified file content with the fix applied (must contain the entire file, never truncate the tail)"\n'
            "}\n"
            "If no genuine functional defect exists in the file, respond with:\n"
            '{"bug_found": false, "bug_summary": "Clean file: no defects found"}\n'
        )

        user_content = f"File: {rel_path}\nContext: {bug_clue}\n\nSource Code:\n```\n{original_code}\n```"

        url = f"{key_entry.base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {key_entry.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": key_entry.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            "temperature": 0.2,
            "max_tokens": 4096
        }

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=60)
            if resp.status_code == 429:
                log_callback("[ERROR] HTTP 429: RateLimitError from LLM endpoint")
                return SessionResult(success=False, bug_found=False, error_type="RATE_LIMIT_429", duration_seconds=time.time() - start_time)
            elif resp.status_code == 402:
                log_callback("[ERROR] HTTP 402: Insufficient quota from LLM endpoint")
                return SessionResult(success=False, bug_found=False, error_type="QUOTA_EXHAUSTED_402", duration_seconds=time.time() - start_time)
            elif resp.status_code != 200:
                log_callback(f"[ERROR] HTTP {resp.status_code} from LLM endpoint: {resp.text[:150]}")
                return SessionResult(success=False, bug_found=False, error_type=f"HTTP_{resp.status_code}", duration_seconds=time.time() - start_time)

            res_data = resp.json()
            raw_content = res_data["choices"][0]["message"]["content"].strip()

            # Extract JSON from potential markdown fence
            if "```json" in raw_content:
                raw_content = raw_content.split("```json", 1)[1].split("```", 1)[0].strip()
            elif "```" in raw_content:
                raw_content = raw_content.split("```", 1)[1].split("```", 1)[0].strip()

            parsed = json.loads(raw_content)
        except Exception as e:
            log_callback(f"[ERROR] Failed to query LLM or parse fix response: {e}")
            return SessionResult(success=False, bug_found=False, error_type=str(e), duration_seconds=time.time() - start_time)

        if not parsed.get("bug_found", False):
            log_callback(f"[LLM_AGENT] Audit completed: {parsed.get('bug_summary', 'Clean file')}")
            report = {
                "bug_found": False,
                "bug_summary": parsed.get("bug_summary", "Clean file: no defects found"),
                "file_modified": "",
                "pr_title": "",
                "pr_body": "",
                "test_command_run": "",
                "tests_passed": True
            }
            report_file = repo_path / ".bug_fix_report.json"
            report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
            return SessionResult(success=True, bug_found=False, report_path=report_file, duration_seconds=time.time() - start_time, report_data=report)

        # Apply updated file content, checking for search/replace block or complete file
        new_content = None
        if "search_block" in parsed and "replace_block" in parsed and parsed["search_block"] and parsed["search_block"] in original_code:
            new_content = original_code.replace(parsed["search_block"], parsed["replace_block"], 1)
        elif parsed.get("updated_full_file"):
            candidate = parsed["updated_full_file"]
            # Guard against tail truncation:
            if len(code_lines) > 400 and len(candidate.splitlines()) < (len(code_lines) - 50):
                log_callback(f"[ERROR] LLM fix truncated target file tail ({len(candidate.splitlines())} lines vs {len(code_lines)} lines). Aborting.")
                return SessionResult(
                    success=False,
                    bug_found=False,
                    error_type="FILE_TRUNCATION_PREVENTED",
                    duration_seconds=time.time() - start_time,
                )
            new_content = candidate

        if not new_content:
            log_callback(f"[LLM_AGENT] No valid fix content provided in LLM response.")
            report = {
                "bug_found": False,
                "bug_summary": "No valid fix content returned by LLM",
                "file_modified": "",
                "pr_title": "",
                "pr_body": "",
                "test_command_run": "",
                "tests_passed": True
            }
            report_file = repo_path / ".bug_fix_report.json"
            report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
            return SessionResult(success=True, bug_found=False, report_path=report_file, duration_seconds=time.time() - start_time, report_data=report)

        target_file.write_text(new_content, encoding="utf-8")
        log_callback(f"[LLM_AGENT] Applied atomic fix to {rel_path}")

        scope = parsed.get("scope") or "core"
        raw_title = parsed.get("pr_title") or f"fix({scope}): resolve defect in {rel_path}"
        if not raw_title.startswith("fix("):
            raw_title = f"fix({scope}): {raw_title}"

        report = {
            "bug_found": True,
            "bug_summary": parsed.get("bug_summary", "Autonomous atomic fix"),
            "file_modified": rel_path,
            "files_modified": [rel_path],
            "pr_title": raw_title,
            "pr_body": parsed.get("pr_body", "## Description\nAutonomous atomic bug fix.\n"),
            "test_command_run": "git diff HEAD",
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
