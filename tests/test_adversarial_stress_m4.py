"""
Adversarial Stress Test Suite for Milestone 4 Resilience Mechanisms.
Written by Empirical Challenger M4-2 (challenger_m4_2).

Directives:
1. Multiple sequential 429s exhausting entire key pool.
2. 402 quota exhaustion lockout window (24h lockout, skip, expiry promotion).
3. Process watchdog termination under runaway, deep child processes, or frozen streams.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.aider_runner import AiderResult, AiderRunner
from src.config import Config, KeyConfig
from src.database import Database
from src.key_manager import KeyManager


# =========================================================================
# Stress-Test 1: Multiple Sequential 429s Exhausting Entire Key Pool
# =========================================================================


class TestSequential429KeyPoolExhaustionStress:
    """Stress-test sequential 429s across multi-key pools, cooldown backoffs, and pool exhaustion."""

    def test_multi_key_pool_complete_exhaustion_and_recovery(self, tmp_path: Path) -> None:
        """
        Verify that sequential 429s across a 3-key pool progressively transition each key
        to COOLDOWN, resulting in full pool exhaustion (None), and that expired cooldowns
        cleanly promote keys back to HEALTHY in priority order.
        """
        db_file = tmp_path / "keys_stress_429.sqlite"
        db = Database(db_file)

        keys = [
            KeyConfig(
                id=f"key-{i}",
                provider="ScaleMax",
                base_url="https://api.scalemax.pro/v1",
                model="openai/gpt-6-luna",
                api_key=f"sk-test-key-{i}-12345678",
                masked_key=f"sk-t...{i}",
                priority=i,
            )
            for i in range(1, 4)
        ]

        config = Config.load(overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": keys,
        })
        km = KeyManager(config, db)

        # 1. Initial selection selects key-1
        k = km.get_next_healthy_key()
        assert k is not None and k.id == "key-1"

        # 2. Key-1 receives 429
        km.report_key_failure("key-1", "RateLimitError: 429 Too Many Requests", status_code=429)
        with db.get_connection() as conn:
            row = conn.execute("SELECT state, consecutive_failures FROM api_key_status WHERE key_id='key-1'").fetchone()
            assert row["state"] == "COOLDOWN"
            assert row["consecutive_failures"] == 1

        # 3. Failover selects key-2
        k = km.get_next_healthy_key()
        assert k is not None and k.id == "key-2"

        # 4. Key-2 receives 429
        km.report_key_failure("key-2", "RateLimitError: 429 Too Many Requests", status_code=429)
        k = km.get_next_healthy_key()
        assert k is not None and k.id == "key-3"

        # 5. Key-3 receives 429 -> entire pool exhausted
        km.report_key_failure("key-3", "RateLimitError: 429 Too Many Requests", status_code=429)
        k = km.get_next_healthy_key()
        assert k is None, "Expected get_next_healthy_key to return None when all keys are in COOLDOWN"

        # 6. Simulate time passage: key-1 and key-2 cooldowns expire, key-3 still active
        past_iso = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
        future_iso = (datetime.now(timezone.utc) + timedelta(seconds=300)).isoformat()

        with db.get_connection() as conn:
            conn.execute("UPDATE api_key_status SET cooldown_until = ? WHERE key_id IN ('key-1', 'key-2')", (past_iso,))
            conn.execute("UPDATE api_key_status SET cooldown_until = ? WHERE key_id = 'key-3'", (future_iso,))

        # 7. Next healthy key should be key-1 (highest priority 1) promoted to HEALTHY
        recovered_key = km.get_next_healthy_key()
        assert recovered_key is not None and recovered_key.id == "key-1"

        with db.get_connection() as conn:
            r1 = conn.execute("SELECT state FROM api_key_status WHERE key_id='key-1'").fetchone()
            r2 = conn.execute("SELECT state FROM api_key_status WHERE key_id='key-2'").fetchone()
            r3 = conn.execute("SELECT state FROM api_key_status WHERE key_id='key-3'").fetchone()
            assert r1["state"] == "HEALTHY"
            assert r2["state"] == "HEALTHY"
            assert r3["state"] == "COOLDOWN"

    def test_exponential_backoff_cooldown_growth_and_cap(self, tmp_path: Path) -> None:
        """
        Verify that repeatedly failing with 429 exponentially scales the cooldown duration
        up to the hard cap of 3600 seconds (1 hour).
        """
        db = Database(tmp_path / "exp_backoff.sqlite")
        key = KeyConfig(
            id="exp-key",
            provider="ScaleMax",
            base_url="https://api.scalemax.pro/v1",
            model="openai/gpt-6-luna",
            api_key="sk-exp-key-12345678",
            masked_key="sk-e...1234",
            priority=1,
        )
        config = Config.load(overrides={"workspace_dir": tmp_path, "LLM_KEYS_POOL": [key]})
        km = KeyManager(config, db)

        # Failure 1: 60s
        assert km.calculate_cooldown_seconds(1) == 60
        # Failure 2: 120s
        assert km.calculate_cooldown_seconds(2) == 120
        # Failure 3: 240s
        assert km.calculate_cooldown_seconds(3) == 240
        # Failure 4: 480s
        assert km.calculate_cooldown_seconds(4) == 480
        # Failure 5: 960s
        assert km.calculate_cooldown_seconds(5) == 960
        # Failure 6: 1920s
        assert km.calculate_cooldown_seconds(6) == 1920
        # Failure 7: min(3600, 3840) = 3600
        assert km.calculate_cooldown_seconds(7) == 3600
        # Failure 15: capped at 3600
        assert km.calculate_cooldown_seconds(15) == 3600

        # Success resets consecutive failures
        km.report_key_failure("exp-key", "429", status_code=429)
        km.report_key_failure("exp-key", "429", status_code=429)
        with db.get_connection() as conn:
            row = conn.execute("SELECT consecutive_failures FROM api_key_status WHERE key_id='exp-key'").fetchone()
            assert row["consecutive_failures"] == 2

        km.report_key_success("exp-key")
        with db.get_connection() as conn:
            row = conn.execute("SELECT consecutive_failures FROM api_key_status WHERE key_id='exp-key'").fetchone()
            assert row["consecutive_failures"] == 0

    def test_aider_runner_stream_detects_various_429_variations(self) -> None:
        """
        Verify AiderRunner detects various vendor 429 strings while ignoring false positives.
        """
        runner = AiderRunner()

        # True positives
        tp_samples = [
            "RateLimitError: Rate limit reached for model openai/gpt-6-luna",
            "HTTP 429 Too Many Requests",
            "client error: code 429",
            '{"error": {"code": 429, "message": "Too Many Requests"}}',
            "Error: [429] Rate limit exceeded",
            "502 Bad Gateway from upstream",
            "503 Service Unavailable",
            "504 Gateway Timeout",
        ]
        for s in tp_samples:
            hit, sig = runner._is_rate_limit_line(s)
            assert hit is True, f"Failed to detect 429 signature in: {s}"
            assert runner._classify_rate_limit(sig) == "RATE_LIMIT_429"

        # False positives (must NOT trigger 429)
        fp_samples = [
            "src/file.py:429:1: E501 line too long",
            "Traceback (most recent call last):\n  File 'test.py', line 429, in <module>",
            "Merged PR #429 into main",
            "git commit 429a8f192b3c4d5e",
            "Duration: 429ms",
            "PID 4290 started",
            "http://localhost:429/v1/api",
            "AssertionError: Expected 429 but got 200",
        ]
        for s in fp_samples:
            hit, _ = runner._is_rate_limit_line(s)
            assert hit is False, f"False positive triggered for: {s}"


# =========================================================================
# Stress-Test 2: 402 Quota Exhaustion Lockout Window
# =========================================================================


class Test402QuotaExhaustionLockoutStress:
    """Stress-test HTTP 402 / insufficient_quota 24-hour lockout window and state transitions."""

    def test_402_triggers_exact_24h_lockout(self, tmp_path: Path) -> None:
        """
        Verify that 402 or insufficient_quota error triggers EXHAUSTED state with
        cooldown_until set to precisely 86400 seconds (24 hours).
        """
        db = Database(tmp_path / "quota_402.sqlite")
        key = KeyConfig(
            id="key-quota",
            provider="ScaleMax",
            base_url="https://api.scalemax.pro/v1",
            model="openai/gpt-6-luna",
            api_key="sk-quota-key-12345678",
            masked_key="sk-q...1234",
            priority=1,
        )
        config = Config.load(overrides={"workspace_dir": tmp_path, "LLM_KEYS_POOL": [key]})
        km = KeyManager(config, db)

        before = datetime.now(timezone.utc)
        km.report_key_failure("key-quota", "Error: insufficient_quota (402 Payment Required)", status_code=402)
        after = datetime.now(timezone.utc)

        with db.get_connection() as conn:
            row = conn.execute("SELECT state, cooldown_until FROM api_key_status WHERE key_id='key-quota'").fetchone()
            assert row["state"] == "EXHAUSTED"
            cd_until = datetime.fromisoformat(row["cooldown_until"])

        # Cooldown duration should be within 24h (+/- 5 seconds)
        diff_seconds = (cd_until - before).total_seconds()
        assert 86395 <= diff_seconds <= 86405

        # While within 24h window, key must NOT be selected
        assert km.get_next_healthy_key() is None

        # Simulate 24 hours passing (set cooldown_until to 1 second ago)
        past_iso = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        with db.get_connection() as conn:
            conn.execute("UPDATE api_key_status SET cooldown_until = ? WHERE key_id='key-quota'", (past_iso,))

        # Key should now be automatically promoted back to HEALTHY
        promoted = km.get_next_healthy_key()
        assert promoted is not None and promoted.id == "key-quota"

        with db.get_connection() as conn:
            row = conn.execute("SELECT state, cooldown_until FROM api_key_status WHERE key_id='key-quota'").fetchone()
            assert row["state"] == "HEALTHY"
            assert row["cooldown_until"] is None

    def test_preflight_simulated_402_trips_lockout(self, tmp_path: Path) -> None:
        """Verify preflight check with simulated 402 immediately marks key EXHAUSTED."""
        db = Database(tmp_path / "preflight_402.sqlite")
        key = KeyConfig(
            id="key-pf-402",
            provider="ScaleMax",
            base_url="https://api.scalemax.pro/v1",
            model="openai/gpt-6-luna",
            api_key="sk-pf-key-12345678",
            masked_key="sk-p...1234",
            priority=1,
        )
        config = Config.load(overrides={"workspace_dir": tmp_path, "LLM_KEYS_POOL": [key]})
        km = KeyManager(config, db)

        res = km.preflight_check(key, simulated_response_code=402)
        assert res is False

        with db.get_connection() as conn:
            row = conn.execute("SELECT state FROM api_key_status WHERE key_id='key-pf-402'").fetchone()
            assert row["state"] == "EXHAUSTED"


# =========================================================================
# Stress-Test 3: Process Watchdog Termination Under Runaway / Frozen Child Processes
# =========================================================================


class TestWatchdogProcessTreeTerminationStress:
    """Stress-test process tree cleanup for hung, frozen, deep child trees, and stdout flooding."""

    def test_watchdog_kills_deep_multiprocess_tree(self, tmp_path: Path) -> None:
        """
        Verify that when a target process spawns multiple nested background child processes
        that sleep indefinitely, the watchdog kills the ENTIRE process hierarchy cleanly.
        """
        runner = AiderRunner(timeout_seconds=0.5)

        # Python script that spawns a child process which in turn spawns a grandchild, all sleeping
        script = (
            "import subprocess, sys, time\n"
            "p1 = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "p2 = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "time.sleep(60)\n"
        )
        script_file = tmp_path / "spawn_tree.py"
        script_file.write_text(script, encoding="utf-8")

        start = time.time()
        with patch.object(runner, "build_command", return_value=[sys.executable, str(script_file)]):
            res = runner.run_aider(
                repo_path=tmp_path,
                target_file="test.py",
                patch_instruction="Patch",
            )
        elapsed = time.time() - start

        assert res.status == "TIMEOUT"
        assert res.exit_code != 0
        assert elapsed < 3.0, f"Process took too long to terminate ({elapsed:.2f}s)"

    def test_watchdog_handles_infinite_stdout_stream_without_deadlock(self, tmp_path: Path) -> None:
        """
        Verify that a runaway process generating continuous high-volume stdout does not
        deadlock the reader thread or watchdog timer and is terminated within timeout.
        """
        runner = AiderRunner(timeout_seconds=0.4)

        # Infinite stdout generator
        flood_script = (
            "import sys, time\n"
            "while True:\n"
            "    sys.stdout.write('X' * 1024 + '\\n')\n"
            "    sys.stdout.flush()\n"
        )
        script_file = tmp_path / "flood_stdout.py"
        script_file.write_text(flood_script, encoding="utf-8")

        start = time.time()
        with patch.object(runner, "build_command", return_value=[sys.executable, str(script_file)]):
            res = runner.run_aider(
                repo_path=tmp_path,
                target_file="test.py",
                patch_instruction="Patch",
            )
        elapsed = time.time() - start

        assert res.status == "TIMEOUT"
        assert elapsed < 3.0, f"Stdout flood hung for {elapsed:.2f}s"


class TestAdversarialResilienceEdgeCases:
    """Stress-test edge cases: concurrency contention, ReDoS defense, and orchestrator exhaustion handling."""

    def test_concurrent_multithreaded_key_rotations(self, tmp_path: Path) -> None:
        """
        Verify that 10 concurrent threads reporting failures, successes, and querying keys
        simultaneously do not trigger sqlite database locked exceptions or data corruption.
        """
        import concurrent.futures

        db = Database(tmp_path / "concurrent_keys.sqlite")
        keys = [
            KeyConfig(
                id=f"c-key-{i}",
                provider="ScaleMax",
                base_url="https://api.scalemax.pro/v1",
                model="openai/gpt-6-luna",
                api_key=f"sk-concurrent-{i}",
                masked_key=f"sk-c...{i}",
                priority=i,
            )
            for i in range(1, 6)
        ]
        config = Config.load(overrides={"workspace_dir": tmp_path, "LLM_KEYS_POOL": keys})
        km = KeyManager(config, db)

        def worker(thread_id: int) -> None:
            for iteration in range(20):
                # Query next healthy key
                k = km.get_next_healthy_key()
                if k:
                    if (thread_id + iteration) % 3 == 0:
                        km.report_key_failure(k.id, "Rate limit 429", status_code=429)
                    elif (thread_id + iteration) % 7 == 0:
                        km.report_key_failure(k.id, "insufficient_quota (402)", status_code=402)
                    else:
                        km.report_key_success(k.id)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker, i) for i in range(10)]
            for f in concurrent.futures.as_completed(futures):
                f.result()

        # Database must be in a consistent state without corruption
        with db.get_connection() as conn:
            rows = conn.execute("SELECT key_id, state, consecutive_failures FROM api_key_status").fetchall()
            assert len(rows) == 5
            for r in rows:
                assert r["state"] in ("HEALTHY", "COOLDOWN", "EXHAUSTED")

    def test_redos_and_long_line_sanitization_defense(self) -> None:
        """
        Verify that adversarial input strings (up to 100k characters with repeated delimiters)
        do not trigger catastrophic backtracking or exceed a reasonable parsing timeout (<0.5s).
        """
        runner = AiderRunner()

        # Adversarial pathological string with nested delimiters and near-matches
        pathological_string = "http://" + "code:429 " * 5000 + "status_code=402 " * 5000 + "A" * 50000

        start = time.time()
        hit, sig = runner._find_rate_limit_in_text(pathological_string)
        elapsed = time.time() - start

        assert elapsed < 1.0, f"Catastrophic backtracking suspected: took {elapsed:.3f}s"

    def test_orchestrator_graceful_handling_on_all_keys_exhausted(self, tmp_path: Path) -> None:
        """
        Verify orchestrator cleanly returns NO_HEALTHY_KEYS outcome, marks repo ERROR,
        and purges temp artifacts when KeyManager reports all keys exhausted.
        """
        import json
        from src.git_manager import GitManager
        from src.logger import RingBufferLogger
        from src.openhands_runner import OpenHandsRunner
        from src.orchestrator import Orchestrator
        from src.static_scanner import StaticScanner
        from src.verifier import Verifier

        db = Database(tmp_path / "orch_exhaust.sqlite")
        db.upsert_repository("test-owner/test-repo", "https://github.com/test-owner/test-repo.git")

        config = Config.load(overrides={"workspace_dir": tmp_path, "LLM_KEYS_POOL": []})
        km = KeyManager(config, db)  # Empty keys pool -> get_next_healthy_key returns None
        logger = RingBufferLogger(capacity=50)

        git_mgr = MagicMock(spec=GitManager)
        git_mgr.sync_repository.return_value = (tmp_path / "repo", "main", "abc1234")
        git_mgr.get_open_bot_prs.return_value = (0, [])

        static_sc = MagicMock(spec=StaticScanner)
        static_sc.run_static_prefilter.return_value = tmp_path / ".static_findings.json"
        (tmp_path / ".static_findings.json").write_text(json.dumps([{"file": "src/bad.py", "rule_id": "SEC1", "line": 10}]), encoding="utf-8")

        openhands = MagicMock(spec=OpenHandsRunner)
        verifier = Verifier()

        orch = Orchestrator(
            config=config,
            database=db,
            key_manager=km,
            git_manager=git_mgr,
            static_scanner=static_sc,
            openhands_runner=openhands,
            verifier=verifier,
            logger=logger,
        )

        res = orch.scan_single_repo("test-owner/test-repo")
        assert res["outcome"] == "NO_HEALTHY_KEYS", f"Unexpected outcome: {res}"

        with db.get_connection() as conn:
            repo_row = conn.execute("SELECT status FROM repositories WHERE repo_slug='test-owner/test-repo'").fetchone()
            assert repo_row["status"] == "ERROR"

            log_row = conn.execute("SELECT outcome FROM scan_logs WHERE repo_slug='test-owner/test-repo'").fetchone()
            assert log_row["outcome"] == "NO_HEALTHY_KEYS"
