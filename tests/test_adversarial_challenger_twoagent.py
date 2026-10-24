"""
Empirical Adversarial Challenge Test Suite for Two-Agent Architecture.
Authored by Challenger Two-Agent 2.

Mandated Challenge Areas:
1. Adversarial Zero Static Scanning Verification (strict assertion traps on all static analysis entry points).
2. Concurrency & Thread-Safety Stress (50 concurrent threads on mark_bug_done and logs.md with Barrier synchronization).
3. Diff Bounds & Budget Enforcement (exact 151 lines vs 150 lines, 4 files vs 3 files, rollback & cleanup verification).
4. Rate Limit Circuit Breaker (429 RateLimit and 402 QuotaExhausted handling with backlog preservation).
"""

from __future__ import annotations

import contextlib
import re
import subprocess
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.aider_runner import AiderResult, AiderRunner
from src.bughunter_agent import TriageSkill
from src.config import Config, KeyConfig
from src.database import Database
from src.fixer_agent import MainFixerAgent
from src.git_manager import GitManager
from src.key_manager import KeyManager
from src.logger import RingBufferLogger
from src.openhands_runner import OpenHandsRunner
from src.orchestrator import Orchestrator
from src.static_scanner import StaticScanner
from src.verifier import Verifier

# =========================================================================
# Adversarial Context Trap Helpers
# =========================================================================

STATIC_ANALYZER_NAMES = {"ruff", "semgrep", "flake8", "bandit", "eslint", "trivy"}


@contextlib.contextmanager
def assert_zero_static_scanning_traps():
    """Wrap all static analysis entry points in strict assertion traps that raise AssertionError

    immediately if invoked.
    """
    orig_subprocess_run = subprocess.run
    orig_subprocess_popen = subprocess.Popen

    def trapped_prefilter(*args, **kwargs):
        raise AssertionError(
            "VIOLATION: StaticScanner.run_static_prefilter was invoked during fixer execution!"
        )

    def trapped_parse_flake8(*args, **kwargs):
        raise AssertionError("VIOLATION: TriageSkill.parse_flake8 was invoked during fixer execution!")

    def trapped_parse_eslint(*args, **kwargs):
        raise AssertionError("VIOLATION: TriageSkill.parse_eslint was invoked during fixer execution!")

    def trapped_parse_bandit(*args, **kwargs):
        raise AssertionError("VIOLATION: TriageSkill.parse_bandit was invoked during fixer execution!")

    def trapped_parse_semgrep(*args, **kwargs):
        raise AssertionError("VIOLATION: TriageSkill.parse_semgrep was invoked during fixer execution!")

    def trapped_parse_trivy(*args, **kwargs):
        raise AssertionError("VIOLATION: TriageSkill.parse_trivy was invoked during fixer execution!")

    def trapped_subprocess_run(cmd, *args, **kwargs):
        cmd_str = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
        for tool in STATIC_ANALYZER_NAMES:
            if re.search(rf"\b{tool}\b", cmd_str, re.IGNORECASE):
                raise AssertionError(
                    f"VIOLATION: subprocess.run invoked static analyzer '{tool}': {cmd_str}"
                )
        return orig_subprocess_run(cmd, *args, **kwargs)

    def trapped_subprocess_popen(cmd, *args, **kwargs):
        cmd_str = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
        for tool in STATIC_ANALYZER_NAMES:
            if re.search(rf"\b{tool}\b", cmd_str, re.IGNORECASE):
                raise AssertionError(
                    f"VIOLATION: subprocess.Popen invoked static analyzer '{tool}': {cmd_str}"
                )
        return orig_subprocess_popen(cmd, *args, **kwargs)

    with patch("src.static_scanner.StaticScanner.run_static_prefilter", side_effect=trapped_prefilter), \
         patch("src.bughunter_agent.TriageSkill.parse_flake8", side_effect=trapped_parse_flake8), \
         patch("src.bughunter_agent.TriageSkill.parse_eslint", side_effect=trapped_parse_eslint), \
         patch("src.bughunter_agent.TriageSkill.parse_bandit", side_effect=trapped_parse_bandit), \
         patch("src.bughunter_agent.TriageSkill.parse_semgrep", side_effect=trapped_parse_semgrep), \
         patch("src.bughunter_agent.TriageSkill.parse_trivy", side_effect=trapped_parse_trivy), \
         patch("subprocess.run", side_effect=trapped_subprocess_run), \
         patch("subprocess.Popen", side_effect=trapped_subprocess_popen):
        yield


# =========================================================================
# 1. Challenge 1: Adversarial Zero Static Scanning Invariant
# =========================================================================

class TestAdversarialZeroStaticScanning:
    """Stress-test the Zero Static Scanning Invariant using adversarial trap hooks."""

    def test_trap_hooks_are_empirically_live(self):
        """Verify that our adversarial traps genuinely fire if static scanners are called."""
        with assert_zero_static_scanning_traps():
            # 1. Direct StaticScanner trap
            scanner = StaticScanner()
            with pytest.raises(AssertionError, match="StaticScanner.run_static_prefilter was invoked"):
                scanner.run_static_prefilter(Path("."), [])

            # 2. TriageSkill traps
            triage = TriageSkill()
            with pytest.raises(AssertionError, match="parse_bandit was invoked"):
                triage.parse_bandit("{}")
            with pytest.raises(AssertionError, match="parse_semgrep was invoked"):
                triage.parse_semgrep("{}")
            with pytest.raises(AssertionError, match="parse_flake8 was invoked"):
                triage.parse_flake8("file:1:1: E501")
            with pytest.raises(AssertionError, match="parse_eslint was invoked"):
                triage.parse_eslint("[]")
            with pytest.raises(AssertionError, match="parse_trivy was invoked"):
                triage.parse_trivy("{}")

            # 3. Subprocess command traps
            with pytest.raises(AssertionError, match="subprocess.run invoked static analyzer 'ruff'"):
                subprocess.run(["ruff", "check", "."], check=False)
            with pytest.raises(AssertionError, match="subprocess.run invoked static analyzer 'semgrep'"):
                subprocess.run(["semgrep", "--config=auto", "."], check=False)

    def test_fix_next_bug_survives_adversarial_assertion_traps(self, tmp_path: Path):
        """EMPIRICAL CHALLENGE:

        MainFixerAgent.fix_next_bug MUST complete remediation with ALL static analysis
        entry points armed with lethal assertion traps.
        """
        repo_dir = tmp_path / "repo_alpha"
        repo_dir.mkdir(parents=True)
        src_dir = repo_dir / "src"
        src_dir.mkdir(parents=True)
        (src_dir / "service.py").write_text(
            "import os\n\ndef run(cmd):\n    os.system(cmd)\n",
            encoding="utf-8"
        )
        bug_log = repo_dir / "Bug-log.md"
        bug_log.write_text(
            "# Bug Log\n\n"
            "## Pending Bugs\n"
            "- [ ] **BUG-001**: src/service.py:4 - [bandit:B605] Starting a process with a partial executable path\n",
            encoding="utf-8"
        )
        audit_log = repo_dir / "logs.md"

        mock_aider = MagicMock(spec=AiderRunner)
        mock_aider.run_aider.return_value = AiderResult(
            exit_code=0,
            status="SUCCESS",
            diff_output=(
                "--- a/src/service.py\n"
                "+++ b/src/service.py\n"
                "@@ -3,2 +3,2 @@\n"
                "-def run(cmd):\n"
                "-    os.system(cmd)\n"
                "+def run(cmd):\n"
                "+    subprocess.run([cmd], check=True)\n"
            ),
            target_file="src/service.py",
        )

        fixer = MainFixerAgent(aider_runner=mock_aider)

        # Execute with lethal traps armed
        with assert_zero_static_scanning_traps():
            res = fixer.fix_next_bug(
                repo_slug="bitxwolf/Airllm-tui",
                repo_path=repo_dir,
                bug_log_path=bug_log,
                logs_path=audit_log,
            )

        assert res.success is True
        assert res.status == "PR_CREATED"
        assert res.bug_id == "BUG-001"
        assert "- [x] **BUG-001**" in bug_log.read_text(encoding="utf-8")
        assert "- [ ] **BUG-001**" not in bug_log.read_text(encoding="utf-8")
        assert audit_log.exists()
        assert "BUG-001" in audit_log.read_text(encoding="utf-8")

    def test_run_fixer_phase_survives_adversarial_assertion_traps(self, tmp_path: Path):
        """EMPIRICAL CHALLENGE:

        Orchestrator.run_fixer_phase across 3 repositories MUST execute cleanly
        without triggering any static analysis traps.
        """
        k1 = KeyConfig(
            id="key-scalemax-1",
            provider="ScaleMax",
            base_url="https://api.scalemax.pro/v1",
            model="openai/gpt-6-luna",
            api_key="sk-scalemax-test-12345678",
            masked_key="sk-s...5678",
            priority=1,
        )
        conf = Config.load(overrides={
            "WORKSPACE_DIR": tmp_path,
            "workspace_dir": tmp_path,
            "TARGET_REPOS": ["bitxwolf/repo1", "bitxwolf/repo2", "bitxwolf/repo3"],
            "target_repos": ["bitxwolf/repo1", "bitxwolf/repo2", "bitxwolf/repo3"],
            "LLM_KEYS_POOL": [k1],
        })

        db = Database(tmp_path / "orch.sqlite")
        km = KeyManager(conf, db)
        km.preflight_check = MagicMock(return_value=True)
        gm = GitManager(tmp_path, max_open_prs=5)
        ss = StaticScanner()
        oh = OpenHandsRunner()
        vf = Verifier()
        rl = RingBufferLogger()

        orch = Orchestrator(conf, db, km, gm, ss, oh, vf, rl)

        # Set up 3 repo directories with Bug-log.md
        for slug in conf.target_repos:
            rdir = conf.repos_dir / slug.replace("/", "__")
            rdir.mkdir(parents=True, exist_ok=True)
            sdir = rdir / "src"
            sdir.mkdir(parents=True, exist_ok=True)
            (sdir / "app.py").write_text("x = 1\n", encoding="utf-8")
            (rdir / "Bug-log.md").write_text(
                f"- [ ] **BUG-001**: src/app.py:1 - [tool:rule] Fix in {slug}\n",
                encoding="utf-8"
            )

        mock_aider = MagicMock(spec=AiderRunner)
        mock_aider.run_aider.return_value = AiderResult(
            exit_code=0,
            status="SUCCESS",
            diff_output="--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n",
            target_file="src/app.py",
        )
        orch.fixer_agent.aider_runner = mock_aider

        # ARM TRAPS AND EXECUTE FIXER PHASE
        with assert_zero_static_scanning_traps():
            results = orch.run_fixer_phase(conf.target_repos)

        assert len(results) == 3
        for r in results:
            assert r["success"] is True
            assert r["outcome"] == "PR_CREATED"


# =========================================================================
# 2. Challenge 2: Concurrency & Thread-Safety Stress (50 Threads)
# =========================================================================

class TestAdversarialConcurrencyStress:
    """Stress-test thread-safety of mark_bug_done and logs.md audit ledger with 50 concurrent threads."""

    def test_fifty_concurrent_threads_mutating_bug_log(self, tmp_path: Path):
        """Run 50 concurrent threads simultaneously mutating distinct entries in Bug-log.md.

        All threads release at the exact same instant using a Barrier(50).
        Verify 0 lost updates, exactly 50 done entries, 0 pending entries.
        """
        log_path = tmp_path / "Bug-log.md"
        total_threads = 50
        lines = ["# AutoBugHunter Backlog\n\n## Pending Bugs"]
        for i in range(1, total_threads + 1):
            lines.append(f"- [ ] **BUG-{i:03d}**: src/module_{i}.py:{i*2} - [tool:rule_{i}] Description for bug {i}")
        lines.append("\n## Fixed Bugs")
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        fixer = MainFixerAgent()
        barrier = threading.Barrier(total_threads)
        errors: list[Exception] = []

        def worker(bug_id: str):
            try:
                barrier.wait(timeout=10.0)
                res = fixer.mark_bug_done(log_path, bug_id)
                assert res is True
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=worker, args=(f"BUG-{i:03d}",))
            for i in range(1, total_threads + 1)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15.0)

        assert len(errors) == 0, f"Thread errors encountered: {errors}"

        content = log_path.read_text(encoding="utf-8")
        done_count = content.count("- [x]")
        pending_count = content.count("- [ ]")

        assert done_count == total_threads, f"Expected {total_threads} done entries, found {done_count}"
        assert pending_count == 0, f"Expected 0 pending entries, found {pending_count}"

        for i in range(1, total_threads + 1):
            expected_sig = f"- [x] **BUG-{i:03d}**: src/module_{i}.py:{i*2} - [tool:rule_{i}] Description for bug {i} (DONE)"
            assert expected_sig in content, f"Missing or corrupted entry for BUG-{i:03d}"

    def test_fifty_concurrent_threads_appending_to_logs_md(self, tmp_path: Path):
        """Run 50 concurrent threads simultaneously appending audit entries to logs.md.

        Verify header is written exactly once, exactly 50 valid table rows exist,
        and 0 rows are corrupted, interleaved, or dropped.
        """
        logs_path = tmp_path / "logs.md"
        total_threads = 50
        fixer = MainFixerAgent()
        barrier = threading.Barrier(total_threads)
        errors: list[Exception] = []

        def worker(idx: int):
            try:
                barrier.wait(timeout=10.0)
                fixer.append_audit_log(
                    logs_path=logs_path,
                    repo_slug="bitxwolf/Airllm-tui",
                    bug_id=f"BUG-{idx:03d}",
                    target_file=f"src/file_{idx}.py",
                    diff_lines=idx * 2,
                    commit_or_branch=f"fix/auto-scope-bug-{idx:03d}",
                    pr_status="PR_CREATED",
                )
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=worker, args=(i,))
            for i in range(1, total_threads + 1)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15.0)

        assert len(errors) == 0, f"Thread errors encountered: {errors}"
        assert logs_path.exists()

        content = logs_path.read_text(encoding="utf-8")
        lines = content.splitlines()

        # 1. Header checks
        assert content.count("# AutoBugHunter Fix Audit Ledger") == 1
        assert content.count("| Timestamp (UTC) | Repository | Bug ID | Target File | Diff Lines | Commit / Branch | PR Status |") == 1
        assert content.count("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |") == 1

        # 2. Data rows check: exactly 50 rows starting with | 20...
        data_rows = [line_item for line_item in lines if line_item.startswith("| 20")]
        assert len(data_rows) == total_threads, f"Expected {total_threads} rows, got {len(data_rows)}"

        # 3. Structural validity: each data row has exactly 7 columns
        seen_bugs = set()
        row_regex = re.compile(
            r"^\|\s*(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s*\|"
            r"\s*(?P<repo>[^|]+)\s*\|"
            r"\s*(?P<bug>BUG-\d{3})\s*\|"
            r"\s*(?P<file>[^|]+)\s*\|"
            r"\s*(?P<diff>\d+)\s*\|"
            r"\s*(?P<branch>[^|]+)\s*\|"
            r"\s*(?P<status>PR_CREATED)\s*\|$"
        )

        for row in data_rows:
            m = row_regex.match(row.strip())
            assert m is not None, f"Malformed markdown row detected: {row}"
            bug_id = m.group("bug")
            assert bug_id not in seen_bugs, f"Duplicate row for {bug_id} detected"
            seen_bugs.add(bug_id)

        assert len(seen_bugs) == total_threads

    def test_fifty_concurrent_threads_simultaneous_both_operations(self, tmp_path: Path):
        """Run 50 concurrent threads performing BOTH mark_bug_done AND append_audit_log simultaneously."""
        log_path = tmp_path / "Bug-log.md"
        logs_path = tmp_path / "logs.md"
        total_threads = 50

        # Prepare Bug-log.md
        lines = ["# Bug Log\n\n## Pending Bugs"]
        for i in range(1, total_threads + 1):
            lines.append(f"- [ ] **BUG-{i:03d}**: src/file_{i}.py:{i} - [bandit:B101] Assert {i}")
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        fixer = MainFixerAgent()
        barrier = threading.Barrier(total_threads)
        errors: list[Exception] = []

        def worker(idx: int):
            try:
                barrier.wait(timeout=10.0)
                # Mutate Bug-log
                m_res = fixer.mark_bug_done(log_path, f"BUG-{idx:03d}")
                assert m_res is True
                # Append audit
                fixer.append_audit_log(
                    logs_path=logs_path,
                    repo_slug="bitxwolf/worldof3js",
                    bug_id=f"BUG-{idx:03d}",
                    target_file=f"src/file_{idx}.py",
                    diff_lines=idx,
                    commit_or_branch=f"fix/bug-{idx:03d}",
                    pr_status="PR_CREATED",
                )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(1, total_threads + 1)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15.0)

        assert len(errors) == 0, f"Thread errors: {errors}"

        # Check Bug-log.md
        bug_content = log_path.read_text(encoding="utf-8")
        assert bug_content.count("- [x]") == total_threads
        assert bug_content.count("- [ ]") == 0

        # Check logs.md
        log_rows = [line_item for line_item in logs_path.read_text(encoding="utf-8").splitlines() if line_item.startswith("| 20")]
        assert len(log_rows) == total_threads


# =========================================================================
# 3. Challenge 3: Diff Bounds & Budget Enforcement
# =========================================================================

class TestAdversarialDiffBoundsAndBudgetEnforcement:
    """Stress-test boundary rejection at 151 lines vs 150 lines, and 4 files vs 3 files.

    Verify that rollback is performed and Bug-log.md remains uncorrupted.
    """

    def test_exact_diff_lines_boundary_150_vs_151(self, tmp_path: Path):
        """Boundary test: 150 diff lines MUST PASS, 151 diff lines MUST BE REJECTED."""
        repo_dir = tmp_path / "repo_boundary"
        repo_dir.mkdir(parents=True)
        src_dir = repo_dir / "src"
        src_dir.mkdir(parents=True)
        (src_dir / "target.py").write_text("# initial\n", encoding="utf-8")

        mock_gm = MagicMock(spec=GitManager)

        # 1. Test 150 diff lines: exactly at the ceiling -> MUST PASS
        log_path_150 = repo_dir / "Bug-log-150.md"
        log_path_150.write_text("- [ ] **BUG-150**: src/target.py:1 - [tool:rule] Fix 150\n", encoding="utf-8")

        diff_150 = "--- a/src/target.py\n+++ b/src/target.py\n" + "".join(f"+line_{i} = {i}\n" for i in range(150))
        mock_aider_150 = MagicMock(spec=AiderRunner)
        mock_aider_150.run_aider.return_value = AiderResult(
            exit_code=0,
            status="SUCCESS",
            diff_output=diff_150,
            target_file="src/target.py",
        )

        fixer_150 = MainFixerAgent(aider_runner=mock_aider_150, git_manager=mock_gm)
        res_150 = fixer_150.fix_next_bug(
            repo_slug="bitxwolf/orb",
            repo_path=repo_dir,
            bug_log_path=log_path_150,
        )
        assert res_150.success is True
        assert res_150.status == "PR_CREATED"
        assert res_150.diff_lines == 150
        assert "- [x] **BUG-150**" in log_path_150.read_text(encoding="utf-8")

        # 2. Test 151 diff lines: 1 line above ceiling -> MUST FAIL & TRIGGER ROLLBACK
        log_path_151 = repo_dir / "Bug-log-151.md"
        log_path_151.write_text("- [ ] **BUG-151**: src/target.py:1 - [tool:rule] Fix 151\n", encoding="utf-8")

        diff_151 = "--- a/src/target.py\n+++ b/src/target.py\n" + "".join(f"+line_{i} = {i}\n" for i in range(151))
        mock_aider_151 = MagicMock(spec=AiderRunner)
        mock_aider_151.run_aider.return_value = AiderResult(
            exit_code=0,
            status="SUCCESS",
            diff_output=diff_151,
            target_file="src/target.py",
        )

        fixer_151 = MainFixerAgent(aider_runner=mock_aider_151, git_manager=mock_gm)
        res_151 = fixer_151.fix_next_bug(
            repo_slug="bitxwolf/orb",
            repo_path=repo_dir,
            bug_log_path=log_path_151,
        )
        assert res_151.success is False
        assert res_151.status == "VERIFICATION_FAILED"
        assert "exceeding limit of 150" in (res_151.error_message or "")

        # Verify rollback was called
        mock_gm.rollback_working_tree.assert_called_with(repo_dir, "main")

        # Invariant: Bug-log-151 must remain pending (- [ ]) and not marked DONE
        log_151_content = log_path_151.read_text(encoding="utf-8")
        assert "- [ ] **BUG-151**" in log_151_content
        assert "- [x]" not in log_151_content

    def test_exact_files_boundary_3_vs_4(self, tmp_path: Path):
        """Boundary test: 3 files modified MUST PASS, 4 files modified MUST BE REJECTED."""
        repo_dir = tmp_path / "repo_files"
        repo_dir.mkdir(parents=True)
        src_dir = repo_dir / "src"
        src_dir.mkdir(parents=True)
        (src_dir / "f1.py").write_text("# f1\n", encoding="utf-8")

        mock_gm = MagicMock(spec=GitManager)

        # 1. Test 3 files modified -> MUST PASS
        log_path_3 = repo_dir / "Bug-log-3.md"
        log_path_3.write_text("- [ ] **BUG-003**: src/f1.py:1 - [tool:rule] Fix 3 files\n", encoding="utf-8")

        diff_3 = (
            "--- a/src/f1.py\n+++ b/src/f1.py\n@@ -1 +1 @@\n-# f1\n+# f1 mod\n"
            "--- a/src/f2.py\n+++ b/src/f2.py\n@@ -1 +1 @@\n-# f2\n+# f2 mod\n"
            "--- a/src/f3.py\n+++ b/src/f3.py\n@@ -1 +1 @@\n-# f3\n+# f3 mod\n"
        )
        mock_aider_3 = MagicMock(spec=AiderRunner)
        mock_aider_3.run_aider.return_value = AiderResult(
            exit_code=0,
            status="SUCCESS",
            diff_output=diff_3,
            target_file="src/f1.py",
        )

        fixer_3 = MainFixerAgent(aider_runner=mock_aider_3, git_manager=mock_gm)
        res_3 = fixer_3.fix_next_bug(
            repo_slug="bitxwolf/medical-for-non-medics",
            repo_path=repo_dir,
            bug_log_path=log_path_3,
        )
        assert res_3.success is True
        assert res_3.status == "PR_CREATED"
        assert "- [x] **BUG-003**" in log_path_3.read_text(encoding="utf-8")

        # 2. Test 4 files modified -> MUST FAIL & TRIGGER ROLLBACK
        log_path_4 = repo_dir / "Bug-log-4.md"
        log_path_4.write_text("- [ ] **BUG-004**: src/f1.py:1 - [tool:rule] Fix 4 files\n", encoding="utf-8")

        diff_4 = (
            "--- a/src/f1.py\n+++ b/src/f1.py\n@@ -1 +1 @@\n-# f1\n+# f1 mod\n"
            "--- a/src/f2.py\n+++ b/src/f2.py\n@@ -1 +1 @@\n-# f2\n+# f2 mod\n"
            "--- a/src/f3.py\n+++ b/src/f3.py\n@@ -1 +1 @@\n-# f3\n+# f3 mod\n"
            "--- a/src/f4.py\n+++ b/src/f4.py\n@@ -1 +1 @@\n-# f4\n+# f4 mod\n"
        )
        mock_aider_4 = MagicMock(spec=AiderRunner)
        mock_aider_4.run_aider.return_value = AiderResult(
            exit_code=0,
            status="SUCCESS",
            diff_output=diff_4,
            target_file="src/f1.py",
        )

        mock_gm.reset_mock()
        fixer_4 = MainFixerAgent(aider_runner=mock_aider_4, git_manager=mock_gm)
        res_4 = fixer_4.fix_next_bug(
            repo_slug="bitxwolf/medical-for-non-medics",
            repo_path=repo_dir,
            bug_log_path=log_path_4,
        )
        assert res_4.success is False
        assert res_4.status == "VERIFICATION_FAILED"
        assert "exceeding limit of 3" in (res_4.error_message or "")

        # Verify rollback was called
        mock_gm.rollback_working_tree.assert_called_with(repo_dir, "main")

        # Invariant: Bug-log-4 must remain pending
        log_4_content = log_path_4.read_text(encoding="utf-8")
        assert "- [ ] **BUG-004**" in log_4_content
        assert "- [x]" not in log_4_content


# =========================================================================
# 4. Challenge 4: Rate Limit Circuit Breaker (429 and 402)
# =========================================================================

class TestAdversarialRateLimitCircuitBreaker:
    """Stress-test upstream rate limits (429) and quota exhaustion (402).

    Verify backlog integrity and circuit breaking without marking bugs DONE.
    """

    def test_aider_rate_limit_429_preserves_backlog(self, tmp_path: Path):
        """When Aider returns RATE_LIMIT_429, bug MUST remain pending in Bug-log.md."""
        repo_dir = tmp_path / "repo_rl429"
        repo_dir.mkdir(parents=True)
        src_dir = repo_dir / "src"
        src_dir.mkdir(parents=True)
        (src_dir / "app.py").write_text("# code\n", encoding="utf-8")

        log_path = repo_dir / "Bug-log.md"
        log_path.write_text("- [ ] **BUG-429**: src/app.py:1 - [tool:rule] Fix me\n", encoding="utf-8")
        logs_path = repo_dir / "logs.md"

        mock_aider = MagicMock(spec=AiderRunner)
        mock_aider.run_aider.return_value = AiderResult(
            exit_code=1,
            diff_output="",
            status="RATE_LIMIT_429",
            error_message="HTTP 429 Too Many Requests: Rate limit exceeded",
            target_file="src/app.py",
        )

        fixer = MainFixerAgent(aider_runner=mock_aider)
        res = fixer.fix_next_bug(
            repo_slug="bitxwolf/BugHunter",
            repo_path=repo_dir,
            bug_log_path=log_path,
            logs_path=logs_path,
        )

        assert res.success is False
        assert res.status == "RATE_LIMIT_429"
        assert "HTTP 429" in (res.error_message or "")

        # Backlog invariant: pending bug must NOT be marked done
        content = log_path.read_text(encoding="utf-8")
        assert "- [ ] **BUG-429**" in content
        assert "- [x]" not in content

        # Audit ledger must NOT record PR_CREATED
        if logs_path.exists():
            assert "PR_CREATED" not in logs_path.read_text(encoding="utf-8")

    def test_aider_quota_exhausted_402_preserves_backlog(self, tmp_path: Path):
        """When Aider returns QUOTA_EXHAUSTED_402, bug MUST remain pending in Bug-log.md."""
        repo_dir = tmp_path / "repo_qe402"
        repo_dir.mkdir(parents=True)
        src_dir = repo_dir / "src"
        src_dir.mkdir(parents=True)
        (src_dir / "app.py").write_text("# code\n", encoding="utf-8")

        log_path = repo_dir / "Bug-log.md"
        log_path.write_text("- [ ] **BUG-402**: src/app.py:1 - [tool:rule] Fix me quota\n", encoding="utf-8")
        logs_path = repo_dir / "logs.md"

        mock_aider = MagicMock(spec=AiderRunner)
        mock_aider.run_aider.return_value = AiderResult(
            exit_code=1,
            diff_output="",
            status="QUOTA_EXHAUSTED_402",
            error_message="HTTP 402 Payment Required: Insufficient quota",
            target_file="src/app.py",
        )

        fixer = MainFixerAgent(aider_runner=mock_aider)
        res = fixer.fix_next_bug(
            repo_slug="bitxwolf/BugHunter",
            repo_path=repo_dir,
            bug_log_path=log_path,
            logs_path=logs_path,
        )

        assert res.success is False
        assert res.status == "QUOTA_EXHAUSTED_402"
        assert "HTTP 402" in (res.error_message or "")

        # Backlog invariant: pending bug must NOT be marked done
        content = log_path.read_text(encoding="utf-8")
        assert "- [ ] **BUG-402**" in content
        assert "- [x]" not in content

    def test_orchestrator_circuit_breaker_when_keys_exhausted(self, tmp_path: Path):
        """When all keys in KeyManager are exhausted/cooldown, Orchestrator.run_fixer_phase

        MUST skip fixing, report NO_HEALTHY_KEYS, and preserve all Bug-log.md backlogs.
        """
        k1 = KeyConfig(
            id="key-1",
            provider="ScaleMax",
            base_url="https://api.scalemax.pro/v1",
            model="openai/gpt-6-luna",
            api_key="sk-test-1",
            masked_key="sk-t...1",
            priority=1,
        )
        conf = Config.load(overrides={
            "WORKSPACE_DIR": tmp_path,
            "workspace_dir": tmp_path,
            "TARGET_REPOS": ["bitxwolf/repo_cb"],
            "target_repos": ["bitxwolf/repo_cb"],
            "LLM_KEYS_POOL": [k1],
        })

        db = Database(tmp_path / "orch_cb.sqlite")
        km = KeyManager(conf, db)
        # Put the key into EXHAUSTED state (simulating 402 or exhausted quota)
        km.report_key_failure("key-1", "Insufficient quota (HTTP 402)", status_code=402)
        assert km.get_next_healthy_key() is None

        gm = GitManager(tmp_path, max_open_prs=5)
        ss = StaticScanner()
        oh = OpenHandsRunner()
        vf = Verifier()
        rl = RingBufferLogger()

        orch = Orchestrator(conf, db, km, gm, ss, oh, vf, rl)

        # Setup repo with pending bug
        rdir = conf.repos_dir / "bitxwolf__repo_cb"
        rdir.mkdir(parents=True, exist_ok=True)
        bug_log = rdir / "Bug-log.md"
        bug_log.write_text("- [ ] **BUG-001**: src/main.py:10 - [flake8:F841] Unused variable\n", encoding="utf-8")

        results = orch.run_fixer_phase(["bitxwolf/repo_cb"])
        assert len(results) == 1
        assert results[0]["outcome"] == "NO_HEALTHY_KEYS"
        assert results[0]["repo_slug"] == "bitxwolf/repo_cb"

        # Backlog must remain untouched
        assert "- [ ] **BUG-001**" in bug_log.read_text(encoding="utf-8")
        assert "- [x]" not in bug_log.read_text(encoding="utf-8")


    def test_orchestrator_key_rotation_on_rate_limit_failure(self, tmp_path: Path):
        """When repo 1 fails with RATE_LIMIT_429, Orchestrator MUST report the key failure

        to KeyManager so repo 2 rotates to the next healthy key (key-backup).
        """
        k1 = KeyConfig(
            id="key-primary",
            provider="ScaleMax",
            base_url="https://api.scalemax.pro/v1",
            model="openai/gpt-6-luna",
            api_key="sk-test-1",
            masked_key="sk-t...1",
            priority=1,
        )
        k2 = KeyConfig(
            id="key-backup",
            provider="ScaleMax",
            base_url="https://api.scalemax.pro/v1",
            model="openai/gpt-6-luna",
            api_key="sk-test-2",
            masked_key="sk-t...2",
            priority=2,
        )
        conf = Config.load(overrides={
            "WORKSPACE_DIR": tmp_path,
            "workspace_dir": tmp_path,
            "TARGET_REPOS": ["bitxwolf/repo_1", "bitxwolf/repo_2"],
            "target_repos": ["bitxwolf/repo_1", "bitxwolf/repo_2"],
            "LLM_KEYS_POOL": [k1, k2],
        })

        db = Database(tmp_path / "orch_rot.sqlite")
        km = KeyManager(conf, db)
        gm = GitManager(tmp_path, max_open_prs=5)
        ss = StaticScanner()
        oh = OpenHandsRunner()
        vf = Verifier()
        rl = RingBufferLogger()

        orch = Orchestrator(conf, db, km, gm, ss, oh, vf, rl)

        # Setup 2 repos
        for slug in ["bitxwolf/repo_1", "bitxwolf/repo_2"]:
            rdir = conf.repos_dir / slug.replace("/", "__")
            rdir.mkdir(parents=True, exist_ok=True)
            (rdir / "src").mkdir(parents=True, exist_ok=True)
            (rdir / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
            (rdir / "Bug-log.md").write_text(
                f"- [ ] **BUG-001**: src/app.py:1 - [tool:rule] Fix in {slug}\n",
                encoding="utf-8"
            )

        def mock_run_aider(repo_path, target_file, patch_instruction, key_entry=None, **kwargs):
            if key_entry and key_entry.id == "key-primary":
                return AiderResult(
                    exit_code=1,
                    diff_output="",
                    status="RATE_LIMIT_429",
                    error_message="HTTP 429 Too Many Requests",
                    target_file=target_file,
                )
            else:
                return AiderResult(
                    exit_code=0,
                    status="SUCCESS",
                    diff_output="--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n",
                    target_file=target_file,
                )

        mock_aider = MagicMock(spec=AiderRunner)
        mock_aider.run_aider.side_effect = mock_run_aider
        orch.fixer_agent.aider_runner = mock_aider

        results = orch.run_fixer_phase(["bitxwolf/repo_1", "bitxwolf/repo_2"])
        assert len(results) == 2
        assert results[0]["outcome"] == "RATE_LIMIT_429"

        # Repo 2 MUST rotate to key-backup and succeed with PR_CREATED
        assert results[1]["outcome"] == "PR_CREATED", (
            f"Expected PR_CREATED for repo_2 after key rotation, got {results[1]['outcome']}. "
            "Orchestrator failed to report 429 failure to KeyManager!"
        )
