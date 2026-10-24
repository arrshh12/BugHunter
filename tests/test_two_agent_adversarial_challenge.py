"""
Empirical Adversarial Challenge Suite for Two-Agent "Bug-Hunter" Architecture.
Targets BugfindingAgent, MainFixerAgent, Bug-log.md state machine, and TriageSkill.

Adversarial Stress Dimensions:
1. Malformed and edge-case Bug-log.md files (CRLF line endings, missing fields, corrupted headers, duplicate IDs, unknown tools, non-standard indentation).
2. State preservation across complex re-scans (multi-cycle additions, alternating fixes, regressions, line shifts).
3. Path traversal resistance and slug normalization (POSIX ../ and Windows ..\\ in repo_slug and target_file).
4. Dense clustering stress (50 findings on adjacent lines, 50 findings on exact same line, bug shadowing vulnerability).
"""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest

from src.bugfinding_agent import BugfindingAgent
from src.bughunter_agent import RawFinding, TriagedFinding, TriageSkill
from src.fixer_agent import MainFixerAgent


@pytest.fixture
def temp_repo(tmp_path: Path) -> Path:
    """Create a minimal mock repository for testing."""
    repo = tmp_path / "mock_repo"
    repo.mkdir(parents=True, exist_ok=True)
    (repo / ".git").mkdir()
    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return repo


# =========================================================================
# 1. Edge-Case Formatting in Bug-log.md
# =========================================================================

class TestAdversarialBugLogFormatting:
    """Stress-test BugfindingAgent and MainFixerAgent against malformed Bug-log.md files."""

    def test_crlf_line_endings_parsing_and_mutation(self, temp_repo: Path):
        """Verify Bug-log.md with Windows CRLF (\\r\\n) is parsed and mutated correctly."""
        log_file = temp_repo / "Bug-log.md"
        # Explicit CRLF content
        crlf_content = (
            "# Bug Log — owner/repo\r\n"
            "\r\n"
            "## Pending Bugs\r\n"
            "- [ ] **BUG-001**: src/app.py:10 - [flake8:E501] line too long\r\n"
            "- [ ] **BUG-002**: src/app.py:20 - [bandit:B602] shell injection\r\n"
            "\r\n"
            "## Fixed Bugs\r\n"
            "- [x] **BUG-000**: src/app.py:5 - [flake8:F401] unused import (DONE)\r\n"
        )
        log_file.write_bytes(crlf_content.encode("utf-8"))

        # Test BugfindingAgent parsing
        agent = BugfindingAgent()
        entries = agent.parse_existing_bug_log(log_file)
        assert len(entries) == 3
        pending = [e for e in entries if not e.is_done]
        done = [e for e in entries if e.is_done]
        assert len(pending) == 2
        assert len(done) == 1
        assert done[0].bug_id == "BUG-000"

        # Test MainFixerAgent parsing
        fixer = MainFixerAgent()
        pending_fixer = fixer.parse_pending_bugs(log_file)
        assert len(pending_fixer) == 2
        assert pending_fixer[0]["bug_id"] == "BUG-001"
        assert pending_fixer[1]["bug_id"] == "BUG-002"

        # Test MainFixerAgent in-place mutation on CRLF file
        updated = fixer.mark_bug_done(log_file, "BUG-001")
        assert updated is True

        # Verify mutation was recorded and file remains valid
        reparsed_entries = agent.parse_existing_bug_log(log_file)
        assert len(reparsed_entries) == 3
        done_ids = {e.bug_id for e in reparsed_entries if e.is_done}
        assert "BUG-000" in done_ids
        assert "BUG-001" in done_ids

    def test_corrupted_headers_and_custom_sections(self, temp_repo: Path):
        """Verify behavior when markdown headers are missing, renamed, or corrupted."""
        log_file = temp_repo / "Bug-log.md"
        # No standard headers, custom title, extra text
        raw_markdown = (
            "Random preamble text without standard header\n"
            "### Some Weird Section\n"
            "- [ ] **BUG-001**: src/app.py:15 - [bandit:B101] assert used\n"
            "Random comment between lines\n"
            "- [x] **BUG-002**: src/app.py:25 - [flake8:E701] multiple statements (DONE)\n"
        )
        log_file.write_text(raw_markdown, encoding="utf-8")

        agent = BugfindingAgent()
        entries = agent.parse_existing_bug_log(log_file)
        assert len(entries) == 2
        assert entries[0].bug_id == "BUG-001"
        assert entries[0].is_done is False
        assert entries[1].bug_id == "BUG-002"
        assert entries[1].is_done is True

        # Test re-generation: verify standard headers are restored and entries retained
        new_finding = TriagedFinding(
            id="src/app.py:35:E501",
            primary_axis="CORRECTNESS",
            severity="WARNING",
            composite_score=50.0,
            blast_radius_score=0.0,
            is_trust_boundary=False,
            inbound_dependents_count=0,
            tools_reporting=["flake8"],
            file="src/app.py",
            line=35,
            column=1,
            rule_id="E501",
            message="Line too long",
            code_snippet="",
        )
        agent.generate_bug_log("owner/repo", [new_finding], repo_path=temp_repo)
        content = log_file.read_text(encoding="utf-8")
        assert "## Pending Bugs" in content
        assert "## Fixed Bugs" in content
        assert "BUG-001" in content
        assert "BUG-002" in content
        assert "BUG-003" in content or "src/app.py:35" in content

    def test_duplicate_bug_ids_mutation_vulnerability(self, temp_repo: Path):
        """Stress-test mark_bug_done behavior when duplicate BUG IDs exist in Bug-log.md.

        Vulnerability check: If two distinct bugs share the same ID (e.g. BUG-001),
        mark_bug_done improperly marks BOTH entries as DONE without fixing the second.
        """
        log_file = temp_repo / "Bug-log.md"
        content = (
            "# Bug Log — owner/repo\n\n"
            "## Pending Bugs\n"
            "- [ ] **BUG-001**: src/file_a.py:10 - [flake8:E501] line too long in file A\n"
            "- [ ] **BUG-001**: src/file_b.py:20 - [bandit:B602] shell injection in file B\n"
        )
        log_file.write_text(content, encoding="utf-8")

        fixer = MainFixerAgent()
        # Mark BUG-001 as done (intended for file A)
        updated = fixer.mark_bug_done(log_file, "BUG-001")
        assert updated is True

        updated_text = log_file.read_text(encoding="utf-8")
        # Check how many lines were mutated to DONE
        done_matches = re.findall(r"- \[x\].*\(DONE\)", updated_text)
        # Only the first matching entry is mutated to DONE, protecting duplicate records
        assert len(done_matches) == 1, "Guarded: mark_bug_done only marks the first matching entry as DONE"

    def test_unbolded_bug_id_dropped_by_parsers(self, temp_repo: Path):
        """Verify empirical parser failure when bug ID lacks ** bold markers.

        e.g. '- [ ] BUG-001: src/app.py:10 - [flake8:E501] line too long'
        The regex interprets 'BUG-001' as the filename and expects digits after ':',
        causing the line to be silently dropped!
        """
        log_file = temp_repo / "Bug-log.md"
        content = (
            "# Bug Log\n\n"
            "- [ ] BUG-001: src/app.py:10 - [flake8:E501] line too long\n"
            "- [ ] **BUG-002**: src/app.py:20 - [flake8:E502] redundant backslash\n"
        )
        log_file.write_text(content, encoding="utf-8")

        agent = BugfindingAgent()
        entries = agent.parse_existing_bug_log(log_file)
        fixer = MainFixerAgent()
        pending = fixer.parse_pending_bugs(log_file)

        # BUG-001 without ** was dropped; only BUG-002 was parsed
        assert len(entries) == 1
        assert entries[0].bug_id == "BUG-002"
        assert len(pending) == 1
        assert pending[0]["bug_id"] == "BUG-002"

    def test_mark_bug_done_fails_when_id_not_bolded(self, temp_repo: Path):
        """Verify empirical state-machine failure:

        If Bug-log.md has an entry with no BUG-ID tag (e.g. '- [ ] src/app.py:10 - [flake8:E501] desc'),
        parse_pending_bugs generates 'BUG-001', but mark_bug_done returns False because it searches for '**BUG-001**',
        leading to remediation loop lockup.
        """
        log_file = temp_repo / "Bug-log.md"
        content = "- [ ] src/app.py:10 - [flake8:E501] line too long\n"
        log_file.write_text(content, encoding="utf-8")

        fixer = MainFixerAgent()
        pending = fixer.parse_pending_bugs(log_file)
        assert len(pending) == 1
        generated_id = pending[0]["bug_id"]  # BUG-001

        # Attempt to mark done
        updated = fixer.mark_bug_done(log_file, generated_id)
        # Fails because '**BUG-001**' is not in the line text
        assert updated is False
        assert "- [ ]" in log_file.read_text(encoding="utf-8")

    def test_non_standard_indentation_and_tabs(self, temp_repo: Path):
        """Verify parsing handles tabs and arbitrary leading whitespace."""
        log_file = temp_repo / "Bug-log.md"
        content = (
            "# Bug Log\n\n"
            "  - [ ]   **BUG-001**: src/app.py:10 - [flake8:E501] indented spaces\n"
            "\t- [ ]\t**BUG-002**: src/app.py:20 - [bandit:B602] tab separated\n"
        )
        log_file.write_text(content, encoding="utf-8")

        agent = BugfindingAgent()
        entries = agent.parse_existing_bug_log(log_file)
        assert len(entries) == 2
        assert entries[0].bug_id == "BUG-001"
        assert entries[1].bug_id == "BUG-002"


# =========================================================================
# 2. State Preservation Across Multi-Cycle Re-Scans
# =========================================================================

class TestAdversarialReScanCycles:
    """Stress-test BugfindingAgent state preservation across alternating discovery and remediation cycles."""

    def test_multi_cycle_interleaved_scan_and_fix(self, temp_repo: Path):
        """Simulate 4 full cycles of scanning, fixing, re-scanning with new, fixed, and regression bugs."""
        agent = BugfindingAgent()
        log_file = temp_repo / "Bug-log.md"
        fixer = MainFixerAgent()

        def make_finding(fpath: str, line: int, rule: str, msg: str) -> TriagedFinding:
            return TriagedFinding(
                id=f"{fpath}:{line}:{rule}",
                primary_axis="CORRECTNESS",
                severity="ERROR",
                composite_score=100.0,
                blast_radius_score=0.0,
                is_trust_boundary=False,
                inbound_dependents_count=0,
                tools_reporting=["flake8"],
                file=fpath,
                line=line,
                column=1,
                rule_id=rule,
                message=msg,
                code_snippet="",
            )

        # Cycle 1: Scanner finds Bug 1 and Bug 2
        f1 = make_finding("src/app.py", 10, "F401", "Unused import foo")
        f2 = make_finding("src/app.py", 20, "E999", "Syntax error")
        agent.generate_bug_log("owner/repo", [f1, f2], repo_path=temp_repo)

        entries_c1 = agent.parse_existing_bug_log(log_file)
        assert len(entries_c1) == 2
        assert [e.bug_id for e in entries_c1] == ["BUG-001", "BUG-002"]
        assert all(not e.is_done for e in entries_c1)

        # Fixer remediates Bug 1 (BUG-001)
        assert fixer.mark_bug_done(log_file, "BUG-001") is True

        # Cycle 2: Scanner re-scans.
        # Bug 1 is fixed (not reported).
        # Bug 2 is still present.
        # Bug 3 is new!
        f3 = make_finding("src/app.py", 30, "B602", "Subprocess injection")
        agent.generate_bug_log("owner/repo", [f2, f3], repo_path=temp_repo)

        entries_c2 = agent.parse_existing_bug_log(log_file)
        assert len(entries_c2) == 3
        done_c2 = [e for e in entries_c2 if e.is_done]
        pending_c2 = [e for e in entries_c2 if not e.is_done]
        assert len(done_c2) == 1
        assert done_c2[0].bug_id == "BUG-001"
        assert len(pending_c2) == 2
        assert pending_c2[0].bug_id == "BUG-002"
        assert pending_c2[1].bug_id == "BUG-003"

        # Fixer remediates Bug 2 (BUG-002)
        assert fixer.mark_bug_done(log_file, "BUG-002") is True

        # Cycle 3: Scanner re-scans.
        # Bug 1 and 2 are fixed (not reported).
        # Bug 3 is still present.
        # Bug 4 is new!
        f4 = make_finding("src/auth.py", 50, "B105", "Hardcoded token")
        agent.generate_bug_log("owner/repo", [f3, f4], repo_path=temp_repo)

        entries_c3 = agent.parse_existing_bug_log(log_file)
        assert len(entries_c3) == 4
        done_c3 = [e for e in entries_c3 if e.is_done]
        pending_c3 = [e for e in entries_c3 if not e.is_done]
        assert len(done_c3) == 2
        assert {e.bug_id for e in done_c3} == {"BUG-001", "BUG-002"}
        assert len(pending_c3) == 2
        assert {e.bug_id for e in pending_c3} == {"BUG-003", "BUG-004"}

        # Cycle 4: Regression test.
        # Scanner falsely re-reports Bug 1 (src/app.py:10:F401).
        # Bug 1 is already in DONE. It must NOT be re-opened as a pending bug!
        agent.generate_bug_log("owner/repo", [f1, f3, f4], repo_path=temp_repo)

        entries_c4 = agent.parse_existing_bug_log(log_file)
        assert len(entries_c4) == 4
        done_c4 = [e for e in entries_c4 if e.is_done]
        pending_c4 = [e for e in entries_c4 if not e.is_done]
        assert len(done_c4) == 2
        assert {e.bug_id for e in done_c4} == {"BUG-001", "BUG-002"}
        # Ensure Bug 1 was NOT re-opened in pending
        assert not any(e.bug_id == "BUG-001" for e in pending_c4)
        assert not any(e.file_path == "src/app.py" and e.line == 10 for e in pending_c4)

    def test_line_number_shift_after_code_insertion(self, temp_repo: Path):
        """Test behavior when a bug's line shifts due to code insertion.

        If a bug was at line 10 and marked DONE, but new code shifted the file so line 10
        now has something else, or a bug at line 20 moved to line 22.
        """
        agent = BugfindingAgent()
        log_file = temp_repo / "Bug-log.md"
        fixer = MainFixerAgent()

        f1 = TriagedFinding(
            id="src/app.py:10:F401",
            primary_axis="CORRECTNESS",
            severity="ERROR",
            composite_score=100.0,
            blast_radius_score=0.0,
            is_trust_boundary=False,
            inbound_dependents_count=0,
            tools_reporting=["flake8"],
            file="src/app.py",
            line=10,
            column=1,
            rule_id="F401",
            message="Unused import",
            code_snippet="",
        )
        agent.generate_bug_log("owner/repo", [f1], repo_path=temp_repo)
        fixer.mark_bug_done(log_file, "BUG-001")

        # After code edit, line shifts to 12
        f1_shifted = TriagedFinding(
            id="src/app.py:12:F401",
            primary_axis="CORRECTNESS",
            severity="ERROR",
            composite_score=100.0,
            blast_radius_score=0.0,
            is_trust_boundary=False,
            inbound_dependents_count=0,
            tools_reporting=["flake8"],
            file="src/app.py",
            line=12,
            column=1,
            rule_id="F401",
            message="Unused import",
            code_snippet="",
        )
        agent.generate_bug_log("owner/repo", [f1_shifted], repo_path=temp_repo)
        entries = agent.parse_existing_bug_log(log_file)
        # Because signature is (file, line, rule), line 12 is treated as a new finding (BUG-002)
        # while line 10 remains in DONE (BUG-001).
        assert len(entries) == 2
        done_list = [e for e in entries if e.is_done]
        pending_list = [e for e in entries if not e.is_done]
        assert len(done_list) == 1
        assert done_list[0].bug_id == "BUG-001"
        assert len(pending_list) == 1
        assert pending_list[0].bug_id == "BUG-002"


# =========================================================================
# 3. Path Traversal & Slug Normalization
# =========================================================================

class TestAdversarialPathTraversal:
    """Stress-test BugfindingAgent and MainFixerAgent against directory traversal attacks."""

    def test_posix_path_traversal_in_repo_slug_generation(self, tmp_path: Path):
        """Verify repo_slug with ../ is normalized and stays in local working directory."""
        agent = BugfindingAgent()
        finding = TriagedFinding(
            id="app.py:1:E501",
            primary_axis="CORRECTNESS",
            severity="WARNING",
            composite_score=50.0,
            blast_radius_score=0.0,
            is_trust_boundary=False,
            inbound_dependents_count=0,
            tools_reporting=["flake8"],
            file="app.py",
            line=1,
            column=1,
            rule_id="E501",
            message="line too long",
            code_snippet="",
        )

        malicious_slug = "../../escaped_repo"
        generated_path = agent.generate_bug_log(malicious_slug, [finding])
        try:
            # Slashes replaced by underscore -> 'Bug-log-.._.._escaped_repo.md'
            # Must resolve in local CWD (no directory hopping via /)
            assert generated_path.parent.resolve() == Path.cwd().resolve()
        finally:
            if generated_path.exists():
                generated_path.unlink()

    def test_windows_backslash_traversal_in_repo_slug(self, tmp_path: Path):
        """Test Windows backslash traversal vulnerability in scan_repositories.

        When slug is '..\\..\\malicious', slug.replace('/', '__') does not replace backslashes!
        As a result, 'repos_dir / slug' escapes repos_dir.
        """
        agent = BugfindingAgent()
        repos_dir = tmp_path / "repos"
        repos_dir.mkdir(parents=True, exist_ok=True)

        windows_slug = r"..\..\malicious"
        res = agent.scan_repositories([windows_slug], repos_dir=repos_dir)
        log_path = res[windows_slug]

        try:
            # Empirical check: did log_path escape repos_dir?
            is_escaped = not log_path.resolve().is_relative_to(repos_dir.resolve())
            assert is_escaped is False, "Guarded: backslash in repo_slug must not escape repos_dir!"
        finally:
            if log_path.exists():
                log_path.unlink()
            if log_path.parent.exists():
                try:
                    log_path.parent.rmdir()
                except Exception:
                    pass

    def test_target_file_traversal_in_main_fixer(self, temp_repo: Path, tmp_path: Path):
        """Test whether a relative target file path in Bug-log.md (e.g. ../secret.py)

        causes ContextExtractionSkill to read sensitive files outside the repo.
        """
        # Create an external secret file outside temp_repo (in tmp_path)
        secret_file = tmp_path / "outside_secret.py"
        secret_file.write_text("SUPER_SECRET_API_KEY = 'secret123'\n", encoding="utf-8")

        log_file = temp_repo / "Bug-log.md"
        # Relative traversal path from temp_repo to secret_file in tmp_path
        rel_traversal = f"../{secret_file.name}"
        log_file.write_text(
            f"# Bug Log\n\n## Pending Bugs\n- [ ] **BUG-001**: {rel_traversal}:1 - [bandit:B105] hardcoded secret\n",
            encoding="utf-8",
        )

        fixer = MainFixerAgent()
        pending = fixer.parse_pending_bugs(log_file)
        assert len(pending) == 1
        target_f = pending[0]["file"]

        # Call context_skill.extract_context
        ctx = fixer.context_skill.extract_context(temp_repo, target_f, 1)
        # Check if it extracted content from outside secret file
        read_secret = "SUPER_SECRET_API_KEY" in ctx.code_slice or "secret123" in ctx.formatted_prompt_block
        assert read_secret is False, "Guarded: relative traversal path in target_file must not escape repo_path!"


# =========================================================================
# 4. Dense Clustering Stress Tests
# =========================================================================

class TestAdversarialDenseClustering:
    """Stress-test proximity deduplication under high-density finding clusters."""

    def test_fifty_findings_on_adjacent_lines(self, temp_repo: Path):
        """Stress test: 50 findings on lines 1..50.

        Verifies clustering boundaries, cluster count, and runtime performance.
        """
        triage = TriageSkill()
        findings = []
        for i in range(1, 51):
            findings.append(
                RawFinding(
                    tool="flake8",
                    rule_id=f"E{100 + i}",
                    file="src/dense.py",
                    line=i,
                    column=1,
                    message=f"Issue on line {i}",
                    severity="WARNING",
                )
            )

        start_time = time.perf_counter()
        clusters = triage.deduplicate(findings)
        elapsed = time.perf_counter() - start_time

        # Fast execution (< 50ms)
        assert elapsed < 0.05

        # With +-2 from cluster base:
        # Base 1 includes lines 1, 2, 3 (size 3)
        # Base 4 includes lines 4, 5, 6 (size 3)
        # ...
        total_in_clusters = sum(len(c) for c in clusters)
        assert total_in_clusters == 50
        # Check cluster 1 base line
        assert clusters[0][0].line == 1
        assert max(f.line for f in clusters[0]) <= 3

    def test_fifty_findings_on_exact_same_line(self, temp_repo: Path):
        """Stress test: 50 distinct findings from multiple tools targeting the exact same line."""
        triage = TriageSkill()
        findings = []
        tools = ["flake8", "bandit", "semgrep", "eslint", "trivy"]
        for i in range(50):
            tool = tools[i % len(tools)]
            findings.append(
                RawFinding(
                    tool=tool,
                    rule_id=f"RULE_{i:03d}",
                    file="src/single_point.py",
                    line=42,
                    column=i + 1,
                    message=f"Duplicate report {i} on line 42",
                    severity="ERROR" if i == 25 else "WARNING",
                )
            )

        clusters = triage.deduplicate(findings)
        # All 50 findings must collapse into exactly 1 cluster
        assert len(clusters) == 1
        assert len(clusters[0]) == 50

        # In triage_and_rank, 1 representative must be selected
        triaged = triage.triage_and_rank(findings, repo_path=temp_repo)
        assert len(triaged) == 1
        assert triaged[0].line == 42
        # All 5 tools should be recognized in tools_reporting
        assert set(triaged[0].tools_reporting) == set(tools)

    def test_bug_shadowing_vulnerability_in_proximity_clustering(self, temp_repo: Path):
        """Vulnerability test: Proximity clustering suppresses distinct severe bugs.

        If Line 10 has a SQL injection (B608) and Line 11 has an unrelated hardcoded secret (B105),
        proximity clustering merges them into 1 cluster and drops the other bug.
        """
        triage = TriageSkill()
        f_sql = RawFinding(
            tool="bandit",
            rule_id="B608",
            file="src/db.py",
            line=10,
            column=5,
            message="Possible SQL injection vector",
            severity="CRITICAL",
        )
        f_secret = RawFinding(
            tool="bandit",
            rule_id="B105",
            file="src/db.py",
            line=11,
            column=1,
            message="Hardcoded password string found",
            severity="CRITICAL",
        )

        triaged = triage.triage_and_rank([f_sql, f_secret], repo_path=temp_repo)
        # Because abs(11 - 10) <= 2, proximity clustering merges them
        # Only 1 TriagedFinding is returned; the second critical defect is shadowed!
        assert len(triaged) == 1
        assert triaged[0].rule_id in ("B608", "B105")
        # Confirms empirical finding: Bug Shadowing occurs when distinct bugs are adjacent!
