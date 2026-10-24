"""
Adversarial Stress Test Harness for Milestone 2: Modular BugHunter Agent with Skills (R1).
Author: challenger_m2_2
Purpose: Adversarially challenge PatchPlanningSkill and BugHunterAgent coordinator in src/bughunter_agent.py.

Stress Dimensions:
1. Strict adherence to One Bug = One PR under all inputs and ranking distributions.
2. Diff budget ceiling (<= 150 lines, <= 3 files) permanently stated and never compromised.
3. Aider prompt generation integrity: no hallucinated formatting, syntax errors, or broken escaping.
4. BugHunterAgent.analyze_and_plan boundary handling:
   - Empty input lists
   - Pure cosmetic readability inputs
   - Non-existent files and invalid paths
   - Extremely large files and out-of-bounds line numbers
   - Syntax-invalid and binary files
   - Multi-threaded concurrent execution
"""

from __future__ import annotations

import concurrent.futures
from pathlib import Path

import pytest

from src.bughunter_agent import (
    BugHunterAgent,
    ContextExtractionSkill,
    ExtractedContext,
    PatchPlan,
    PatchPlanningSkill,
    RawFinding,
    TriagedFinding,
    TriageSkill,
)
from src.static_scanner import FiveAxisTriageEngine


class TestAdversarialPatchPlanningSkill:
    """Adversarial stress-testing of PatchPlanningSkill."""

    def test_one_bug_one_pr_invariant_strictly_enforced(self):
        """Verify that formulate_plan produces a single atomic plan adhering to One Bug = One PR."""
        planner = PatchPlanningSkill()
        finding = TriagedFinding(
            id="src/payment.py:100:CRITICAL_AUTH_BYPASS",
            primary_axis="security",
            severity="CRITICAL",
            composite_score=250.0,
            blast_radius_score=50.0,
            is_trust_boundary=True,
            inbound_dependents_count=5,
            tools_reporting=["bandit", "semgrep"],
            file="src/payment.py",
            line=100,
            column=4,
            rule_id="CRITICAL_AUTH_BYPASS",
            message="Direct password verification without salt",
            code_snippet="if password == stored_pw: return True",
            stride_category="Elevation of Privilege",
            owasp_category="A07:2021-Identification and Authentication Failures",
        )
        context = ExtractedContext(
            file_path="src/payment.py",
            target_line=100,
            enclosing_symbol="class PaymentService -> def verify_admin",
            imports_slice="import hmac",
            code_slice="def verify_admin(password, stored_pw):\n    if password == stored_pw:\n        return True",
            context_type="ast_python",
            total_lines=250,
            formatted_prompt_block="=== SURGICAL CONTEXT ===",
        )

        plan = planner.formulate_plan(finding, context)

        # Invariant 1: Exactly 1 target file and line
        assert plan.target_file == "src/payment.py"
        assert plan.target_line == 100
        assert plan.rule_id == "CRITICAL_AUTH_BYPASS"

        # Invariant 2: PR title follows conventional format with single file
        assert plan.pr_title == "fix(payment): resolve CRITICAL_AUTH_BYPASS in payment.py"

        # Invariant 3: Instructions must explicitly forbid touching any other bug or file
        inst_text = "\n".join(plan.patch_instructions)
        assert "Strict Invariant: One Bug = One PR." in inst_text
        assert "Fix ONLY this functional issue." in inst_text
        assert "Do NOT modify any other functions or files." in inst_text

    def test_diff_budget_ceiling_permanently_stated_and_uncompromised(self):
        """Verify that diff ceiling (<=150 lines, <=3 files) is permanently stated across all representations."""
        planner = PatchPlanningSkill()
        finding = TriagedFinding(
            id="src/core.py:1:BUG",
            primary_axis="correctness",
            severity="ERROR",
            composite_score=150.0,
            blast_radius_score=0.0,
            is_trust_boundary=False,
            inbound_dependents_count=0,
            tools_reporting=["flake8"],
            file="src/core.py",
            line=1,
            column=1,
            rule_id="BUG",
            message="Something broken",
            code_snippet="",
        )
        context = ExtractedContext(
            file_path="src/core.py",
            target_line=1,
            enclosing_symbol="def run",
            imports_slice="",
            code_slice="def run(): pass",
            context_type="ast_python",
            total_lines=10,
            formatted_prompt_block="===",
        )

        plan = planner.formulate_plan(finding, context)

        # Budget constants on dataclass
        assert plan.diff_ceiling_lines == 150
        assert plan.diff_ceiling_files == 3

        # Budget constraints in instructions
        assert any("<= 150 lines of diff and at most 3 files" in inst for inst in plan.patch_instructions)

        # Budget constraints in PR body
        assert "diff <= 150 lines" in plan.pr_body

        # Budget constraints in Aider prompt
        assert "<= 150 lines" in plan.aider_prompt

    def test_scope_synthesis_adversarial_paths(self):
        """Stress-test scope synthesis with adversarial, weird, and malicious paths."""
        planner = PatchPlanningSkill()

        # Standard file
        assert planner.synthesize_scope("src/auth.py") == "auth"

        # Hyphenated and dotted stems
        assert planner.synthesize_scope("services/order-processing.v2.py") == "order-processing.v2"

        # Windows backslashes and quotes
        assert planner.synthesize_scope('"C:\\app\\src\\database_pool.py"') == "database_pool"

        # Weird characters and spaces
        assert planner.synthesize_scope("src/my $weird%module^.py") == "myweirdmodule"

        # Empty or root-only paths should fall back to 'core'
        assert planner.synthesize_scope("") == "core"
        assert planner.synthesize_scope("   ") == "core"
        assert planner.synthesize_scope("///") == "core"
        assert planner.synthesize_scope("!!!@@@###$$$") == "core"

    def test_aider_prompt_syntax_integrity_with_multiline_and_shell_chars(self):
        """Verify prompt formatting does not break when message contains multiline, quotes, backticks, or shell chars."""
        planner = PatchPlanningSkill()
        adversarial_msg = (
            "Potential vulnerability:\n\t- Unsafe eval: `os.system('$USER')`\n"
            "\t- Line 2: \"quoted string\" and 'single quote' \r\n"
            "\t- Special metacharacters: $PATH, `whoami`, && rm -rf /, <xml> & </xml>"
        )
        finding = TriagedFinding(
            id="src/vuln.py:42:RCE",
            primary_axis="security",
            severity="CRITICAL",
            composite_score=200.0,
            blast_radius_score=30.0,
            is_trust_boundary=True,
            inbound_dependents_count=1,
            tools_reporting=["bandit"],
            file="src/vuln.py",
            line=42,
            column=1,
            rule_id="RCE",
            message=adversarial_msg,
            code_snippet="os.system(arg)",
        )
        context = ExtractedContext(
            file_path="src/vuln.py",
            target_line=42,
            enclosing_symbol="def execute",
            imports_slice="import os",
            code_slice="def execute(arg):\n    os.system(arg)",
            context_type="ast_python",
            total_lines=10,
            formatted_prompt_block="=== SURGICAL CONTEXT ===",
        )

        plan = planner.formulate_plan(finding, context)

        # Message in instructions must be flattened (no raw newlines/CRLF breaking list formatting)
        clean_desc = plan.patch_instructions[1]
        assert "\n" not in clean_desc
        assert "\r" not in clean_desc
        assert "\t" not in clean_desc

        # Aider prompt structure
        assert plan.aider_prompt.startswith("Fix bug `RCE` in `src/vuln.py` at line 42.")
        assert "MESSAGE:" in plan.aider_prompt
        assert "ENCLOSING SYMBOL: def execute" in plan.aider_prompt
        assert "=== SURGICAL CONTEXT ===" in plan.aider_prompt
        assert "INSTRUCTIONS:\n1. Open file" in plan.aider_prompt

    def test_massive_finding_message_prompt_generation(self):
        """Verify prompt generation survives massive finding messages without crashing."""
        planner = PatchPlanningSkill()
        huge_msg = "Error detected: " + ("overflow " * 5000)
        finding = TriagedFinding(
            id="src/big.py:1:BIG",
            primary_axis="correctness",
            severity="ERROR",
            composite_score=100.0,
            blast_radius_score=0.0,
            is_trust_boundary=False,
            inbound_dependents_count=0,
            tools_reporting=["flake8"],
            file="src/big.py",
            line=1,
            column=1,
            rule_id="BIG",
            message=huge_msg,
            code_snippet="",
        )
        context = ExtractedContext(
            file_path="src/big.py",
            target_line=1,
            enclosing_symbol="def f",
            imports_slice="",
            code_slice="def f(): pass",
            context_type="ast_python",
            total_lines=5,
            formatted_prompt_block="===",
        )

        plan = planner.formulate_plan(finding, context)
        assert len(plan.aider_prompt) > 40000
        assert plan.diff_ceiling_lines == 150


class TestAdversarialBugHunterAgentCoordinator:
    """Adversarial stress-testing of BugHunterAgent coordinator."""

    def test_analyze_and_plan_empty_and_null_inputs(self, tmp_path: Path):
        """Stress-test analyze_and_plan with empty findings lists."""
        agent = BugHunterAgent()

        assert agent.analyze_and_plan(tmp_path, []) is None
        assert agent.analyze_and_plan(tmp_path, [], skip_files=["src/a.py"]) is None

    def test_analyze_and_plan_all_cosmetic_readability_dropped(self, tmp_path: Path):
        """Verify that when 100% of raw findings are cosmetic, analyze_and_plan returns None."""
        agent = BugHunterAgent()
        cosmetic_findings = [
            RawFinding(tool="flake8", rule_id="E501", file="src/service.py", line=10, message="line too long (120 > 79)"),
            RawFinding(tool="flake8", rule_id="D101", file="src/service.py", line=20, message="Missing docstring in public class"),
            RawFinding(tool="flake8", rule_id="I001", file="src/service.py", line=1, message="Import block is unsorted"),
            RawFinding(tool="flake8", rule_id="W291", file="src/service.py", line=5, message="trailing whitespace"),
            RawFinding(tool="flake8", rule_id="COM812", file="src/service.py", line=30, message="trailing comma missing"),
        ]

        plan = agent.analyze_and_plan(tmp_path, cosmetic_findings)
        assert plan is None

    def test_analyze_and_plan_with_non_existent_files(self, tmp_path: Path):
        """Verify behavior when raw findings reference non-existent files."""
        agent = BugHunterAgent()
        findings = [
            RawFinding(
                tool="semgrep",
                rule_id="python.security.command-injection",
                file="src/non_existent_module.py",
                line=42,
                severity="ERROR",
                message="Command injection via subprocess",
            )
        ]

        # Repo path exists, but the file inside does not exist
        plan = agent.analyze_and_plan(tmp_path, findings)

        # Agent should gracefully generate a plan with empty context rather than raising FileNotFoundError
        assert plan is not None
        assert plan.target_file == "src/non_existent_module.py"
        assert plan.target_line == 42
        assert "(File Not Found)" in plan.patch_instructions[0]
        assert plan.diff_ceiling_lines == 150
        assert plan.diff_ceiling_files == 3

    def test_analyze_and_plan_with_non_existent_repo_path(self):
        """Verify behavior when repo_path itself does not exist on disk."""
        agent = BugHunterAgent()
        bogus_repo = Path("C:/definitely/non_existent_repo_dir_12345")
        findings = [
            RawFinding(
                tool="bandit",
                rule_id="B602",
                file="src/broken.py",
                line=10,
                severity="ERROR",
                message="shell=True",
            )
        ]

        # Must not crash
        plan = agent.analyze_and_plan(bogus_repo, findings)
        assert plan is not None
        assert plan.target_file == "src/broken.py"
        assert "(File Not Found)" in plan.patch_instructions[0]

    def test_analyze_and_plan_all_files_in_skip_list(self, tmp_path: Path):
        """When all findings match skip_files, analyze_and_plan returns None."""
        agent = BugHunterAgent()
        findings = [
            RawFinding(tool="flake8", rule_id="F821", file="src/skipped_a.py", line=10, severity="ERROR", message="undefined name 'x'"),
            RawFinding(tool="flake8", rule_id="F821", file="src/skipped_b.py", line=20, severity="ERROR", message="undefined name 'y'"),
        ]
        plan = agent.analyze_and_plan(
            tmp_path,
            findings,
            skip_files=["src/skipped_a.py", "src/skipped_b.py"],
        )
        assert plan is None

    def test_analyze_and_plan_picks_single_highest_priority_bug(self, tmp_path: Path):
        """Verify strict One Bug = One PR: when multiple bugs are present, only top ranked bug is planned."""
        src_dir = tmp_path / "src"
        src_dir.mkdir(parents=True)
        (src_dir / "auth.py").write_text("def login(): pass\n", encoding="utf-8")
        (src_dir / "db.py").write_text("def query(): pass\n", encoding="utf-8")

        agent = BugHunterAgent()
        findings = [
            # Low severity warning in db.py
            RawFinding(tool="flake8", rule_id="B001", file="src/db.py", line=1, severity="WARNING", message="bare except"),
            # Critical vulnerability in auth.py (web_server trust boundary)
            RawFinding(tool="bandit", rule_id="B602", file="src/auth.py", line=1, severity="HIGH", message="shell injection"),
            # Medium warning in db.py
            RawFinding(tool="flake8", rule_id="F841", file="src/db.py", line=1, severity="WARNING", message="unused variable"),
        ]

        plan = agent.analyze_and_plan(tmp_path, findings)
        assert plan is not None
        # Highest ranked bug must be chosen (B602 in auth.py)
        assert plan.target_file == "src/auth.py"
        assert plan.rule_id == "B602"
        assert plan.scope == "auth"
        assert plan.diff_ceiling_lines == 150
        assert plan.diff_ceiling_files == 3

    def test_analyze_and_plan_thread_safety_concurrency(self, tmp_path: Path):
        """Stress-test BugHunterAgent coordinator under concurrent execution across multiple threads."""
        src_dir = tmp_path / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        (src_dir / "worker.py").write_text(
            "def task(n):\n    return n * 2\n",
            encoding="utf-8",
        )

        agent = BugHunterAgent()

        def _run_worker(idx: int) -> PatchPlan | None:
            findings = [
                RawFinding(
                    tool="flake8",
                    rule_id=f"F{800 + idx}",
                    file="src/worker.py",
                    line=2,
                    severity="ERROR",
                    message=f"Error {idx}",
                )
            ]
            return agent.analyze_and_plan(tmp_path, findings)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(_run_worker, i) for i in range(20)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert len(results) == 20
        assert all(r is not None for r in results)
        assert all(r.diff_ceiling_lines == 150 for r in results)
        assert all(r.diff_ceiling_files == 3 for r in results)


class TestAdversarialContextExtractionSkill:
    """Adversarial stress-testing of ContextExtractionSkill."""

    def test_huge_python_file_does_not_dump_entire_file(self, tmp_path: Path):
        """Verify surgical slicing on a 5000-line Python file keeps prompt compact."""
        skill = ContextExtractionSkill()
        filler_lines = [f"# Filler line {i}" for i in range(1, 2000)]
        target_fn = [
            "def surgical_target_function(param: int) -> int:",
            "    # Line 2002: target bug",
            "    return param + 10",
        ]
        more_filler = [f"# Filler line {i}" for i in range(2004, 5000)]
        all_lines = filler_lines + target_fn + more_filler
        huge_file = tmp_path / "huge_module.py"
        huge_file.write_text("\n".join(all_lines), encoding="utf-8")

        ctx = skill.extract_context(tmp_path, "huge_module.py", line_number=2002)

        assert ctx.context_type == "ast_python"
        assert ctx.enclosing_symbol == "def surgical_target_function"
        assert "surgical_target_function" in ctx.code_slice
        assert ctx.total_lines == 4998
        # Context slice must be compact (< 20 lines), not the 5000 lines
        assert len(ctx.code_slice.splitlines()) < 20
        assert "Filler line 100" not in ctx.code_slice
        assert "Filler line 4000" not in ctx.code_slice

    def test_line_number_out_of_bounds(self, tmp_path: Path):
        """Verify that line numbers beyond EOF or <= 0 do not raise IndexError."""
        skill = ContextExtractionSkill()
        file_path = tmp_path / "small.py"
        file_path.write_text("x = 1\ny = 2\n", encoding="utf-8")

        # Line 0
        ctx_0 = skill.extract_context(tmp_path, "small.py", line_number=0)
        assert ctx_0.total_lines == 2

        # Line negative
        ctx_neg = skill.extract_context(tmp_path, "small.py", line_number=-10)
        assert ctx_neg.total_lines == 2

        # Line 999999
        ctx_huge = skill.extract_context(tmp_path, "small.py", line_number=999999)
        assert ctx_huge.total_lines == 2

    def test_binary_and_non_utf8_file_handling(self, tmp_path: Path):
        """Verify graceful fallback with replacement characters for non-UTF-8 content."""
        skill = ContextExtractionSkill()
        bin_file = tmp_path / "corrupted.py"
        # Write bytes that are invalid UTF-8
        bin_file.write_bytes(b"import sys\n\xff\xfe\x00\x01\x80\x81\nprint('hello')\n")

        ctx = skill.extract_context(tmp_path, "corrupted.py", line_number=1)
        # Should gracefully read with replacement chars and fallback to text_window due to syntax error
        assert ctx.total_lines > 0
        assert ctx.context_type in ("ast_python", "text_window")

    def test_deeply_nested_classes_and_functions(self, tmp_path: Path):
        """Verify extraction inside deeply nested classes and functions."""
        skill = ContextExtractionSkill()
        source = (
            "class Outer:\n"
            "    class Inner:\n"
            "        def method(self):\n"
            "            def helper():\n"
            "                # Line 5: deeply nested\n"
            "                return 42\n"
            "            return helper()\n"
        )
        f = tmp_path / "nested.py"
        f.write_text(source, encoding="utf-8")

        ctx = skill.extract_context(tmp_path, "nested.py", line_number=5)
        assert ctx.context_type == "ast_python"
        # Enclosing symbol should capture innermost function helper
        assert "helper" in ctx.enclosing_symbol
        assert "return 42" in ctx.code_slice


# ==============================================================================
# EMPIRICAL BUG REPRODUCERS (XFAIL: Confirmed Edge Case Flaws in Milestone 2)
# ==============================================================================


class TestEmpiricalBugReproducers:
    """
    Empirical tests demonstrating confirmed bugs and edge cases in Milestone 2 implementation:
    1. Cosmetic finding with snippet swallows real security finding due to pre-axis best selection.
    2. Transitive chaining in proximity clustering collapses distinct bugs across entire files.
    3. analyze_and_plan returns plan for non-existent file when valid file is available.
    """

    @pytest.mark.xfail(reason="Bug: Cosmetic finding with code snippet swallows real security finding in same cluster")
    def test_bug_1_cosmetic_finding_with_snippet_swallows_security_vulnerability(self, tmp_path: Path):
        """
        When a cosmetic finding (e.g. E501) on line 11 has a code snippet and a Bandit security
        finding on line 10 does not, max(cluster) selects E501 based on snippet presence.
        Then E501 is classified as READABILITY, causing the entire cluster (and the security bug)
        to be silently dropped.
        Expected: The security bug must survive triage and be ranked at the top.
        """
        skill = TriageSkill()
        f_sec = RawFinding(
            tool="bandit",
            rule_id="B602",
            file="src/service.py",
            line=10,
            severity="WARNING",
            message="subprocess call with shell=True",
            code_snippet="",
        )
        f_cosmetic = RawFinding(
            tool="flake8",
            rule_id="E501",
            file="src/service.py",
            line=11,
            severity="WARNING",
            message="line too long (88 > 79 characters)",
            code_snippet="a = b + c",
        )

        triaged = skill.triage_and_rank([f_sec, f_cosmetic], repo_path=tmp_path)

        # The security bug MUST survive triage
        assert len(triaged) == 1, f"Expected 1 triaged security bug, got {len(triaged)} (dropped!)"
        assert triaged[0].rule_id == "B602"
        assert triaged[0].primary_axis == FiveAxisTriageEngine.AXIS_SECURITY

    @pytest.mark.xfail(reason="Bug: Transitive chaining in deduplicate merges distinct bugs across entire file into 1 cluster")
    def test_bug_2_deduplicate_transitive_chaining_collapses_distinct_bugs(self):
        """
        When findings occur on lines 1, 3, 5, 7, 9, 11, 13, 15, 17, 19,
        abs(f.line - current_cluster[-1].line) <= 2 transitively chains all 10 distinct bugs
        into a single cluster, discarding 9 of them.
        Expected: Clusters should not chain across >2 lines from the cluster base.
        """
        skill = TriageSkill()
        findings = [
            RawFinding(
                tool="flake8",
                rule_id=f"F82{i}",
                file="src/app.py",
                line=2 * i + 1,
                severity="ERROR",
                message=f"Undefined name var_{i}",
            )
            for i in range(10)
        ]
        clusters = skill.deduplicate(findings)

        # 10 findings separated by 2 lines spanning line 1 to 19 should NOT be 1 single cluster
        assert len(clusters) > 1, f"Expected multiple bounded clusters, but got 1 chained cluster of size {len(clusters[0])}"

    @pytest.mark.xfail(reason="Bug: analyze_and_plan returns plan for non-existent file instead of advancing to valid file")
    def test_bug_3_analyze_and_plan_selects_non_existent_file_over_valid_existing_file(self, tmp_path: Path):
        """
        When top ranked finding points to a non-existent file on disk and second finding points
        to an existing file, analyze_and_plan generates an invalid plan with (File Not Found)
        rather than advancing to the valid existing file.
        Expected: Plan should target the valid file that exists on disk.
        """
        src_dir = tmp_path / "src"
        src_dir.mkdir(parents=True)
        valid_file = src_dir / "valid_service.py"
        valid_file.write_text("def handle():\n    return 42\n", encoding="utf-8")

        agent = BugHunterAgent()
        findings = [
            # Higher score but file does not exist
            RawFinding(
                tool="semgrep",
                rule_id="python.security.command-injection",
                file="src/deleted_script.py",
                line=5,
                severity="ERROR",
                message="Command injection in deleted script",
            ),
            # Valid file that exists on disk
            RawFinding(
                tool="flake8",
                rule_id="F821",
                file="src/valid_service.py",
                line=2,
                severity="ERROR",
                message="undefined name in valid service",
            ),
        ]

        plan = agent.analyze_and_plan(tmp_path, findings)
        assert plan is not None
        assert plan.target_file == "src/valid_service.py", (
            f"Expected plan for existing file 'src/valid_service.py', but got '{plan.target_file}'"
        )

