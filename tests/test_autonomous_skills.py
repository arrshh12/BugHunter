"""
Autonomous Skills Test Suite Alias & Compatibility Wrapper.
Tests bug finding and code writing agent skills and verifies prompt files.
"""

from __future__ import annotations

from pathlib import Path
import pytest

from tests.test_agent_skills import (
    test_five_axis_weights_and_ordering,
    test_five_axis_triage_ranking_ordering,
    test_severity_multipliers_preserve_hierarchical_order,
    test_filtering_of_readability_noise,
    test_trust_boundary_path_detection,
    test_trust_boundary_score_elevation,
    test_stride_and_owasp_mapping,
    test_verifier_conventional_commit_validation,
    test_verifier_scope_synthesis,
    test_verifier_validate_reproducer_fields,
    test_verifier_reproducer_enforcement_in_pipeline,
    test_git_manager_scoped_atomic_branch,
    test_task_prompt_stop_the_line_content,
    test_cosmetic_comment_rules_dropped_from_triage,
    test_trust_boundary_windows_casing_and_backslashes,
    test_trust_boundary_score_elevation_with_casing,
)


def test_bug_finder_prompt_file_contents():
    """Verify prompts/bug_finder_prompt.txt codifies 5-axis triage and threat modeling."""
    prompt_path = Path("prompts/bug_finder_prompt.txt")
    assert prompt_path.exists(), "prompts/bug_finder_prompt.txt must exist"
    content = prompt_path.read_text(encoding="utf-8")
    assert "5-AXIS TRIAGE STANDARD" in content
    assert "code-review-and-quality" in content
    assert "Correctness (Weight: 100)" in content
    assert "Security (Weight: 100)" in content
    assert "Readability (Weight: 0 - AUTOMATIC DROP)" in content
    assert "BOUNDARY DEFENSE & THREAT MODELING" in content
    assert "security-and-hardening" in content
    assert "STRIDE Classification" in content
    assert "OWASP Top 10 Mapping" in content
