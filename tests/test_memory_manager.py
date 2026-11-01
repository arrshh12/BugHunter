"""
Unit tests for src/memory_manager.py (Unified MemoryManager).
Tests Layer 1 episodic recall, false positive checks, and Layer 2 structural graph integration.
"""

from __future__ import annotations

from pathlib import Path
import pytest

from src.database import Database
from src.memory_manager import MemoryManager


@pytest.fixture
def mem_setup(tmp_path: Path):
    db_path = tmp_path / "test_mem.sqlite"
    db = Database(db_path)
    repo_path = tmp_path / "mock_repo"
    repo_path.mkdir(parents=True, exist_ok=True)
    src_dir = repo_path / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "service.py").write_text(
        "def compute_total(items, cache={}):\n    return sum(items)\n",
        encoding="utf-8"
    )
    mm = MemoryManager(db, repo_path=repo_path)
    return mm, db, repo_path


def test_memory_manager_record_and_check_fp(mem_setup):
    mm, db, repo_path = mem_setup
    code = "def compute_total(items, cache={}):\n    return sum(items)\n"

    # Initially, no past false positive
    skip, reason = mm.check_past_false_positive(code, rule_id="B006")
    assert skip is False
    assert reason is None

    # Record false positive
    row_id = mm.record_bug_outcome(
        repo_slug="owner/mock-repo",
        snippet=code,
        outcome="false_positive",
        reason="Default dict cache intentional in test",
        rule_id="B006",
        file_path="src/service.py",
        stride_category="Denial of Service",
        owasp_category="A03:2021-Injection",
    )
    assert row_id > 0

    # Now should skip with > 0.88 similarity
    skip2, reason2 = mm.check_past_false_positive(code, rule_id="B006")
    assert skip2 is True
    assert "false_positive" in reason2
    assert "Default dict cache intentional in test" in reason2


def test_memory_manager_structural_context(mem_setup):
    mm, db, repo_path = mem_setup

    ctx = mm.get_structural_context("src/service.py", line_number=1)
    assert ctx is not None
    assert ctx.target_file == "src/service.py"
    assert any("compute_total" in s for s in ctx.target_symbols)

    prompt_ctx = mm.generate_prompt_context("src/service.py", line_number=1)
    assert "LAYER 2 STRUCTURAL CODEBASE MEMORY" in prompt_ctx
    assert "def compute_total(items, cache)" in prompt_ctx
