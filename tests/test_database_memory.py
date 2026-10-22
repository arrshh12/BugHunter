"""
Comprehensive tests for Layer 1 Episodic & Rejection Memory (sqlite-vec + DeterministicCodeVectorizer).
"""

from __future__ import annotations

import concurrent.futures
import sqlite3
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from src.database import Database, DeterministicCodeVectorizer


def test_vectorizer_deterministic_properties():
    """Verify DeterministicCodeVectorizer generates 384-dim normalized unit vectors."""
    code_a = "def process_data(items, cache={}):\n    return cache.get(items)"
    code_renamed = "def process_data(elements, cache={}):\n    return cache.get(elements)"
    code_different = "import os\nos.system('rm -rf /')"

    vec_a = DeterministicCodeVectorizer.vectorize(code_a, rule_id="B006")
    assert len(vec_a) == 384
    # Check L2 norm is ~ 1.0
    norm = sum(x * x for x in vec_a) ** 0.5
    assert pytest.approx(norm, rel=1e-4) == 1.0

    # Same snippet produces identical vector
    vec_a2 = DeterministicCodeVectorizer.vectorize(code_a, rule_id="B006")
    dot_identical = sum(x * y for x, y in zip(vec_a, vec_a2))
    assert pytest.approx(dot_identical, rel=1e-5) == 1.0

    # Renamed variable retains high similarity > 0.88
    vec_renamed = DeterministicCodeVectorizer.vectorize(code_renamed, rule_id="B006")
    dot_renamed = sum(x * y for x, y in zip(vec_a, vec_renamed))
    assert dot_renamed > 0.88

    # Completely different code has much lower similarity
    vec_diff = DeterministicCodeVectorizer.vectorize(code_different, rule_id="S605")
    dot_diff = sum(x * y for x, y in zip(vec_a, vec_diff))
    assert dot_diff < 0.60

    # Serialization round-trip
    b = DeterministicCodeVectorizer.to_bytes(vec_a)
    assert len(b) == 384 * 4  # 384 32-bit floats = 1536 bytes
    unpacked = DeterministicCodeVectorizer.from_bytes(b)
    assert len(unpacked) == 384
    assert pytest.approx(unpacked[0], rel=1e-5) == vec_a[0]


def test_sqlite_vec_loaded(tmp_path: Path):
    """Verify sqlite-vec extension is loaded on database connections."""
    db = Database(tmp_path / "vec_test.sqlite")
    with db.get_connection() as conn:
        try:
            row = conn.execute("SELECT vec_version()").fetchone()
            assert row is not None
            assert str(row[0]).startswith("v0.")
        except sqlite3.OperationalError:
            pytest.skip("sqlite-vec not loaded or not supported in this environment")


def test_bug_memory_schema_and_triggers_sync(tmp_path: Path):
    """Verify bug_memory table, bug_memory_vec virtual table, and triggers synchronize properly."""
    db = Database(tmp_path / "sync_test.sqlite")
    with db.get_connection() as conn:
        if not db._has_vec_table(conn):
            pytest.skip("sqlite-vec not supported in this environment")

    # Insert a bug memory record
    snippet = "def fetch(url, headers={}):\n    pass"
    row_id = db.record_bug_memory(
        repo_slug="pallets/flask",
        commit_sha="a1b2c3d4",
        rule_id="B006",
        file_path="src/flask/app.py",
        code_snippet=snippet,
        patch_outcome="false_positive",
        rejection_reason="Singleton headers dictionary pattern intended",
        stride_category="Denial of Service",
        owasp_category="A03:2021-Injection",
    )
    assert row_id > 0

    # Verify insertion in relational table and automatic vector table sync
    with db.get_connection() as conn:
        r_rel = conn.execute("SELECT * FROM bug_memory WHERE id = ?", (row_id,)).fetchone()
        assert r_rel is not None
        assert r_rel["rule_id"] == "B006"
        assert r_rel["patch_outcome"] == "false_positive"
        assert r_rel["stride_category"] == "Denial of Service"
        assert r_rel["owasp_category"] == "A03:2021-Injection"
        assert r_rel["embedding"] is not None

        r_vec = conn.execute("SELECT count(*) FROM bug_memory_vec WHERE id = ?", (row_id,)).fetchone()
        assert r_vec[0] == 1

        # Test trigger update
        new_vec = DeterministicCodeVectorizer.vectorize("def fetch_updated(): pass", rule_id="B006")
        new_bytes = DeterministicCodeVectorizer.to_bytes(new_vec)
        conn.execute("UPDATE bug_memory SET embedding = ? WHERE id = ?", (new_bytes, row_id))

        # Check vector table still has 1 row and matches new vector
        row_vec_check = conn.execute("""
            SELECT id, (1.0 - distance) as sim
            FROM bug_memory_vec
            WHERE embedding MATCH ? AND k = 1
        """, (new_bytes,)).fetchone()
        assert row_vec_check is not None
        assert row_vec_check[0] == row_id
        assert pytest.approx(row_vec_check[1], rel=1e-4) == 1.0

        # Test trigger delete
        conn.execute("DELETE FROM bug_memory WHERE id = ?", (row_id,))
        count_vec = conn.execute("SELECT count(*) FROM bug_memory_vec WHERE id = ?", (row_id,)).fetchone()[0]
        assert count_vec == 0


def test_query_similar_bugs_and_prefilter(tmp_path: Path):
    """Verify KNN cosine similarity search with distance < 0.12 (similarity > 0.88)."""
    db = Database(tmp_path / "filter_test.sqlite")

    snippet_orig = "def compute(cache={}):\n    return cache"
    db.record_bug_memory(
        repo_slug="test/repo",
        commit_sha="c1",
        rule_id="B006",
        file_path="src/util.py",
        code_snippet=snippet_orig,
        patch_outcome="false_positive",
        rejection_reason="Mutable cache default is expected cache store",
    )

    # 1. Exact query should have similarity ~ 1.0
    results = db.query_similar_bugs(snippet_orig, rule_id="B006", threshold=0.88)
    assert len(results) == 1
    assert results[0]["rule_id"] == "B006"
    assert results[0]["similarity"] >= 0.99
    assert results[0]["distance"] <= 0.01

    # 2. Renamed variable query should have similarity > 0.88
    snippet_minor = "def compute(memo={}):\n    return memo"
    should_skip, reason = db.should_skip_finding(snippet_minor, rule_id="B006", threshold=0.88)
    assert should_skip is True
    assert reason is not None
    assert "false_positive" in reason
    assert "B006" in reason

    # 3. Different bug rule should not be skipped
    snippet_other = "x = eval(user_input)"
    should_skip, reason = db.should_skip_finding(snippet_other, rule_id="S102", threshold=0.88)
    assert should_skip is False
    assert reason is None


def test_should_skip_finding_outcomes(tmp_path: Path):
    """Verify should_skip_finding only triggers on 'false_positive' or 'rejected' outcomes."""
    db = Database(tmp_path / "outcomes_test.sqlite")

    # Record verified fix
    db.record_bug_memory(
        repo_slug="test/repo",
        commit_sha="c1",
        rule_id="E501",
        file_path="src/main.py",
        code_snippet="line = 'a' * 120",
        patch_outcome="applied",
    )

    # Even with identical code, an 'applied' outcome does not cause skipping
    skip, reason = db.should_skip_finding("line = 'a' * 120", rule_id="E501", threshold=0.88)
    assert skip is False
    assert reason is None

    # Now record rejected fix
    db.record_bug_memory(
        repo_slug="test/repo",
        commit_sha="c2",
        rule_id="E501",
        file_path="src/main.py",
        code_snippet="line = 'b' * 120",
        patch_outcome="rejected",
        rejection_reason="Exceeded 150 lines diff budget",
    )

    skip_rej, reason_rej = db.should_skip_finding("line = 'b' * 120", rule_id="E501", threshold=0.88)
    assert skip_rej is True
    assert reason_rej is not None
    assert "rejected" in reason_rej
    assert "Exceeded 150 lines diff budget" in reason_rej


def test_pure_python_fallback_mode(tmp_path: Path):
    """Verify fallback mode works using pure Python cosine distance when sqlite-vec table is unavailable."""
    db = Database(tmp_path / "fallback_test.sqlite")

    snippet = "def parse(cfg={}): pass"
    db.record_bug_memory(
        repo_slug="test/repo",
        commit_sha="c1",
        rule_id="B006",
        file_path="src/parser.py",
        code_snippet=snippet,
        patch_outcome="false_positive",
        rejection_reason="Config default singleton",
    )

    # Force _has_vec_table to return False to test fallback code path
    with patch.object(db, "_has_vec_table", return_value=False):
        results = db.query_similar_bugs(snippet, rule_id="B006", threshold=0.88)
        assert len(results) == 1
        assert results[0]["rule_id"] == "B006"
        assert results[0]["similarity"] >= 0.99

        skip, reason = db.should_skip_finding(snippet, rule_id="B006", threshold=0.88)
        assert skip is True
        assert "false_positive" in reason


def test_multithreaded_bug_memory_concurrency(tmp_path: Path):
    """Verify concurrent reads and writes to bug_memory do not deadlock in WAL mode."""
    db = Database(tmp_path / "concurrent_vec.sqlite")

    def writer_task(idx: int):
        for i in range(10):
            db.record_bug_memory(
                repo_slug="owner/repo",
                commit_sha=f"sha_{idx}_{i}",
                rule_id=f"RULE_{idx % 3}",
                file_path=f"src/file_{i}.py",
                code_snippet=f"def func_{idx}_{i}(x=[]): return x",
                patch_outcome="rejected" if (idx + i) % 2 == 0 else "verified",
                rejection_reason=f"Test rejection {idx}-{i}",
            )

    def reader_task(idx: int):
        for _ in range(10):
            db.query_similar_bugs(
                code_snippet=f"def func_{idx}_0(x=[]): return x",
                rule_id=f"RULE_{idx % 3}",
                threshold=0.85,
            )

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        writer_futures = [executor.submit(writer_task, i) for i in range(4)]
        reader_futures = [executor.submit(reader_task, i) for i in range(4)]
        for f in concurrent.futures.as_completed(writer_futures + reader_futures):
            f.result()

    with db.get_connection() as conn:
        count = conn.execute("SELECT count(*) FROM bug_memory").fetchone()[0]
        assert count == 40
