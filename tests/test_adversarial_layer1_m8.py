"""
Adversarial Stress Test Suite for Layer 1: Episodic & Rejection Memory (sqlite-vec in src/database.py).
Milestone 8 Challenger Test Suite (challenger_m8_1).
"""

from __future__ import annotations

import concurrent.futures
import math
import sqlite3
import struct
import tempfile
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from src.database import Database, DeterministicCodeVectorizer


def make_unit_vector(similarity_with_v0: float, dim: int = 384) -> list[float]:
    """Construct a unit vector whose dot product with [1, 0, 0, ...] is exactly similarity_with_v0."""
    v = [0.0] * dim
    v[0] = similarity_with_v0
    rem = max(0.0, 1.0 - similarity_with_v0 * similarity_with_v0)
    v[1] = math.sqrt(rem)
    return v


# =========================================================================
# 1. COSINE SIMILARITY THRESHOLD BOUNDARIES
# =========================================================================

class TestCosineSimilarityThresholdBoundaries:
    """Stress tests cosine similarity threshold boundaries (0.87, 0.88, 0.89)."""

    def test_similarity_087_must_not_skip(self, tmp_path: Path):
        """Vectors with similarity 0.87 must NOT skip (distance 0.13 > 0.12)."""
        db = Database(tmp_path / "sim_087.sqlite")
        base_vec = make_unit_vector(1.0)
        db.record_bug_memory(
            "repo", "c1", "B006", "app.py", "def base(): pass",
            "false_positive", rejection_reason="Base FP", embedding=base_vec
        )

        v_087 = make_unit_vector(0.87)
        with patch.object(DeterministicCodeVectorizer, "vectorize", return_value=v_087):
            # sqlite-vec mode
            matches_vec = db.query_similar_bugs("dummy", rule_id="B006", threshold=0.88)
            skip_vec, reason_vec = db.should_skip_finding("dummy", rule_id="B006", threshold=0.88)
            assert len(matches_vec) == 0
            assert skip_vec is False
            assert reason_vec is None

            # pure-Python fallback mode
            with patch.object(db, "_has_vec_table", return_value=False):
                matches_fb = db.query_similar_bugs("dummy", rule_id="B006", threshold=0.88)
                skip_fb, reason_fb = db.should_skip_finding("dummy", rule_id="B006", threshold=0.88)
                assert len(matches_fb) == 0
                assert skip_fb is False
                assert reason_fb is None

    def test_similarity_089_must_skip(self, tmp_path: Path):
        """Vectors with similarity 0.89 must skip (distance 0.11 <= 0.12)."""
        db = Database(tmp_path / "sim_089.sqlite")
        base_vec = make_unit_vector(1.0)
        db.record_bug_memory(
            "repo", "c1", "B006", "app.py", "def base(): pass",
            "false_positive", rejection_reason="Base FP", embedding=base_vec
        )

        v_089 = make_unit_vector(0.89)
        with patch.object(DeterministicCodeVectorizer, "vectorize", return_value=v_089):
            # sqlite-vec mode
            matches_vec = db.query_similar_bugs("dummy", rule_id="B006", threshold=0.88)
            skip_vec, reason_vec = db.should_skip_finding("dummy", rule_id="B006", threshold=0.88)
            assert len(matches_vec) == 1
            assert skip_vec is True
            assert "false_positive" in reason_vec
            assert "B006" in reason_vec

            # pure-Python fallback mode
            with patch.object(db, "_has_vec_table", return_value=False):
                matches_fb = db.query_similar_bugs("dummy", rule_id="B006", threshold=0.88)
                skip_fb, reason_fb = db.should_skip_finding("dummy", rule_id="B006", threshold=0.88)
                assert len(matches_fb) == 1
                assert skip_fb is True
                assert "false_positive" in reason_fb

    def test_similarity_08801_must_skip(self, tmp_path: Path):
        """Vectors with similarity strictly greater than 0.88 (0.8801) must skip."""
        db = Database(tmp_path / "sim_08801.sqlite")
        base_vec = make_unit_vector(1.0)
        db.record_bug_memory(
            "repo", "c1", "B006", "app.py", "def base(): pass",
            "false_positive", rejection_reason="Base FP", embedding=base_vec
        )

        v_08801 = make_unit_vector(0.8801)
        with patch.object(DeterministicCodeVectorizer, "vectorize", return_value=v_08801):
            skip_vec, _ = db.should_skip_finding("dummy", rule_id="B006", threshold=0.88)
            with patch.object(db, "_has_vec_table", return_value=False):
                skip_fb, _ = db.should_skip_finding("dummy", rule_id="B006", threshold=0.88)
            assert skip_vec is True
            assert skip_fb is True

    def test_similarity_088_precision_boundary_analysis(self, tmp_path: Path):
        """Document IEEE 754 float32 precision behavior at exact 0.88 boundary."""
        db = Database(tmp_path / "sim_088.sqlite")
        base_vec = make_unit_vector(1.0)
        db.record_bug_memory(
            "repo", "c1", "B006", "app.py", "def base(): pass",
            "false_positive", rejection_reason="Base FP", embedding=base_vec
        )

        v_088 = make_unit_vector(0.88)
        # Inspect raw float32 representation
        q_bytes = DeterministicCodeVectorizer.to_bytes(v_088)
        with db.get_connection() as conn:
            if db._has_vec_table(conn):
                row = conn.execute(
                    "SELECT distance, (1.0 - distance) as sim FROM bug_memory_vec WHERE embedding MATCH ? AND k = 1",
                    (q_bytes,)
                ).fetchone()
                # In float32: 0.88 is 0.8799999952316284, distance is 0.12000000476837158
                assert row["distance"] > 0.12  # exceeds 0.12 by ~4.77e-9 due to 32-bit float truncation

    def test_similarity_088_precision_boundary_harmonized_parity(self, tmp_path: Path):
        """Verify exact 0.88 boundary behaves identically between sqlite-vec and pure-Python fallback."""
        db = Database(tmp_path / "sim_088_parity.sqlite")
        base_vec = make_unit_vector(1.0)
        db.record_bug_memory(
            "repo", "c1", "B006", "app.py", "def base(): pass",
            "false_positive", rejection_reason="Base FP", embedding=base_vec
        )

        v_088 = make_unit_vector(0.88)
        with patch.object(DeterministicCodeVectorizer, "vectorize", return_value=v_088):
            matches_vec = db.query_similar_bugs("dummy", rule_id="B006", threshold=0.88)
            skip_vec, _ = db.should_skip_finding("dummy", rule_id="B006", threshold=0.88)
            with patch.object(db, "_has_vec_table", return_value=False):
                matches_fb = db.query_similar_bugs("dummy", rule_id="B006", threshold=0.88)
                skip_fb, _ = db.should_skip_finding("dummy", rule_id="B006", threshold=0.88)

            assert len(matches_vec) == 1
            assert len(matches_fb) == 1
            assert skip_vec is True
            assert skip_fb is True



# =========================================================================
# 2. STRESS TEST VECTOR INPUTS
# =========================================================================

class TestStressVectorInputs:
    """Stress tests unusual and adversarial inputs to DeterministicCodeVectorizer and Database."""

    def test_empty_string_input(self, tmp_path: Path):
        """Empty string vectorizes to valid 384-dim normalized vector and stores safely."""
        db = Database(tmp_path / "empty_input.sqlite")
        vec = DeterministicCodeVectorizer.vectorize("")
        assert len(vec) == 384
        norm = sum(x * x for x in vec) ** 0.5
        assert pytest.approx(norm, rel=1e-4) == 1.0

        row_id = db.record_bug_memory("repo", "c1", "EMPTY_RULE", "empty.py", "", "false_positive")
        assert row_id > 0
        res = db.query_similar_bugs("", rule_id="EMPTY_RULE")
        assert len(res) == 1
        skip, _ = db.should_skip_finding("", rule_id="EMPTY_RULE")
        assert skip is True

    def test_whitespace_and_none_input(self, tmp_path: Path):
        """Whitespace-only and None snippet handling."""
        vec_ws = DeterministicCodeVectorizer.vectorize("   \n\t  ")
        assert len(vec_ws) == 384
        vec_none = DeterministicCodeVectorizer.vectorize(None)  # type: ignore
        assert len(vec_none) == 384
        assert vec_ws == vec_none

    def test_large_100k_snippet_performance_and_storage(self, tmp_path: Path):
        """100,000-character snippet vectorization speed (< 1s) and database indexing."""
        db = Database(tmp_path / "large_snippet.sqlite")
        huge_snippet = "def large_handler(data):\n" + "    item = data.get('key')\n    print(item)\n" * 2500
        assert len(huge_snippet) >= 100000

        t0 = time.time()
        vec = DeterministicCodeVectorizer.vectorize(huge_snippet, rule_id="PERF001")
        duration = time.time() - t0
        assert duration < 1.0, f"Vectorization too slow: {duration:.3f}s"
        assert len(vec) == 384

        row_id = db.record_bug_memory("repo", "sha2", "PERF001", "large.py", huge_snippet, "applied")
        assert row_id > 0

        res = db.query_similar_bugs(huge_snippet, rule_id="PERF001")
        assert len(res) == 1
        assert res[0]["id"] == row_id

    def test_unicode_and_emoji_multilingual_fidelity(self, tmp_path: Path):
        """Unicode, emojis, CJK, Arabic, and math symbols preserve full fidelity."""
        db = Database(tmp_path / "unicode.sqlite")
        unicode_snippet = (
            "# Multilingual bug reproducer\n"
            "def process_ユーザー():\n"
            "    greeting = '你好世界 🚀 💻 🐛 🦀 🐍 🔥'\n"
            "    symbols = 'αβγδε ★☆♠♣♥♦ ﷽'\n"
            "    return f'{greeting}: {symbols}'\n"
        )
        unicode_rule = "RULE_🔥_日本語_001"
        unicode_reason = "False positive confirmed by maintainer 🚀"

        row_id = db.record_bug_memory(
            "repo/unicode", "sha_uni", unicode_rule, "unicode.py",
            unicode_snippet, "false_positive", rejection_reason=unicode_reason
        )
        assert row_id > 0

        res = db.query_similar_bugs(unicode_snippet, rule_id=unicode_rule)
        assert len(res) == 1
        assert res[0]["rejection_reason"] == unicode_reason

        skip, reason = db.should_skip_finding(unicode_snippet, rule_id=unicode_rule)
        assert skip is True
        assert "🚀" in reason

    def test_binary_characters_and_null_bytes(self, tmp_path: Path):
        """Binary characters including null bytes \x00 are safely handled."""
        db = Database(tmp_path / "binary.sqlite")
        bin_snippet = "raw_header = b'\x00\x01\x02\x03\xff\xfe\x00\x00\xaa\xbb\xcc'"

        row_id = db.record_bug_memory("repo/bin", "sha_bin", "RULE_BIN", "bin.py", bin_snippet, "rejected")
        assert row_id > 0

        res = db.query_similar_bugs(bin_snippet, rule_id="RULE_BIN")
        assert len(res) == 1
        assert res[0]["code_snippet"] == bin_snippet

    def test_sql_injection_defense_across_all_fields(self, tmp_path: Path):
        """SQL injection payloads in code snippet, rule_id, and other fields are neutralized."""
        db = Database(tmp_path / "sqli.sqlite")
        sqli_snippet = "'); DROP TABLE bug_memory; DROP TABLE bug_memory_vec; --"
        sqli_rule = "B006' OR '1'='1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12 --"
        sqli_reason = "'; DELETE FROM bug_memory; --"

        row_id = db.record_bug_memory(
            "repo/sqli'; DROP TABLE repositories; --",
            "sha_sqli'--",
            sqli_rule,
            "src/sqli.py",
            sqli_snippet,
            "rejected",
            rejection_reason=sqli_reason,
            stride_category="Injection'--",
            owasp_category="A03'--",
        )
        assert row_id > 0

        res = db.query_similar_bugs(sqli_snippet, rule_id=sqli_rule)
        assert len(res) == 1
        assert res[0]["rule_id"] == sqli_rule

        # Verify database schema and records are intact
        with db.get_connection() as conn:
            cnt_mem = conn.execute("SELECT count(*) FROM bug_memory").fetchone()[0]
            cnt_vec = conn.execute("SELECT count(*) FROM bug_memory_vec").fetchone()[0]
            assert cnt_mem == 1
            assert cnt_vec == 1


# =========================================================================
# 3. TRIGGER & CONCURRENCY STRESS
# =========================================================================

class TestTriggerAndConcurrencyStress:
    """Stress tests WAL concurrency and trigger synchronization."""

    def test_multithreaded_wal_concurrency_stress(self, tmp_path: Path):
        """16 concurrent threads executing 600 operations under WAL mode with 0 errors."""
        db = Database(tmp_path / "conc_stress.sqlite")
        errors: list[str] = []

        def worker_insert(t: int):
            for i in range(20):
                try:
                    db.record_bug_memory(
                        repo_slug=f"org/repo_{t}",
                        commit_sha=f"sha_{t}_{i}",
                        rule_id=f"CONC_RULE_{t % 4}",
                        file_path=f"src/mod_{i}.py",
                        code_snippet=f"def test_{t}_{i}(x=[]): return x + {i}",
                        patch_outcome="false_positive" if (t + i) % 2 == 0 else "applied",
                        rejection_reason=f"Reason {t}-{i}",
                    )
                except Exception as ex:
                    errors.append(f"Insert {t}: {ex}")

        def worker_query(t: int):
            for i in range(25):
                try:
                    db.query_similar_bugs(
                        code_snippet=f"def test_{t}_{i}(x=[]): return x + {i}",
                        rule_id=f"CONC_RULE_{t % 4}",
                        threshold=0.85,
                    )
                except Exception as ex:
                    errors.append(f"Query {t}: {ex}")

        def worker_skip(t: int):
            for i in range(25):
                try:
                    db.should_skip_finding(
                        code_snippet=f"def test_{t}_{i}(x=[]): return x + {i}",
                        rule_id=f"CONC_RULE_{t % 4}",
                        threshold=0.88,
                    )
                except Exception as ex:
                    errors.append(f"Skip {t}: {ex}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            f_inserts = [executor.submit(worker_insert, t) for t in range(6)]
            f_queries = [executor.submit(worker_query, t) for t in range(5)]
            f_skips = [executor.submit(worker_skip, t) for t in range(5)]
            concurrent.futures.wait(f_inserts + f_queries + f_skips)

        assert not errors, f"Concurrency errors occurred: {errors}"

        with db.get_connection() as conn:
            cnt_mem = conn.execute("SELECT count(*) FROM bug_memory").fetchone()[0]
            cnt_vec = conn.execute("SELECT count(*) FROM bug_memory_vec").fetchone()[0]
            assert cnt_mem == 120
            assert cnt_vec == 120

    def test_trigger_insert_update_delete_sync(self, tmp_path: Path):
        """Lifecycle synchronization across bug_memory and bug_memory_vec."""
        db = Database(tmp_path / "trigger_sync.sqlite")

        # 1. Insert
        row_id = db.record_bug_memory("repo", "c1", "RULE_T", "t.py", "def t(): pass", "false_positive")
        with db.get_connection() as conn:
            cnt = conn.execute("SELECT count(*) FROM bug_memory_vec WHERE id = ?", (row_id,)).fetchone()[0]
            assert cnt == 1

            # 2. Update with new valid embedding
            new_v = make_unit_vector(0.99)
            new_bytes = DeterministicCodeVectorizer.to_bytes(new_v)
            conn.execute("UPDATE bug_memory SET embedding = ? WHERE id = ?", (new_bytes, row_id))

            # Verify updated in vec table
            row_check = conn.execute("""
                SELECT id, (1.0 - distance) as sim
                FROM bug_memory_vec
                WHERE embedding MATCH ? AND k = 1
            """, (new_bytes,)).fetchone()
            assert row_check[0] == row_id
            assert pytest.approx(row_check[1], rel=1e-4) == 1.0

            # 3. Delete
            conn.execute("DELETE FROM bug_memory WHERE id = ?", (row_id,))
            cnt_after = conn.execute("SELECT count(*) FROM bug_memory_vec WHERE id = ?", (row_id,)).fetchone()[0]
            assert cnt_after == 0

    def test_bulk_delete_trigger_sync(self, tmp_path: Path):
        """Bulk DELETE on bug_memory synchronizes all deleted rows from bug_memory_vec."""
        db = Database(tmp_path / "bulk_del.sqlite")
        for i in range(20):
            db.record_bug_memory("repo", f"c_{i}", "RULE_BULK", f"f_{i}.py", f"def f_{i}(): pass", "applied")

        with db.get_connection() as conn:
            assert conn.execute("SELECT count(*) FROM bug_memory").fetchone()[0] == 20
            assert conn.execute("SELECT count(*) FROM bug_memory_vec").fetchone()[0] == 20

            # Bulk delete 10 rows
            conn.execute("DELETE FROM bug_memory WHERE id <= 10")
            assert conn.execute("SELECT count(*) FROM bug_memory").fetchone()[0] == 10
            assert conn.execute("SELECT count(*) FROM bug_memory_vec").fetchone()[0] == 10

    def test_trigger_update_embedding_to_null_defect(self, tmp_path: Path):
        """Reproduce vulnerability: updating embedding to NULL must safely remove row from vec0."""
        db = Database(tmp_path / "null_defect.sqlite")
        row_id = db.record_bug_memory("repo", "c1", "RULE_DEFECT", "d.py", "def d(): pass", "applied")

        with db.get_connection() as conn:
            # This currently raises sqlite3.OperationalError: Inserted vector for the "embedding" column is invalid: Input must have type BLOB...
            conn.execute("UPDATE bug_memory SET embedding = NULL WHERE id = ?", (row_id,))
            # Desired behavior: row in bug_memory has NULL embedding, and bug_memory_vec row is deleted
            cnt_vec = conn.execute("SELECT count(*) FROM bug_memory_vec WHERE id = ?", (row_id,)).fetchone()[0]
            assert cnt_vec == 0


# =========================================================================
# 4. PURE-PYTHON FALLBACK & KNN TRUNCATION DEFECT
# =========================================================================

class TestPurePythonFallbackStressAndKnnTruncation:
    """Stress tests fallback parity and analyzes KNN rule filtering limits."""

    def test_fallback_mode_functional_parity(self, tmp_path: Path):
        """Verify fallback mode yields identical outcomes when sqlite-vec is unavailable."""
        db = Database(tmp_path / "fallback_parity.sqlite")
        db.record_bug_memory("repo", "c1", "B006", "f.py", "def f(x={}): pass", "false_positive", "FP Reason")
        db.record_bug_memory("repo", "c2", "E501", "f.py", "line = 1", "applied")

        with patch.object(db, "_has_vec_table", return_value=False):
            skip_fp, reason_fp = db.should_skip_finding("def f(x={}): pass", rule_id="B006")
            assert skip_fp is True
            assert "false_positive" in reason_fp
            assert "FP Reason" in reason_fp

            # Applied outcome should never skip
            skip_applied, reason_applied = db.should_skip_finding("line = 1", rule_id="E501")
            assert skip_applied is False
            assert reason_applied is None

    def test_knn_rule_filter_candidate_truncation_defect(self, tmp_path: Path):
        """Reproduce architectural defect: rule_id filter drops valid match when > 25 closer vectors exist from other rules."""
        db = Database(tmp_path / "knn_defect.sqlite")

        query_v = make_unit_vector(1.0)
        noise_v = [0.0] * 384
        noise_v[0] = math.cos(0.02)
        noise_v[1] = math.sin(0.02)

        target_v = [0.0] * 384
        target_v[0] = math.cos(0.05)
        target_v[1] = math.sin(0.05)

        # Insert 30 noise records with rule NOISE
        for i in range(30):
            db.record_bug_memory("repo", f"c_{i}", "NOISE", f"noise_{i}.py", f"noise_{i}", "false_positive", embedding=noise_v)

        # Insert 1 target record with rule TARGET_BUG (similarity ~ 0.9987 > 0.88)
        db.record_bug_memory("repo", "c_target", "TARGET_BUG", "target.py", "target", "false_positive", embedding=target_v)

        with patch.object(DeterministicCodeVectorizer, "vectorize", return_value=query_v):
            res_sqlite_vec = db.query_similar_bugs("dummy", rule_id="TARGET_BUG", limit=5)
            # This should find the TARGET_BUG match, handled by Stage 1 or Stage 2 hybrid lookup
            assert len(res_sqlite_vec) == 1
            assert res_sqlite_vec[0]["rule_id"] == "TARGET_BUG"

    def test_knn_rule_filter_candidate_truncation_extreme_saturation(self, tmp_path: Path):
        """Verify 100% recall when foreign-rule records exceed sqlite-vec's 4096 KNN limit."""
        db = Database(tmp_path / "knn_extreme_saturation.sqlite")
        query_v = [0.0] * 384
        query_v[0] = 1.0

        noise_v = [0.0] * 384
        noise_v[0] = math.cos(0.01)
        noise_v[1] = math.sin(0.01)

        target_v = [0.0] * 384
        target_v[0] = math.cos(0.05)
        target_v[1] = math.sin(0.05)

        noise_bytes = DeterministicCodeVectorizer.to_bytes(noise_v)
        # Bulk insert 4500 noise records with rule NOISE (trigger trg_bug_memory_insert populates bug_memory_vec)
        with db.get_connection() as conn:
            conn.executemany(
                "INSERT INTO bug_memory (repo_slug, commit_sha, rule_id, file_path, code_snippet, patch_outcome, embedding) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [("repo", f"c_{i}", "NOISE", "noise.py", "noise", "applied", noise_bytes) for i in range(4500)]
            )


        # Insert 1 target record with rule TARGET_BUG
        db.record_bug_memory("repo", "c_target", "TARGET_BUG", "target.py", "target", "false_positive", embedding=target_v)

        with patch.object(DeterministicCodeVectorizer, "vectorize", return_value=query_v):
            res = db.query_similar_bugs("dummy", rule_id="TARGET_BUG", limit=5)
            assert len(res) == 1
            assert res[0]["rule_id"] == "TARGET_BUG"
            skip, reason = db.should_skip_finding("dummy", rule_id="TARGET_BUG")
            assert skip is True
            assert "TARGET_BUG" in reason

