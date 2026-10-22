"""
Empirical Verification Test Suite for Challenger m8_iter2_1.
Strict adversarial validation of Layer 1 defects remediation in src/database.py.
"""

from __future__ import annotations

import math
from pathlib import Path
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
# CHECK 1: DEFECT 1 - UPDATE EMBEDDING = NULL AND SUBSEQUENT RESTORATION
# =========================================================================

class TestDefect1NullUpdateAndRestoration:
    """
    Verify:
    1. UPDATE bug_memory SET embedding = NULL does not crash.
    2. bug_memory_vec row is cleanly deleted when embedding is set to NULL.
    3. Subsequent UPDATE with valid embedding restores vector properly into bug_memory_vec.
    4. Querying vector matches restored row.
    5. Setting embedding back to NULL deletes it again without error.
    """

    def test_null_update_and_vector_restoration_lifecycle(self, tmp_path: Path):
        db_path = tmp_path / "defect1_verification.sqlite"
        db = Database(db_path)

        # 1. Record bug memory with vector v1
        v1 = make_unit_vector(0.95)
        row_id = db.record_bug_memory(
            repo_slug="test/repo",
            commit_sha="c1",
            rule_id="RULE_DEFECT1",
            file_path="src/app.py",
            code_snippet="def foo(): pass",
            patch_outcome="false_positive",
            rejection_reason="FP Initial",
            embedding=v1,
        )
        assert row_id > 0

        # Verify initial state in bug_memory_vec
        with db.get_connection() as conn:
            cnt_vec = conn.execute("SELECT count(*) FROM bug_memory_vec WHERE id = ?", (row_id,)).fetchone()[0]
            assert cnt_vec == 1

        # 2. Execute UPDATE bug_memory SET embedding = NULL WHERE id = ?
        with db.get_connection() as conn:
            conn.execute("UPDATE bug_memory SET embedding = NULL WHERE id = ?", (row_id,))

        # Verify no crash, row remains in bug_memory with NULL embedding, and removed from bug_memory_vec
        with db.get_connection() as conn:
            mem_row = conn.execute("SELECT id, embedding FROM bug_memory WHERE id = ?", (row_id,)).fetchone()
            assert mem_row["id"] == row_id
            assert mem_row["embedding"] is None
            cnt_vec = conn.execute("SELECT count(*) FROM bug_memory_vec WHERE id = ?", (row_id,)).fetchone()[0]
            assert cnt_vec == 0

        # When embedding is NULL:
        # A) Non-matching snippet yields 0 matches (vector search cannot match since vec0 row is gone)
        with patch.object(DeterministicCodeVectorizer, "vectorize", return_value=v1):
            matches_diff = db.query_similar_bugs("def different_snippet(): pass", rule_id="RULE_DEFECT1")
            assert len(matches_diff) == 0

        # B) Exact matching snippet falls back to string equivalence
        matches_exact = db.query_similar_bugs("def foo(): pass", rule_id="RULE_DEFECT1")
        assert len(matches_exact) == 1
        assert matches_exact[0]["similarity"] == 1.0

        # 3. Subsequent UPDATE restoring vector: UPDATE bug_memory SET embedding = v2 WHERE id = ?
        v2 = make_unit_vector(0.98)
        v2_bytes = DeterministicCodeVectorizer.to_bytes(v2)
        with db.get_connection() as conn:
            conn.execute("UPDATE bug_memory SET embedding = ? WHERE id = ?", (v2_bytes, row_id))

        # Verify bug_memory_vec has restored row
        with db.get_connection() as conn:
            cnt_vec = conn.execute("SELECT count(*) FROM bug_memory_vec WHERE id = ?", (row_id,)).fetchone()[0]
            assert cnt_vec == 1

        # 4. Confirm vector query finds restored row with high similarity
        with patch.object(DeterministicCodeVectorizer, "vectorize", return_value=v2):
            matches_v2 = db.query_similar_bugs("dummy", rule_id="RULE_DEFECT1")
            assert len(matches_v2) == 1
            assert matches_v2[0]["id"] == row_id
            assert pytest.approx(matches_v2[0]["similarity"], abs=1e-3) == 1.0

            skip, reason = db.should_skip_finding("dummy", rule_id="RULE_DEFECT1")
            assert skip is True
            assert "RULE_DEFECT1" in reason

        # 5. Subsequent UPDATE back to NULL again
        with db.get_connection() as conn:
            conn.execute("UPDATE bug_memory SET embedding = NULL WHERE id = ?", (row_id,))
            cnt_vec = conn.execute("SELECT count(*) FROM bug_memory_vec WHERE id = ?", (row_id,)).fetchone()[0]
            assert cnt_vec == 0

        # 6. Verify reconnection and idempotent reconciliation
        db_reconnected = Database(db_path)
        with db_reconnected.get_connection() as conn:
            cnt_vec = conn.execute("SELECT count(*) FROM bug_memory_vec WHERE id = ?", (row_id,)).fetchone()[0]
            assert cnt_vec == 0


# =========================================================================
# CHECK 2: DEFECT 2 - FOREIGN RULE SATURATION (30 AND 5,000 ROWS)
# =========================================================================

class TestDefect2ForeignRuleSaturationAndRecall:
    """
    Verify:
    1. 100% recall with 30 foreign-rule embeddings closer than target finding.
    2. 100% recall with 5,000 foreign-rule embeddings closer than target finding (exceeds 4096 KNN limit).
    3. Multi-target retrieval under 5,000 foreign-rule saturation.
    4. Parity between sqlite-vec mode and fallback mode under saturation.
    """

    def test_30_foreign_rule_saturation_100_percent_recall(self, tmp_path: Path):
        db = Database(tmp_path / "defect2_30_foreign.sqlite")

        # Query vector: [1, 0, 0, ...]
        query_v = make_unit_vector(1.0)

        # Foreign noise vector closer than target: angle 0.01 (sim ~ 0.99995)
        noise_v = [0.0] * 384
        noise_v[0] = math.cos(0.01)
        noise_v[1] = math.sin(0.01)

        # Target finding vector: angle 0.05 (sim ~ 0.99875)
        target_v = [0.0] * 384
        target_v[0] = math.cos(0.05)
        target_v[1] = math.sin(0.05)

        # Ingest 30 foreign-rule embeddings
        for i in range(30):
            db.record_bug_memory(
                repo_slug="test/repo",
                commit_sha=f"c_noise_{i}",
                rule_id="FOREIGN_RULE_NOISE",
                file_path=f"src/noise_{i}.py",
                code_snippet=f"def noise_{i}(): pass",
                patch_outcome="applied",
                embedding=noise_v,
            )

        # Ingest target finding
        target_id = db.record_bug_memory(
            repo_slug="test/repo",
            commit_sha="c_target",
            rule_id="TARGET_RULE_30",
            file_path="src/target.py",
            code_snippet="def target_bug(): pass",
            patch_outcome="false_positive",
            rejection_reason="Known False Positive Rule 30",
            embedding=target_v,
        )

        with patch.object(DeterministicCodeVectorizer, "vectorize", return_value=query_v):
            # Query similar bugs with rule_id="TARGET_RULE_30"
            matches = db.query_similar_bugs("dummy", rule_id="TARGET_RULE_30", limit=5)
            assert len(matches) == 1, f"Expected 1 match for target rule, got {len(matches)}"
            assert matches[0]["id"] == target_id
            assert matches[0]["rule_id"] == "TARGET_RULE_30"
            assert pytest.approx(matches[0]["similarity"], abs=1e-3) == math.cos(0.05)

            # Test should_skip_finding with rule_id
            skip, reason = db.should_skip_finding("dummy", rule_id="TARGET_RULE_30")
            assert skip is True
            assert "TARGET_RULE_30" in reason
            assert "Known False Positive Rule 30" in reason

    def test_5000_foreign_rule_saturation_100_percent_recall(self, tmp_path: Path):
        db = Database(tmp_path / "defect2_5000_foreign.sqlite")

        # Query vector: [1, 0, 0, ...]
        query_v = make_unit_vector(1.0)

        # Foreign noise vector closer than target: angle 0.01 (sim ~ 0.99995)
        noise_v = [0.0] * 384
        noise_v[0] = math.cos(0.01)
        noise_v[1] = math.sin(0.01)
        noise_bytes = DeterministicCodeVectorizer.to_bytes(noise_v)

        # Target vectors (2 different findings for the same target rule)
        target1_v = [0.0] * 384
        target1_v[0] = math.cos(0.04)  # sim ~ 0.9992
        target1_v[1] = math.sin(0.04)

        target2_v = [0.0] * 384
        target2_v[0] = math.cos(0.08)  # sim ~ 0.9968
        target2_v[1] = math.sin(0.08)

        # Bulk ingest 5,000 foreign-rule embeddings in transaction
        with db.get_connection() as conn:
            conn.executemany(
                """
                INSERT INTO bug_memory (repo_slug, commit_sha, rule_id, file_path, code_snippet, patch_outcome, embedding)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    ("test/noise_repo", f"c_noise_{i}", "FOREIGN_5000", f"noise_{i}.py", f"noise_{i}", "applied", noise_bytes)
                    for i in range(5000)
                ]
            )

        # Ingest target findings
        t1_id = db.record_bug_memory(
            repo_slug="test/repo",
            commit_sha="c_t1",
            rule_id="TARGET_RULE_5000",
            file_path="src/target1.py",
            code_snippet="def target1(): pass",
            patch_outcome="false_positive",
            rejection_reason="FP 1 in 5000",
            embedding=target1_v,
        )
        t2_id = db.record_bug_memory(
            repo_slug="test/repo",
            commit_sha="c_t2",
            rule_id="TARGET_RULE_5000",
            file_path="src/target2.py",
            code_snippet="def target2(): pass",
            patch_outcome="rejected",
            rejection_reason="Rejected 2 in 5000",
            embedding=target2_v,
        )

        with db.get_connection() as conn:
            cnt_noise = conn.execute("SELECT count(*) FROM bug_memory WHERE rule_id = 'FOREIGN_5000'").fetchone()[0]
            assert cnt_noise == 5000
            cnt_vec = conn.execute("SELECT count(*) FROM bug_memory_vec").fetchone()[0]
            assert cnt_vec == 5002

        with patch.object(DeterministicCodeVectorizer, "vectorize", return_value=query_v):
            # 1. Test sqlite-vec mode (triggers Stage 2 B-Tree hybrid fallback because 5000 > 4096 KNN limit)
            matches_vec = db.query_similar_bugs("dummy", rule_id="TARGET_RULE_5000", limit=5)
            assert len(matches_vec) == 2, f"Expected 2 matches for target rule, got {len(matches_vec)}"
            assert matches_vec[0]["id"] == t1_id
            assert matches_vec[1]["id"] == t2_id
            assert matches_vec[0]["similarity"] > matches_vec[1]["similarity"]

            skip_vec, reason_vec = db.should_skip_finding("dummy", rule_id="TARGET_RULE_5000")
            assert skip_vec is True
            assert "TARGET_RULE_5000" in reason_vec

            # 2. Test pure-Python fallback mode
            with patch.object(db, "_has_vec_table", return_value=False):
                matches_fb = db.query_similar_bugs("dummy", rule_id="TARGET_RULE_5000", limit=5)
                assert len(matches_fb) == 2
                assert matches_fb[0]["id"] == t1_id
                assert matches_fb[1]["id"] == t2_id

                skip_fb, reason_fb = db.should_skip_finding("dummy", rule_id="TARGET_RULE_5000")
                assert skip_fb is True
                assert "TARGET_RULE_5000" in reason_fb


# =========================================================================
# CHECK 3: DEFECT 3 - FLOAT32 BOUNDARY PRECISION PARITY AT 0.87, 0.88, 0.89
# =========================================================================

class TestDefect3Float32BoundaryParity:
    """
    Verify 100% behavioral parity between sqlite-vec mode and pure-Python fallback mode
    at 0.87, 0.8799, 0.88, 0.8801, and 0.89.
    """

    @pytest.mark.parametrize("sim_val, expected_skip, desc", [
        (0.87, False, "Below threshold: must not skip in either mode"),
        (0.8799, False, "Just below threshold: must not skip in either mode"),
        (0.88, True, "Exact 0.88 boundary: must skip identically in both modes with float32 epsilon"),
        (0.8801, True, "Just above threshold: must skip identically in both modes"),
        (0.89, True, "Above threshold: must skip identically in both modes"),
    ])
    def test_boundary_precision_parity(self, tmp_path: Path, sim_val: float, expected_skip: bool, desc: str):
        db = Database(tmp_path / f"boundary_{sim_val}.sqlite")
        base_vec = make_unit_vector(1.0)
        db.record_bug_memory(
            repo_slug="test/repo",
            commit_sha="c_base",
            rule_id="RULE_BOUNDARY",
            file_path="src/app.py",
            code_snippet="def base_func(): pass",
            patch_outcome="false_positive",
            rejection_reason=f"FP at boundary test {sim_val}",
            embedding=base_vec,
        )

        test_vec = make_unit_vector(sim_val)
        with patch.object(DeterministicCodeVectorizer, "vectorize", return_value=test_vec):
            # Mode A: sqlite-vec
            matches_vec = db.query_similar_bugs("dummy", rule_id="RULE_BOUNDARY", threshold=0.88)
            skip_vec, _ = db.should_skip_finding("dummy", rule_id="RULE_BOUNDARY", threshold=0.88)

            # Mode B: fallback mode
            with patch.object(db, "_has_vec_table", return_value=False):
                matches_fb = db.query_similar_bugs("dummy", rule_id="RULE_BOUNDARY", threshold=0.88)
                skip_fb, _ = db.should_skip_finding("dummy", rule_id="RULE_BOUNDARY", threshold=0.88)

            # Assert identical outcomes between sqlite-vec and fallback
            assert len(matches_vec) == len(matches_fb), (
                f"Count divergence at {sim_val}: sqlite-vec={len(matches_vec)}, fallback={len(matches_fb)} ({desc})"
            )
            assert skip_vec == skip_fb, (
                f"Skip divergence at {sim_val}: sqlite-vec={skip_vec}, fallback={skip_fb} ({desc})"
            )
            assert skip_vec == expected_skip, (
                f"Expected skip={expected_skip} at {sim_val}, got {skip_vec} ({desc})"
            )


# =========================================================================
# CHECK 4: ADVANCED ADVERSARIAL STRESS - BATCH NULLS, ROLLBACKS & PARITY
# =========================================================================

class TestAdvancedDefectStress:
    """Stress tests complex edge cases across all three remediated areas."""

    def test_defect1_batch_update_null_and_rollback(self, tmp_path: Path):
        """Batch NULL updates and transaction rollback safety."""
        db = Database(tmp_path / "defect1_batch.sqlite")
        v = make_unit_vector(1.0)
        v_bytes = DeterministicCodeVectorizer.to_bytes(v)

        for i in range(10):
            db.record_bug_memory("repo", f"c_{i}", "RULE_BATCH", f"f_{i}.py", f"def f_{i}(): pass", "applied", embedding=v)

        with db.get_connection() as conn:
            assert conn.execute("SELECT count(*) FROM bug_memory_vec").fetchone()[0] == 10

            # Batch update 5 rows to NULL
            conn.execute("UPDATE bug_memory SET embedding = NULL WHERE id <= 5")
            assert conn.execute("SELECT count(*) FROM bug_memory_vec").fetchone()[0] == 5

        # Transaction that sets rest to NULL and triggers rollback via exception
        try:
            with db.get_connection() as conn:
                conn.execute("UPDATE bug_memory SET embedding = NULL WHERE id > 5")
                assert conn.execute("SELECT count(*) FROM bug_memory_vec").fetchone()[0] == 0
                raise RuntimeError("Simulated failure to verify rollback")
        except RuntimeError:
            pass

        with db.get_connection() as conn:
            # After rollback, rows 6-10 must still be present in bug_memory_vec
            assert conn.execute("SELECT count(*) FROM bug_memory_vec").fetchone()[0] == 5

            # Subsequent update restoring rows 1-5
            conn.execute("UPDATE bug_memory SET embedding = ? WHERE id <= 5", (v_bytes,))
            assert conn.execute("SELECT count(*) FROM bug_memory_vec").fetchone()[0] == 10

    def test_defect2_mixed_outcomes_under_5000_foreign_records(self, tmp_path: Path):
        """Under 5,000 foreign records, verify 'applied' outcome does NOT cause skip, but 'rejected' does."""
        db = Database(tmp_path / "defect2_mixed.sqlite")
        query_v = make_unit_vector(1.0)

        noise_v = [0.0] * 384
        noise_v[0] = math.cos(0.01)
        noise_v[1] = math.sin(0.01)
        noise_bytes = DeterministicCodeVectorizer.to_bytes(noise_v)

        # Ingest 5,000 foreign-rule records
        with db.get_connection() as conn:
            conn.executemany(
                "INSERT INTO bug_memory (repo_slug, commit_sha, rule_id, file_path, code_snippet, patch_outcome, embedding) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [("repo", f"c_{i}", "FOREIGN_MIX", "noise.py", "noise", "applied", noise_bytes) for i in range(5000)]
            )

        # Target finding with outcome 'applied' (identical snippet and vector)
        target_v = make_unit_vector(0.99)
        db.record_bug_memory("repo", "c_app", "TARGET_APPLIED", "app.py", "def app(): pass", "applied", embedding=target_v)

        # Target finding with outcome 'rejected' (identical snippet and vector)
        db.record_bug_memory("repo", "c_rej", "TARGET_REJECTED", "rej.py", "def rej(): pass", "rejected", rejection_reason="Too complex", embedding=target_v)

        with patch.object(DeterministicCodeVectorizer, "vectorize", return_value=query_v):
            # Target 'applied' must NOT skip
            skip_app, reason_app = db.should_skip_finding("dummy", rule_id="TARGET_APPLIED")
            assert skip_app is False
            assert reason_app is None

            # Target 'rejected' MUST skip
            skip_rej, reason_rej = db.should_skip_finding("dummy", rule_id="TARGET_REJECTED")
            assert skip_rej is True
            assert "Too complex" in reason_rej

    def test_defect3_fine_grained_epsilon_parity(self, tmp_path: Path):
        """Evaluate fine-grained boundaries around 0.88 with steps of 0.0001."""
        db = Database(tmp_path / "defect3_fine.sqlite")
        base_v = make_unit_vector(1.0)
        db.record_bug_memory("repo", "c1", "RULE_FINE", "f.py", "def f(): pass", "false_positive", "FP Fine", embedding=base_v)

        fine_values = [0.8790, 0.8795, 0.8799, 0.8800, 0.8801, 0.8805, 0.8810]
        for val in fine_values:
            test_v = make_unit_vector(val)
            with patch.object(DeterministicCodeVectorizer, "vectorize", return_value=test_v):
                # sqlite-vec mode
                skip_vec, _ = db.should_skip_finding("dummy", rule_id="RULE_FINE", threshold=0.88)
                matches_vec = db.query_similar_bugs("dummy", rule_id="RULE_FINE", threshold=0.88)

                # fallback mode
                with patch.object(db, "_has_vec_table", return_value=False):
                    skip_fb, _ = db.should_skip_finding("dummy", rule_id="RULE_FINE", threshold=0.88)
                    matches_fb = db.query_similar_bugs("dummy", rule_id="RULE_FINE", threshold=0.88)

                # Parity assertion: both modes must agree 100% on count and skip decision
                assert len(matches_vec) == len(matches_fb), f"Count divergence at {val}"
                assert skip_vec == skip_fb, f"Skip decision divergence at {val}"

