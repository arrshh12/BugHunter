"""
Unit tests for src/database.py: SQLite WAL engine, relational schemas, CRUD operations, and stats aggregation.
"""

import concurrent.futures
from pathlib import Path
import sqlite3
import threading
import pytest
from src.database import Database


def test_database_initialization_and_wal(tmp_path: Path):
    """Verify database creates tables, indexes, and enables WAL mode."""
    db_file = tmp_path / "test_bh.sqlite"
    db = Database(db_file)
    assert db_file.exists()

    with db.get_connection() as conn:
        journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert journal_mode.upper() == "WAL"

        # Check tables
        tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        assert "repositories" in tables
        assert "pull_requests" in tables
        assert "api_key_status" in tables
        assert "scan_logs" in tables

        # Check indexes
        indexes = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()]
        assert "idx_repo_status" in indexes
        assert "idx_repo_exhausted" in indexes
        assert "idx_pr_repo" in indexes
        assert "idx_key_state" in indexes
        assert "idx_scan_repo" in indexes


def test_repository_lifecycle(tmp_path: Path):
    """Verify upserting, updating status, and scan results for repositories."""
    db = Database(tmp_path / "repo_test.sqlite")

    db.upsert_repository("owner/repo-1", default_branch="develop", status="IDLE", open_pr_count=1)
    stats = db.get_stats()
    assert stats["kpis"]["total_repos"] == 1
    repo = stats["repositories"][0]
    assert repo["repo_slug"] == "owner/repo-1"
    assert repo["default_branch"] == "develop"
    assert repo["open_pr_count"] == 1

    # Update status
    db.update_repository_status("owner/repo-1", status="SCANNING")
    with db.get_connection() as conn:
        row = conn.execute("SELECT status FROM repositories WHERE repo_slug='owner/repo-1'").fetchone()
        assert row["status"] == "SCANNING"

    # Record scan result
    db.record_scan_result("owner/repo-1", commit_sha="abc1234", fully_exhausted=1)
    stats = db.get_stats()
    assert stats["kpis"]["exhausted_repos"] == 1
    assert stats["repositories"][0]["last_scanned_sha"] == "abc1234"
    assert stats["repositories"][0]["fully_exhausted"] == 1

    # Update open pr count
    db.update_open_pr_count("owner/repo-1", count=4)
    with db.get_connection() as conn:
        row = conn.execute("SELECT open_pr_count FROM repositories WHERE repo_slug='owner/repo-1'").fetchone()
        assert row["open_pr_count"] == 4


def test_pull_request_recording(tmp_path: Path):
    """Verify recording a PR increments repo totals and resets exhausted flag."""
    db = Database(tmp_path / "pr_test.sqlite")
    db.upsert_repository("owner/repo-test", default_branch="main", status="IDLE", open_pr_count=0)
    db.record_scan_result("owner/repo-test", commit_sha="sha1", fully_exhausted=1)

    pr_id = db.record_pull_request(
        repo_slug="owner/repo-test",
        pr_number=101,
        pr_url="https://github.com/owner/repo-test/pull/101",
        branch_name="fix/auto-repo-1a2b3c",
        commit_sha="sha2",
        file_modified="src/bug.py",
        pr_title="fix: resolve null check",
        bug_summary="Fixed None check on user model",
        llm_key_id="key-1"
    )
    assert pr_id > 0

    stats = db.get_stats()
    assert stats["kpis"]["total_prs_created"] == 1
    assert stats["kpis"]["exhausted_repos"] == 0
    repo = stats["repositories"][0]
    assert repo["total_prs_created"] == 1
    assert repo["open_pr_count"] == 1
    assert repo["fully_exhausted"] == 0
    assert len(stats["recent_prs"]) == 1
    assert stats["recent_prs"][0]["pr_number"] == 101


def test_api_key_status_and_usage(tmp_path: Path):
    """Verify API key upsert, status updates, and usage metrics tracking."""
    db = Database(tmp_path / "key_test.sqlite")
    db.upsert_api_key(
        key_id="k-1",
        provider="ScaleMax",
        model="claude-haiku-5.5",
        base_url="https://api.sm.ai/v1",
        masked_key="sk-1...5678",
        state="HEALTHY"
    )

    stats = db.get_stats()
    assert stats["kpis"]["total_keys"] == 1
    assert stats["kpis"]["healthy_keys"] == 1

    # Record failure
    db.update_api_key_status("k-1", state="COOLDOWN", consecutive_failures=2, cooldown_until="2026-10-21T06:00:00Z", last_error="429 Rate Limit")
    stats = db.get_stats()
    assert stats["kpis"]["healthy_keys"] == 0
    assert stats["keys"][0]["state"] == "COOLDOWN"
    assert stats["keys"][0]["consecutive_failures"] == 2

    # Record failure usage
    db.record_api_key_usage("k-1", success=False)
    with db.get_connection() as conn:
        row = conn.execute("SELECT total_uses, consecutive_failures FROM api_key_status WHERE key_id='k-1'").fetchone()
        assert row["total_uses"] == 1
        assert row["consecutive_failures"] == 3

    # Record success usage
    db.record_api_key_usage("k-1", success=True)
    stats = db.get_stats()
    assert stats["kpis"]["healthy_keys"] == 1
    assert stats["keys"][0]["state"] == "HEALTHY"
    assert stats["keys"][0]["total_uses"] == 2
    assert stats["keys"][0]["total_successes"] == 1
    assert stats["keys"][0]["consecutive_failures"] == 0


def test_scan_logs_and_reset_exhausted(tmp_path: Path):
    """Verify scan log entries and reset_exhausted behavior."""
    db = Database(tmp_path / "scan_test.sqlite")
    log_id = db.add_scan_log("owner/repo", commit_sha="sha1", key_id="k-1", outcome="SUCCESS", duration_seconds=12.5, details="PR created")
    assert log_id > 0

    # Test reset_exhausted
    db.upsert_repository("owner/repoA", default_branch="main")
    db.upsert_repository("owner/repoB", default_branch="main")
    db.record_scan_result("owner/repoA", "shaA", fully_exhausted=1)
    db.record_scan_result("owner/repoB", "shaB", fully_exhausted=1)

    assert db.get_stats()["kpis"]["exhausted_repos"] == 2
    reset_count = db.reset_exhausted()
    assert reset_count == 2
    assert db.get_stats()["kpis"]["exhausted_repos"] == 0


def test_transaction_rollback_on_error(tmp_path: Path):
    """Verify that exceptions inside get_connection() roll back changes."""
    db = Database(tmp_path / "rollback_test.sqlite")
    db.upsert_repository("owner/rollback-repo", default_branch="main")

    with pytest.raises(RuntimeError):
        with db.get_connection() as conn:
            conn.execute("UPDATE repositories SET status='ERROR' WHERE repo_slug='owner/rollback-repo'")
            raise RuntimeError("Forced simulation error")

    with db.get_connection() as conn:
        row = conn.execute("SELECT status FROM repositories WHERE repo_slug='owner/rollback-repo'").fetchone()
        assert row["status"] == "IDLE"


def test_database_wal_multithreaded_concurrency_stress(tmp_path: Path):
    """Stress test SQLite WAL mode with concurrent writers and readers across 10 threads.

    Proves:
    1. Zero 'database is locked' errors under high concurrent contention.
    2. Write transactions commit atomically and updates are consistently recorded.
    3. Readers can read concurrently during heavy write activity (WAL non-blocking isolation).
    4. 500+ total operations executed across 10 threads (5 writers, 5 readers).
    """
    db_file = tmp_path / "wal_stress.sqlite"
    db = Database(db_file)

    # Pre-populate keys for writers to update
    for w in range(5):
        db.upsert_api_key(
            key_id=f"key-{w}",
            provider="ScaleMax",
            model="claude-haiku-5.5",
            base_url="https://api.sm.ai/v1",
            masked_key=f"sk-{w}...5678",
            state="HEALTHY",
        )

    num_writers = 5
    num_readers = 5
    ops_per_thread = 30  # Writers perform 4-5 ops per loop (>=600 ops); readers perform 2 ops per loop (>=300 ops); Total > 900 ops
    errors: list[Exception] = []
    lock = threading.Lock()

    def writer_task(writer_id: int):
        try:
            for i in range(ops_per_thread):
                slug = f"owner/repo-{writer_id}-{i}"
                db.upsert_repository(slug, default_branch="main", status="SCANNING")
                db.update_open_pr_count(slug, count=i)
                db.update_api_key_status(f"key-{writer_id}", state="HEALTHY", consecutive_failures=0, cooldown_until=None)
                if i % 2 == 0:
                    db.record_pull_request(
                        repo_slug=slug,
                        pr_number=writer_id * 1000 + i,
                        pr_url=f"https://github.com/{slug}/pull/{i}",
                        branch_name=f"fix/auto-{writer_id}-{i}",
                        commit_sha="a" * 40,
                        file_modified="src/core.py",
                        pr_title=f"fix: concurrency test {writer_id}-{i}",
                        llm_key_id=f"key-{writer_id}",
                    )
                db.add_scan_log(
                    repo_slug=slug,
                    commit_sha="a" * 40,
                    key_id=f"key-{writer_id}",
                    outcome="SUCCESS",
                    duration_seconds=0.1,
                )
        except Exception as e:
            with lock:
                errors.append(e)

    def reader_task(reader_id: int):
        try:
            for _ in range(ops_per_thread):
                stats = db.get_stats()
                assert isinstance(stats["kpis"]["total_repos"], int)
                assert isinstance(stats["repositories"], list)
                with db.get_connection() as conn:
                    rows = conn.execute("SELECT count(*) FROM repositories").fetchone()
                    assert rows[0] >= 0
                    conn.execute("SELECT status FROM repositories LIMIT 5").fetchall()
        except Exception as e:
            with lock:
                errors.append(e)

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_writers + num_readers) as executor:
        futures = []
        for w in range(num_writers):
            futures.append(executor.submit(writer_task, w))
        for r in range(num_readers):
            futures.append(executor.submit(reader_task, r))
        concurrent.futures.wait(futures)

    # Assert zero exceptions and zero 'database is locked' errors
    assert len(errors) == 0, f"Encountered concurrency errors: {errors}"

    # Verify data integrity: all repositories upserted
    stats = db.get_stats()
    expected_repos = num_writers * ops_per_thread
    assert stats["kpis"]["total_repos"] == expected_repos

    # Verify journal mode remains WAL
    with db.get_connection() as conn:
        journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert journal_mode.upper() == "WAL"

