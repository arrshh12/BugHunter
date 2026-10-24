"""
Unit tests for StateSyncer (Method A persistent GitHub state sync).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.state_syncer import StateSyncer


def test_state_syncer_disabled_without_repo(tmp_path: Path):
    db_path = tmp_path / "bughunter.sqlite"
    state_dir = tmp_path / "state"
    syncer = StateSyncer(db_path=db_path, state_dir=state_dir, state_repo="", github_token="fake_token")

    assert syncer.restore_state() is False
    assert syncer.backup_state() is False


def test_state_syncer_restore_and_backup(tmp_path: Path):
    db_path = tmp_path / "bughunter.sqlite"
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)

    # Create dummy database
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE test (id INT);")
    conn.commit()
    conn.close()

    mock_logger = MagicMock()
    syncer = StateSyncer(
        db_path=db_path,
        state_dir=state_dir,
        state_repo="owner/state-repo",
        github_token="fake_token",
        logger=mock_logger,
    )

    with patch.object(syncer, "_ensure_cloned_repo", return_value=True), \
         patch("subprocess.run") as mock_subproc:

        # Mock git status (has changes)
        status_mock = MagicMock()
        status_mock.stdout = " M bughunter.sqlite\n"
        status_mock.returncode = 0

        # Mock commit and push
        ok_mock = MagicMock()
        ok_mock.returncode = 0

        def subproc_side_effect(cmd, **kwargs):
            if "status" in cmd:
                return status_mock
            return ok_mock

        mock_subproc.side_effect = subproc_side_effect

        success = syncer.backup_state()
        assert success is True


def test_state_syncer_restore_existing(tmp_path: Path):
    db_path = tmp_path / "bughunter.sqlite"
    state_dir = tmp_path / "state"
    clone_dir = state_dir / ".state_repo_sync"
    clone_dir.mkdir(parents=True, exist_ok=True)

    # Place a dummy db in clone dir
    remote_db = clone_dir / "bughunter.sqlite"
    remote_db.write_bytes(b"SQLITE_TEST_CONTENT")

    mock_logger = MagicMock()
    syncer = StateSyncer(
        db_path=db_path,
        state_dir=state_dir,
        state_repo="owner/state-repo",
        github_token="fake_token",
        logger=mock_logger,
    )

    with patch.object(syncer, "_ensure_cloned_repo", return_value=True):
        success = syncer.restore_state()
        assert success is True
        assert db_path.exists()
        assert db_path.read_bytes() == b"SQLITE_TEST_CONTENT"


def test_state_syncer_restore_purges_stale_wal_and_shm(tmp_path: Path):
    """Verify restore_state unlinks stale local -wal and -shm files to prevent replay corruption."""
    db_path = tmp_path / "bughunter.sqlite"
    wal_file = tmp_path / "bughunter.sqlite-wal"
    shm_file = tmp_path / "bughunter.sqlite-shm"
    wal_file.write_bytes(b"STALE_WAL")
    shm_file.write_bytes(b"STALE_SHM")

    state_dir = tmp_path / "state"
    clone_dir = state_dir / ".state_repo_sync"
    clone_dir.mkdir(parents=True, exist_ok=True)
    remote_db = clone_dir / "bughunter.sqlite"
    remote_db.write_bytes(b"NEW_SQLITE_DATA")

    syncer = StateSyncer(db_path=db_path, state_dir=state_dir, state_repo="owner/state-repo", github_token="fake_token")
    with patch.object(syncer, "_ensure_cloned_repo", return_value=True):
        assert syncer.restore_state() is True
        assert not wal_file.exists()
        assert not shm_file.exists()
        assert db_path.read_bytes() == b"NEW_SQLITE_DATA"


def test_state_syncer_backup_force_push_on_remote_ahead(tmp_path: Path):
    """Verify backup_state falls back to force push if normal push is rejected by non-fast-forward."""
    db_path = tmp_path / "bughunter.sqlite"
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)

    # Valid sqlite DB
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE t (x INT);")
    conn.commit()
    conn.close()

    syncer = StateSyncer(db_path=db_path, state_dir=state_dir, state_repo="owner/state-repo", github_token="fake_token")

    status_mock = MagicMock(stdout=" M bughunter.sqlite\n", returncode=0)
    commit_mock = MagicMock(returncode=0)
    # First push rejected (non-fast-forward), second push (--force) succeeds
    reject_push = MagicMock(returncode=1, stderr="error: failed to push some refs (non-fast-forward)\n")
    success_push = MagicMock(returncode=0, stderr="")

    push_calls = []

    def mock_subproc(cmd, **kwargs):
        if "status" in cmd:
            return status_mock
        elif "commit" in cmd:
            return commit_mock
        elif "push" in cmd:
            push_calls.append(cmd)
            if "--force" in cmd:
                return success_push
            return reject_push
        return MagicMock(returncode=0)

    with patch.object(syncer, "_ensure_cloned_repo", return_value=True), \
         patch("subprocess.run", side_effect=mock_subproc):
        success = syncer.backup_state()
        assert success is True
        # Verified that force push was triggered as fallback
        assert any("--force" in cmd for cmd in push_calls)


def test_state_syncer_backup_passive_checkpoint_and_wal_copy_fallback(tmp_path: Path):
    """Verify backup_state uses passive checkpoint and copies -wal and -shm files on copy fallback."""
    db_path = tmp_path / "bughunter.sqlite"
    wal_file = tmp_path / "bughunter.sqlite-wal"
    shm_file = tmp_path / "bughunter.sqlite-shm"

    # Create DB in WAL mode with active WAL transactions
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("CREATE TABLE t (id INT, val TEXT);")
    conn.execute("INSERT INTO t VALUES (1, 'active_wal');")
    conn.commit()
    conn.close()

    wal_file.write_bytes(b"ACTIVE_WAL_PAYLOAD")
    shm_file.write_bytes(b"ACTIVE_SHM_PAYLOAD")

    state_dir = tmp_path / "state"
    syncer = StateSyncer(db_path=db_path, state_dir=state_dir, state_repo="owner/state-repo", github_token="fake_token")

    # Force SQLite backup to raise an exception so it exercises the copy fallback
    with patch.object(syncer, "_ensure_cloned_repo", return_value=True), \
         patch("sqlite3.connect", side_effect=sqlite3.OperationalError("database is locked")), \
         patch("subprocess.run") as mock_sub:
        mock_sub.return_value = MagicMock(returncode=0, stdout=" M bughunter.sqlite\n")
        assert syncer.backup_state() is True

        dest_dir = state_dir / ".state_repo_sync"
        assert (dest_dir / "bughunter.sqlite").exists()
        assert (dest_dir / "bughunter.sqlite-wal").exists()
        assert (dest_dir / "bughunter.sqlite-shm").exists()
        assert (dest_dir / "bughunter.sqlite-wal").read_bytes() == b"ACTIVE_WAL_PAYLOAD"

