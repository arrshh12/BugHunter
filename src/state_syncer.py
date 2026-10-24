"""
State persistence synchronization for AutoBugHunter 24/7.
Backs up and restores bughunter.sqlite snapshot to/from a private GitHub repository.
"""

from __future__ import annotations

import base64
import shutil
import sqlite3
import subprocess
from pathlib import Path
from typing import Any


class StateSyncer:
    """Manages snapshot synchronization between local SQLite DB and a private GitHub repo."""

    def __init__(
        self,
        db_path: Path,
        state_dir: Path,
        state_repo: str,
        github_token: str,
        logger: Any | None = None,
    ) -> None:
        self.db_path = Path(db_path).resolve()
        self.state_dir = Path(state_dir).resolve()
        self.state_repo = (state_repo or "").strip()
        self.github_token = (github_token or "").strip()
        self.logger = logger
        self._clone_dir = self.state_dir / ".state_repo_sync"

    def _log(self, level: str, msg: str) -> None:
        if self.logger:
            if hasattr(self.logger, "log"):
                self.logger.log(level, msg)
            elif hasattr(self.logger, "info") and level == "INFO":
                self.logger.info(msg)
            elif hasattr(self.logger, "warning") and level in ("WARN", "WARNING"):
                self.logger.warning(msg)
            elif hasattr(self.logger, "error") and level == "ERROR":
                self.logger.error(msg)
        else:
            print(f"[{level}] [STATE_SYNC] {msg}")

    def _auth_git_cmd(self, extra_args: list[str]) -> list[str]:
        cmd = ["git"]
        if self.github_token:
            auth_bytes = f"x-access-token:{self.github_token}".encode()
            auth_b64 = base64.b64encode(auth_bytes).decode("ascii")
            cmd.extend(["-c", f"http.https://github.com/.extraHeader=AUTHORIZATION: basic {auth_b64}"])
        cmd.extend(extra_args)
        return cmd

    def _ensure_cloned_repo(self) -> bool:
        """Ensure the state repo is cloned locally in _clone_dir."""
        if not self.state_repo or not self.github_token:
            return False

        if (self._clone_dir / ".git").exists():
            # Pull latest
            try:
                cmd = self._auth_git_cmd(["pull", "--ff-only", "origin", "main"])
                res = subprocess.run(cmd, cwd=self._clone_dir, capture_output=True, text=True, timeout=30)
                if res.returncode == 0:
                    return True
            except Exception as e:
                self._log("WARN", f"Failed to pull state repo updates: {e}")
                return True  # Still can use existing clone

        # Fresh clone
        if self._clone_dir.exists():
            shutil.rmtree(self._clone_dir, ignore_errors=True)
        self._clone_dir.mkdir(parents=True, exist_ok=True)

        clone_url = f"https://github.com/{self.state_repo}.git"
        cmd = self._auth_git_cmd(["clone", clone_url, str(self._clone_dir)])
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if res.returncode == 0:
                # Configure git identity in clone dir
                subprocess.run(["git", "config", "user.name", "arrshh12"], cwd=self._clone_dir, check=False)
                subprocess.run(["git", "config", "user.email", "arrshh12@users.noreply.github.com"], cwd=self._clone_dir, check=False)
                return True
            self._log("WARN", f"Failed to clone state repo {self.state_repo}: {res.stderr.strip()[:200]}")
            return False
        except Exception as e:
            self._log("WARN", f"Exception cloning state repo {self.state_repo}: {e}")
            return False

    def restore_state(self) -> bool:
        """Download remote SQLite database from private state repo on startup if available."""
        if not self.state_repo:
            return False

        self._log("INFO", f"Checking remote state repository '{self.state_repo}' for persistent database...")
        if not self._ensure_cloned_repo():
            return False

        remote_db = self._clone_dir / "bughunter.sqlite"
        if remote_db.exists() and remote_db.stat().st_size > 0:
            try:
                self.db_path.parent.mkdir(parents=True, exist_ok=True)
                # Purge stale local WAL/SHM files to prevent SQLite replaying stale local transactions
                for suffix in ("-wal", "-shm"):
                    stale_file = self.db_path.parent / (self.db_path.name + suffix)
                    if stale_file.exists():
                        try:
                            stale_file.unlink()
                        except OSError:
                            pass
                shutil.copy2(remote_db, self.db_path)
                self._log("INFO", f"Successfully restored persistent database ({remote_db.stat().st_size} bytes) from {self.state_repo}")
                return True
            except Exception as e:
                self._log("ERROR", f"Failed to restore bughunter.sqlite from state repo: {e}")
                return False
        else:
            self._log("INFO", f"No existing bughunter.sqlite found in {self.state_repo}. Initializing clean database.")
            return False

    def backup_state(self) -> bool:
        """Checkpoint SQLite WAL and push bughunter.sqlite snapshot to private GitHub repo."""
        if not self.state_repo or not self.github_token:
            return False

        if not self.db_path.exists() or self.db_path.stat().st_size == 0:
            return False

        # 1. Ensure clone dir is ready
        if not self._ensure_cloned_repo():
            return False

        self._clone_dir.mkdir(parents=True, exist_ok=True)
        dest_file = self._clone_dir / "bughunter.sqlite"

        # 2. Perform atomic crash-consistent SQLite backup
        try:
            src_conn = sqlite3.connect(str(self.db_path), timeout=10)
            src_conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            dest_conn = sqlite3.connect(str(dest_file), timeout=10)
            src_conn.backup(dest_conn)
            dest_conn.close()
            src_conn.close()
        except Exception as e:
            self._log("WARN", f"SQLite online backup warning: {e}; falling back to copy2")
            try:
                shutil.copy2(self.db_path, dest_file)
            except Exception as copy_err:
                self._log("ERROR", f"Failed to stage bughunter.sqlite into sync repo: {copy_err}")
                return False

        # 3. Check git status in clone dir
        status_res = subprocess.run(["git", "status", "--porcelain"], cwd=self._clone_dir, capture_output=True, text=True)
        if not status_res.stdout.strip():
            # No changes to commit
            return True

        # Configure git identity in clone repo
        subprocess.run(["git", "config", "user.name", "arrshh12"], cwd=self._clone_dir, check=False)
        subprocess.run(["git", "config", "user.email", "arrshh12@users.noreply.github.com"], cwd=self._clone_dir, check=False)
        subprocess.run(["git", "branch", "-M", "main"], cwd=self._clone_dir, check=False)

        # 4. Commit and push
        try:
            subprocess.run(["git", "add", "bughunter.sqlite"], cwd=self._clone_dir, check=True)
            commit_res = subprocess.run(
                ["git", "commit", "-m", "chore(state): snapshot bughunter.sqlite [skip ci]"],
                cwd=self._clone_dir,
                capture_output=True,
                text=True,
            )
            if commit_res.returncode != 0:
                status_check = subprocess.run(["git", "status", "--porcelain"], cwd=self._clone_dir, capture_output=True, text=True)
                if not status_check.stdout.strip():
                    return True
                return False

            push_cmd = self._auth_git_cmd(["push", "origin", "main"])
            push_res = subprocess.run(push_cmd, cwd=self._clone_dir, capture_output=True, text=True, timeout=60)
            if push_res.returncode == 0:
                self._log("INFO", f"Successfully synced persistent database snapshot to {self.state_repo}")
                return True

            # If remote advanced, force push newest snapshot
            err_msg = (push_res.stderr or "").lower()
            if "rejected" in err_msg or "fetch first" in err_msg or "non-fast-forward" in err_msg:
                self._log("WARN", f"Remote state repo is ahead; force updating state snapshot on {self.state_repo}")
                force_push_cmd = self._auth_git_cmd(["push", "--force", "origin", "main"])
                f_res = subprocess.run(force_push_cmd, cwd=self._clone_dir, capture_output=True, text=True, timeout=60)
                if f_res.returncode == 0:
                    self._log("INFO", f"Successfully synced persistent database snapshot to {self.state_repo} via force push")
                    return True
                self._log("WARN", f"Force push to {self.state_repo} failed: {f_res.stderr.strip()[:200]}")

            self._log("WARN", f"Failed to push state snapshot to {self.state_repo}: {push_res.stderr.strip()[:200]}")
            return False
        except Exception as e:
            self._log("ERROR", f"Exception during state backup push: {e}")
            return False
