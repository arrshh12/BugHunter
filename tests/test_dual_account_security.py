"""
Security and Invariant Tests for Dual-Account Separation & RULE-NO-AUTOMERGE Protocol.

Verifies:
1. Developer Global Git Protection:
   - configure_git_and_gh() does NOT invoke 'git config --global' or 'gh auth login'.
   - sync_repository() scopes bot user credentials strictly locally (git config --local).
2. Strict RULE-NO-AUTOMERGE Enforcement:
   - GitManager.merge_pull_request() and auto_merge_pr() raise PermissionError.
   - ReviewMonitor.merge_pr() raises PermissionError.
   - Config.load(overrides={"ENABLE_AUTO_MERGE": "true"}) raises ValueError.
3. Bot Scope Confinement & Push Guard:
   - Bot token cannot push directly to bitxwolf/BugHunter main branch (RULE-GIT-06).
   - Config correctly attributes bot_github_user='arrshh12' and main_github_user='bitxwolf'.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.config import Config
from src.git_manager import GitManager
from src.review_monitor import ReviewMonitor


class TestDualAccountGitProtection:
    """Tests ensuring developer's global @bitxwolf identity is never modified."""

    def test_configure_git_and_gh_does_not_mutate_global_config(self, tmp_path: Path):
        """configure_git_and_gh() must never call git config --global or gh auth login."""
        gm = GitManager(workspace_dir=tmp_path, github_token="mock_token")

        with patch("subprocess.run") as mock_run:
            gm.configure_git_and_gh()
            # Verify no subprocess call was made to set global git config or login
            for call_args in mock_run.call_args_list:
                cmd = call_args[0][0] if call_args[0] else []
                assert "--global" not in cmd, f"Global git mutation detected in command: {cmd}"
                assert "login" not in cmd, f"Global gh login detected in command: {cmd}"

    def test_sync_repository_configures_bot_identity_locally_only(self, tmp_path: Path):
        """sync_repository() configures git user.name and user.email strictly locally."""
        gm = GitManager(workspace_dir=tmp_path, github_token="mock_token")
        repo_path, branch, sha = gm.sync_repository("owner/local-id-test", allow_init=True)

        # Check local config inside repo
        p_name = subprocess.run(["git", "config", "--local", "user.name"], cwd=repo_path, capture_output=True, text=True, check=True)
        p_email = subprocess.run(["git", "config", "--local", "user.email"], cwd=repo_path, capture_output=True, text=True, check=True)

        assert p_name.stdout.strip() in ("arrshh12", "mock_user")
        assert "users.noreply.github.com" in p_email.stdout.strip()


class TestNoAutoMergeProtocol:
    """Tests strictly verifying RULE-NO-AUTOMERGE across all components."""

    def test_git_manager_merge_pull_request_raises_permission_error(self, tmp_path: Path):
        """GitManager.merge_pull_request() must raise PermissionError."""
        gm = GitManager(workspace_dir=tmp_path)
        with pytest.raises(PermissionError, match="RULE-NO-AUTOMERGE Violation"):
            gm.merge_pull_request("bitxwolf/Airllm-tui", 1)

    def test_git_manager_auto_merge_pr_raises_permission_error(self, tmp_path: Path):
        """GitManager.auto_merge_pr() must raise PermissionError."""
        gm = GitManager(workspace_dir=tmp_path)
        with pytest.raises(PermissionError, match="RULE-NO-AUTOMERGE Violation"):
            gm.auto_merge_pr("bitxwolf/orb", 2)

    def test_review_monitor_merge_pr_raises_permission_error(self, tmp_path: Path):
        """ReviewMonitor.merge_pr() must raise PermissionError."""
        rm = ReviewMonitor(
            config=MagicMock(),
            database=MagicMock(),
            git_manager=MagicMock(),
            verifier=MagicMock(),
        )
        with pytest.raises(PermissionError, match="RULE-NO-AUTOMERGE Violation"):
            rm.merge_pr("bitxwolf/BugHunter", 5)

    @pytest.mark.parametrize("flag_val", ["true", "True", "1", "yes", True])
    def test_config_load_rejects_enable_auto_merge(self, tmp_path: Path, flag_val):
        """Config.load() must reject ENABLE_AUTO_MERGE=true with ValueError."""
        with pytest.raises(ValueError, match="RULE-NO-AUTOMERGE Violation"):
            Config.load(overrides={"ENABLE_AUTO_MERGE": flag_val, "WORKSPACE_DIR": tmp_path})


class TestBotScopeAndPushGuards:
    """Tests verifying account role demarcation and bot push guards."""

    def test_config_dual_account_attributes(self, tmp_path: Path):
        """Config initializes bot_github_user and main_github_user correctly."""
        cfg = Config.load(overrides={
            "WORKSPACE_DIR": tmp_path,
            "BOT_GITHUB_USER": "arrshh12",
            "MAIN_GITHUB_USER": "bitxwolf",
            "BOT_GITHUB_TOKEN": "mock_token",
        })
        assert cfg.bot_github_user == "arrshh12"
        assert cfg.main_github_user == "bitxwolf"
        assert cfg.enable_auto_merge is False
        assert cfg.github_token == "mock_token"

    def test_bot_cannot_push_directly_to_bughunter_main(self, tmp_path: Path):
        """push_atomic_branch() raises PermissionError if attempting to push directly to bitxwolf/BugHunter main."""
        gm = GitManager(workspace_dir=tmp_path, github_token="mock_token")
        repo_dir = tmp_path / "repos" / "bitxwolf__BugHunter"
        repo_dir.mkdir(parents=True)

        subprocess.run(["git", "init", "-b", "main"], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "arrshh12"], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "arrshh12@users.noreply.github.com"], cwd=repo_dir, check=True, capture_output=True)
        (repo_dir / "README.md").write_text("content", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo_dir, check=True, capture_output=True)

        # Attempting to push branch 'main' to bitxwolf/BugHunter must be blocked
        with pytest.raises(PermissionError, match="RULE-GIT-06 Violation"):
            gm.push_atomic_branch(repo_dir, branch_name="main", repo_slug="bitxwolf/BugHunter")
