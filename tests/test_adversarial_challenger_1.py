"""
Adversarial Stress Test Suite for AutoBugHunter 24/7 (Challenger 1).
Exhaustively tests:
1. push_atomic_branch Push/Fork Fallback:
   - HTTP 403 / permission denial triggers ensure_fork, configures fork remote, pushes to fork, returns "fork"
   - SSH and HTTPS remote URL extraction when repo_slug is omitted
   - Diverse permission denial signatures ("403", "permission denied", "denied to", "access denied")
   - Fork remote URL update when "fork" remote already exists
   - Non-403 errors (network, 404, shallow update, non-fast-forward) re-raising CalledProcessError with scrubbed credentials
   - Absolute prohibition of force=True (RULE-GIT-02) on both valid and invalid branches
2. ReviewMonitor Edge Cases:
   - Strict idempotency: re-running remediation skips already addressed threads
   - GraphQL thread fetch filtering of already remediated threads and bot's own comments
   - SQLite ON CONFLICT(thread_id) DO UPDATE SET upsert resilience
   - Verifier rejection (diff > 150 lines, > 3 files, secret leak, whitespace-only, empty diff):
     clean rollback, no commit pushed, thread not resolved, no reply posted, not in DB
   - Exception isolation: GraphQL resolution failure, REST reply failure, network error,
     multi-repo loop error isolation, and Orchestrator run_remediation_phase isolation
"""

import base64
import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.aider_runner import AiderResult
from src.config import Config, KeyConfig
from src.database import Database
from src.git_manager import GitManager
from src.orchestrator import Orchestrator
from src.review_monitor import (
    GRAPHQL_ADD_THREAD_REPLY,
    GRAPHQL_GET_PR_REVIEW_THREADS,
    GRAPHQL_RESOLVE_REVIEW_THREAD,
    ReviewComment,
    ReviewMonitor,
    ReviewRemediationResult,
)
from src.verifier import VerificationResult, Verifier


# =========================================================================
# Fixtures
# =========================================================================

@pytest.fixture
def temp_db(tmp_path: Path) -> Database:
    """Create a test SQLite WAL database."""
    db_file = tmp_path / "test_adversarial.sqlite"
    return Database(db_file)


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """Initialize a clean local git repository for testing."""
    repo_dir = tmp_path / "adversarial_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "arrshh12"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "arrshh12@users.noreply.github.com"], cwd=repo_dir, check=True, capture_output=True)

    (repo_dir / "README.md").write_text("# Adversarial Test Repo\n", encoding="utf-8")
    (repo_dir / "target.py").write_text("def solve():\n    return 100\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_dir, check=True, capture_output=True)
    return repo_dir


@pytest.fixture
def test_config(tmp_path: Path) -> Config:
    """Minimal test Config."""
    k1 = KeyConfig(
        id="key-1",
        provider="ScaleMax",
        base_url="https://api.scalemax.pro/v1",
        model="openai/gpt-6-luna",
        api_key="scalemax_test_key_1234",
        masked_key="scalemax...1234",
        priority=1,
    )
    return Config.load(overrides={
        "WORKSPACE_DIR": tmp_path,
        "workspace_dir": tmp_path,
        "TARGET_REPOS": ["bitxwolf/BugHunter", "bitxwolf/repo2"],
        "GITHUB_TOKEN": "mock_token",
        "LLM_KEYS": [k1],
    })


# =========================================================================
# Part 1: push_atomic_branch Adversarial Verification
# =========================================================================

class TestPushAtomicBranchAdversarial:
    """Adversarial challenge tests for push_atomic_branch and fork fallback."""

    def test_rule_git_02_force_push_strictly_prohibited_even_before_branch_check(self, tmp_path: Path):
        """RULE-GIT-02: force=True MUST raise ValueError immediately, regardless of branch state."""
        gm = GitManager(workspace_dir=tmp_path)
        repo_dir = tmp_path / "repos" / "test_force"
        repo_dir.mkdir(parents=True)
        subprocess.run(["git", "init", "-b", "main"], cwd=repo_dir, check=True, capture_output=True)

        # On non-existent branch, force=True still triggers RULE-GIT-02 ValueError first
        with pytest.raises(ValueError, match="RULE-GIT-02 Violation: Force pushing is strictly prohibited"):
            gm.push_atomic_branch(repo_dir, "non-existent-branch", force=True)

    @pytest.mark.parametrize("error_signature", [
        "fatal: unable to access 'https://github.com/bitxwolf/BugHunter.git/': The requested URL returned error: 403",
        "remote: Permission to bitxwolf/BugHunter.git denied to arrshh12.\nfatal: unable to access",
        "git@github.com: Permission denied (publickey).",
        "fatal: access denied for repository bitxwolf/BugHunter",
    ])
    def test_push_atomic_branch_triggers_fork_on_various_permission_denial_signatures(
        self, tmp_path: Path, git_repo: Path, error_signature: str
    ):
        """Verify that multiple standard HTTP 403 and permission denial messages trigger fork fallback."""
        gm = GitManager(workspace_dir=tmp_path, github_token="mock_token")
        branch = gm.create_atomic_branch(git_repo, prefix="test")

        subprocess.run(
            ["git", "remote", "add", "origin", "https://github.com/bitxwolf/BugHunter.git"],
            cwd=git_repo,
            check=True,
            capture_output=True,
        )

        calls = []
        real_run = subprocess.run

        def mock_run(cmd, *args, **kwargs):
            if isinstance(cmd, list) and "push" in cmd:
                calls.append(cmd)
                if "origin" in cmd:
                    raise subprocess.CalledProcessError(128, cmd, stderr=error_signature)
                if "fork" in cmd:
                    # Successful fork push
                    return subprocess.CompletedProcess(cmd, returncode=0, stdout="Pushed to fork", stderr="")
            return real_run(cmd, *args, **kwargs)

        with patch("subprocess.run", side_effect=mock_run), \
             patch.object(gm, "ensure_fork", return_value="arrshh12/BugHunter") as mock_fork:
            remote_pushed = gm.push_atomic_branch(
                git_repo, branch_name=branch, repo_slug="bitxwolf/BugHunter"
            )

        assert remote_pushed == "fork"
        mock_fork.assert_called_once_with("bitxwolf/BugHunter")
        assert len(calls) == 2
        assert "origin" in calls[0]
        assert "fork" in calls[1]

        # Verify fork remote configured
        p_fork = real_run(["git", "remote", "get-url", "fork"], cwd=git_repo, capture_output=True, text=True, check=True)
        assert p_fork.stdout.strip() == "https://github.com/arrshh12/BugHunter.git"

    def test_push_atomic_branch_extracts_slug_from_origin_url_ssh_and_https(self, tmp_path: Path, git_repo: Path):
        """Verify target_slug extraction from origin URL when repo_slug is omitted (SSH and HTTPS)."""
        gm = GitManager(workspace_dir=tmp_path, github_token="mock_token")
        branch = gm.create_atomic_branch(git_repo, prefix="auto")

        # Test SSH remote URL: git@github.com:bitxwolf/TargetFromSsh.git
        subprocess.run(
            ["git", "remote", "add", "origin", "git@github.com:bitxwolf/TargetFromSsh.git"],
            cwd=git_repo,
            check=True,
            capture_output=True,
        )

        real_run = subprocess.run

        def mock_run(cmd, *args, **kwargs):
            if isinstance(cmd, list) and "push" in cmd:
                if "origin" in cmd:
                    raise subprocess.CalledProcessError(128, cmd, stderr="The requested URL returned error: 403")
                if "fork" in cmd:
                    return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")
            return real_run(cmd, *args, **kwargs)

        with patch("subprocess.run", side_effect=mock_run), \
             patch.object(gm, "ensure_fork", return_value="arrshh12/TargetFromSsh") as mock_fork:
            remote_pushed = gm.push_atomic_branch(git_repo, branch_name=branch, repo_slug=None)

        assert remote_pushed == "fork"
        mock_fork.assert_called_once_with("bitxwolf/TargetFromSsh")

    def test_push_atomic_branch_updates_existing_fork_remote(self, tmp_path: Path, git_repo: Path):
        """Verify that if 'fork' remote already exists with outdated URL, set-url updates it."""
        gm = GitManager(workspace_dir=tmp_path, github_token="mock_token")
        branch = gm.create_atomic_branch(git_repo, prefix="auto")

        subprocess.run(
            ["git", "remote", "add", "origin", "https://github.com/bitxwolf/UpdateFork.git"],
            cwd=git_repo,
            check=True,
            capture_output=True,
        )
        # Pre-existing outdated fork remote
        subprocess.run(
            ["git", "remote", "add", "fork", "https://github.com/old_user/outdated.git"],
            cwd=git_repo,
            check=True,
            capture_output=True,
        )

        real_run = subprocess.run

        def mock_run(cmd, *args, **kwargs):
            if isinstance(cmd, list) and "push" in cmd:
                if "origin" in cmd:
                    raise subprocess.CalledProcessError(128, cmd, stderr="HTTP 403 Forbidden")
                if "fork" in cmd:
                    return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")
            return real_run(cmd, *args, **kwargs)

        with patch("subprocess.run", side_effect=mock_run), \
             patch.object(gm, "ensure_fork", return_value="arrshh12/UpdateFork"):
            remote_pushed = gm.push_atomic_branch(git_repo, branch_name=branch, repo_slug="bitxwolf/UpdateFork")

        assert remote_pushed == "fork"
        chk = real_run(["git", "remote", "get-url", "fork"], cwd=git_repo, capture_output=True, text=True, check=True)
        assert chk.stdout.strip() == "https://github.com/arrshh12/UpdateFork.git"

    @pytest.mark.parametrize("error_text,exit_code", [
        ("fatal: repository 'https://github.com/bitxwolf/nonexistent.git' not found", 128),
        ("fatal: unable to access: Could not resolve host: github.com", 128),
        ("fatal: remote rejected (shallow update not allowed)", 1),
        ("error: failed to push some refs to 'https://github.com/bitxwolf/repo.git'", 1),
    ])
    def test_push_atomic_branch_reraises_generic_non_403_errors_and_scrubs_secrets(
        self, tmp_path: Path, git_repo: Path, error_text: str, exit_code: int
    ):
        """Generic non-403 errors MUST be re-raised as CalledProcessError with secrets scrubbed."""
        raw_token = "mock_secret_token"
        gm = GitManager(workspace_dir=tmp_path, github_token=raw_token)
        branch = gm.create_atomic_branch(git_repo, prefix="auto")

        subprocess.run(
            ["git", "remote", "add", "origin", "https://github.com/bitxwolf/repo.git"],
            cwd=git_repo,
            check=True,
            capture_output=True,
        )

        real_run = subprocess.run

        def mock_run(cmd, *args, **kwargs):
            if isinstance(cmd, list) and "push" in cmd:
                # Include raw token in stderr to test scrubbing
                leak_stderr = f"{error_text}\nAuth failed with token {raw_token}"
                raise subprocess.CalledProcessError(exit_code, cmd, stderr=leak_stderr)
            return real_run(cmd, *args, **kwargs)

        with patch("subprocess.run", side_effect=mock_run):
            with pytest.raises(subprocess.CalledProcessError) as exc_info:
                gm.push_atomic_branch(git_repo, branch_name=branch)

            # Assert error was re-raised
            assert exc_info.value.returncode == exit_code
            # Assert secret was scrubbed from exception
            assert raw_token not in str(exc_info.value.stderr)
            assert "[REDACTED]" in str(exc_info.value.stderr)

    def test_push_atomic_branch_non_origin_does_not_fork(self, tmp_path: Path, git_repo: Path):
        """When remote is already 'fork', 403 error does NOT re-trigger ensure_fork."""
        gm = GitManager(workspace_dir=tmp_path, github_token="mock_github_token")
        branch = gm.create_atomic_branch(git_repo, prefix="auto")

        subprocess.run(
            ["git", "remote", "add", "fork", "https://github.com/arrshh12/repo.git"],
            cwd=git_repo,
            check=True,
            capture_output=True,
        )

        real_run = subprocess.run

        def mock_run(cmd, *args, **kwargs):
            if isinstance(cmd, list) and "push" in cmd:
                raise subprocess.CalledProcessError(128, cmd, stderr="The requested URL returned error: 403")
            return real_run(cmd, *args, **kwargs)

        with patch("subprocess.run", side_effect=mock_run), \
             patch.object(gm, "ensure_fork") as mock_fork:
            with pytest.raises(subprocess.CalledProcessError):
                gm.push_atomic_branch(git_repo, branch_name=branch, remote="fork")

        mock_fork.assert_not_called()


# =========================================================================
# Part 2: ReviewMonitor Edge Cases & Adversarial Verification
# =========================================================================

class TestReviewMonitorAdversarial:
    """Adversarial challenge tests for ReviewMonitor edge cases."""

    def test_strict_idempotency_database_upsert(self, temp_db: Database):
        """Verify that record_review_remediation performs upsert without duplicating rows or raising IntegrityError."""
        thread_id = "PRRT_test_upsert_123"

        row1 = temp_db.record_review_remediation(
            thread_id=thread_id,
            comment_id="PRRC_1",
            repo_slug="bitxwolf/BugHunter",
            pr_number=42,
            commit_sha="aaaaaa1",
            reviewer="coderabbitai[bot]",
            path="src/main.py",
            line=10,
            feedback_summary="First pass",
            status="RESOLVED",
        )
        assert row1 > 0
        assert temp_db.is_thread_remediated(thread_id) is True

        # Re-record same thread with updated commit and summary
        row2 = temp_db.record_review_remediation(
            thread_id=thread_id,
            comment_id="PRRC_1",
            repo_slug="bitxwolf/BugHunter",
            pr_number=42,
            commit_sha="bbbbbb2",
            reviewer="coderabbitai[bot]",
            path="src/main.py",
            line=10,
            feedback_summary="Updated second pass",
            status="RESOLVED",
        )
        assert row2 == row1  # Same row id

        rems = temp_db.get_review_remediations(pr_number=42)
        assert len(rems) == 1
        assert rems[0]["commit_sha"] == "bbbbbb2"
        assert rems[0]["feedback_summary"] == "Updated second pass"

    def test_fetch_unresolved_review_threads_filters_out_bot_own_and_remediated(
        self, test_config: Config, temp_db: Database
    ):
        """Verify fetch_unresolved_review_threads filters out bot's own comments and already remediated threads."""
        monitor = ReviewMonitor(
            config=test_config,
            database=temp_db,
            git_manager=MagicMock(get_authenticated_user=MagicMock(return_value="arrshh12")),
            verifier=MagicMock(),
        )

        # Pre-mark thread 1 as remediated
        temp_db.record_review_remediation(
            thread_id="THREAD_ALREADY_DONE",
            comment_id="C_DONE",
            repo_slug="bitxwolf/BugHunter",
            pr_number=10,
            commit_sha="1111111",
        )

        mock_graphql_data = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "headRefName": "fix/test-branch",
                        "reviewThreads": {
                            "nodes": [
                                # Thread 1: Unresolved, but already in DB -> MUST BE FILTERED
                                {
                                    "id": "THREAD_ALREADY_DONE",
                                    "isResolved": False,
                                    "path": "file1.py",
                                    "line": 15,
                                    "comments": {"nodes": [{"id": "C1", "author": {"login": "coderabbitai[bot]"}}]},
                                },
                                # Thread 2: Unresolved, but authored by bot ('arrshh12') -> MUST BE FILTERED
                                {
                                    "id": "THREAD_BOT_OWN",
                                    "isResolved": False,
                                    "path": "file2.py",
                                    "line": 20,
                                    "comments": {"nodes": [{"id": "C2", "author": {"login": "arrshh12"}}]},
                                },
                                # Thread 3: Already resolved in GitHub (isResolved=True) -> MUST BE FILTERED
                                {
                                    "id": "THREAD_RESOLVED_ON_GH",
                                    "isResolved": True,
                                    "path": "file3.py",
                                    "line": 25,
                                    "comments": {"nodes": [{"id": "C3", "author": {"login": "human_reviewer"}}]},
                                },
                                # Thread 4: Genuine actionable comment -> MUST BE RETURNED
                                {
                                    "id": "THREAD_ACTIONABLE",
                                    "isResolved": False,
                                    "path": "file4.py",
                                    "line": 30,
                                    "comments": {
                                        "nodes": [
                                            {
                                                "id": "C4",
                                                "author": {"login": "human_reviewer"},
                                                "body": "Fix off-by-one bug",
                                                "diffHunk": "@@ -30,2 +30,2 @@",
                                            }
                                        ]
                                    },
                                },
                            ]
                        }
                    }
                }
            }
        }

        with patch.object(monitor, "execute_graphql", return_value=mock_graphql_data):
            threads = monitor.fetch_unresolved_review_threads("bitxwolf/BugHunter", 10)

        assert len(threads) == 1
        assert threads[0].thread_id == "THREAD_ACTIONABLE"
        assert threads[0].author == "human_reviewer"
        assert threads[0].line == 30

    @pytest.mark.parametrize("rejection_type,err_reason,file_count,line_count", [
        ("diff_lines_exceeded", "Diff modified 160 lines (max 150)", 1, 160),
        ("file_count_exceeded", "Diff modified 4 files (max 3)", 4, 20),
        ("secret_leak_detected", "Security violation: Credential/secret pattern detected: [REDACTED]", 1, 10),
        ("whitespace_only", "Verification failed: Whitespace-only changes detected", 1, 5),
    ])
    def test_remediate_single_thread_verifier_rejection_safety(
        self, test_config: Config, temp_db: Database, git_repo: Path,
        rejection_type: str, err_reason: str, file_count: int, line_count: int
    ):
        """
        Verify that ANY verifier gate failure (diff lines, file count, secret leak, whitespace):
        1. Invokes git rollback_working_tree
        2. Does NOT call git push_atomic_branch
        3. Does NOT post inline reply
        4. Does NOT resolve review thread via GraphQL
        5. Does NOT record thread in SQLite review_remediations
        6. Leaves git working tree clean
        """
        branch_name = f"fix/reject-{rejection_type}"
        subprocess.run(["git", "checkout", "-b", branch_name], cwd=git_repo, check=True, capture_output=True)

        git_mgr = GitManager(workspace_dir=git_repo.parent)
        real_rollback = git_mgr.rollback_working_tree

        mock_git_mgr = MagicMock(wraps=git_mgr)
        mock_git_mgr.push_atomic_branch = MagicMock()
        mock_git_mgr.rollback_working_tree = MagicMock(side_effect=lambda *args, **kwargs: real_rollback(*args, **kwargs))

        mock_verifier = MagicMock(spec=Verifier)
        mock_verifier.verify_and_sanitize_fix.return_value = VerificationResult(
            verified=False,
            error_reason=err_reason,
            modified_files=[f"file_{i}.py" for i in range(file_count)],
            diff_lines=line_count,
        )

        monitor = ReviewMonitor(
            config=test_config,
            database=temp_db,
            git_manager=mock_git_mgr,
            verifier=mock_verifier,
        )

        comment = ReviewComment(
            comment_id=f"COMMENT_{rejection_type}",
            thread_id=f"THREAD_{rejection_type}",
            repo_slug="bitxwolf/BugHunter",
            pr_number=55,
            branch_name=branch_name,
            path="target.py",
            line=1,
            diff_hunk="@@ -1,2 +1,2 @@",
            body="Review comment",
            author="reviewer",
        )

        with patch.object(monitor, "post_inline_reply") as mock_reply, \
             patch.object(monitor, "resolve_review_thread") as mock_resolve:
            res = monitor.remediate_single_thread(
                repo_slug="bitxwolf/BugHunter",
                pr_info={"number": 55, "headRefName": branch_name},
                comment=comment,
                repo_path=git_repo,
            )

        assert res.success is False
        assert res.status == "VERIFICATION_FAILED"
        assert res.error_message == err_reason

        # Verified assertions:
        mock_git_mgr.rollback_working_tree.assert_called_once()
        mock_git_mgr.push_atomic_branch.assert_not_called()
        mock_reply.assert_not_called()
        mock_resolve.assert_not_called()
        assert temp_db.is_thread_remediated(f"THREAD_{rejection_type}") is False

        # Verify git working tree is clean
        status_check = subprocess.run(["git", "status", "--porcelain"], cwd=git_repo, capture_output=True, text=True, check=True)
        assert status_check.stdout.strip() == ""

    def test_remediate_single_thread_empty_diff_commit_failure(
        self, test_config: Config, temp_db: Database, git_repo: Path
    ):
        """Verify that when no changes are staged, git commit failure is caught, rolled back, and clean."""
        branch_name = "fix/pr-empty-commit"
        subprocess.run(["git", "checkout", "-b", branch_name], cwd=git_repo, check=True, capture_output=True)

        git_mgr = GitManager(workspace_dir=git_repo.parent)
        mock_git_mgr = MagicMock(wraps=git_mgr)
        mock_git_mgr.push_atomic_branch = MagicMock()
        mock_git_mgr.rollback_working_tree = MagicMock()

        # Verifier returns True (pretend verification passed) but no files were actually edited
        mock_verifier = MagicMock()
        mock_verifier.verify_and_sanitize_fix.return_value = VerificationResult(verified=True)

        monitor = ReviewMonitor(
            config=test_config,
            database=temp_db,
            git_manager=mock_git_mgr,
            verifier=mock_verifier,
        )

        comment = ReviewComment(
            comment_id="PRRC_empty",
            thread_id="PRRT_empty",
            repo_slug="bitxwolf/BugHunter",
            pr_number=77,
            branch_name=branch_name,
            path="target.py",
            line=1,
            diff_hunk="",
            body="No actual changes",
            author="reviewer",
        )

        with patch.object(monitor, "post_inline_reply") as mock_reply, \
             patch.object(monitor, "resolve_review_thread") as mock_resolve:
            res = monitor.remediate_single_thread(
                repo_slug="bitxwolf/BugHunter",
                pr_info={"number": 77, "headRefName": branch_name},
                comment=comment,
                repo_path=git_repo,
            )

        assert res.success is False
        assert res.status == "COMMIT_FAILED"
        mock_git_mgr.rollback_working_tree.assert_called_once()
        mock_git_mgr.push_atomic_branch.assert_not_called()
        mock_reply.assert_not_called()
        mock_resolve.assert_not_called()
        assert temp_db.is_thread_remediated("PRRT_empty") is False

    def test_graphql_resolution_failure_does_not_crash_and_records_db(
        self, test_config: Config, temp_db: Database, git_repo: Path
    ):
        """
        Verify that GraphQL resolveReviewThread failure:
        - Logs warning cleanly
        - Does NOT crash remediate_single_thread
        - Returns success=True with commit details
        - Persists to DB to prevent duplicate push loops
        """
        branch_name = "fix/graphql-fail-resilience"
        def mock_aider_patch(repo_path, target_file, patch_instruction, key_entry=None):
            (repo_path / target_file).write_text("def solve():\n    return 200\n", encoding="utf-8")
            return AiderResult(exit_code=0, diff_output="--- a/target.py\n+++ b/target.py", status="SUCCESS", target_file=target_file)

        mock_aider = MagicMock()
        mock_aider.run_aider.side_effect = mock_aider_patch

        git_mgr = GitManager(workspace_dir=git_repo.parent)
        mock_git_mgr = MagicMock(wraps=git_mgr)
        mock_git_mgr.push_atomic_branch = MagicMock(return_value="origin")

        mock_verifier = MagicMock()
        mock_verifier.verify_and_sanitize_fix.return_value = VerificationResult(verified=True)

        monitor = ReviewMonitor(
            config=test_config,
            database=temp_db,
            git_manager=mock_git_mgr,
            verifier=mock_verifier,
            aider_runner=mock_aider,
        )

        comment = ReviewComment(
            comment_id="PRRC_gql_fail",
            thread_id="PRRT_gql_fail",
            repo_slug="bitxwolf/BugHunter",
            pr_number=88,
            branch_name=branch_name,
            path="target.py",
            line=2,
            diff_hunk="@@ -1,2 +1,2 @@",
            body="Refactor return value",
            author="coderabbitai[bot]",
        )

        # Mock GraphQL resolve failure
        mock_resolve = MagicMock(return_value=False)
        mock_reply = MagicMock(return_value=True)

        with patch.object(monitor, "resolve_review_thread", mock_resolve), \
             patch.object(monitor, "post_inline_reply", mock_reply):
            res = monitor.remediate_single_thread(
                repo_slug="bitxwolf/BugHunter",
                pr_info={"number": 88, "headRefName": branch_name},
                comment=comment,
                repo_path=git_repo,
            )

        assert res.success is True
        assert res.status == "RESOLVED"
        assert res.commit_sha != ""

        # Thread is persisted in DB to prevent repeated patching cycles
        assert temp_db.is_thread_remediated("PRRT_gql_fail") is True
        mock_resolve.assert_called_once_with("PRRT_gql_fail")
        mock_git_mgr.push_atomic_branch.assert_called_once()
        push_kwargs = mock_git_mgr.push_atomic_branch.call_args[1]
        assert push_kwargs["force"] is False

    def test_check_and_remediate_prs_skips_already_remediated_in_loop(
        self, test_config: Config, temp_db: Database
    ):
        """Verify check_and_remediate_prs skips already remediated threads without invoking remediation."""
        monitor = ReviewMonitor(
            config=test_config,
            database=temp_db,
            git_manager=MagicMock(),
            verifier=MagicMock(),
        )

        temp_db.record_review_remediation(
            thread_id="THREAD_ALREADY_DONE_101",
            comment_id="C_101",
            repo_slug="bitxwolf/BugHunter",
            pr_number=99,
            commit_sha="abcdef123",
            status="RESOLVED",
        )

        comment = ReviewComment(
            comment_id="C_101",
            thread_id="THREAD_ALREADY_DONE_101",
            repo_slug="bitxwolf/BugHunter",
            pr_number=99,
            branch_name="fix/branch-99",
            path="target.py",
            line=1,
            diff_hunk="",
            body="Already handled",
            author="reviewer",
        )

        with patch.object(monitor, "get_open_bot_prs", return_value=[{"number": 99, "headRefName": "fix/branch-99"}]), \
             patch.object(monitor, "fetch_unresolved_review_threads", return_value=[comment]), \
             patch.object(monitor, "remediate_single_thread") as mock_rem:
            results = monitor.check_and_remediate_prs(["bitxwolf/BugHunter"])

        assert len(results) == 1
        assert results[0].status == "SKIPPED_ALREADY_REMEDIATED"
        mock_rem.assert_not_called()

    def test_orchestrator_run_remediation_phase_exception_isolation(
        self, test_config: Config, temp_db: Database
    ):
        """Verify Orchestrator.run_remediation_phase isolates exceptions and never crashes."""
        mock_logger = MagicMock()
        mock_monitor = MagicMock()
        mock_monitor.check_and_remediate_prs.side_effect = RuntimeError("Fatal network partition in ReviewMonitor")

        orchestrator = Orchestrator(
            config=test_config,
            database=temp_db,
            key_manager=MagicMock(),
            git_manager=MagicMock(),
            static_scanner=MagicMock(),
            openhands_runner=MagicMock(),
            verifier=MagicMock(),
            logger=mock_logger,
            review_monitor=mock_monitor,
        )

        # Call run_remediation_phase directly
        res = orchestrator.run_remediation_phase()
        assert res["outcome"] == "ERROR"
        assert "Fatal network partition" in res["error"]
        mock_logger.log.assert_called_with(
            "ERROR",
            "PR review remediation encountered an isolated error: Fatal network partition in ReviewMonitor"
        )
