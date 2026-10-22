"""
Unit tests for src/git_manager.py: Git synchronization, collision guards, and branch management.
"""

import base64
import subprocess
from pathlib import Path
import pytest
from src.git_manager import GitManager


def test_git_manager_init_and_discovery(tmp_path: Path):
    """Verify GitManager initializes workspace and parses repository lists."""
    gm = GitManager(workspace_dir=tmp_path, github_token="mock_token", max_open_prs=5)
    assert gm.repos_dir.exists()

    repos = gm.discover_or_load_repos("owner/repo1, owner/repo2\nowner/repo3")
    assert repos == ["owner/repo1", "owner/repo2", "owner/repo3"]


def test_git_sync_repository(tmp_path: Path):
    """Verify sync_repository creates a valid git repository and returns SHA."""
    gm = GitManager(workspace_dir=tmp_path)
    repo_path, branch, sha = gm.sync_repository("owner/test-sync-repo", allow_init=True)

    assert repo_path.exists()
    assert (repo_path / ".git").exists()
    assert branch in ("main", "master")
    assert len(sha) == 40


def test_sync_repository_raises_runtime_error_on_failed_clone(tmp_path: Path, monkeypatch):
    """Verify sync_repository raises RuntimeError when clone fails."""
    gm = GitManager(workspace_dir=tmp_path)

    # 1. CalledProcessError during clone
    def mock_fail(cmd, *args, **kwargs):
        if isinstance(cmd, list) and "clone" in cmd:
            raise subprocess.CalledProcessError(128, cmd, stderr="fatal: repository not found")
        return subprocess.run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", mock_fail)
    with pytest.raises(RuntimeError, match=r"Failed to clone repository owner/failed-clone-repo"):
        gm.sync_repository("owner/failed-clone-repo", allow_init=False)

    # 2. Generic Exception during clone
    def mock_exc(cmd, *args, **kwargs):
        if isinstance(cmd, list) and "clone" in cmd:
            raise RuntimeError("Network unreachable")
        return subprocess.run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", mock_exc)
    with pytest.raises(RuntimeError, match=r"Failed to clone repository owner/failed-clone-repo-2"):
        gm.sync_repository("owner/failed-clone-repo-2", allow_init=False)


def test_get_open_bot_prs_and_skip_files(tmp_path: Path):
    """Verify extracting modified files from open PRs and writing .skip_files.txt."""
    gm = GitManager(workspace_dir=tmp_path)
    repo_path, _, _ = gm.sync_repository("owner/collision-repo", allow_init=True)

    simulated_prs = [
        {"number": 10, "headRefName": "fix/auto-1", "files": [{"path": "src/auth.py"}, {"path": "src/user.py"}]},
        {"number": 11, "headRefName": "fix/auto-2", "files": [{"path": "src/db.py"}]}
    ]

    count, skip_files = gm.get_open_bot_prs("owner/collision-repo", repo_path, simulated_open_prs=simulated_prs)
    assert count == 2
    assert "src/auth.py" in skip_files
    assert "src/user.py" in skip_files
    assert "src/db.py" in skip_files

    skip_file_on_disk = repo_path / ".skip_files.txt"
    assert skip_file_on_disk.exists()
    content = skip_file_on_disk.read_text(encoding="utf-8")
    assert "src/auth.py" in content
    assert "src/db.py" in content


def test_create_atomic_branch_and_force_push_guard(tmp_path: Path):
    """Verify atomic branch naming and refusal of force pushes."""
    gm = GitManager(workspace_dir=tmp_path)
    repo_path, _, _ = gm.sync_repository("owner/branch-repo", allow_init=True)

    branch = gm.create_atomic_branch(repo_path, prefix="auto")
    assert branch.startswith("fix/auto-")

    # Verify branch is checked out
    p = subprocess.run(["git", "branch", "--show-current"], cwd=repo_path, capture_output=True, text=True, check=True)
    assert p.stdout.strip() == branch

    # Force push must raise ValueError
    with pytest.raises(ValueError, match="RULE-GIT-02 Violation"):
        gm.push_atomic_branch(repo_path, branch, force=True)


def test_rollback_working_tree_and_purge_artifacts(tmp_path: Path):
    """Verify rollback resets dirty modifications and cleans temporary files."""
    gm = GitManager(workspace_dir=tmp_path)
    repo_path, branch, _ = gm.sync_repository("owner/rollback-repo", allow_init=True)

    # Create dirty changes and temporary files
    dirty_file = repo_path / "README.md"
    dirty_file.write_text("DIRTY MODIFICATION", encoding="utf-8")
    untracked = repo_path / "untracked.tmp"
    untracked.write_text("untracked", encoding="utf-8")
    skip_file = repo_path / ".skip_files.txt"
    skip_file.write_text("src/skip.py", encoding="utf-8")

    gm.rollback_working_tree(repo_path, default_branch=branch)

    assert not untracked.exists()
    assert not skip_file.exists()
    assert "DIRTY MODIFICATION" not in dirty_file.read_text(encoding="utf-8")


# =========================================================================
# Security Unit Tests for GitManager
# =========================================================================

def test_git_manager_slug_validation(tmp_path: Path):
    """Verify sync_repository and get_open_bot_prs reject invalid slugs and path traversal."""
    gm = GitManager(workspace_dir=tmp_path)
    invalid_slugs = [
        "../../etc",
        "owner/../../etc",
        "owner/..",
        "..owner/repo",
        "owner..",
        "owner/repo..",
        "owner/..repo",
        "owner\\repo",
        "-bad_flag/repo",
        "owner/-bad_flag",
        "owner/repo/extra",
        "single_token",
        "",
        "owner/repo;rm -rf /",
    ]
    for bad_slug in invalid_slugs:
        with pytest.raises(ValueError, match="[Ii]nvalid repository slug|Path traversal|Argument injection"):
            gm.sync_repository(bad_slug)

        with pytest.raises(ValueError, match="[Ii]nvalid repository slug|Path traversal|Argument injection"):
            gm.get_open_bot_prs(bad_slug, tmp_path)


def test_git_manager_sanitized_cloning(tmp_path: Path, monkeypatch):
    """Verify git clone arguments pass clean URL without token and inject extraHeader with basic auth."""
    secret_token = "ghp_111122223333444455556666777788889999"
    gm = GitManager(workspace_dir=tmp_path, github_token=secret_token)

    auth_bytes = f"x-access-token:{secret_token}".encode("utf-8")
    expected_b64 = base64.b64encode(auth_bytes).decode("ascii")
    expected_header_arg = f"http.https://github.com/.extraHeader=AUTHORIZATION: basic {expected_b64}"
    clean_clone_url = "https://github.com/owner/secure-clone-repo.git"

    executed_commands = []
    original_run = subprocess.run

    def mock_subprocess_run(cmd, *args, **kwargs):
        executed_commands.append(cmd)
        if isinstance(cmd, list) and "clone" in cmd:
            # 1. Clean URL check: token must NOT appear in any arg
            for arg in cmd:
                assert secret_token not in arg, f"Secret token leaked in git clone arg: {arg}"
                assert not arg.startswith("https://x-access-token:"), f"Embedded token in URL: {arg}"
            # 2. Verify clean URL is passed
            assert clean_clone_url in cmd
            # 3. Verify extraHeader basic auth configuration is passed
            assert "-c" in cmd
            c_index = cmd.index("-c")
            assert cmd[c_index + 1] == expected_header_arg

            # Simulate successful clone by initializing the repo at target
            target_path = Path(cmd[-1])
            target_path.mkdir(parents=True, exist_ok=True)
            original_run(["git", "init", "-b", "main"], cwd=target_path, check=True, capture_output=True)
            original_run(["git", "config", "user.name", "Test"], cwd=target_path, check=True, capture_output=True)
            original_run(["git", "config", "user.email", "test@test.local"], cwd=target_path, check=True, capture_output=True)
            (target_path / "README.md").write_text("# Repo\n", encoding="utf-8")
            original_run(["git", "add", "README.md"], cwd=target_path, check=True, capture_output=True)
            original_run(["git", "commit", "-m", "init"], cwd=target_path, check=True, capture_output=True)

            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        return original_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    repo_path, branch, sha = gm.sync_repository("owner/secure-clone-repo")
    assert repo_path.exists()
    assert len(sha) == 40
    assert any("clone" in cmd for cmd in executed_commands)


def test_git_manager_exception_scrubbing(tmp_path: Path):
    """Verify _scrub_credentials replaces tokens, PATs, Bearer/Basic headers, and extraHeader flags."""
    secret_token = "ghp_111122223333444455556666777788889999"
    gm = GitManager(workspace_dir=tmp_path, github_token=secret_token)

    auth_bytes = f"x-access-token:{secret_token}".encode("utf-8")
    b64_token = base64.b64encode(auth_bytes).decode("ascii")

    raw_exception_text = (
        f"fatal: unable to access 'https://x-access-token:{secret_token}@github.com/owner/repo.git/': "
        f"The requested URL returned error: 403 with header AUTHORIZATION: basic {b64_token} "
        f"using flag -c http.https://github.com/.extraHeader=AUTHORIZATION: basic {b64_token}"
    )

    scrubbed = gm._scrub_credentials(raw_exception_text)
    assert secret_token not in scrubbed
    assert b64_token not in scrubbed
    assert "[REDACTED]" in scrubbed
    assert "http.https://github.com/.extraHeader=[REDACTED]" in scrubbed


def test_push_atomic_branch_raises_when_remote_configured(tmp_path: Path):
    """Verify push_atomic_branch re-raises CalledProcessError with scrubbed credentials when origin remote is configured."""
    from unittest.mock import patch

    token = "ghp_SecretToken12345678901234567890123456"
    gm = GitManager(workspace_dir=tmp_path, github_token=token)
    repo_dir = tmp_path / "repos" / "test_repo"
    repo_dir.mkdir(parents=True)

    subprocess.run(["git", "init", "-b", "main"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=repo_dir, check=True, capture_output=True)
    (repo_dir / "README.md").write_text("test", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo_dir, check=True, capture_output=True)
    branch = gm.create_atomic_branch(repo_dir)

    # Configure mock origin remote
    subprocess.run(["git", "remote", "add", "origin", "https://github.com/fake/repo.git"], cwd=repo_dir, check=True, capture_output=True)

    real_run = subprocess.run
    push_err = subprocess.CalledProcessError(
        returncode=1,
        cmd=["git", "push", "origin", branch],
        stderr=f"fatal: remote rejected with token {token}"
    )

    def mock_push(cmd, *args, **kwargs):
        if isinstance(cmd, list) and len(cmd) > 1 and "push" in cmd:
            raise push_err
        return real_run(cmd, *args, **kwargs)

    with patch("subprocess.run", side_effect=mock_push):
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            gm.push_atomic_branch(repo_dir, branch)

        assert token not in str(exc_info.value.stderr)
        assert "[REDACTED]" in str(exc_info.value.stderr)


def test_push_atomic_branch_swallows_when_remote_unconfigured(tmp_path: Path):
    """Verify push_atomic_branch swallows errors when no origin remote exists (backward compatibility)."""
    token = "ghp_SecretToken12345678901234567890123456"
    gm = GitManager(workspace_dir=tmp_path, github_token=token)
    repo_dir = tmp_path / "repos" / "test_local_only"
    repo_dir.mkdir(parents=True)

    subprocess.run(["git", "init", "-b", "main"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=repo_dir, check=True, capture_output=True)
    (repo_dir / "README.md").write_text("test", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo_dir, check=True, capture_output=True)
    branch = gm.create_atomic_branch(repo_dir)

    # Note: NO remote origin is added.
    # Push attempt will fail because 'origin' doesn't exist, but it should be swallowed.
    gm.push_atomic_branch(repo_dir, branch)


