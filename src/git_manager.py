"""
Git Workspace Manager for AutoBugHunter 24/7: Repository sync, collision guard, and branch management.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

REPO_SLUG_REGEX = re.compile(r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$")


def validate_repo_slug(repo_slug: str) -> None:
    """Validate repository slug format preventing path traversal and argument injection."""
    if not repo_slug or not isinstance(repo_slug, str):
        raise ValueError(f"Invalid repository slug: {repo_slug!r}")
    if "\\" in repo_slug or not REPO_SLUG_REGEX.match(repo_slug):
        raise ValueError(f"Invalid repository slug format: '{repo_slug}'")
    parts = repo_slug.split("/")
    if len(parts) != 2:
        raise ValueError(f"Invalid repository slug format: '{repo_slug}'")
    owner, repo = parts
    if owner in (".", "..") or repo in (".", "..") or ".." in owner or ".." in repo:
        raise ValueError(f"Path traversal detected in repository slug: '{repo_slug}'")
    if repo_slug.startswith("-") or owner.startswith("-") or repo.startswith("-"):
        raise ValueError(f"Argument injection detected in repository slug: '{repo_slug}'")


class GitManager:
    """Manages Git operations, collision guards, hard-reset synchronization, and atomic branch lifecycles."""

    TEMPORARY_FILES = [".skip_files.txt", ".static_findings.json", ".bug_fix_report.json"]

    def __init__(self, workspace_dir: Path | str, github_token: str = "", max_open_prs: int = 5):
        self.workspace_dir = Path(workspace_dir).resolve()
        self.repos_dir = self.workspace_dir / "repos"
        self.repos_dir.mkdir(parents=True, exist_ok=True)
        self.github_token = github_token
        self.max_open_prs = max_open_prs

    def _scrub_credentials(self, text: str) -> str:
        """Scrub tokens and auth headers from exception messages and command strings."""
        if not text:
            return text
        scrubbed = str(text)
        if self.github_token:
            scrubbed = scrubbed.replace(self.github_token, "[REDACTED]")
            try:
                auth_bytes = f"x-access-token:{self.github_token}".encode("utf-8")
                auth_b64 = base64.b64encode(auth_bytes).decode("ascii")
                scrubbed = scrubbed.replace(auth_b64, "[REDACTED]")
                token_b64 = base64.b64encode(self.github_token.encode("utf-8")).decode("ascii")
                scrubbed = scrubbed.replace(token_b64, "[REDACTED]")
            except Exception:
                pass
        scrubbed = re.sub(r"ghp_[A-Za-z0-9_]{36,}", "[REDACTED]", scrubbed)
        scrubbed = re.sub(r"github_pat_[A-Za-z0-9_]{82,}", "[REDACTED]", scrubbed)
        scrubbed = re.sub(r"gh[ours]_[A-Za-z0-9_]{36,}", "[REDACTED]", scrubbed)
        scrubbed = re.sub(r"(?i)\bbasic\s+[A-Za-z0-9+/=]{20,}", "basic [REDACTED]", scrubbed)
        scrubbed = re.sub(r"(?i)\bbearer\s+[A-Za-z0-9_\-\.=]{20,}", "bearer [REDACTED]", scrubbed)
        scrubbed = re.sub(r"http\.https://github\.com/\.extraHeader=[^\s'\"]+", "http.https://github.com/.extraHeader=[REDACTED]", scrubbed)
        scrubbed = re.sub(r"http\.extraHeader=[^\s'\"]+", "http.extraHeader=[REDACTED]", scrubbed)
        return scrubbed

    def _gh_env(self) -> dict[str, str]:
        """Construct environment with explicit GitHub authentication for gh CLI calls."""
        env = os.environ.copy()
        if self.github_token:
            env["GH_TOKEN"] = self.github_token
            env["GITHUB_TOKEN"] = self.github_token
        return env

    def configure_git_and_gh(self) -> None:
        """Configure global git bot identity and authenticate GitHub CLI."""
        try:
            subprocess.run(["git", "config", "--global", "user.name", "AutoBugHunter[bot]"], check=False, capture_output=True)
            subprocess.run(["git", "config", "--global", "user.email", "autobughunter[bot]@users.noreply.github.com"], check=False, capture_output=True)
        except Exception:
            pass

        if self.github_token and shutil.which("gh"):
            try:
                subprocess.run(
                    ["gh", "auth", "login", "--with-token"],
                    input=self.github_token,
                    text=True,
                    check=False,
                    capture_output=True,
                    env=self._gh_env(),
                    timeout=30
                )
            except Exception:
                pass

    def get_authenticated_user(self) -> Optional[str]:
        """Return authenticated GitHub username using gh CLI or cached identity."""
        if not self.github_token:
            return None
        if hasattr(self, "_cached_auth_user") and self._cached_auth_user:
            return self._cached_auth_user
        if shutil.which("gh"):
            try:
                res = subprocess.run(
                    ["gh", "api", "user", "--jq", ".login"],
                    capture_output=True,
                    text=True,
                    env=self._gh_env(),
                    timeout=15,
                    check=True
                )
                user = res.stdout.strip()
                if user:
                    self._cached_auth_user = user
                    return user
            except Exception:
                pass
        return None

    def has_push_access(self, repo_slug: str) -> bool:
        """Check whether authenticated user has direct push access to repo_slug."""
        validate_repo_slug(repo_slug)
        auth_user = self.get_authenticated_user()
        if auth_user and repo_slug.lower().startswith(f"{auth_user.lower()}/"):
            return True
        if shutil.which("gh") and self.github_token:
            try:
                res = subprocess.run(
                    ["gh", "api", f"repos/{repo_slug}", "--jq", ".permissions.push"],
                    capture_output=True,
                    text=True,
                    env=self._gh_env(),
                    timeout=15,
                    check=False
                )
                if res.returncode == 0 and res.stdout.strip().lower() == "true":
                    return True
            except Exception:
                pass
        return False

    def ensure_fork(self, repo_slug: str) -> Optional[str]:
        """Ensure a fork of repo_slug exists under authenticated user's account, returning fork slug."""
        validate_repo_slug(repo_slug)
        auth_user = self.get_authenticated_user()
        if not auth_user:
            return None
        parts = repo_slug.split("/")
        if len(parts) != 2:
            return None
        repo_name = parts[1]
        fork_slug = f"{auth_user}/{repo_name}"

        if shutil.which("gh") and self.github_token:
            # 1. Check if fork repo already exists
            try:
                res = subprocess.run(
                    ["gh", "api", f"repos/{fork_slug}", "--jq", ".full_name"],
                    capture_output=True,
                    text=True,
                    env=self._gh_env(),
                    timeout=15,
                    check=False
                )
                if res.returncode == 0 and res.stdout.strip().lower() == fork_slug.lower():
                    return fork_slug
            except Exception:
                pass

            # 2. Trigger fork creation via gh CLI
            try:
                fork_res = subprocess.run(
                    ["gh", "repo", "fork", repo_slug, "--clone=false"],
                    capture_output=True,
                    text=True,
                    env=self._gh_env(),
                    timeout=30,
                    check=False
                )
                if fork_res.returncode == 0:
                    return fork_slug
            except Exception:
                pass
        return None

    def discover_or_load_repos(self, target_repos_str: str, auto_discover: bool = False) -> list[str]:
        """Load target repositories from string or discover active repos via GitHub CLI."""
        if not auto_discover:
            if not target_repos_str:
                return []
            repos = []
            for item in target_repos_str.replace("\n", ",").split(","):
                slug = item.strip()
                if slug:
                    repos.append(slug)
            return repos

        # Auto-discover non-fork, non-archived repositories via gh CLI
        if shutil.which("gh"):
            try:
                res = subprocess.run(
                    ["gh", "repo", "list", "--limit", "100", "--json", "nameWithOwner,isFork,isArchived"],
                    capture_output=True,
                    text=True,
                    env=self._gh_env(),
                    timeout=30,
                    check=True
                )
                data = json.loads(res.stdout)
                discovered = [
                    item["nameWithOwner"]
                    for item in data
                    if not item.get("isFork", False) and not item.get("isArchived", False)
                ]
                if discovered:
                    return discovered[:20]
            except Exception:
                pass

        # Fallback to target_repos_str if gh fails
        return [r.strip() for r in target_repos_str.replace("\n", ",").split(",") if r.strip()][:20]

    def sync_repository(self, repo_slug: str, existing_path: Optional[Path] = None, allow_init: bool = False) -> tuple[Path, str, str]:
        """Hard-reset sync working tree to origin default branch, returning (repo_path, default_branch, head_sha)."""
        validate_repo_slug(repo_slug)
        target_path = existing_path or (self.repos_dir / repo_slug.replace("/", "__"))
        target_path.mkdir(parents=True, exist_ok=True)

        # If not already a git repository, clone or initialize
        if not (target_path / ".git").exists():
            if allow_init:
                subprocess.run(["git", "init", "-b", "main"], cwd=target_path, check=True, capture_output=True)
                subprocess.run(["git", "config", "user.name", "AutoBugHunter[bot]"], cwd=target_path, check=True, capture_output=True)
                subprocess.run(["git", "config", "user.email", "autobughunter[bot]@users.noreply.github.com"], cwd=target_path, check=True, capture_output=True)
                readme = target_path / "README.md"
                if not readme.exists():
                    readme.write_text(f"# {repo_slug}\n", encoding="utf-8")
                    subprocess.run(["git", "add", "README.md"], cwd=target_path, check=True, capture_output=True)
                    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=target_path, check=True, capture_output=True)
            else:
                cloned = False
                clean_clone_url = f"https://github.com/{repo_slug}.git"
                clone_cmd = ["git"]
                if self.github_token:
                    auth_bytes = f"x-access-token:{self.github_token}".encode("utf-8")
                    auth_b64 = base64.b64encode(auth_bytes).decode("ascii")
                    clone_cmd.extend(["-c", f"http.https://github.com/.extraHeader=AUTHORIZATION: basic {auth_b64}"])
                clone_cmd.extend(["clone", clean_clone_url, str(target_path)])
                try:
                    subprocess.run(
                        clone_cmd,
                        check=True,
                        capture_output=True,
                        timeout=120
                    )
                    cloned = True
                except subprocess.CalledProcessError as e:
                    scrubbed_cmd = [self._scrub_credentials(str(c)) for c in e.cmd] if isinstance(e.cmd, list) else self._scrub_credentials(str(e.cmd))
                    e.cmd = scrubbed_cmd
                    if e.stderr:
                        e.stderr = self._scrub_credentials(e.stderr)
                    if e.stdout:
                        e.stdout = self._scrub_credentials(e.stdout)
                    cloned = False
                except Exception:
                    cloned = False

                if not cloned:
                    raise RuntimeError(f"Failed to clone repository {repo_slug}")

        # Abort any in-progress merges or rebases
        subprocess.run(["git", "rebase", "--abort"], cwd=target_path, check=False, capture_output=True)
        subprocess.run(["git", "merge", "--abort"], cwd=target_path, check=False, capture_output=True)

        # Hard reset and clean working tree
        subprocess.run(["git", "reset", "--hard", "HEAD"], cwd=target_path, check=True, capture_output=True)
        subprocess.run(["git", "clean", "-fd"], cwd=target_path, check=True, capture_output=True)

        # Detect default branch
        default_branch = "main"
        p_remote = subprocess.run(
            ["git", "symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
            cwd=target_path,
            capture_output=True,
            text=True,
            check=False
        )
        if p_remote.returncode == 0 and p_remote.stdout.strip():
            ref = p_remote.stdout.strip()
            if ref.startswith("origin/"):
                default_branch = ref[len("origin/"):]
            else:
                default_branch = ref
        else:
            # Check if main exists, else master
            p_branches = subprocess.run(["git", "branch", "--list"], cwd=target_path, capture_output=True, text=True, check=False)
            branch_out = p_branches.stdout
            if "main" in branch_out:
                default_branch = "main"
            elif "master" in branch_out:
                default_branch = "master"

        # Checkout default branch and pull if remote exists
        subprocess.run(["git", "checkout", default_branch], cwd=target_path, check=False, capture_output=True)
        pull_cmd = ["git"]
        if self.github_token:
            auth_bytes = f"x-access-token:{self.github_token}".encode("utf-8")
            auth_b64 = base64.b64encode(auth_bytes).decode("ascii")
            pull_cmd.extend(["-c", f"http.https://github.com/.extraHeader=AUTHORIZATION: basic {auth_b64}"])
        pull_cmd.extend(["pull", "--ff-only", "origin", default_branch])
        subprocess.run(pull_cmd, cwd=target_path, check=False, capture_output=True)

        # In fork mode: configure fork remote if authenticated user lacks push access to repo_slug
        if self.github_token and shutil.which("gh"):
            try:
                if not self.has_push_access(repo_slug):
                    fork_slug = self.ensure_fork(repo_slug)
                    if fork_slug:
                        fork_url = f"https://github.com/{fork_slug}.git"
                        p_fork = subprocess.run(["git", "remote", "get-url", "fork"], cwd=target_path, capture_output=True, text=True, check=False)
                        if p_fork.returncode == 0:
                            subprocess.run(["git", "remote", "set-url", "fork", fork_url], cwd=target_path, check=False, capture_output=True)
                        else:
                            subprocess.run(["git", "remote", "add", "fork", fork_url], cwd=target_path, check=False, capture_output=True)
            except Exception:
                pass

        # Get HEAD commit SHA
        p_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=target_path, capture_output=True, text=True, check=True)
        head_sha = p_sha.stdout.strip()

        return target_path, default_branch, head_sha

    def get_open_bot_prs(
        self,
        repo_slug: str,
        repo_path: Path,
        simulated_open_prs: Optional[list[dict[str, Any]]] = None
    ) -> tuple[int, list[str]]:
        """Query open PRs authored by bot, write .skip_files.txt, and return (count, skip_files)."""
        validate_repo_slug(repo_slug)
        prs = simulated_open_prs

        if prs is None and shutil.which("gh"):
            try:
                res = subprocess.run(
                    [
                        "gh", "pr", "list",
                        "--repo", repo_slug,
                        "--author", "@me",
                        "--state", "open",
                        "--json", "number,headRefName,files"
                    ],
                    capture_output=True,
                    text=True,
                    env=self._gh_env(),
                    timeout=30,
                    check=True
                )
                prs = json.loads(res.stdout)
            except Exception:
                prs = []

        if prs is None:
            prs = []

        skip_files: set[str] = set()
        for pr in prs:
            for f in pr.get("files", []):
                if isinstance(f, dict):
                    p = f.get("path", "")
                    if p:
                        skip_files.add(p)
                elif isinstance(f, str) and f:
                    skip_files.add(f)

        sorted_skip = sorted(list(skip_files))
        skip_file_path = repo_path / ".skip_files.txt"
        skip_file_path.write_text("\n".join(sorted_skip), encoding="utf-8")

        return len(prs), sorted_skip

    def create_atomic_branch(self, repo_path: Path, prefix: str = "auto", scope: Optional[str] = None) -> str:
        """Create and checkout isolated branch matching RULE-GIT-01: fix/<prefix>-[<scope>-]<repo_short>-<hex6>."""
        repo_short = repo_path.name[:8]
        hex6 = f"{int(time.time() * 1000) % 0xFFFFFF:06x}"
        if scope:
            clean_scope = re.sub(r"[^a-zA-Z0-9_-]", "", scope.lower())
            if clean_scope:
                branch_name = f"fix/{prefix}-{clean_scope}-{repo_short}-{hex6}"
            else:
                branch_name = f"fix/{prefix}-{repo_short}-{hex6}"
        else:
            branch_name = f"fix/{prefix}-{repo_short}-{hex6}"
        subprocess.run(["git", "checkout", "-b", branch_name], cwd=repo_path, check=True, capture_output=True)
        return branch_name

    def push_atomic_branch(self, repo_path: Path, branch_name: str, force: bool = False, remote: str = "origin") -> None:
        """Push branch to origin or fork remote without force push (enforcing RULE-GIT-02)."""
        if force:
            raise ValueError("RULE-GIT-02 Violation: Force pushing is strictly prohibited")

        # Verify branch exists locally
        p = subprocess.run(["git", "branch", "--list", branch_name], cwd=repo_path, capture_output=True, text=True, check=True)
        if branch_name not in p.stdout:
            raise ValueError(f"Branch {branch_name} does not exist locally")

        try:
            push_cmd = ["git"]
            if self.github_token:
                auth_bytes = f"x-access-token:{self.github_token}".encode("utf-8")
                auth_b64 = base64.b64encode(auth_bytes).decode("ascii")
                push_cmd.extend(["-c", f"http.https://github.com/.extraHeader=AUTHORIZATION: basic {auth_b64}"])
            push_cmd.extend(["push", remote, branch_name])
            subprocess.run(push_cmd, cwd=repo_path, check=True, capture_output=True, timeout=120)
        except subprocess.CalledProcessError as e:
            scrubbed_cmd = [self._scrub_credentials(str(c)) for c in e.cmd] if isinstance(e.cmd, list) else self._scrub_credentials(str(e.cmd))
            e.cmd = scrubbed_cmd
            if e.stderr:
                e.stderr = self._scrub_credentials(e.stderr)
            if e.stdout:
                e.stdout = self._scrub_credentials(e.stdout)

            # Check if remote is configured
            has_remote = False
            try:
                check_remote = subprocess.run(
                    ["git", "remote", "get-url", remote],
                    cwd=repo_path, capture_output=True, text=True, check=False
                )
                has_remote = (check_remote.returncode == 0 and bool(check_remote.stdout.strip()))
            except Exception:
                has_remote = False

            if has_remote:
                raise e
            # In test environments without remote configured, ignore push failure
            pass
        except Exception as e:
            # Check if remote is configured before ignoring generic exceptions
            has_remote = False
            try:
                check_remote = subprocess.run(
                    ["git", "remote", "get-url", remote],
                    cwd=repo_path, capture_output=True, text=True, check=False
                )
                has_remote = (check_remote.returncode == 0 and bool(check_remote.stdout.strip()))
            except Exception:
                has_remote = False

            if has_remote:
                raise e
            # In test environments without remote configured, ignore push failure
            pass

    def rollback_working_tree(self, repo_path: Path, default_branch: str = "main") -> None:
        """Clean working tree, checkout default branch, and purge temporary artifacts."""
        subprocess.run(["git", "checkout", default_branch], cwd=repo_path, check=False, capture_output=True)
        subprocess.run(["git", "reset", "--hard", "HEAD"], cwd=repo_path, check=True, capture_output=True)
        subprocess.run(["git", "clean", "-fd"], cwd=repo_path, check=True, capture_output=True)

        for tf in self.TEMPORARY_FILES:
            target = repo_path / tf
            if target.exists():
                try:
                    target.unlink()
                except OSError:
                    pass
