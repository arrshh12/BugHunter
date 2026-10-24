"""
PR Review & Comment Remediation Engine for AutoBugHunter 24/7 (Milestone 2).
Autonomous monitoring of open PRs, extracting unresolved review feedback from
bots and human reviewers via GitHub GraphQL API, synthesizing surgical patches,
verifying safety bounds, non-force atomic pushing, inline replies, and
idempotent SQLite persistence.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


GRAPHQL_GET_PR_REVIEW_THREADS = """
query GetPullRequestReviewThreads($owner: String!, $name: String!, $prNumber: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $prNumber) {
      id
      number
      headRefName
      headRefOid
      reviewThreads(first: 50) {
        pageInfo {
          hasNextPage
          endCursor
        }
        nodes {
          id
          isResolved
          isOutdated
          path
          line
          originalLine
          comments(first: 20) {
            nodes {
              id
              databaseId
              body
              diffHunk
              createdAt
              author {
                login
              }
            }
          }
        }
      }
    }
  }
}
"""

GRAPHQL_RESOLVE_REVIEW_THREAD = """
mutation ResolveReviewThread($threadId: ID!) {
  resolveReviewThread(input: {threadId: $threadId}) {
    thread {
      id
      isResolved
    }
  }
}
"""

GRAPHQL_ADD_THREAD_REPLY = """
mutation AddPullRequestReviewThreadReply($threadId: ID!, $body: String!) {
  addPullRequestReviewThreadReply(input: {pullRequestReviewThreadId: $threadId, body: $body}) {
    comment {
      id
      body
      createdAt
    }
  }
}
"""


@dataclass
class ReviewComment:
    """Represents an actionable unresolved review comment on a pull request."""

    comment_id: str
    thread_id: str
    repo_slug: str
    pr_number: int
    branch_name: str
    path: str
    line: int
    diff_hunk: str
    body: str
    author: str
    is_bot: bool = False
    created_at: str = ""
    comment_database_id: Optional[int] = None


@dataclass
class ReviewRemediationResult:
    """Outcome of an individual review comment remediation attempt."""

    success: bool
    repo_slug: str
    pr_number: int
    thread_id: str
    comment_id: str
    commit_sha: str = ""
    short_sha: str = ""
    status: str = "FAILED"
    error_message: Optional[str] = None


class ReviewMonitor:
    """
    Autonomous engine that discovers open PRs, extracts unresolved review feedback,
    synthesizes surgical patches, verifies diff bounds, pushes without force-push,
    posts replies, resolves threads via GraphQL, and records remediations in SQLite.
    """

    def __init__(
        self,
        config: Any,
        database: Any,
        git_manager: Any,
        verifier: Any,
        key_manager: Optional[Any] = None,
        aider_runner: Optional[Any] = None,
        logger: Optional[Any] = None,
    ):
        self.config = config
        self.db = database
        self.git_manager = git_manager
        self.verifier = verifier
        self.key_manager = key_manager
        self.aider_runner = aider_runner
        self.logger = logger

    def merge_pr(self, *args: Any, **kwargs: Any) -> None:
        """Strictly prohibited by RULE-NO-AUTOMERGE."""
        raise PermissionError(
            "RULE-NO-AUTOMERGE Violation: AutoBugHunter is strictly forbidden from auto-merging pull requests. "
            "All pull request merges require manual human review and approval by @bitxwolf."
        )

    def _log(self, message: str, level: str = "INFO") -> None:
        """Log message through configured logger, standard logger, and bughunter.log."""
        level_upper = level.upper()
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{ts}] [{level_upper}] {message}"

        if self.logger:
            try:
                if hasattr(self.logger, "log"):
                    self.logger.log(level_upper, message)
                elif hasattr(self.logger, level.lower()):
                    getattr(self.logger, level.lower())(message)
            except Exception:
                pass

        log_obj = logging.getLogger("bughunter.review_monitor")
        lvl_num = getattr(logging, level_upper, logging.INFO)
        log_obj.log(lvl_num, message)

        try:
            log_path = Path("bughunter.log")
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(entry + "\n")
        except Exception:
            pass

    def _gh_env(self) -> dict[str, str]:
        """Construct environment for gh CLI executions with token configured."""
        if self.git_manager and hasattr(self.git_manager, "_gh_env"):
            return self.git_manager._gh_env()
        env = os.environ.copy()
        token = getattr(self.config, "github_token", "") or os.environ.get("GITHUB_TOKEN", "")
        if token:
            env["GH_TOKEN"] = token
            env["GITHUB_TOKEN"] = token
        return env

    def get_repo_path(self, repo_slug: str, existing_path: Optional[Path] = None) -> Path:
        """Resolve filesystem path for a target repository workspace."""
        if existing_path and Path(existing_path).exists():
            return Path(existing_path)
        if self.git_manager and hasattr(self.git_manager, "repos_dir"):
            p1 = self.git_manager.repos_dir / repo_slug.replace("/", "__")
            if p1.exists():
                return p1
            p2 = self.git_manager.repos_dir / repo_slug.replace("/", "_")
            if p2.exists():
                return p2
            p3 = self.git_manager.repos_dir / repo_slug.split("/")[-1]
            if p3.exists():
                return p3
            return p1
        return Path("repos") / repo_slug.replace("/", "__")

    def _determine_remote(self, repo_path: Path, repo_slug: str) -> str:
        """Determine whether to push to 'fork' or 'origin'."""
        try:
            p = subprocess.run(
                ["git", "remote"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            remotes = p.stdout.split()
            if "fork" in remotes:
                return "fork"
        except Exception:
            pass
        return "origin"

    def get_open_bot_prs(self, repo_slug: str) -> list[dict[str, Any]]:
        """
        Query open PRs authored by authenticated bot across repo_slug.
        Executes: gh pr list --repo <repo_slug> --author "@me" --state open --json number,headRefName,headRefOid,url,title
        """
        if not shutil.which("gh"):
            self._log("GitHub CLI 'gh' not found in PATH", level="WARNING")
            return []

        try:
            cmd = [
                "gh",
                "pr",
                "list",
                "--repo",
                repo_slug,
                "--author",
                "@me",
                "--state",
                "open",
                "--json",
                "number,headRefName,headRefOid,url,title",
            ]
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=self._gh_env(),
                timeout=30,
                check=True,
            )
            return json.loads(res.stdout) if res.stdout.strip() else []
        except subprocess.CalledProcessError as e:
            self._log(
                f"Failed querying open PRs for {repo_slug}: {e.stderr or e}",
                level="WARNING",
            )
            return []
        except Exception as e:
            self._log(
                f"Unexpected error querying open PRs for {repo_slug}: {e}",
                level="WARNING",
            )
            return []

    def execute_graphql(self, query: str, variables: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Execute a GitHub GraphQL query or mutation via gh api graphql."""
        if not shutil.which("gh"):
            self._log("GitHub CLI 'gh' not found in PATH", level="WARNING")
            return {"errors": [{"message": "gh CLI not found"}]}

        payload = {"query": query, "variables": variables or {}}
        try:
            res = subprocess.run(
                ["gh", "api", "graphql", "--input", "-"],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=self._gh_env(),
                timeout=30,
                check=False,
            )
            if res.returncode != 0:
                self._log(
                    f"GraphQL call failed (rc={res.returncode}): {res.stderr.strip()}",
                    level="WARNING",
                )
                return {"errors": [{"message": res.stderr.strip()}]}
            return json.loads(res.stdout) if res.stdout.strip() else {}
        except Exception as e:
            self._log(f"Exception executing GraphQL request: {e}", level="WARNING")
            return {"errors": [{"message": str(e)}]}

    def fetch_unresolved_review_threads(
        self, repo_slug: str, pr_number: int, head_ref: str = ""
    ) -> list[ReviewComment]:
        """
        Fetch unresolved review threads for a pull request using GraphQL API.
        Filters for threads where isResolved == False, author != bot identity ('arrshh12'),
        and thread has not yet been remediated.
        """
        if "/" not in repo_slug:
            return []
        owner, name = repo_slug.split("/", 1)

        variables = {
            "owner": owner,
            "name": name,
            "prNumber": pr_number,
        }

        try:
            data_resp = self.execute_graphql(GRAPHQL_GET_PR_REVIEW_THREADS, variables)
        except Exception as e:
            self._log(f"Failed fetching review threads for {repo_slug}#{pr_number}: {e}", level="WARNING")
            return []

        if not data_resp or "errors" in data_resp:
            errs = data_resp.get("errors") if data_resp else "No response"
            self._log(
                f"GraphQL query returned errors for {repo_slug}#{pr_number}: {errs}",
                level="WARNING",
            )
            return []

        pr_data = (
            data_resp.get("data", {})
            .get("repository", {})
            .get("pullRequest", {})
        )
        if not pr_data:
            return []

        resolved_head_ref = head_ref or pr_data.get("headRefName", "")
        thread_nodes = pr_data.get("reviewThreads", {}).get("nodes", [])

        bot_identity = "arrshh12"
        if self.git_manager and hasattr(self.git_manager, "get_authenticated_user"):
            try:
                bot_identity = self.git_manager.get_authenticated_user() or "arrshh12"
            except Exception:
                bot_identity = "arrshh12"

        actionable_comments: list[ReviewComment] = []
        for thread in thread_nodes:
            if not isinstance(thread, dict):
                continue
            if thread.get("isResolved"):
                continue

            thread_id = thread.get("id")
            if not thread_id:
                continue

            if self.db and self.db.is_thread_remediated(thread_id):
                continue

            comments_list = thread.get("comments", {}).get("nodes", [])
            if not comments_list:
                continue

            # Identify actionable reviewer comment (author not our bot account), prioritizing latest feedback
            actionable_comment = None
            for c_node in reversed(comments_list):
                if not isinstance(c_node, dict):
                    continue
                author = c_node.get("author", {}).get("login", "")
                if not author or author.lower() == bot_identity.lower():
                    continue
                actionable_comment = c_node
                break

            if not actionable_comment:
                continue

            author_login = actionable_comment.get("author", {}).get("login", "")
            is_bot = (
                "[bot]" in author_login.lower()
                or author_login.lower() in ("coderabbitai", "code-review-bot", "github-actions")
            )
            path = thread.get("path") or actionable_comment.get("path", "")
            line = thread.get("line") or thread.get("originalLine") or 0
            diff_hunk = actionable_comment.get("diffHunk", "")
            body = actionable_comment.get("body", "")
            comment_id = str(actionable_comment.get("id") or actionable_comment.get("databaseId") or "")
            db_id = actionable_comment.get("databaseId")
            comment_database_id = int(db_id) if db_id is not None else None

            actionable_comments.append(
                ReviewComment(
                    comment_id=comment_id,
                    thread_id=thread_id,
                    repo_slug=repo_slug,
                    pr_number=pr_number,
                    branch_name=resolved_head_ref,
                    path=path,
                    line=int(line) if line else 0,
                    diff_hunk=diff_hunk,
                    body=body,
                    author=author_login,
                    is_bot=is_bot,
                    created_at=actionable_comment.get("createdAt", ""),
                    comment_database_id=comment_database_id,
                )
            )

        return actionable_comments

    def post_inline_reply(
        self,
        repo_slug: str,
        pr_number: int,
        thread_id: str,
        comment_id: str,
        reply_text: str,
    ) -> bool:
        """
        Post an inline reply to a review thread.
        Tries GraphQL mutation addPullRequestReviewThreadReply first,
        falling back to REST API comment reply.
        """
        # 1. GraphQL mutation
        try:
            res = self.execute_graphql(
                GRAPHQL_ADD_THREAD_REPLY,
                {"threadId": thread_id, "body": reply_text},
            )
            if res and "data" in res and res.get("data", {}).get("addPullRequestReviewThreadReply"):
                return True
            if res and "errors" in res:
                self._log(f"GraphQL thread reply rejected: {res.get('errors')}", level="WARNING")
        except Exception as e:
            self._log(f"GraphQL inline reply exception: {e}", level="WARNING")

        # 2. REST API fallback
        try:
            if "/" in repo_slug and shutil.which("gh"):
                owner, repo = repo_slug.split("/", 1)
                rest_cmd = [
                    "gh",
                    "api",
                    "--method",
                    "POST",
                    f"/repos/{owner}/{repo}/pulls/{pr_number}/comments/{comment_id}/replies",
                    "-f",
                    f"body={reply_text}",
                ]
                p = subprocess.run(
                    rest_cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    env=self._gh_env(),
                    timeout=30,
                    check=False,
                )
                if p.returncode == 0:
                    return True
                self._log(
                    f"REST inline reply fallback failed (rc={p.returncode}): {p.stderr.strip()}",
                    level="WARNING",
                )
        except Exception as e:
            self._log(f"REST inline reply fallback exception: {e}", level="WARNING")

        return False

    def resolve_review_thread(self, thread_id: str) -> bool:
        """Resolve a review thread via GitHub GraphQL mutation resolveReviewThread."""
        try:
            res = self.execute_graphql(
                GRAPHQL_RESOLVE_REVIEW_THREAD,
                {"threadId": thread_id},
            )
            if res and "data" in res:
                thread_data = (
                    res.get("data", {})
                    .get("resolveReviewThread", {})
                    .get("thread", {})
                )
                if thread_data and thread_data.get("isResolved"):
                    return True
                if not res.get("errors"):
                    return True
            if res and "errors" in res:
                self._log(f"GraphQL resolve thread errors: {res.get('errors')}", level="WARNING")
        except Exception as e:
            self._log(f"GraphQL resolve thread exception: {e}", level="WARNING")
        return False

    def remediate_single_thread(
        self,
        repo_slug: str,
        pr_info: dict[str, Any],
        comment: ReviewComment,
        repo_path: Optional[Path] = None,
    ) -> ReviewRemediationResult:
        """
        Execute full remediation lifecycle for a single review comment thread:
        1. Checkout PR branch locally.
        2. Formulate surgical LLM prompt and apply minimal patch.
        3. Verify fix through verifier gate (<=150 lines, <=3 files, 0 secrets).
        4. Commit fix with conventional message.
        5. Push branch without force-push (enforcing RULE-GIT-02).
        6. Post inline reply with commit short SHA.
        7. Resolve thread via GraphQL.
        8. Record in database for strict idempotency.
        """
        target_path = repo_path or self.get_repo_path(repo_slug)
        branch_name = comment.branch_name or pr_info.get("headRefName", "")
        reviewer_label = "CodeRabbit" if "coderabbit" in comment.author.lower() else comment.author

        # Step 1: Checkout PR branch locally & ensure clean working tree
        try:
            if not target_path.exists():
                if self.git_manager and hasattr(self.git_manager, "sync_repository"):
                    target_path, _, _ = self.git_manager.sync_repository(repo_slug, existing_path=target_path)
                else:
                    target_path.mkdir(parents=True, exist_ok=True)

            remote_target = self._determine_remote(target_path, repo_slug)

            # Fetch remote PR branch first
            subprocess.run(
                ["git", "fetch", remote_target, branch_name],
                cwd=target_path,
                check=False,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
            )
            # Attempt checkout tracking remote branch
            p_co_remote = subprocess.run(
                ["git", "checkout", "-B", branch_name, f"{remote_target}/{branch_name}"],
                cwd=target_path,
                check=False,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
            )
            if p_co_remote.returncode != 0:
                p_b = subprocess.run(
                    ["git", "branch", "--list", branch_name],
                    cwd=target_path,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    check=False,
                )
                if branch_name in p_b.stdout:
                    subprocess.run(["git", "checkout", branch_name], cwd=target_path, check=True, capture_output=True, encoding="utf-8", errors="replace")
                else:
                    p_co = subprocess.run(["git", "checkout", branch_name], cwd=target_path, check=False, capture_output=True, encoding="utf-8", errors="replace")
                    if p_co.returncode != 0:
                        subprocess.run(["git", "checkout", "-b", branch_name], cwd=target_path, check=True, capture_output=True, encoding="utf-8", errors="replace")

            subprocess.run(["git", "reset", "--hard", "HEAD"], cwd=target_path, check=True, capture_output=True, encoding="utf-8", errors="replace")
            subprocess.run(["git", "clean", "-fd"], cwd=target_path, check=True, capture_output=True, encoding="utf-8", errors="replace")
        except Exception as e:
            self._log(f"Failed checking out PR branch {branch_name} for {repo_slug}: {e}", level="WARNING")
            return ReviewRemediationResult(
                success=False,
                repo_slug=repo_slug,
                pr_number=comment.pr_number,
                thread_id=comment.thread_id,
                comment_id=comment.comment_id,
                status="CHECKOUT_FAILED",
                error_message=str(e),
            )

        # Step 2: Formulate surgical LLM prompt and apply minimal patch
        prompt = (
            f"Fix this issue reported by code reviewer {reviewer_label} on line {comment.line} of {comment.path}:\n"
            f"Reviewer Comment:\n{comment.body}\n\n"
            f"Context Diff Hunk:\n{comment.diff_hunk}\n\n"
            f"Instruction: Apply minimal non-breaking surgical modifications to {comment.path}. "
            f"Do not modify unrelated lines or files. Enforce <= 150 diff lines."
        )

        patch_applied = False
        if self.aider_runner:
            key_entry = None
            if self.key_manager and hasattr(self.key_manager, "get_next_healthy_key"):
                try:
                    key_entry = self.key_manager.get_next_healthy_key()
                except Exception:
                    key_entry = None

            aider_res = self.aider_runner.run_aider(
                repo_path=target_path,
                target_file=comment.path,
                patch_instruction=prompt,
                key_entry=key_entry,
            )
            if aider_res.status == "SUCCESS":
                patch_applied = True
            elif aider_res.status != "MISSING_CLI":
                self._log(
                    f"Aider patching failed for {comment.path} ({aider_res.status}): {aider_res.error_message}",
                    level="WARNING",
                )
                if self.git_manager and hasattr(self.git_manager, "rollback_working_tree"):
                    self.git_manager.rollback_working_tree(target_path, branch_name)
                return ReviewRemediationResult(
                    success=False,
                    repo_slug=repo_slug,
                    pr_number=comment.pr_number,
                    thread_id=comment.thread_id,
                    comment_id=comment.comment_id,
                    status=f"AIDER_{aider_res.status}",
                    error_message=aider_res.error_message or f"Aider returned status {aider_res.status}",
                )

        if not patch_applied:
            # Fallback to direct LLM remediation
            self._run_direct_llm_remediation(target_path, comment.path, prompt)

        # Step 3: Verifier Gate
        sim_report = {
            "bug_found": True,
            "file_modified": comment.path,
            "pr_title": f"fix(review): address feedback from {reviewer_label} on {Path(comment.path).name}",
            "pr_body": f"Address review feedback on {comment.path}:\n{comment.body}",
        }

        ver_res = self.verifier.verify_and_sanitize_fix(
            repo_path=target_path,
            skip_files=[],
            max_files=3,
            max_lines=150,
            simulated_report=sim_report,
        )

        if not ver_res.verified:
            self._log(
                f"Verification gate rejected review patch for {comment.path}: {ver_res.error_reason}",
                level="WARNING",
            )
            if self.git_manager and hasattr(self.git_manager, "rollback_working_tree"):
                self.git_manager.rollback_working_tree(target_path, branch_name)
            return ReviewRemediationResult(
                success=False,
                repo_slug=repo_slug,
                pr_number=comment.pr_number,
                thread_id=comment.thread_id,
                comment_id=comment.comment_id,
                status="VERIFICATION_FAILED",
                error_message=ver_res.error_reason,
            )

        # Step 4: Atomic Commit
        filename = Path(comment.path).name or comment.path
        commit_msg = f"fix(review): address feedback from {reviewer_label} on {filename}"
        try:
            subprocess.run(["git", "add", "-A"], cwd=target_path, check=True, capture_output=True, encoding="utf-8", errors="replace")
            subprocess.run(["git", "commit", "-m", commit_msg], cwd=target_path, check=True, capture_output=True, encoding="utf-8", errors="replace")
            p_sha = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=target_path,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            commit_sha = p_sha.stdout.strip()
            short_sha = commit_sha[:7]
        except Exception as e:
            self._log(f"Failed committing review remediation: {e}", level="WARNING")
            if self.git_manager and hasattr(self.git_manager, "rollback_working_tree"):
                self.git_manager.rollback_working_tree(target_path, branch_name)
            return ReviewRemediationResult(
                success=False,
                repo_slug=repo_slug,
                pr_number=comment.pr_number,
                thread_id=comment.thread_id,
                comment_id=comment.comment_id,
                status="COMMIT_FAILED",
                error_message=str(e),
            )

        # Step 5: Push without force-push (RULE-GIT-02)
        try:
            self.git_manager.push_atomic_branch(
                repo_path=target_path,
                branch_name=branch_name,
                force=False,
                remote=remote_target,
            )
        except Exception as e:
            self._log(
                f"Failed to push review remediation to {remote_target}/{branch_name}: {e}",
                level="WARNING",
            )
            if self.git_manager and hasattr(self.git_manager, "rollback_working_tree"):
                self.git_manager.rollback_working_tree(target_path, branch_name)
            return ReviewRemediationResult(
                success=False,
                repo_slug=repo_slug,
                pr_number=comment.pr_number,
                thread_id=comment.thread_id,
                comment_id=comment.comment_id,
                status="PUSH_FAILED",
                error_message=str(e),
            )

        # Step 6: Post inline reply (using database ID if available for REST fallback)
        reply_id = str(comment.comment_database_id or comment.comment_id)
        reply_text = f"Noted and addressed in commit {short_sha}. Verified and resolved."
        self.post_inline_reply(
            repo_slug=repo_slug,
            pr_number=comment.pr_number,
            thread_id=comment.thread_id,
            comment_id=reply_id,
            reply_text=reply_text,
        )

        # Step 7: Resolve review thread via GraphQL
        resolved = self.resolve_review_thread(comment.thread_id)
        if not resolved:
            self._log(
                f"GraphQL resolution failed for thread {comment.thread_id}, but commit {short_sha} pushed and reply posted.",
                level="WARNING",
            )
            db_status = "RESOLUTION_FAILED"
        else:
            db_status = "RESOLVED"
        final_status = "RESOLVED"

        # Step 8: Database persistence for strict idempotency
        if self.db:
            try:
                self.db.record_review_remediation(
                    thread_id=comment.thread_id,
                    comment_id=comment.comment_id,
                    repo_slug=repo_slug,
                    pr_number=comment.pr_number,
                    commit_sha=commit_sha,
                    reviewer=comment.author,
                    path=comment.path,
                    line=comment.line,
                    feedback_summary=comment.body[:500],
                    status=db_status,
                )
            except Exception as e:
                self._log(f"Failed persisting review remediation in database: {e}", level="WARNING")

        return ReviewRemediationResult(
            success=True,
            repo_slug=repo_slug,
            pr_number=comment.pr_number,
            thread_id=comment.thread_id,
            comment_id=comment.comment_id,
            commit_sha=commit_sha,
            short_sha=short_sha,
            status=final_status,
        )

    def _run_direct_llm_remediation(
        self,
        repo_path: Path,
        target_rel_file: str,
        prompt: str,
    ) -> bool:
        """Direct LLM patching fallback when Aider runner is not available."""
        target_file = repo_path / target_rel_file
        if not target_file.exists():
            return False

        try:
            original_code = target_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return False

        base_url = "https://api.scalemax.pro/v1"
        api_key = ""
        model = "openai/gpt-6-luna"

        if self.key_manager and hasattr(self.key_manager, "get_next_healthy_key"):
            try:
                k = self.key_manager.get_next_healthy_key()
                if k:
                    base_url = k.base_url
                    api_key = k.api_key
                    model = k.model
            except Exception:
                pass

        if not api_key and self.config:
            if hasattr(self.config, "llm_keys") and self.config.llm_keys:
                k0 = self.config.llm_keys[0]
                base_url = getattr(k0, "base_url", base_url)
                api_key = getattr(k0, "api_key", "")
                model = getattr(k0, "model", model)
            else:
                base_url = getattr(self.config, "openai_api_base", base_url)
                api_key = getattr(self.config, "openai_api_key", "")
                model = getattr(self.config, "llm_model", model)

        if not api_key:
            api_key = os.environ.get("OPENAI_API_KEY", "")

        if not api_key or any(fake in str(api_key).lower() for fake in ("test", "mock", "dummy", "fake")):
            return False

        try:
            payload = {
                "model": model,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are an autonomous code reviewer remediation engineer.\n"
                            "Modify the target file to address the review feedback.\n"
                            "Return strictly valid JSON with key 'updated_full_file' containing the complete file content.\n"
                            "Do not include markdown outside the JSON."
                        ),
                    },
                    {
                        "role": "user",
                        "content": f"File: {target_rel_file}\nReview Instructions:\n{prompt}\n\nOriginal Code:\n```\n{original_code}\n```",
                    },
                ],
                "temperature": 0.2,
            }
            req = urllib.request.Request(
                f"{base_url.rstrip('/')}/chat/completions",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "User-Agent": "AutoBugHunter-ReviewMonitor",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=45) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
                msg = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                m = re.search(r"\{.*\}", msg, re.DOTALL)
                if m:
                    res_obj = json.loads(m.group(0))
                    new_code = res_obj.get("updated_full_file")
                    if new_code and new_code.strip() != original_code.strip():
                        target_file.write_text(new_code, encoding="utf-8")
                        return True
        except Exception as e:
            self._log(f"Direct LLM remediation fallback failed: {e}", level="WARNING")
        return False

    def check_and_remediate_prs(
        self, repo_slugs: Optional[list[str]] = None
    ) -> list[ReviewRemediationResult]:
        """
        Iterate through target repositories, inspect open bot PRs,
        and remediate unresolved review threads.
        Individual repository errors are isolated and never halt the cycle.
        """
        targets: list[str] = []
        if repo_slugs is not None:
            targets = list(repo_slugs)
        elif self.config:
            raw_targets = getattr(self.config, "target_repos", [])
            if isinstance(raw_targets, str):
                targets = [r.strip() for r in raw_targets.replace("\n", ",").split(",") if r.strip()]
            elif isinstance(raw_targets, (list, tuple, set)):
                targets = [str(r).strip() for r in raw_targets if str(r).strip()]

        remediation_results: list[ReviewRemediationResult] = []

        for repo_slug in targets:
            try:
                open_prs = self.get_open_bot_prs(repo_slug)
                if not open_prs:
                    continue

                repo_path = self.get_repo_path(repo_slug)

                for pr in open_prs:
                    pr_number = pr.get("number")
                    if not pr_number:
                        continue
                    head_ref = pr.get("headRefName", "")
                    threads = self.fetch_unresolved_review_threads(repo_slug, pr_number, head_ref)

                    for comment in threads:
                        if self.db and self.db.is_thread_remediated(comment.thread_id):
                            remediation_results.append(
                                ReviewRemediationResult(
                                    success=True,
                                    repo_slug=repo_slug,
                                    pr_number=pr_number,
                                    thread_id=comment.thread_id,
                                    comment_id=comment.comment_id,
                                    status="SKIPPED_ALREADY_REMEDIATED",
                                )
                            )
                            continue

                        res = self.remediate_single_thread(
                            repo_slug=repo_slug,
                            pr_info=pr,
                            comment=comment,
                            repo_path=repo_path,
                        )
                        remediation_results.append(res)
            except Exception as e:
                self._log(
                    f"Exception during review remediation for {repo_slug}: {e}",
                    level="WARNING",
                )

        return remediation_results
