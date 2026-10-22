"""
Unit tests for src/verifier.py: Diff bounds enforcer, secret leak detection, and artifact purging.
"""

from pathlib import Path
import pytest
from src.verifier import ConventionalTitle, Verifier


@pytest.fixture
def verifier():
    return Verifier()


def test_verifier_valid_atomic_patch(tmp_path: Path, verifier):
    """Verify that a compliant patch passes verification."""
    diff = """--- a/src/auth.py
+++ b/src/auth.py
@@ -10,2 +10,4 @@
-    return user.role
+    if user is None:
+        return None
+    return user.role
"""
    report = {
        "bug_found": True,
        "files_modified": ["src/auth.py"],
        "pr_title": "fix: add null check on user role",
        "pr_body": "Fixed None dereference."
    }

    res = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path,
        skip_files=[],
        max_files=3,
        max_lines=150,
        simulated_report=report,
        custom_diff=diff
    )
    assert res.verified is True
    assert res.pr_title == "fix: add null check on user role"
    assert res.modified_files == ["src/auth.py"]


def test_verifier_rejects_empty_diff(tmp_path: Path, verifier):
    """Verify empty diff is rejected."""
    report = {"bug_found": True, "files_modified": ["src/app.py"]}
    res = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path,
        skip_files=[],
        simulated_report=report,
        custom_diff=""
    )
    assert res.verified is False
    assert "empty" in res.error_reason.lower()


def test_verifier_rejects_whitespace_diff(tmp_path: Path, verifier):
    """Verify whitespace-only changes are rejected."""
    diff = "   \n\t\n   "
    report = {"bug_found": True, "files_modified": ["src/app.py"]}
    res = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path,
        skip_files=[],
        simulated_report=report,
        custom_diff=diff
    )
    assert res.verified is False
    assert "whitespace" in res.error_reason.lower() or "empty" in res.error_reason.lower()


def test_verifier_rejects_too_many_files(tmp_path: Path, verifier):
    """Verify patches modifying more than max_files are rejected."""
    diff = "diff --git a/f1.py b/f1.py\n+x=1\n"
    report = {
        "bug_found": True,
        "files_modified": ["f1.py", "f2.py", "f3.py", "f4.py"]
    }
    res = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path,
        skip_files=[],
        max_files=3,
        simulated_report=report,
        custom_diff=diff
    )
    assert res.verified is False
    assert "exceeding limit of 3" in res.error_reason


def test_verifier_rejects_too_many_lines(tmp_path: Path, verifier):
    """Verify patches modifying more than max_lines are rejected."""
    diff = "\n".join(["+ line"] * 160)
    report = {"bug_found": True, "files_modified": ["f1.py"]}
    res = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path,
        skip_files=[],
        max_lines=150,
        simulated_report=report,
        custom_diff=diff
    )
    assert res.verified is False
    assert "exceeding limit of 150" in res.error_reason


def test_verifier_rejects_skip_files_collision(tmp_path: Path, verifier):
    """Verify changes to files listed in skip_files are rejected."""
    diff = "diff --git a/src/locked.py b/src/locked.py\n+x=1\n"
    report = {"bug_found": True, "files_modified": ["src/locked.py"]}
    res = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path,
        skip_files=["src/locked.py"],
        simulated_report=report,
        custom_diff=diff
    )
    assert res.verified is False
    assert "collision skip list" in res.error_reason


def test_verifier_rejects_secret_leaks(tmp_path: Path, verifier):
    """Verify patches introducing PATs or API keys are rejected."""
    diff = """--- a/src/config.py
+++ b/src/config.py
@@ -1,1 +1,2 @@
+GITHUB_TOKEN = "ghp_123456789012345678901234567890123456"
"""
    report = {"bug_found": True, "files_modified": ["src/config.py"]}
    res = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path,
        skip_files=[],
        simulated_report=report,
        custom_diff=diff
    )
    assert res.verified is False
    assert "credential leak" in res.error_reason.lower()


def test_verifier_purges_temporary_artifacts(tmp_path: Path, verifier):
    """Verify temporary orchestration artifacts are deleted from disk."""
    for tf in [".skip_files.txt", ".static_findings.json", ".bug_fix_report.json"]:
        (tmp_path / tf).write_text("data", encoding="utf-8")

    purged = verifier.purge_temp_artifacts(tmp_path)
    assert len(purged) == 3
    for tf in [".skip_files.txt", ".static_findings.json", ".bug_fix_report.json"]:
        assert not (tmp_path / tf).exists()


def test_verifier_catches_pkcs8_private_keys(tmp_path: Path, verifier):
    """Verify PKCS#8 private keys without algorithm prefix are caught."""
    diff = """--- a/keys.py
+++ b/keys.py
@@ -1,1 +1,2 @@
+KEY = "-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC..."
"""
    findings = verifier.scan_for_secrets(diff)
    assert len(findings) >= 1
    assert any("BEGIN PRIVATE KEY" in f for f in findings)


def test_verifier_diff_lines_counts_only_changes(tmp_path: Path, verifier):
    """Verify diff_lines calculation excludes diff headers (---, +++) and unified metadata."""
    diff = """diff --git a/file.py b/file.py
index 0000000..1111111 100644
--- a/file.py
+++ b/file.py
@@ -1,5 +1,5 @@
 context line 1
-old line
+new line 1
+new line 2
 context line 2
"""
    report = {"bug_found": True, "files_modified": ["file.py"]}
    res = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path,
        skip_files=[],
        simulated_report=report,
        custom_diff=diff
    )
    assert res.verified is True
    # 1 removed line (-old line) + 2 added lines (+new line 1, +new line 2) = 3 changed lines
    assert res.diff_lines == 3


def test_verifier_git_status_rename_and_quoted_paths(tmp_path: Path, verifier):
    """Verify git status porcelain parser handles renames ('->') and quoted paths with spaces."""
    import subprocess
    repo = tmp_path / "test_repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test Committer"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=repo, check=True)

    # Initial commit
    (repo / "old_name.py").write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "old_name.py"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True)

    # 1. Rename file
    subprocess.run(["git", "mv", "old_name.py", "new_name.py"], cwd=repo, check=True)

    # 2. Add file with spaces
    (repo / "spaced file.py").write_text("y = 2\n", encoding="utf-8")
    subprocess.run(["git", "add", "spaced file.py"], cwd=repo, check=True)

    report = {"bug_found": True, "pr_title": "fix: rename and add", "pr_body": "test"}
    (repo / ".bug_fix_report.json").write_text('{"bug_found": true, "pr_title": "fix: rename and add"}', encoding="utf-8")

    res = verifier.verify_and_sanitize_fix(
        repo_path=repo,
        skip_files=[],
        max_files=3,
        max_lines=150,
        simulated_report=report,
    )
    assert res.verified is True
    assert "new_name.py" in res.modified_files
    assert "spaced file.py" in res.modified_files
    # Neither filename should retain quotes or rename arrow
    for f in res.modified_files:
        assert '"' not in f
        assert "'" not in f
        assert "->" not in f


def test_verifier_custom_diff_quotes_stripped(tmp_path: Path, verifier):
    """Verify quoted filenames in simulated report are stripped cleanly."""
    diff = "--- a/file.py\n+++ b/file.py\n@@ -1,1 +1,2 @@\n-x=1\n+x=2\n"
    report = {
        "bug_found": True,
        "files_modified": ['"src/file.py"', "'src/other.py'"],
        "pr_title": "fix: stripped quotes"
    }
    res = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path,
        skip_files=[],
        simulated_report=report,
        custom_diff=diff
    )
    assert res.verified is True
    assert res.modified_files == ["src/file.py", "src/other.py"]


def test_verifier_empty_pr_title_fallback(tmp_path: Path, verifier):
    """Verify empty pr_title in report falls back to non-empty default title."""
    diff = "--- a/f.py\n+++ b/f.py\n@@ -1,1 +1,2 @@\n-a=1\n+a=2\n"
    report = {"bug_found": True, "files_modified": ["f.py"], "pr_title": "", "pr_body": ""}
    res = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path,
        skip_files=[],
        simulated_report=report,
        custom_diff=diff
    )
    assert res.verified is True
    assert res.pr_title == "fix: automated atomic patch"
    assert res.pr_body == "Automated bug remediation fix."


# =========================================================================
# Exact Boundary Verification Tests (3 vs 4 files, 150 vs 151 lines)
# =========================================================================

def test_verifier_files_boundary_3_allowed_vs_4_rejected(tmp_path: Path, verifier):
    """Verify exact file boundary: exactly 3 files modified is allowed; exactly 4 files is rejected."""
    # 1. Exactly 3 files modified (within limit <= 3) -> pass
    report_3 = {
        "bug_found": True,
        "files_modified": ["src/f1.py", "src/f2.py", "src/f3.py"],
        "pr_title": "fix: patch 3 files"
    }
    diff_3 = "diff --git a/f1.py b/f1.py\n+x=1\n"
    res_3 = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path,
        skip_files=[],
        max_files=3,
        simulated_report=report_3,
        custom_diff=diff_3
    )
    assert res_3.verified is True
    assert len(res_3.modified_files) == 3

    # 2. Exactly 4 files modified (exceeding limit of 3) -> fail
    report_4 = {
        "bug_found": True,
        "files_modified": ["src/f1.py", "src/f2.py", "src/f3.py", "src/f4.py"],
        "pr_title": "fix: patch 4 files"
    }
    res_4 = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path,
        skip_files=[],
        max_files=3,
        simulated_report=report_4,
        custom_diff=diff_3
    )
    assert res_4.verified is False
    assert "Modified 4 files, exceeding limit of 3" in res_4.error_reason


def test_verifier_lines_boundary_150_allowed_vs_151_rejected(tmp_path: Path, verifier):
    """Verify exact lines boundary: exactly 150 changed lines is allowed; exactly 151 changed lines is rejected."""
    report = {"bug_found": True, "files_modified": ["src/app.py"]}

    # 1. Exactly 150 lines (within limit <= 150) -> pass
    diff_150 = "\n".join(["+ line"] * 150)
    res_150 = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path,
        skip_files=[],
        max_lines=150,
        simulated_report=report,
        custom_diff=diff_150
    )
    assert res_150.verified is True
    assert res_150.diff_lines == 150

    # 2. Exactly 151 lines (exceeding limit of 150) -> fail
    diff_151 = "\n".join(["+ line"] * 151)
    res_151 = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path,
        skip_files=[],
        max_lines=150,
        simulated_report=report,
        custom_diff=diff_151
    )
    assert res_151.verified is False
    assert "Diff changed 151 lines, exceeding limit of 150" in res_151.error_reason
    assert res_151.diff_lines == 151


def test_verifier_edge_cases_additions_deletions_modifications(tmp_path: Path, verifier):
    """Verify line counting across pure additions, pure deletions, mixed changes, unified modifications, and headers."""
    report = {"bug_found": True, "files_modified": ["src/app.py"]}

    # Edge Case A1: 150 pure additions -> pass
    diff_add_150 = "\n".join(["+ added_line"] * 150)
    res_add_150 = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path, skip_files=[], max_lines=150,
        simulated_report=report, custom_diff=diff_add_150
    )
    assert res_add_150.verified is True
    assert res_add_150.diff_lines == 150

    # Edge Case A2: 151 pure additions -> fail
    diff_add_151 = "\n".join(["+ added_line"] * 151)
    res_add_151 = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path, skip_files=[], max_lines=150,
        simulated_report=report, custom_diff=diff_add_151
    )
    assert res_add_151.verified is False
    assert res_add_151.diff_lines == 151

    # Edge Case B1: 150 pure deletions -> pass
    diff_del_150 = "\n".join(["- deleted_line"] * 150)
    res_del_150 = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path, skip_files=[], max_lines=150,
        simulated_report=report, custom_diff=diff_del_150
    )
    assert res_del_150.verified is True
    assert res_del_150.diff_lines == 150

    # Edge Case B2: 151 pure deletions -> fail
    diff_del_151 = "\n".join(["- deleted_line"] * 151)
    res_del_151 = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path, skip_files=[], max_lines=150,
        simulated_report=report, custom_diff=diff_del_151
    )
    assert res_del_151.verified is False
    assert res_del_151.diff_lines == 151

    # Edge Case C1: 75 additions + 75 deletions = 150 -> pass
    diff_mixed_150 = "\n".join(["+ add"] * 75 + ["- del"] * 75)
    res_mix_150 = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path, skip_files=[], max_lines=150,
        simulated_report=report, custom_diff=diff_mixed_150
    )
    assert res_mix_150.verified is True
    assert res_mix_150.diff_lines == 150

    # Edge Case C2: 75 additions + 76 deletions = 151 -> fail
    diff_mixed_151 = "\n".join(["+ add"] * 75 + ["- del"] * 76)
    res_mix_151 = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path, skip_files=[], max_lines=150,
        simulated_report=report, custom_diff=diff_mixed_151
    )
    assert res_mix_151.verified is False
    assert res_mix_151.diff_lines == 151

    # Edge Case D1: 75 unified modifications (75 removals + 75 additions = 150 lines) -> pass
    diff_mod_75 = "\n".join(["- old_val\n+ new_val" for _ in range(75)])
    res_mod_75 = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path, skip_files=[], max_lines=150,
        simulated_report=report, custom_diff=diff_mod_75
    )
    assert res_mod_75.verified is True
    assert res_mod_75.diff_lines == 150

    # Edge Case D2: 76 unified modifications (76 removals + 76 additions = 152 lines) -> fail
    diff_mod_76 = "\n".join(["- old_val\n+ new_val" for _ in range(76)])
    res_mod_76 = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path, skip_files=[], max_lines=150,
        simulated_report=report, custom_diff=diff_mod_76
    )
    assert res_mod_76.verified is False
    assert res_mod_76.diff_lines == 152

    # Edge Case E: Diff headers and context lines do not count towards line limit
    diff_with_context = (
        "diff --git a/src/app.py b/src/app.py\n"
        "index 1234567..abcdefg 100644\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -1,200 +1,200 @@\n"
        + "\n".join([f" context line {i}" for i in range(100)])
        + "\n"
        + "\n".join(["+ new line"] * 150)
    )
    res_ctx = verifier.verify_and_sanitize_fix(
        repo_path=tmp_path, skip_files=[], max_lines=150,
        simulated_report=report, custom_diff=diff_with_context
    )
    assert res_ctx.verified is True
    assert res_ctx.diff_lines == 150


def test_verifier_captures_untracked_files_diff_and_lines(tmp_path: Path, verifier):
    """Verify git add -N . includes newly created untracked files in diff_lines and modified_files."""
    import subprocess
    repo = tmp_path / "repo_untracked"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=repo, check=True, capture_output=True)
    (repo / "base.py").write_text("print('base')\n", encoding="utf-8")
    subprocess.run(["git", "add", "base.py"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

    # Create new untracked reproducer test file
    (repo / "tests").mkdir(parents=True, exist_ok=True)
    (repo / "tests" / "test_repro.py").write_text("def test_bug():\n    assert True\n", encoding="utf-8")

    report = {"bug_found": True, "pr_title": "fix: add repro test"}
    res = verifier.verify_and_sanitize_fix(repo_path=repo, skip_files=[], simulated_report=report)

    assert res.verified is True
    assert any("test_repro.py" in f for f in res.modified_files)
    assert res.diff_lines >= 2


def test_verifier_catches_secret_leaks_in_untracked_files(tmp_path: Path, verifier):
    """Verify secrets inside newly created untracked files are detected and rejected."""
    import subprocess
    repo = tmp_path / "repo_untracked_secret"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=repo, check=True, capture_output=True)
    (repo / "base.py").write_text("print('base')\n", encoding="utf-8")
    subprocess.run(["git", "add", "base.py"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

    # Untracked file containing leaked token
    (repo / "test_leak.py").write_text('TOKEN = "ghp_111122223333444455556666777788889999"\n', encoding="utf-8")

    report = {"bug_found": True, "pr_title": "fix: test with secret"}
    res = verifier.verify_and_sanitize_fix(repo_path=repo, skip_files=[], simulated_report=report)

    assert res.verified is False
    assert "credential leak" in res.error_reason.lower()


def test_verifier_enforces_line_bounds_on_untracked_files(tmp_path: Path, verifier):
    """Verify untracked files exceeding 150 lines are rejected."""
    import subprocess
    repo = tmp_path / "repo_untracked_limit"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=repo, check=True, capture_output=True)
    (repo / "base.py").write_text("print('base')\n", encoding="utf-8")
    subprocess.run(["git", "add", "base.py"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

    # Create 155-line untracked file
    (repo / "large_module.py").write_text("\n".join(["x = 1"] * 155) + "\n", encoding="utf-8")

    report = {"bug_found": True, "pr_title": "fix: large module"}
    res = verifier.verify_and_sanitize_fix(repo_path=repo, skip_files=[], max_lines=150, simulated_report=report)

    assert res.verified is False
    assert "exceeding limit of 150" in res.error_reason
    assert res.diff_lines == 155


def test_verifier_untracked_within_exact_150_lines_allowed(tmp_path: Path, verifier):
    """Verify untracked file with exactly 150 lines passes verification."""
    import subprocess
    repo = tmp_path / "repo_untracked_150"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=repo, check=True, capture_output=True)
    (repo / "base.py").write_text("print('base')\n", encoding="utf-8")
    subprocess.run(["git", "add", "base.py"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

    # Create 150-line untracked file
    (repo / "allowed_module.py").write_text("\n".join(["x = 1"] * 150) + "\n", encoding="utf-8")

    report = {"bug_found": True, "pr_title": "fix: exact 150 lines"}
    res = verifier.verify_and_sanitize_fix(repo_path=repo, skip_files=[], max_lines=150, simulated_report=report)

    assert res.verified is True
    assert res.diff_lines == 150


def test_conventional_title_hash_and_collection_compatibility():
    """Verify ConventionalTitle can be hashed, producing a valid int, and used in sets and dict keys."""
    t1 = ConventionalTitle("fix(database): fix connection leak", "fix: fix connection leak")
    t2 = ConventionalTitle("fix(database): fix connection leak", "fix: fix connection leak")
    t3 = ConventionalTitle("fix(auth): fix session expiry")

    # 1. hash produces a valid int
    h1 = hash(t1)
    assert isinstance(h1, int)
    assert hash(t1) == hash(t2)
    assert hash(t1) == hash("fix(database): fix connection leak")

    # 2. set insertion and deduplication
    s = {t1, t2, t3}
    assert len(s) == 2
    assert t1 in s
    assert t3 in s
    assert "fix(database): fix connection leak" in s

    # 3. dict key storage and lookup
    d = {t1: "database_val", t3: "auth_val"}
    assert d[t1] == "database_val"
    assert d[t2] == "database_val"
    assert d["fix(database): fix connection leak"] == "database_val"
    assert d[t3] == "auth_val"
    assert len(d) == 2

    # 4. Hash consistency with dict keys
    d[t2] = "updated_val"
    assert len(d) == 2
    assert d[t1] == "updated_val"
