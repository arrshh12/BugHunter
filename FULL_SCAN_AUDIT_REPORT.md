## Verification Audit: Are the Bugs Fixed?

**Verdict:** **PARTIALLY FIXED (6/15 Resolved, 9 Still Outstanding — 2 Critical Blockers Remain)**

A verification check of the codebase was conducted against the findings identified in the review. While several key fixes were applied, **2 Critical security and operational issues** and **7 Required issues** remain unaddressed.

---

### Scorecard & Status

| Severity | Issue | Location | Status | Current Code State |
| :--- | :--- | :--- | :--- | :--- |
| **Critical** | Untracked files secret scan bypass | [`src/verifier.py:189-192`](file:///c:/antigravity/bughunter/src/verifier.py#L189-L192) | **FIXED** | Added `git add -N .` before taking `git diff HEAD`. Untracked files are now staged for diff capture. |
| **Critical** | Remote WebSocket origin 1008 rejection | [`src/web_server.py:146-151`](file:///c:/antigravity/bughunter/src/web_server.py#L146-L151) | **FIXED** | Added Host header parsing and `ALLOWED_ORIGINS` inspection to dynamic whitelist. |
| **Critical** | Silent push swallow on remote | [`src/git_manager.py:413-440`](file:///c:/antigravity/bughunter/src/git_manager.py#L413-L440) | **FIXED** | Added `has_remote` check; re-raises `CalledProcessError` if remote is configured. |
| **Critical** | WebSocket `/ws/logs` auth bypass on loopback | [`src/web_server.py:126-133`](file:///c:/antigravity/bughunter/src/web_server.py#L126-L133) | **NOT FIXED** | Still falls into `else:` branch when candidate token is empty; allows unauthenticated access if host is loopback or reverse proxy. |
| **Critical** | Fake repo creation on clone failure | [`src/git_manager.py:250-258`](file:///c:/antigravity/bughunter/src/git_manager.py#L250-L258) | **NOT FIXED** | Still runs `git init -b main` with `# {repo_slug}` dummy README when clone fails, falsely marking failed clones as clean. |
| **Required** | Relative `task_prompt_path` in OpenHands | [`src/orchestrator.py:206-210`](file:///c:/antigravity/bughunter/src/orchestrator.py#L206-L210) | **FIXED** | Resolved to absolute path via `Path(__file__).resolve().parent.parent`. |
| **Required** | Windows duplicate file handle lock | [`src/logger.py:235-238`](file:///c:/antigravity/bughunter/src/logger.py#L235-L238) | **FIXED** | Reuses `ring_logger._file_handler` in `setup_logger` instead of creating a second handler. |
| **Required** | Unbounded table scan in fallback memory | [`src/database.py:682`](file:///c:/antigravity/bughunter/src/database.py#L682) | **FIXED** | Added `ORDER BY id DESC LIMIT 500` and unit test [`test_query_similar_bugs_fallback_limit_500`](file:///c:/antigravity/bughunter/tests/test_database.py#L268-L293). |
| **Required** | `ConventionalTitle` unhashable (`__hash__ = None`) | [`src/verifier.py:15-33`](file:///c:/antigravity/bughunter/src/verifier.py#L15-L33) | **NOT FIXED** | Still defines `__eq__` without `__hash__`, crashing when used in sets, dicts, or caching. |
| **Required** | Preflight health check never invoked | [`src/orchestrator.py:196-203`](file:///c:/antigravity/bughunter/src/orchestrator.py#L196-L203) | **NOT FIXED** | Still calls `get_next_healthy_key()` without invoking `preflight_check(key)`. |
| **Required** | `PLR09` complexity shadowed by `PLR` | [`src/static_scanner.py:143`](file:///c:/antigravity/bughunter/src/static_scanner.py#L143) vs [`194`](file:///c:/antigravity/bughunter/src/static_scanner.py#L194) | **NOT FIXED** | `PLR` is still checked in Correctness before `PLR09` in Architecture; line 194 remains dead code. |
| **Required** | PR Number ignored from `gh pr create` | [`src/orchestrator.py:384, 404-414`](file:///c:/antigravity/bughunter/src/orchestrator.py#L384) | **NOT FIXED** | `pr_number` remains the random integer `100 + int(time.time()) % 1000`; not extracted from returned URL. |
| **Required** | Resurrecting old findings on clean scans | [`src/orchestrator.py:133-138`](file:///c:/antigravity/bughunter/src/orchestrator.py#L133-L138) | **NOT FIXED** | `if not current_data: findings_path.write_text(...)` still restores old findings when 0 bugs are found. |
| **Required** | Stored XSS in dashboard | [`src/templates/dashboard.html:264, 305`](file:///c:/antigravity/bughunter/src/templates/dashboard.html#L264) | **NOT FIXED** | `p.pr_title`, `p.pr_url`, and `r.repo_slug` are still interpolated directly into `innerHTML` unescaped. |
| **Required** | Single repo exception terminates daemon | [`src/orchestrator.py:70-430`](file:///c:/antigravity/bughunter/src/orchestrator.py#L70-L430) | **NOT FIXED** | `scan_single_repo` lacks top-level try/except around steps 2–7; one failing repo halts the 24/7 process. |

---

### Detailed Inspection of Remaining Issues

#### 1. [CRITICAL] WebSocket Auth Bypass on Loopback / Reverse Proxy
- **File:** [`src/web_server.py:126-133`](file:///c:/antigravity/bughunter/src/web_server.py#L126-L133)
- **Problem:**
  ```python
  if candidate:
      if not api_key or not hmac.compare_digest(candidate, api_key):
          await websocket.close(code=1008)
          return
  else:
      # If candidate is None, any connection from loopback connects WITHOUT API key!
      if client_host not in ("127.0.0.1", "::1", "localhost", "testclient"):
          await websocket.close(code=1008)
          return
  ```
  When `DASHBOARD_API_KEY` is configured, omitting `?token=` from loopback or through a local reverse proxy (where `client_host == "127.0.0.1"`) completely bypasses authentication.
- **Fix:** Enforce the key check whenever `api_key` is configured:
  ```python
  if api_key:
      if not candidate or not hmac.compare_digest(candidate, api_key):
          await websocket.close(code=1008)
          return
  elif client_host not in ("127.0.0.1", "::1", "localhost", "testclient"):
      await websocket.close(code=1008)
      return
  ```

#### 2. [CRITICAL] Fake Repo Fallback on Clone Failure
- **File:** [`src/git_manager.py:250-258`](file:///c:/antigravity/bughunter/src/git_manager.py#L250-L258)
- **Problem:** If `git clone` fails (network error, bad token, private repository), it silently initializes a local git repo, creates a dummy `README.md`, and returns it. The orchestrator scans the dummy repo, finds no bugs, and permanently marks the repo as `CLEAN_EXHAUSTED`.
- **Fix:** Raise an exception on clone failure:
  ```python
  if not cloned:
      raise RuntimeError(f"Failed to clone repository {repo_slug}")
  ```

#### 3. [REQUIRED] `ConventionalTitle` Is Unhashable
- **File:** [`src/verifier.py:15-33`](file:///c:/antigravity/bughunter/src/verifier.py#L15-L33)
- **Problem:** Overriding `__eq__` without `__hash__` on `str` sets `__hash__ = None`. Putting `pr_title` into a set, dict, or caching layer raises `TypeError: unhashable type: 'ConventionalTitle'`.
- **Fix:** Add `def __hash__(self) -> int: return super().__hash__()`.

#### 4. [REQUIRED] Preflight Ping Is Never Executed
- **File:** [`src/orchestrator.py:196-203`](file:///c:/antigravity/bughunter/src/orchestrator.py#L196-L203)
- **Problem:** `key_manager.preflight_check(key)` is never called before invoking OpenHands. Dead or exhausted keys immediately trigger a failed agent session rather than failing fast in 5 seconds and rotating.
- **Fix:** Loop through healthy keys until one passes `self.key_manager.preflight_check(key)`.

#### 5. [REQUIRED] Complexity Rules Shadowed in Static Triage
- **File:** [`src/static_scanner.py:143`](file:///c:/antigravity/bughunter/src/static_scanner.py#L143) vs [`src/static_scanner.py:194`](file:///c:/antigravity/bughunter/src/static_scanner.py#L194)
- **Problem:** `rule_upper.startswith("PLR")` matches all `PLR09` rules in Correctness (weight 100), making `rule_upper.startswith("PLR09")` in Architecture (weight 40) unreachable dead code.
- **Fix:** Exclude `PLR09` from the correctness check: `(rule_upper.startswith("PLR") and not rule_upper.startswith("PLR09"))`.

#### 6. [REQUIRED] PR Number Mismatch
- **File:** [`src/orchestrator.py:384, 404-414`](file:///c:/antigravity/bughunter/src/orchestrator.py#L384)
- **Problem:** `pr_number` is assigned `100 + int(time.time()) % 1000`. When `gh pr create` succeeds, `pr_url` is updated, but `pr_number` is never extracted from the URL, writing mismatched metadata to the database.
- **Fix:** Extract the PR number from `pr_url`:
  ```python
  m = re.search(r"/pull/(\d+)", pr_url)
  if m:
      pr_number = int(m.group(1))
  ```

#### 7. [REQUIRED] Fixed Bugs Resurrected on Clean Scans
- **File:** [`src/orchestrator.py:133-138`](file:///c:/antigravity/bughunter/src/orchestrator.py#L133-L138)
- **Problem:**
  ```python
  if pre_findings_content and findings_path.exists():
      try:
          current_data = json.loads(findings_path.read_text(encoding="utf-8"))
          if not current_data:
              findings_path.write_text(pre_findings_content, encoding="utf-8")
      except Exception:
          pass
  ```
  When a repo has fixed all bugs and `current_data` is empty, this code restores old findings, trapping clean repos in an infinite scan loop.
- **Fix:** Delete this block completely.

#### 8. [REQUIRED] Stored XSS in Dashboard
- **File:** [`src/templates/dashboard.html:264, 305`](file:///c:/antigravity/bughunter/src/templates/dashboard.html#L264)
- **Problem:** `r.repo_slug`, `p.pr_title`, and `p.pr_url` are inserted directly into `innerHTML` without HTML entity escaping.
- **Fix:** Define an `escapeHtml()` helper and sanitize all dynamic database strings before injecting into DOM.

#### 9. [REQUIRED] Uncaught Exception in Single Repo Halts Daemon
- **File:** [`src/orchestrator.py:70-430`](file:///c:/antigravity/bughunter/src/orchestrator.py#L70-L430)
- **Problem:** `scan_single_repo` lacks an outer `try...except Exception` block. An unexpected failure in any repository terminates the 24/7 continuous daemon loop.
- **Fix:** Wrap the inner logic in `try...except Exception as e`, log the error, mark repo status as `ERROR`, trigger `git_manager.rollback_working_tree`, and continue to the next repository.