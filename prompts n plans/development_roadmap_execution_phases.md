# Development Roadmap & Execution Phases

This roadmap breaks the build into **7 sequential, testable phases** designed for autonomous execution inside **Antigravity**. Every phase has strict deliverables and verification commands that must pass before advancing to the next phase.

---

## Phase 1: Project Scaffolding, Configuration & SQLite WAL State Engine
### Objective
Create the directory layout, environment loader, structured logger, and thread-safe SQLite WAL database engine.

### Target Files to Create
* `requirements.txt`
* `.env.example`
* `src/__init__.py`
* `src/config.py`
* `src/database.py`
* `src/logger.py`

### Implementation Details
1. Define all environment variables in `src/config.py` using dataclasses or Pydantic settings (`GITHUB_TOKEN`, `TARGET_REPOS`, `AUTO_DISCOVER_REPOS`, `LLM_KEYS_POOL`, `MAX_OPEN_PRS_PER_REPO`, `MAX_FILES_PER_PR`, `SCAN_COOLDOWN_SECONDS`, `AGENT_TIMEOUT_SECONDS`, `DASHBOARD_PORT`).
2. Build `src/database.py` implementing the 4 core tables (`repositories`, `pull_requests`, `api_key_status`, `scan_logs`) with `PRAGMA journal_mode=WAL;`.
3. Implement an in-memory + WebSocket pub/sub ring buffer in `src/logger.py` (stores the latest $500$ log lines for live UI streaming).

### Verification Criteria
* Run `python3 -c "from src.database import Database; db = Database('/tmp/test_bh.sqlite'); print(db.get_stats())"` and verify zero errors and all 4 tables initialized.

---

## Phase 2: Multi-Key LLM Pool Manager & Pre-Flight Circuit Breaker
### Objective
Build the fault-tolerant key rotator that manages ScaleMax (`openai/claude-haiku-5.5`) and backup free API keys, including pre-flight verification and exponential cooldown backoff.

### Target Files to Create
* `src/key_manager.py`
* `tests/test_key_manager.py`

### Implementation Details
1. Parse `LLM_KEYS_POOL` entries formatted as `base_url|model|api_key`.
2. Implement `get_next_healthy_key()` which checks SQLite `cooldown_until` timestamps and promotes expired cooldown keys back to `HEALTHY`.
3. Implement `preflight_check(key_entry)` using `requests.post` to `<base_url>/chat/completions` with `max_tokens=1` and a $5\text{s}$ timeout to catch `429` or `401/402` errors *before* spinning up OpenHands.
4. Implement `report_key_failure(key_id, error_text)` and `report_key_success(key_id)`.

### Verification Criteria
* Run `pytest tests/test_key_manager.py` verifying automatic rotation across 3 mock keys when key #1 returns `HTTP 429` and key #2 returns `HTTP 402`.

---

## Phase 3: Git Workspace Manager, Auto-Discovery & Open PR Collision Guard
### Objective
Implement safe repository cloning, syncing, branch detection, and GitHub PR collision detection.

### Target Files to Create
* `src/git_manager.py`
* `tests/test_git_manager.py`

### Implementation Details
1. Implement `configure_git_and_gh()` to set global Git author identity and authenticate `gh auth login --with-token`.
2. Implement `discover_or_load_repos()` to either parse the 20 repos from `TARGET_REPOS` or fetch non-fork, non-archived repos via the GitHub REST API.
3. Implement `sync_repository(repo_slug)` which clones or hard-resets the repo to `origin/<default_branch>` and returns `(repo_path, default_branch, head_sha)`.
4. Implement `get_open_bot_prs(repo_path)` which calls `gh pr list --author "@me" --state open --json number,headRefName,files` and returns `(open_pr_count, skip_files_list)`.

### Verification Criteria
* Run `pytest tests/test_git_manager.py` using a temporary local Git repo to verify clean reset, default branch resolution, and `.skip_files.txt` generation.

---

## Phase 4: Static Analysis Pre-Filter & OpenHands Headless Runner
### Objective
Build the static pre-scanner and the OpenHands CLI execution bridge with strict process-group timeouts and live output capture.

### Target Files to Create
* `prompts/task_prompt.txt`
* `src/static_scanner.py`
* `src/openhands_runner.py`

### Implementation Details
1. Author `prompts/task_prompt.txt` enforcing the **One Bug = One Fix** protocol, reading `.skip_files.txt` and `.static_findings.json`, running repository tests, and writing `.bug_fix_report.json`.
2. Implement `run_static_prefilter(repo_path, skip_files)` in `src/static_scanner.py` to execute `ruff` and `semgrep` with a $60\text{s}$ timeout and output top actionable findings to `.static_findings.json`.
3. Implement `run_openhands_session(repo_path, key_manager, log_callback)` in `src/openhands_runner.py`:
   * Injects `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`, and `RUNTIME=process`.
   * Starts `openhands --headless --override-with-envs -f /app/prompts/task_prompt.txt` in a new process group (`start_new_session=True`).
   * Monitors output for rate-limit signatures (`429`, `RateLimitError`, `insufficient_quota`); if detected, terminates the process, rotates the key via `key_manager`, resets the working tree, and retries seamlessly.

### Verification Criteria
* Verify `src/static_scanner.py` produces valid JSON on a sample buggy Python file and respects `.skip_files.txt`.

---

## Phase 5: Verification Gate, Diff Sanitizer & Atomic PR Dispatcher
### Objective
Ensure zero broken, noisy, or secret-leaking PRs are ever submitted to GitHub, and automate atomic branch creation and PR submission.

### Target Files to Create
* `src/verifier.py`
* `src/orchestrator.py`
* `tests/test_verifier.py`

### Implementation Details
1. In `src/verifier.py`, implement `verify_and_sanitize_fix(repo_path, skip_files, max_files=3)`:
   * Reads and deletes `.bug_fix_report.json`, `.skip_files.txt`, and `.static_findings.json`.
   * Checks `git diff -w` is non-empty (rejects whitespace-only changes).
   * Checks modified file list against `skip_files` and `max_files`.
   * Scans added lines (`+`) in `git diff` against regex patterns for leaked credentials (`ghp_[A-Za-z0-9]{36}`, `sk-[A-Za-z0-9]{20,}`, `BEGIN .* PRIVATE KEY`).
2. In `src/orchestrator.py`, implement the `BugHunterOrchestrator` class that ties Phases 1–5 together into the continuous 24/7 loop and dispatches `gh pr create`.

### Verification Criteria
* Run `pytest tests/test_verifier.py` confirming that whitespace-only diffs, modifications to skipped files, and diffs containing mock API keys are rejected and rolled back via `git reset --hard`.

---

## Phase 6: Mission Control Web Dashboard & Live Telemetry UI
### Objective
Create the FastAPI web server and reactive single-page dashboard (`http://localhost:8080`) for real-time observability and daemon control.

### Target Files to Create
* `src/web_server.py`
* `src/templates/dashboard.html`

### Implementation Details
1. Build FastAPI endpoints in `src/web_server.py`:
   * `GET /`: Serves the Mission Control Dashboard HTML.
   * `GET /api/state`: Returns JSON snapshot of all 20 repositories, recent PRs, KPI metrics, and API key pool status.
   * `POST /api/control/toggle-pause`: Pauses or resumes the 24/7 orchestrator loop.
   * `POST /api/control/scan-now/{repo_owner}/{repo_name}`: Queues an immediate high-priority scan for a specific repository.
   * `POST /api/control/reset-exhausted`: Resets `fully_exhausted = 0` so repos can be re-audited on demand.
   * `WS /ws/logs`: Streams live orchestrator and OpenHands stdout/stderr events to the browser.
2. Build `src/templates/dashboard.html` adhering strictly to the specifications in `ui.md`.

### Verification Criteria
* Start the web server locally, call `curl -s http://localhost:8080/api/state | jq .`, and verify valid JSON response and HTML rendering.

---

## Phase 7: ARM64 Docker Packaging & Production Entrypoint
### Objective
Package the entire application for 24/7 execution on Oracle Cloud Free Tier ARM64 (`linux/arm64`) with automatic restart and persistent volume mounts.

### Target Files to Create
* `main.py`
* `Dockerfile`
* `docker-compose.yml`
* `scripts/deploy_oracle_arm64.sh`
* `README.md`

### Implementation Details
1. Create `main.py` which launches the FastAPI Uvicorn server in a background daemon thread and runs `BugHunterOrchestrator.run_forever()` on the main thread with graceful `SIGINT`/`SIGTERM` handling.
2. Create the multi-arch `Dockerfile` (`python:3.12-slim-bookworm`) installing `git`, `gh`, `curl`, `jq`, `build-essential`, `nodejs`, `npm`, `openhands-ai`, `semgrep`, `ruff`, `pytest`, `fastapi`, `uvicorn[standard]`, and `websockets`.
3. Create `docker-compose.yml` with `20G` memory limit, persistent `/workspace/repos` and `/workspace/state` volumes, and port `8080:8080`.
4. Write `scripts/deploy_oracle_arm64.sh` to automate Docker installation, firewall port opening, and container startup on Oracle Cloud Ubuntu 24.04 ARM64.

### Verification Criteria
* Run full unit test suite (`pytest`) and verify syntax compilation (`python3 -m py_compile main.py src/*.py`).