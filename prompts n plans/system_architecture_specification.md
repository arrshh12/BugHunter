# System Architecture & Technical Specification

## 1. High-Level System Topology

```text
+-----------------------------------------------------------------------------------+
|                   ORACLE CLOUD FREE TIER VM (Ampere A1 ARM64)                     |
|                         4 OCPUs | 24 GB RAM | Ubuntu 24.04                        |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  |                 DOCKER CONTAINER: openhands-bughunter                       |  |
|  |                                                                             |  |
|  |  +-----------------------------------+   +-------------------------------+  |  |
|  |  |   FastAPI Mission Control (:8080) |   |   24/7 Orchestrator Daemon    |  |  |
|  |  |  - Live WebSocket Log Streamer    |<->|  - Repo Sync & Git Manager    |  |  |
|  |  |  - Repo Matrix & PR Feed UI       |   |  - PR Collision Guard (gh)    |  |  |
|  |  |  - API Key Health & Controls      |   |  - Diff & Verification Gate   |  |  |
|  |  +-----------------+-----------------+   +-------+---------------+-------+  |  |
|  |                    |                             |               |          |  |
|  |                    v                             v               v          |  |
|  |  +-----------------------------------+   +---------------+ +-------------+  |  |
|  |  |  SQLite WAL State Engine          |   | Key Rotator & | | Static Pre- |  |  |
|  |  |  (/workspace/state/bughunter.db)  |   | CircuitBrkr   | | Filter      |  |  |
|  |  +-----------------------------------+   +-------+-------+ | (Semgrep /  |  |  |
|  |                                                  |         |  Ruff)      |  |  |
|  |                                                  v         +------+------+  |  |
|  |                                          +------------------------+------+  |  |
|  |                                          |  OpenHands Headless Sandbox   |  |  |
|  |                                          |  (RUNTIME=process, isolated)  |  |  |
|  |                                          +---------------+---------------+  |  |
|  +----------------------------------------------------------|------------------+  |
+-------------------------------------------------------------|---------------------+
                                                              |
               +----------------------------------------------+------------------------------+
               |                                              |                              |
               v                                              v                              v
+------------------------------+             +--------------------------------+   +--------------------+
| ScaleMax API (Primary)       |             | Fallback Free API Key Pool     |   | GitHub REST / GraphQL
| Model: claude-haiku-5.5      |             | (Secondary ScaleMax /          |   | (20 Target Repos,  |
| OpenAI-Compatible Endpoint   |             |  OpenRouter / Gemini Free)     |   |  Atomic Branches & |
+------------------------------+             +--------------------------------+   |  Pull Requests)    |
                                                                                  +--------------------+
```

---

## 2. Technology Stack

| Layer | Technology | Rationale |
| :--- | :--- | :--- |
| **Host OS & Arch** | Ubuntu 24.04 LTS (`linux/arm64`) | Native OS for Oracle Cloud Free Tier Ampere A1 (4 OCPU, $24\text{ GB}$ RAM). |
| **Containerization** | Docker + Docker Compose v2 | Reproducible packaging, resource limits ($20\text{ GB}$ RAM cap), auto-restart on crash. |
| **Orchestrator Core** | Python 3.12 (`asyncio` + `threading`) | Coordinates the 24/7 loop, subprocess timeouts, Git operations, and FastAPI web server. |
| **AI Coding Harness** | OpenHands (`openhands-ai` CLI) | Full autonomous code navigation, bash test execution, and surgical file editing in `--headless` mode. |
| **Static Pre-Scanners** | Semgrep OSS, Ruff, Python AST | Identifies syntax errors, security anti-patterns, and undefined variables at $0$ token cost before LLM invocation. |
| **LLM Routing** | LiteLLM (built into OpenHands) + Custom Key Pool Manager | Seamlessly routes `openai/claude-haiku-5.5` to ScaleMax `base_url` and fails over to backup keys. |
| **State Persistence** | SQLite 3 (Write-Ahead Logging `WAL` mode) | Zero-overhead ACID database shared safely between the Orchestrator thread and FastAPI dashboard thread. |
| **GitHub Integration** | Git CLI + GitHub CLI (`gh`) + PyGithub/REST | Reliable branch creation, PR collision checks, and automated PR submission via PAT. |
| **Control Plane UI** | FastAPI + Uvicorn + Tailwind CSS + HTMX / WebSockets | Single-process reactive dashboard requiring zero Node.js frontend build complexity. |

---

## 3. Core Subsystem Architecture

### 3.1 Repository Workspace Manager (`src/git_manager.py`)
Manages the lifecycle of all 20 repositories inside `/workspace/repos/`:
1. **Auto-Discovery Mode:** If `AUTO_DISCOVER_REPOS=true`, queries `https://api.github.com/user/repos?per_page=100&affiliation=owner` to dynamically populate the 20 repositories, or reads explicit slugs from `TARGET_REPOS`.
2. **Clean-State Guarantee:** Before any operation, executes:
   ```bash
   git rebase --abort || true
   git merge --abort || true
   git reset --hard HEAD
   git clean -fd
   git checkout <default_branch>
   git pull --ff-only origin <default_branch>
   ```
3. **Collision Inspection:** Queries open PRs authored by the bot account. Extracts all modified file paths and writes `.skip_files.txt` into the target repo root.

### 3.2 Multi-Key LLM Pool & Circuit Breaker (`src/key_manager.py`)
Handles high-availability LLM routing across ScaleMax and backup free keys:
* **Configuration Format:** Parsed from `LLM_KEYS_POOL` or `/workspace/state/keys.json`. Each key entry has:
  * `id`: Unique identifier (`scalemax-primary-1`, `backup-free-2`, etc.)
  * `provider`: Display name (`ScaleMax`, `OpenRouter`, `Custom`)
  * `base_url`: OpenAI-compatible base URL (e.g., `https://api.scalemax.ai/v1`)
  * `model`: LiteLLM model string (e.g., `openai/claude-haiku-5.5`)
  * `api_key`: Secret key string
* **Circuit Breaker States:**
  * `HEALTHY`: Ready for selection (ordered by priority index).
  * `COOLDOWN`: Temporarily disabled after hitting `HTTP 429` or transient `5xx`. Cooldown duration follows exponential backoff:
    $$T_{\text{cooldown}} = \min\left(3600, 60 \times 2^{\text{consecutive\_failures} - 1}\right)\text{ seconds}$$
  * `EXHAUSTED`: Disabled for $24\text{ hours}$ if `HTTP 402` / `insufficient_quota` is returned.
* **Pre-Flight Ping:** Before launching a heavy OpenHands subprocess, `key_manager.py` sends a 5-token pre-flight `/v1/chat/completions` ping ($3\text{s}$ timeout) to verify the selected key is live and not rate-limited.

### 3.3 Static Analysis Pre-Filter (`src/static_scanner.py`)
Runs inside the target repository prior to invoking OpenHands:
* Executes `ruff check --output-format=json .` (for Python files) and `semgrep --config=auto --json --quiet .` (for multi-language security/bug patterns), filtering out any file listed in `.skip_files.txt`.
* Compiles top high-confidence findings (up to 10 items) into `.static_findings.json`.
* OpenHands reads `.static_findings.json` first so it can immediately investigate concrete leads before performing broader codebase exploration.

### 3.4 OpenHands Headless Bridge (`src/openhands_runner.py`)
Invokes the OpenHands CLI in an isolated process group:
* Sets environment variables dynamically from the active key in `KeyManager`:
  * `LLM_BASE_URL`
  * `LLM_MODEL`
  * `LLM_API_KEY`
  * `RUNTIME=process`
* Streams `stdout` and `stderr` line-by-line into the WebSocket log broadcaster (for the live UI) and an in-memory ring buffer to detect rate-limit exceptions in real time.
* Enforces a strict process-group timeout (`os.killpg`) so zombie test processes cannot leak memory.

### 3.5 Verification & Diff Sanitizer Gate (`src/verifier.py`)
Validates the agent's work before any Git commit or push is allowed:
1. Deletes `.skip_files.txt`, `.static_findings.json`, and `.bug_fix_report.json` from the working tree.
2. Parses `.bug_fix_report.json` in memory (`bug_found`, `file_modified`, `pr_title`, `pr_body`, `test_command_run`).
3. Runs `git status --porcelain` and `git diff --stat`:
   * Rejects and rolls back if $0$ files were modified.
   * Rejects and rolls back if any modified file is in `skip_files`.
   * Rejects and rolls back if modified file count $> \text{MAX\_FILES\_PER\_PR}$ (default $3$).
   * Rejects and rolls back if diff contains only whitespace changes (`git diff -w` is empty).
   * Rejects and rolls back if diff introduces any secret patterns (`ghp_`, `sk-`, `PRIVATE KEY`).

---

## 4. SQLite Database Schema (`/workspace/state/bughunter.sqlite`)

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS repositories (
    repo_slug TEXT PRIMARY KEY,
    default_branch TEXT NOT NULL DEFAULT 'main',
    last_scanned_sha TEXT,
    fully_exhausted INTEGER NOT NULL DEFAULT 0,
    open_pr_count INTEGER NOT NULL DEFAULT 0,
    total_prs_created INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'IDLE', -- IDLE, SYNCING, SCANNING, VERIFYING, PAUSED, ERROR
    last_scan_at TIMESTAMP,
    last_error TEXT
);

CREATE TABLE IF NOT EXISTS pull_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_slug TEXT NOT NULL,
    pr_number INTEGER,
    pr_url TEXT NOT NULL,
    branch_name TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    file_modified TEXT NOT NULL,
    pr_title TEXT NOT NULL,
    bug_summary TEXT,
    llm_key_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_key_status (
    key_id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    base_url TEXT NOT NULL,
    masked_key TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'HEALTHY', -- HEALTHY, COOLDOWN, EXHAUSTED
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    total_uses INTEGER NOT NULL DEFAULT 0,
    total_successes INTEGER NOT NULL DEFAULT 0,
    cooldown_until TIMESTAMP,
    last_error TEXT,
    last_used_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_slug TEXT NOT NULL,
    commit_sha TEXT,
    key_id TEXT,
    outcome TEXT NOT NULL, -- PR_CREATED, CLEAN_EXHAUSTED, SKIPPED_MAX_PRS, RATE_LIMITED, VERIFICATION_FAILED, ERROR
    duration_seconds REAL,
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## 5. End-to-End Execution State Machine

1. **`BOOT`**: Initialize SQLite tables, load `.env` & key pool, authenticate `gh` CLI, start FastAPI background server on port `8080`, enter 24/7 `MAIN_LOOP`.
2. **`SELECT_REPO`**: Fetch next active repository from `TARGET_REPOS` (skipping any repo manually paused via UI).
3. **`SYNC_AND_GUARD`**: Clone/pull latest `default_branch`. Query `gh pr list`. If `open_pr_count >= MAX_OPEN_PRS_PER_REPO`, log `SKIPPED_MAX_PRS` and move to next repo. If `HEAD == last_scanned_sha` and `fully_exhausted == 1`, skip to next repo.
4. **`STATIC_PREFILTER`**: Run `ruff` / `semgrep` on non-skipped files; write `.static_findings.json`.
5. **`KEY_ACQUISITION`**: Select highest-priority `HEALTHY` key from `KeyManager` and run pre-flight ping. If ping fails with `429`/`402`, trip circuit breaker and rotate to next key.
6. **`OPENHANDS_EXECUTION`**: Run `openhands --headless` with `task_prompt.txt`. Stream telemetry to UI.
7. **`VERIFY_AND_SANITIZE`**: Parse `.bug_fix_report.json`. Clean temp files. Validate `git diff -w` is non-empty and within atomic bounds.
8. **`DISPATCH_PR`**:
   * If `bug_found == true` and verification passes: checkout `fix/auto-<uuid6>`, commit, push, run `gh pr create`, record PR in `pull_requests` table, set `fully_exhausted = 0` (so the repo will be scanned again for the next bug!).
   * If `bug_found == false`: set `fully_exhausted = 1` for `HEAD` SHA so the repo rests until new commits arrive.