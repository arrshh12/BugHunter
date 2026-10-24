# Project: AutoBugHunter 24/7

Autonomous, containerized daemon running on Oracle Cloud Free Tier ARM64 (`linux/arm64`) that continuously monitors 20+ GitHub repositories, isolates single bugs via static analysis pre-filters and headless OpenHands, applies minimal atomic patches, verifies tests pass, and submits Pull Requests.

## Architecture

```
                                  +------------------------------------+
                                  |   Mission Control UI (FastAPI)     |
                                  |   Port 8080 | Cyber-Ops Dark Theme |
                                  |   GET / | /api/state | /ws/logs    |
                                  +-----------------+------------------+
                                                    |
                                    reads state /   | control commands
                                    streams logs    |
                                                    v
+----------------------------------------------------------------------------------------+
|                      Orchestrator Master Loop (src/orchestrator.py)                     |
|                                                                                        |
|  [Select Repo] ---> [Sync & Guard] ---> [Static Pre-Filter] ---> [Key Acquisition]     |
|         ^            (git_manager)      (Ruff + Semgrep)         (key_manager)         |
|         |                  |                    |                      |               |
|         |                  v                    v                      v               |
|         |           .skip_files.txt   .static_findings.json     ScaleMax / Fallback    |
|         |                  \                    /                      |               |
|         |                   +---------+--------+                       v               |
|         |                             |                     [OpenHands Headless]       |
|         |                             +-------------------> (openhands_runner)         |
|         |                                                              |               |
|         |                                                              v               |
|         |                                                    .bug_fix_report.json      |
|         |                                                              |               |
|         +--- [Clean/Exhausted] <--- [Verification Gate] <--------------+               |
|         |                            (src/verifier.py)                                 |
|         |                                  | (valid atomic diff)                       |
|         |                                  v                                           |
|         +--------------------------- [Dispatch PR]                                     |
|                                       (gh pr create)                                   |
+----------------------------------------------------------------------------------------+
                               |                         |
                               v                         v
               +-------------------------------+  +-------------------------------+
               |    SQLite WAL Database        |  |     Ring-Buffer Logger        |
               |    (src/database.py)          |  |     (src/logger.py)           |
               | - repositories                |  | - 500-line deque in-memory    |
               | - pull_requests               |  | - File rotation (10MB x 5)    |
               | - api_key_status              |  | - WebSocket pub/sub stream    |
               | - scan_logs                   |  +-------------------------------+
               +-------------------------------+
```

### Module Boundaries
1. `src/config.py`: Centralized typed settings, environment loading, directory creation, and key pool parsing.
2. `src/database.py`: SQLite 3 engine with WAL mode (`PRAGMA journal_mode=WAL`), connection pooling via context manager, and schema migrations.
3. `src/logger.py`: Ring buffer logger (500 items), rotating file logging, and asynchronous WebSocket broadcast mechanism.
4. `src/key_manager.py`: Resilient multi-key router, pre-flight ping, exponential cooldown for 429/5xx, 24h exhaustion for 402, and automatic recovery.
5. `src/git_manager.py`: Git repository workspace manager, default branch resolution, hard-reset clean sync, open PR collision guard, and `.skip_files.txt`.
6. `src/static_scanner.py`: Local static analysis pre-filter using Ruff and Semgrep OSS, false-positive filtering, severity ranking, and `.static_findings.json`.
7. `prompts/task_prompt.txt`: Task prompt for OpenHands enforcing "One Bug = One PR", test execution, and `.bug_fix_report.json`.
8. `src/openhands_runner.py`: Headless OpenHands CLI executor, cross-platform process tree isolation (`start_new_session` / `CREATE_NEW_PROCESS_GROUP`), real-time rate limit detection, and report parsing.
9. `src/verifier.py`: Verification gate enforcing diff bounds (<= 3 files, <= 150 lines, non-empty `git diff -w`), regex secret sanitization, collision guards, and artifact purging.
10. `src/orchestrator.py`: 24/7 continuous daemon loop coordinating repository selection, state tracking, PR dispatch via `gh pr create`, and exhaustion marks.
11. `src/web_server.py`: FastAPI server serving `dashboard.html`, `/api/state`, `/api/control/*`, and WebSocket `/ws/logs`.
12. `src/templates/dashboard.html`: Cyber-ops dark dashboard styled with Tailwind CSS (CDN) and Lucide Icons (CDN).
13. `main.py`: Application entrypoint running FastAPI in a background daemon thread and Orchestrator on the main thread.
14. `Dockerfile` & `docker-compose.yml`: Multi-arch ARM64 container packaging, 20 GB RAM limit, persistent volume mounts.
15. `scripts/deploy_oracle_arm64.sh`: Deployment automation script for Ubuntu 24.04 ARM64 with iptables port 8080 configuration.
16. `scripts/pre_commit_secret_sanitizer.py` & `scripts/install_hooks.py`: Git pre-commit hook preventing credential and temporary file leakage.

---

## Feature Inventory

| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Git Repository Init & Attributes | Initialize git repo, configure LF line endings in `.gitattributes`, `.gitignore` | M1 | explorer_survey_1 |
| 2 | Pre-Commit Secret Sanitizer | Detect and block simulated PATs (`ghp_`, `github_pat_`), API keys (`sk-`, `sk-ant-`, `AIza`), private keys, and high-entropy assignments | M1 | explorer_survey_1, PRD NFR-04 |
| 3 | Temporary File Pre-Commit Guard | Block staging of `.skip_files.txt`, `.static_findings.json`, `.bug_fix_report.json`, `.env`, and `*.sqlite` | M1 | explorer_survey_1, RULE-GIT-05 |
| 4 | Pre-Commit Hook Installer | Script `scripts/install_hooks.py` to install `.git/hooks/pre-commit` cross-platform | M1 | explorer_survey_1 |
| 5 | Dependencies & Pyproject Specification | Define `requirements.txt` and `pyproject.toml` with runtime and testing dependencies | M1 | explorer_survey_1, PRD |
| 6 | Typed Settings Loader | `src/config.py` loading `.env` and environment variables with type coercion and defaults | M2 | spec_miner_survey_1 |
| 7 | Key Pool Parser | Parse multi-key pool (`base_url\|model\|api_key` or JSON array) from environment | M2 | spec_miner_survey_1 |
| 8 | Path & Directory Resolver | Dynamically resolve workspace, repos, and state paths and create directories | M2 | spec_miner_survey_1 |
| 9 | SQLite WAL Engine Init | Initialize `bughunter.sqlite` with WAL mode, busy timeout 10000ms, and synchronous NORMAL | M2 | spec_miner_survey_1, R2 |
| 10 | Database Relational Schemas | 4 tables: `repositories`, `pull_requests`, `api_key_status`, `scan_logs` + 5 indexes | M2 | spec_miner_survey_1, R2 |
| 11 | Thread-Safe DB Context Manager | Context manager providing connections with `check_same_thread=False` and autocommit/rollback | M2 | spec_miner_survey_1 |
| 12 | Repository State Tracking | CRUD operations for repository status, commit SHA, PR counts, and exhaustion flags | M2 | spec_miner_survey_1 |
| 13 | Pull Request Audit Ledger | Record created PRs with branch, SHA, file, title, summary, key ID, and timestamp | M2 | spec_miner_survey_1 |
| 14 | API Key State Synchronization | Synchronize key health (`HEALTHY`, `COOLDOWN`, `EXHAUSTED`), failure counts, and cooldown timestamps | M2 | spec_miner_survey_1 |
| 15 | Scan Logs Audit Trail | Record scan duration, commit SHA, key ID, outcome, and error details | M2 | spec_miner_survey_1 |
| 16 | KPI & State Aggregator | Compute aggregated stats for `/api/state` (repos, PRs, healthy keys, cycles) | M2 | spec_miner_survey_1, UI Spec |
| 17 | Reset Exhausted State in DB | Reset `fully_exhausted = 0` across all repositories on demand | M2 | spec_miner_survey_1 |
| 18 | Fixed-Capacity Ring Buffer | Retain latest 500 log lines in thread-safe memory deque | M2 | spec_miner_survey_1, R2 |
| 19 | Rotating File Logger | Write logs to `bughunter.log` with size rotation (10 MB x 5 backups) | M2 | spec_miner_survey_1 |
| 20 | WebSocket Live Broadcaster | Async pub/sub broadcaster dispatching logs to active WebSocket subscribers | M2 | spec_miner_survey_1, UI Spec |
| 21 | Initial Buffer Replay | Replay last 50-100 log lines to newly connected WebSocket clients | M2 | spec_miner_survey_1 |
| 22 | Priority-Ordered Key Selection | Select highest-priority healthy key from configured pool | M2 | spec_miner_survey_1 |
| 23 | Pre-Flight Health Ping | Send 1-token `/v1/chat/completions` request with 5s timeout to verify key viability | M2 | spec_miner_survey_1 |
| 24 | Exponential Cooldown Circuit Breaker | Trip key to `COOLDOWN` on 429/5xx with formula $T = \min(3600, 60 \times 2^{F-1})$ | M2 | spec_miner_survey_1, R2 |
| 25 | 24-Hour Quota Exhaustion Trip | Trip key to `EXHAUSTED` for 24h ($86400$s) on HTTP 402 or `insufficient_quota` | M2 | spec_miner_survey_1, R2 |
| 26 | Automatic Cooldown Recovery | Promote expired cooldown keys back to `HEALTHY` upon evaluation | M2 | spec_miner_survey_1 |
| 27 | Key Masking Utility | Mask keys showing only first 4 and last 4 characters (`sk-sc...9a2f`) | M2 | spec_miner_survey_1 |
| 28 | Pool-Wide Exhaustion Sleep | Sleep for 60 seconds if all keys are cooling down, without crashing daemon | M2 | spec_miner_survey_1 |
| 29 | Git & GH CLI Configuration | Set bot user identity and authenticate GitHub CLI via `GITHUB_TOKEN` | M3 | spec_miner_survey_2, R3 |
| 30 | Repository Discovery & Loading | Parse `TARGET_REPOS` or query GitHub API for non-fork, non-archived repositories | M3 | spec_miner_survey_2 |
| 31 | Clean Repository Sync | Hard-reset working tree (`reset --hard`, `clean -fd`), checkout default branch, and pull `--ff-only` | M3 | spec_miner_survey_2, R3 |
| 32 | Open Bot PR Query & Collision Guard | Query `gh pr list --author "@me"`; if open PRs >= 5, pause repo scan for cycle | M3 | spec_miner_survey_2, R3 |
| 33 | `.skip_files.txt` Generator | Extract modified files from open PRs and write to `.skip_files.txt` | M3 | spec_miner_survey_2, R3 |
| 34 | Temporary Artifact Purge | Remove `.skip_files.txt`, `.static_findings.json`, `.bug_fix_report.json` before git commit | M3 | spec_miner_survey_2, RULE-GIT-05 |
| 35 | Atomic Branch Creator | Create and checkout isolated branch `fix/auto-<repo_short>-<hex6>` | M3 | spec_miner_survey_2, RULE-GIT-01 |
| 36 | Safe Branch Push | Push branch to origin without `--force` | M3 | spec_miner_survey_2, RULE-GIT-02 |
| 37 | Static Pre-Filter Runner | Run Ruff and Semgrep on target repo with 90s timeout, compile `.static_findings.json` | M3 | spec_miner_survey_2, R3 |
| 38 | Ruff AST Lint Execution | Run `ruff check --output-format=json .` for AST bugs and syntax issues | M3 | spec_miner_survey_2, R3 |
| 39 | Semgrep OSS Execution | Run `semgrep --config=auto --json --quiet .` for multi-language security issues | M3 | spec_miner_survey_2, R3 |
| 40 | False Positive & Skip Filter | Filter out findings for files in `.skip_files.txt` and low-value style rules (E501) | M3 | spec_miner_survey_2 |
| 41 | Severity Ranking & Top-N Cap | Rank findings by severity (ERROR > WARNING > INFO) and cap output to top 10 items | M3 | spec_miner_survey_2 |
| 42 | OpenHands Task Prompt Templating | `prompts/task_prompt.txt` enforcing "One Bug = One PR", test execution, `.bug_fix_report.json` | M4 | spec_miner_survey_2, R3 |
| 43 | Headless OpenHands Runner | Execute `openhands --headless --override-with-envs -f task_prompt.txt` with `RUNTIME=process` | M4 | spec_miner_survey_2, R3 |
| 44 | Environment Variable Injection | Pass `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`, and `WORKSPACE_BASE` to OpenHands | M4 | spec_miner_survey_2 |
| 45 | Process-Tree Isolation | Launch subprocess in new process group (`start_new_session=True` / `CREATE_NEW_PROCESS_GROUP`) | M4 | spec_miner_survey_2, R3 |
| 46 | Process Tree Timeout Termination | Enforce 1200s timeout and terminate process tree via `os.killpg` / process tree kill | M4 | spec_miner_survey_2, RULE-SYS-02 |
| 47 | Real-Time Rate Limit Detection | Scan stdout/stderr for `429`, `RateLimitError`, `402`, `insufficient_quota` and kill immediately | M4 | spec_miner_survey_2 |
| 48 | Bug Fix Report Parser | Parse `.bug_fix_report.json` produced by OpenHands | M4 | spec_miner_survey_2 |
| 49 | Verification Gate Runner | `verify_and_sanitize_fix()` executing full verification pipeline before staging | M4 | spec_miner_survey_2, R4 |
| 50 | Non-Empty Diff & Whitespace Check | Reject empty diffs and whitespace-only diffs (`git diff -w` is empty) | M4 | spec_miner_survey_2, R4 |
| 51 | Diff Boundary Enforcer | Enforce modified files <= 3 and total changed lines <= 150 | M4 | spec_miner_survey_2, R4 |
| 52 | Collision File Guard Check | Reject fix if any modified file appears in `skip_files` | M4 | spec_miner_survey_2, R4 |
| 53 | Runtime Secret Sanitizer Check | Scan diff added lines (`+`) against regexes for PATs, API keys, private keys | M4 | spec_miner_survey_2, R4 |
| 54 | Automated Test Verification | Verify tests passed in `.bug_fix_report.json` or run repository test command | M4 | spec_miner_survey_2, R4 |
| 55 | Continuous 24/7 Scanning Loop | Orchestrator loop iterating across all 20+ repos through all execution stages | M5 | spec_miner_survey_2, R4 |
| 56 | PR Creation & Dispatch | Execute `gh pr create` with structured template, branch, title, and body | M5 | spec_miner_survey_2, R4 |
| 57 | Exhaustion & Re-Scan Logic | Mark `fully_exhausted = 0` on PR created, or `1` if clean audit with no bugs | M5 | spec_miner_survey_2, R4 |
| 58 | Clean Working Tree Rollback | Execute `git reset --hard HEAD && git clean -fd` on failure or clean scan | M5 | spec_miner_survey_2 |
| 59 | Scan Logs Recording | Record scan execution, duration, commit SHA, key ID, and outcome in database | M5 | spec_miner_survey_2 |
| 60 | FastAPI Web Application | FastAPI app serving dashboard HTML and static assets on port 8080 (`/`) | M6 | spec_miner_survey_2, R5 |
| 61 | State API (`GET /api/state`) | Return complete JSON state snapshot polled every 3s by frontend | M6 | spec_miner_survey_2, R5 |
| 62 | Pause Control (`POST /api/control/toggle-pause`) | Toggle orchestrator scanning pause flag | M6 | spec_miner_survey_2, R5 |
| 63 | Force Scan Control (`POST /api/control/scan-now/{owner}/{repo}`) | Queue high-priority scan for specified repository | M6 | spec_miner_survey_2, R5 |
| 64 | Reset Exhausted Control (`POST /api/control/reset-exhausted`) | Reset `fully_exhausted = 0` for all repos in database | M6 | spec_miner_survey_2, R5 |
| 65 | WebSocket Live Logs (`/ws/logs`) | Stream live stdout/stderr log lines to connected dashboard clients | M6 | spec_miner_survey_2, R5 |
| 66 | Cyber-Ops Dark Dashboard UI | Single-page UI (`dashboard.html`) styled with Tailwind CDN and Lucide Icons | M6 | spec_miner_survey_2, R5 |
| 67 | Top Command Header Component | Header with animated status dot, pause button, and reset cache button | M6 | spec_miner_survey_2 |
| 68 | Top KPI Metric Strip Component | 4 metric cards: Repos Tracked, Atomic PRs Created, Active LLM Engine, Cycle/Guard | M6 | spec_miner_survey_2 |
| 69 | 20-Repo Status Matrix Component | Table listing repos, HEAD SHA, status badge, open PRs, lifetime fixes, and Scan Now | M6 | spec_miner_survey_2 |
| 70 | Live Terminal Window Component | Monospace terminal window with auto-scroll lock and color-coded log prefixes | M6 | spec_miner_survey_2 |
| 71 | Key Pool & Circuit Breaker Component | Cards showing key priority, model, masked key, circuit state, cooldown timer | M6 | spec_miner_survey_2 |
| 72 | Atomic PR Feed Component | Chronological feed of PRs with repo badge, target file, branch, and GitHub link | M6 | spec_miner_survey_2 |
| 73 | Application Entrypoint `main.py` | Runs FastAPI server in background daemon thread and Orchestrator on main thread | M6 | spec_miner_survey_2, R5 |
| 74 | Multi-Arch ARM64 Dockerfile | Multi-stage Dockerfile based on `python:3.12-slim-bookworm` with `dpkg --print-architecture` | M6 | explorer_survey_1, R5 |
| 75 | Docker Compose Configuration | `docker-compose.yml` with 20 GB RAM limit, 3.5 OCPUs, volume mounts, env pass-through | M6 | explorer_survey_1, R5 |
| 76 | Oracle Cloud ARM64 Deploy Script | `scripts/deploy_oracle_arm64.sh` configuring Docker, iptables port 8080, and startup | M6 | explorer_survey_1, R5 |
| 77 | Full E2E Test Suite (Tiers 1-4) | Comprehensive test suite verifying all features opaque-box | M7 | Dual Track, Acceptance Criteria |
| 78 | Adversarial Coverage Hardening (Tier 5) | White-box stress testing, gap analysis, and robustness hardening | M7 | Project Pattern |
| 79 | Multi-Scanner Ingestion & Proximity Clustering | `src/bugfinding_agent.py`: Ingests Flake8, ESLint, Bandit, Semgrep, Trivy findings and clusters within $\pm 2$ lines | TAM1 | R1, explorer_arch_1 |
| 80 | Per-Repo Bug-log.md Generation & State Retention | `src/bugfinding_agent.py`: Formats task checkboxes, retains `DONE` items on re-scans, protects via `.git/info/exclude` | TAM1 | R1, explorer_arch_2 |
| 81 | Zero Static Scanning Backlog Consumption | `src/fixer_agent.py`: Parses `Bug-log.md` with zero static scanners invoked during fix operations | TAM2 | R2, explorer_arch_1 |
| 82 | Surgical AST Context & Patch Planning | `src/fixer_agent.py`: Extracts symbol slice via AST and formulates plan enforcing One Bug = One PR, $\le 150$ diff lines | TAM2 | R2, explorer_arch_1 |
| 83 | Headless Aider Remediation Engine | `src/fixer_agent.py`: Headless patch execution with `openai/gpt-6-luna` pointing to `https://api.scalemax.pro/v1` | TAM2 | R2, explorer_arch_1 |
| 84 | Verification Gate & In-Place Atomic Mutation | `src/fixer_agent.py`: Verifies diff bounds ($\le 3$ files, $\le 150$ lines) and mutates item to `- [x] ... (DONE)` atomically | TAM3 | R3, explorer_arch_2 |
| 85 | Fix Audit Ledger Append (`logs.md`) | `src/fixer_agent.py`: Thread-safe append of ISO 8601 UTC timestamp, slug, bug ID, diff lines, branch, and PR status | TAM3 | R3, explorer_arch_2 |
| 86 | Dedicated Bot Account Identity (`arrshh12`) | `src/git_manager.py`, `src/fixer_agent.py`: Resolves `arrshh12` bot identity and formats `head_spec=arrshh12:<branch>` | TAM3 | User Directive |
| 87 | Orchestrator Two-Agent Cycle Integration | `src/orchestrator.py`: Orchestrates decoupled discovery (`run_bugfinding_phase`) and remediation (`run_fixer_phase`) | TAM4 | R4, explorer_arch_2 |

---

## Milestones

| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Project Foundation, Environment & Secret Sanitizer | Git repository setup, LF line endings, `.gitattributes`, `.gitignore`, dependencies (`pyproject.toml`, `requirements.txt`), pre-commit secret sanitizer hook (`scripts/pre_commit_secret_sanitizer.py`, `scripts/install_hooks.py`) | none | DONE |
| M2 | Core Persistence, Logger & Resilient Key Routing | `src/config.py`, SQLite WAL `src/database.py` (4 tables, 5 indexes, stats, reset), ring-buffer logger `src/logger.py` (deque, file rotation, WebSocket broadcaster), and multi-key circuit breaker `src/key_manager.py` (ScaleMax routing, preflight ping, 429 exponential backoff, 402 24h exhaustion, key masking) | M1 | DONE |
| M3 | Git Workspace Manager & Static Pre-Filter | `src/git_manager.py` (git/gh config, repo discovery, hard-reset sync, collision guard, `.skip_files.txt`, branch creation), and `src/static_scanner.py` (Ruff and Semgrep runners, skip-file filtering, severity ranking, top-10 cap, `.static_findings.json`) | M1, M2 | DONE |
| M4 | OpenHands Runner, Task Prompt & Verifier Gate | `prompts/task_prompt.txt` (One Bug = One PR rule, test run mandate, `.bug_fix_report.json`), `src/openhands_runner.py` (CLI runner, process-tree isolation, real-time rate limit detection, timeout kills), and `src/verifier.py` (diff bounds <= 3 files, <= 150 lines, non-whitespace diff, secret leak scanning, collision guard, artifact purge) | M1, M2, M3 | DONE |
| M5 | Orchestrator Continuous Loop & PR Dispatcher | `src/orchestrator.py` (24/7 continuous cycle, state transitions, branch checkout, commit, push, `gh pr create` dispatch with template, `fully_exhausted` logic, scan logs recording) | M1, M2, M3, M4 | DONE |
| M6 | Mission Control UI & ARM64 Container Packaging | `src/web_server.py` (FastAPI app, `/`, `/api/state`, `/api/control/*`, `/ws/logs`), `src/templates/dashboard.html` (cyber-ops dark theme, Tailwind CDN, Lucide CDN, responsive grid), `main.py` (dual-thread entrypoint), `Dockerfile`, `docker-compose.yml` (20GB RAM limit), and `scripts/deploy_oracle_arm64.sh` | M1, M2, M3, M4, M5 | DONE |
| M7 | Final E2E Suite Pass & Adversarial Hardening | Phase 1: 100% pass rate on E2E test suite (Tiers 1-4). Phase 2: Adversarial coverage hardening (Tier 5) with Challengers | M1-M6, TEST_READY.md | DONE |

## AutoBugHunter Remediation Pipeline Refactor Milestones (R1-R4)

| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| RM1 | Model Shift & ScaleMax Configuration (R3) | `src/config.py`, `src/openhands_runner.py`, `.env.example`, `tests/test_config_scalemax.py`. Shift all default and fallback models from `longcat-preview` to `openai/gpt-6-luna`, base URL to `https://api.scalemax.pro/v1`, dynamic key pool loading, and subprocess env propagation. | none | DONE |
| RM2 | Modular BugHunter Agent with Skills (R1) | `src/bughunter_agent.py`, `tests/test_bughunter_agent.py`. Implemented modular skills: `TriageSkill` (multi-scanner parsing for Flake8, ESLint, Bandit, Semgrep, Trivy, $\pm 2$ proximity clustering, 5-axis ranking), `ContextExtractionSkill` (surgical AST extraction with decorator preservation and fallback), `PatchPlanningSkill` (One Bug = One PR, $\le 150$ lines diff, $\le 3$ files). | RM1 | DONE |
| RM3 | Aider Execution Runner (R2) | `src/aider_runner.py`, `tests/test_aider_runner.py`. Headless CLI wrapper for `aider`, process tree isolation via `psutil` + `taskkill` / `os.killpg`, rate limit false positive sanitization (excluding ports, line numbers, commit hashes), `stdin=subprocess.DEVNULL`, and bounded diff hunk extraction. | RM1, RM2 | DONE |
| RM4 | Comprehensive Test Suite & E2E Verification (R4) | `tests/test_e2e_remediation.py`, `tests/test_e2e_pipeline_boundaries_adversarial.py`, `tests/test_adversarial_stress_m4.py`. Full pipeline integration, resilience, 100% full repo test pass (735 passed, 0 failures), zero `longcat` references, clean compilation and linting, zero integrity violations. | RM1, RM2, RM3 | DONE |

## Two-Agent "Bug-Hunter" Architecture Milestones (TAM1-TAM4)

| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| TAM1 | Bugfinding Agent & Per-Repo Bug-log.md Generation (R1) | `src/bugfinding_agent.py`. Autonomous discovery across 5 repos, multi-scanner triage (Flake8, ESLint, Bandit, Semgrep, Trivy), $\pm 2$ lines proximity clustering, 5-axis ranking, `Bug-log.md` task checkbox generation, state retention of `DONE` items on re-scans, `.git/info/exclude` safety. | RM2 | DONE |
| TAM2 | Main Fixer Agent with Direct Backlog Consumption & Zero Static Scanning (R2) | `src/fixer_agent.py`. Consumes pending bugs directly from `Bug-log.md` with strict zero static scanning invariant, AST context extraction via `ContextExtractionSkill`, surgical patch planning via `PatchPlanningSkill`, headless Aider execution with `openai/gpt-6-luna` at `https://api.scalemax.pro/v1`. | RM3, TAM1 | DONE |
| TAM3 | Backlog Mutation, Audit Ledger & Dedicated Bot Identity (R3) | `src/fixer_agent.py`, `src/git_manager.py`, `logs.md`. In-place atomic update of `Bug-log.md` to `DONE`, thread-safe append to `logs.md` audit ledger, resolution of `arrshh12` bot identity, and formatting `head_spec=arrshh12:<branch>`. | TAM2 | DONE |
| TAM4 | Orchestrator Integration & Comprehensive Test Suite (R4) | `src/orchestrator.py`, `tests/test_two_agent_architecture.py`. Master integration (`run_two_agent_cycle`, `run_bugfinding_phase`, `run_fixer_phase`) preserving 100% backward compatibility, comprehensive 6-class automated test suite (15 passed), zero regressions across full test suite. | TAM1, TAM2, TAM3 | DONE |

---

## Interface Contracts

### `src/config.py` ↔ System
```python
@dataclass
class KeyConfig:
    id: str
    provider: str
    base_url: str
    model: str
    api_key: str
    masked_key: str
    priority: int

@dataclass
class Config:
    github_token: str
    target_repos: list[str]
    auto_discover_repos: bool
    llm_keys: list[KeyConfig]
    max_open_prs_per_repo: int
    max_files_per_pr: int
    max_diff_lines: int
    scan_cooldown_seconds: int
    agent_timeout_seconds: int
    static_scan_timeout_seconds: int
    git_timeout_seconds: int
    preflight_timeout_seconds: int
    dashboard_host: str
    dashboard_port: int
    workspace_dir: Path
    repos_dir: Path
    state_dir: Path
    db_path: Path
    log_file_path: Path
    log_ring_buffer_size: int

    @classmethod
    def load(cls, env_file: Optional[Path] = None) -> "Config": ...
```

### `src/database.py` ↔ Core Services
```python
class Database:
    def __init__(self, db_path: str | Path): ...
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]: ...
    def init_db(self) -> None: ...
    def upsert_repository(self, repo_slug: str, default_branch: str = "main", ...) -> None: ...
    def update_repository_status(self, repo_slug: str, status: str, last_error: Optional[str] = None) -> None: ...
    def record_scan_result(self, repo_slug: str, commit_sha: str, fully_exhausted: int, last_error: Optional[str] = None) -> None: ...
    def update_open_pr_count(self, repo_slug: str, count: int) -> None: ...
    def record_pull_request(self, repo_slug: str, pr_number: int, pr_url: str, branch_name: str, commit_sha: str, file_modified: str, pr_title: str, bug_summary: Optional[str] = None, llm_key_id: Optional[str] = None) -> int: ...
    def upsert_api_key(self, key_id: str, provider: str, model: str, base_url: str, masked_key: str, state: str = "HEALTHY") -> None: ...
    def update_api_key_status(self, key_id: str, state: str, consecutive_failures: int, cooldown_until: Optional[str], last_error: Optional[str] = None) -> None: ...
    def record_api_key_usage(self, key_id: str, success: bool) -> None: ...
    def add_scan_log(self, repo_slug: str, commit_sha: Optional[str], key_id: Optional[str], outcome: str, duration_seconds: float, details: Optional[str] = None) -> int: ...
    def get_stats(self) -> dict[str, Any]: ...
    def reset_exhausted(self) -> int: ...
```

### `src/key_manager.py` ↔ OpenHands Runner & Database
```python
class KeyManager:
    def __init__(self, config: Config, database: Database): ...
    def get_next_healthy_key(self) -> Optional[KeyConfig]: ...
    def preflight_check(self, key: KeyConfig) -> bool: ...
    def report_key_failure(self, key_id: str, error_message: str, status_code: Optional[int] = None) -> None: ...
    def report_key_success(self, key_id: str) -> None: ...
```

### `src/git_manager.py` ↔ Orchestrator
```python
class GitManager:
    def __init__(self, workspace_dir: Path, github_token: str, max_open_prs: int = 5): ...
    def configure_git_and_gh(self) -> None: ...
    def discover_or_load_repos(self, target_repos_str: str, auto_discover: bool) -> list[str]: ...
    def sync_repository(self, repo_slug: str) -> tuple[Path, str, str]: ...
    def get_open_bot_prs(self, repo_slug: str, repo_path: Path) -> tuple[int, list[str]]: ...
    def create_atomic_branch(self, repo_path: Path, prefix: str = "auto") -> str: ...
    def push_atomic_branch(self, repo_path: Path, branch_name: str) -> None: ...
    def rollback_working_tree(self, repo_path: Path, default_branch: str) -> None: ...
```

### `src/static_scanner.py` ↔ OpenHands Runner
```python
class StaticScanner:
    def __init__(self, timeout_seconds: int = 90, max_findings: int = 10): ...
    def run_static_prefilter(self, repo_path: Path, skip_files: list[str]) -> Path: ...
```

### `src/openhands_runner.py` ↔ Orchestrator
```python
class OpenHandsRunner:
    def __init__(self, timeout_seconds: int = 1200): ...
    def run_openhands_session(
        self,
        repo_path: Path,
        key_entry: KeyConfig,
        task_prompt_path: Path,
        log_callback: Callable[[str], None]
    ) -> SessionResult: ...
```

### `src/verifier.py` ↔ Orchestrator
```python
class Verifier:
    def verify_and_sanitize_fix(
        self,
        repo_path: Path,
        skip_files: list[str],
        max_files: int = 3,
        max_lines: int = 150
    ) -> VerificationResult: ...
```

---

## Code Layout

```
c:\antigravity\bughunter\
├── .git/                                 # Git metadata
├── .gitattributes                        # LF line endings enforcement
├── .gitignore                            # Python, SQLite, environment ignores
├── .env.example                          # Clean configuration template
├── pyproject.toml                        # Project metadata & tool configurations
├── requirements.txt                      # Production dependencies
├── main.py                               # Application entrypoint (daemon + web)
├── Dockerfile                            # Multi-arch ARM64 container
├── docker-compose.yml                    # Container specification & 20GB limit
├── src/
│   ├── __init__.py
│   ├── config.py                         # Settings & environment parser
│   ├── database.py                       # SQLite WAL engine (4 tables)
│   ├── logger.py                         # Ring buffer & WebSocket broadcaster
│   ├── key_manager.py                    # Multi-key circuit breaker
│   ├── git_manager.py                    # Git & gh workspace manager
│   ├── static_scanner.py                 # Ruff + Semgrep pre-filter
│   ├── openhands_runner.py               # Headless OpenHands process runner
│   ├── verifier.py                       # Verification gate & secret sanitizer
│   ├── orchestrator.py                   # 24/7 scanning loop & PR dispatcher
│   ├── bughunter_agent.py                # Modular skills (Triage, Context, Patch)
│   ├── bugfinding_agent.py               # BugfindingAgent multi-scanner discovery
│   ├── fixer_agent.py                    # MainFixerAgent zero-scanner remediation
│   ├── aider_runner.py                   # Headless Aider runner (gpt-6-luna)
│   ├── web_server.py                     # FastAPI Mission Control dashboard API
│   └── templates/
│       └── dashboard.html                # Cyber-Ops dark theme dashboard
├── prompts/
│   └── task_prompt.txt                   # OpenHands task prompt template
├── scripts/
│   ├── pre_commit_secret_sanitizer.py    # Pre-commit hook script
│   ├── install_hooks.py                  # Hook installer script
│   └── deploy_oracle_arm64.sh            # OCI Ubuntu ARM64 deployment script
└── tests/
    ├── __init__.py
    ├── conftest.py                       # Shared pytest fixtures & mocks
    ├── test_config.py                    # Settings tests
    ├── test_database.py                  # SQLite WAL & CRUD tests
    ├── test_logger.py                    # Ring buffer & WebSocket tests
    ├── test_key_manager.py               # Key failover & cooldown tests
    ├── test_git_manager.py               # Git sync & collision tests
    ├── test_static_scanner.py            # Static pre-filter tests
    ├── test_openhands_runner.py          # Process isolation & timeout tests
    ├── test_verifier.py                  # Verification gate & secret regex tests
    ├── test_orchestrator.py              # Scanning loop & PR dispatch tests
    ├── test_web_server.py                # Dashboard API & WebSocket tests
    ├── test_aider_runner.py              # Headless Aider runner tests
    ├── test_bughunter_agent.py           # Modular skills tests
    └── test_two_agent_architecture.py    # Comprehensive two-agent architecture suite
```
