# Product Requirement Document (PRD): AutoBugHunter 24/7

## 1. Executive Summary & Vision
**AutoBugHunter 24/7** is an autonomous, containerized software engineering daemon that continuously monitors, audits, patches, and submits verified GitHub Pull Requests across a portfolio of 20+ repositories. Powered by the **OpenHands** headless agent harness and a fault-tolerant **ScaleMax OpenAI-compatible API pool (Claude Haiku 5.5 + fallback free keys)**, the system runs 24/7 on an **Oracle Cloud Free Tier ARM64 (`linux/arm64`)** instance.

The core product philosophy is **Strict Atomic Remediation**:
> **One Reproducible Bug = One Minimal Code Fix = One Verified Pull Request.**

---

## 2. Target Operational Environment
* **Cloud Host:** Oracle Cloud Infrastructure (OCI) Always Free Tier — Ampere A1 Compute (`VM.Standard.A1.Flex`).
* **Hardware Allocation:** 4 ARM64 OCPUs, $24\text{ GB}$ RAM, $50\text{ GB}$–$100\text{ GB}$ Block Volume NVMe storage.
* **Container Runtime:** Docker Engine + Docker Compose (`linux/arm64` native build, memory capped at $20\text{ GB}$ to reserve $4\text{ GB}$ for the host Ubuntu 24.04 LTS kernel).
* **Agent Harness:** OpenHands CLI (`openhands-ai`) running in headless process runtime (`RUNTIME=process`) alongside deterministic static analysis pre-filters (`semgrep`, `ruff`).
* **LLM Provider Strategy:** Primary OpenAI-compatible ScaleMax endpoint running `openai/claude-haiku-5.5`, backed by an automated multi-key failover rotator supporting unlimited backup/free API keys.
* **GitHub Authentication:** Dedicated Personal Access Token (PAT) with fine-grained `Contents: Read & Write` and `Pull Requests: Read & Write` permissions across all 20 target repositories.

---

## 3. Core Functional Requirements (FR)

### FR-01: Multi-Repository Discovery & Synchronization
* **Description:** The system must manage a configurable list of 20+ GitHub repositories (`TARGET_REPOS` in `.env` or auto-fetched via the GitHub API).
* **Behavior:**
  * Clone missing repositories into `/workspace/repos/<owner>__<repo>`.
  * Before every scan cycle, reset dirty working trees (`git reset --hard && git clean -fd`), checkout the default branch (`main` or `master`), and pull the latest upstream commits.
  * Record the latest `HEAD` commit SHA in SQLite.

### FR-02: Stateful Commit & File Deduplication
* **Description:** Prevent redundant token burn by tracking audited commits and file hashes in a persistent SQLite database (`/workspace/state/bughunter.sqlite`).
* **Behavior:**
  * If a repository's `HEAD` commit SHA has already been marked as `fully_exhausted = 1` (meaning zero remaining bugs were found across all files on that commit), skip the repository until a new commit is pushed.
  * Track per-file SHA-256 digests so unchanged files that passed audit on previous commits are deprioritized in favor of newly modified or unaudited files.

### FR-03: Open PR Collision Guard
* **Description:** Prevent merge conflicts and duplicate PR spam on the same file or repository.
* **Behavior:**
  * Query `gh pr list --author "@me" --state open --json number,headRefName,files` before scanning a repository.
  * Enforce a configurable per-repository ceiling (`MAX_OPEN_PRS_PER_REPO`, default $5$). If open bot PRs $\ge 5$, skip the repository for the current cycle.
  * Extract all file paths modified in currently open bot PRs and write them to `.skip_files.txt` so OpenHands is forbidden from touching files that already have a pending PR.

### FR-04: Hybrid Bug Discovery Pipeline (Static Pre-Filter + OpenHands Agent)
* **Description:** Combine zero-cost deterministic static analysis with deep LLM reasoning.
* **Behavior:**
  * Run fast static analyzers (`ruff check`, `semgrep --config=auto`, syntax compilers) first and store diagnostics in `.static_findings.json`.
  * Invoke OpenHands headlessly (`openhands --headless --override-with-envs -f /app/task_prompt.txt`) with access to `.static_findings.json` and `.skip_files.txt`.
  * The agent must identify **at most one** concrete, reproducible bug per invocation (null/None dereference, unhandled exception, off-by-one error, resource leak, broken import, race condition, logic flaw, or security vulnerability).

### FR-05: Strict "One Bug = One PR" Atomic Fix Protocol
* **Description:** Every Pull Request must address exactly one isolated bug with the smallest possible diff.
* **Behavior:**
  * Even a 1-line fix qualifies for its own dedicated branch (`fix/auto-<short-hash>`) and Pull Request.
  * If a repository contains 4 distinct bugs, the system must execute 4 separate scan-fix-verify-PR cycles, generating 4 independent branches and 4 independent Pull Requests.
  * Stylistic changes, formatting rewrites, comment additions, or variable renamings without functional bug fixes are strictly prohibited.

### FR-06: Containerized Verification Gate
* **Description:** Never open a Pull Request that breaks the build or fails existing tests.
* **Behavior:**
  * OpenHands must execute available repository test suites (`pytest`, `npm test`, `cargo test`, `go test`) or language syntax checks before finalizing its fix.
  * After OpenHands exits, the Python orchestrator independently validates:
    1. `.bug_fix_report.json` exists and reports `"bug_found": true`.
    2. Temporary artifacts (`.skip_files.txt`, `.static_findings.json`, `.bug_fix_report.json`) are removed before staging.
    3. `git diff` is non-empty and modifies $\le 3$ files (configurable `MAX_FILES_PER_PR`) to prevent accidental mass-refactoring.
    4. None of the modified files appear in the restricted `.skip_files.txt` list.

### FR-07: Multi-Key LLM Pool & Automatic Failover Rotator
* **Description:** Ensure uninterrupted 24/7 execution when individual API keys hit rate limits (`HTTP 429`), quota exhaustion (`HTTP 402`), or temporary upstream timeouts (`HTTP 502/503/504`).
* **Behavior:**
  * Accept a prioritized pool of API keys in `.env` (`LLM_KEYS_POOL`), supporting ScaleMax (`openai/claude-haiku-5.5`) as primary and multiple backup ScaleMax/OpenRouter/Gemini free keys.
  * Track key health, token usage estimates, error counts, and cooldown timestamps in SQLite.
  * Automatically rotate to the next healthy key and retry the current repository scan when a rate-limit or quota error occurs.

### FR-08: Mission Control Web Dashboard & Live Telemetry API
* **Description:** Provide a lightweight, real-time web interface (`http://<oracle-vm-ip>:8080`) to monitor the 24/7 daemon without needing SSH access.
* **Behavior:**
  * Display live status of all 20 repositories (Last Scanned SHA, Open Bot PRs, Total Bugs Fixed, Current Status).
  * Stream real-time OpenHands agent logs over WebSockets.
  * Show API Key Pool health (Active Key, Cooldown Timers, Failover Count).
  * Provide one-click controls: Pause/Resume Daemon, Force Scan Specific Repo, and Clear Exhausted Cache.

---

## 4. Non-Functional Requirements (NFR)
* **NFR-01 (Resource Isolation):** Total container memory consumption must stay $\le 20\text{ GB}$ RAM and CPU usage $\le 3.5\text{ OCPUs}$ on the 4-OCPU Oracle Ampere A1 instance.
* **NFR-02 (Crash Recovery):** If OpenHands hangs on a runaway test suite, the orchestrator must enforce a hard subprocess timeout ($1200\text{ seconds}$), kill the child process tree, run `git reset --hard`, log the timeout, and advance to the next repository.
* **NFR-03 (Git Safety):** The orchestrator must never execute `git push --force` or push commits directly to `main`, `master`, `dev`, or `production` branches.
* **NFR-04 (Zero Credential Leakage):** The agent prompt and pre-commit sanitizer must block any modification or commit that includes `.env` files, private keys, or tokens matching `ghp_*` / `sk-*`.

---

## 5. Success Metrics (KPIs)
1. **Daemon Uptime:** $\ge 99.5\%$ continuous autonomous uptime over 30-day rolling windows.
2. **PR Merge Acceptance Rate:** $\ge 80\%$ of opened PRs represent genuine, valid bug fixes accepted by the repository owner.
3. **Zero Duplicate/Conflicting PRs:** $0$ instances of two open bot PRs modifying the same lines of the same file simultaneously.
4. **Failover Recovery Time:** $< 5\text{ seconds}$ to detect an API rate limit, mark the key on cooldown, switch to the next key in the pool, and resume execution.