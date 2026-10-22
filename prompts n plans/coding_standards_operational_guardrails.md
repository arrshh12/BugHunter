# Coding Standards, Constraints & Operational Guardrails (`rules.md`)

All AI agents operating during **Build-Time (in Antigravity)** and **Runtime (inside the 24/7 Docker Container)** must strictly obey the rules defined in this document.

---

## 1. Git & Repository Safety Rules (CRITICAL)

* **RULE-GIT-01 (No Direct Pushes to Default Branches):** The orchestrator and OpenHands agent must **NEVER** push commits directly to `main`, `master`, `develop`, or `production`. Every fix must be committed to an isolated branch matching `fix/auto-<repo_short>-<6_char_hex>`.
* **RULE-GIT-02 (No Force Pushing):** Never execute `git push --force` or `git push -f`.
* **RULE-GIT-03 (Atomic Diff Boundary):** A single Pull Request must fix **exactly one bug** and modify at most `MAX_FILES_PER_PR` (default $3$) files and at most $150$ changed lines unless explicitly overridden.
* **RULE-GIT-04 (No Cosmetic or Stylistic PRs):** Diffs where `git diff -w` (ignore whitespace) produces empty output, or changes consisting solely of comment edits, import reordering, or variable renaming without fixing a functional defect, must be rejected by `src/verifier.py` and rolled back.
* **RULE-GIT-05 (Clean Workspace Before & After):** Before and after every repository scan, the working tree must be cleaned of untracked build artifacts (`git reset --hard` and `git clean -fd`), and temporary orchestration files (`.skip_files.txt`, `.static_findings.json`, `.bug_fix_report.json`) must never be staged or committed.

---

## 2. Subprocess, Memory & Concurrency Rules (Oracle ARM64)

* **RULE-SYS-01 (Mandatory Subprocess Timeouts):** Every `subprocess.run` or `subprocess.Popen` call in the codebase must define an explicit `timeout` parameter:
  * Git / `gh` CLI commands: $\le 120\text{ seconds}$
  * Static analysis (`ruff`, `semgrep`): $\le 90\text{ seconds}$
  * OpenHands headless session: $\le 1200\text{ seconds}$ (`AGENT_TIMEOUT_SECONDS`)
* **RULE-SYS-02 (Process Tree Termination):** OpenHands spawns child shells and test runners. Always launch OpenHands with `start_new_session=True` (`os.setsid`) and terminate timeouts using `os.killpg(os.getpgid(proc.pid), signal.SIGKILL)` so orphan test runners never leak RAM on the $24\text{ GB}$ VM.
* **RULE-SYS-03 (SQLite Concurrency):** Because the FastAPI dashboard thread and the Orchestrator daemon thread access `/workspace/state/bughunter.sqlite` concurrently:
  * Always enable `PRAGMA journal_mode=WAL;` and `PRAGMA busy_timeout=10000;`.
  * Use context managers (`with self._get_conn() as conn:`) with `check_same_thread=False`.
* **RULE-SYS-04 (ARM64 Compatibility):** Do not include any `x86_64`-only binary downloads in the `Dockerfile`. Always use `$(dpkg --print-architecture)` when fetching `.deb` packages or CLI binaries so builds succeed natively on Oracle Ampere A1 (`arm64`) as well as `amd64`.

---

## 3. LLM API Key & Token Conservation Rules

* **RULE-LLM-01 (Zero Hardcoded Secrets):** Never hardcode GitHub PATs, ScaleMax keys, or OpenRouter keys in source code, unit tests, or Dockerfiles. Load all secrets exclusively from environment variables (`.env`).
* **RULE-LLM-02 (Masked Logging):** Whenever logging an API key or displaying it in the Mission Control UI (`/api/state`), mask all characters except the first 4 and last 4 (e.g., `sk-sc...9a2f`).
* **RULE-LLM-03 (Commit Deduplication First):** Never invoke an LLM on a repository whose current `HEAD` commit SHA is marked `fully_exhausted = 1` in SQLite, unless the user explicitly triggers a manual force-scan from the UI.
* **RULE-LLM-04 (Immediate Failover on Rate Limits):** If any LLM call or OpenHands session emits `429`, `RateLimitError`, `quota_exceeded`, `insufficient_quota`, `402 Payment Required`, or `503 Service Unavailable`:
  1. Immediately mark the active key as `COOLDOWN` (or `EXHAUSTED` for `402`).
  2. Rotate to the next available `HEALTHY` key in `LLM_KEYS_POOL`.
  3. If **all** keys in the pool are simultaneously in `COOLDOWN`, sleep for $60\text{ seconds}$ without crashing the daemon until the earliest key cooldown expires.

---

## 4. Python Code Quality Standards (For Antigravity Build Agents)

* **RULE-CODE-01 (Complete Implementations Only):** Never write placeholder comments like `# TODO: implement later` or `pass` in production modules. Every function must be fully implemented.
* **RULE-CODE-02 (Type Annotations & Docstrings):** All public functions and class methods in `src/` must include Python 3.12 type hints (`list[str]`, `dict[str, Any]`, `Path`, `Optional[...]`) and concise docstrings.
* **RULE-CODE-03 (Secret Leak Pre-Commit Guard):** `src/verifier.py` must scan every staged `git diff` against secret regexes (`ghp_[A-Za-z0-9_]+`, `github_pat_[A-Za-z0-9_]+`, `sk-[A-Za-z0-9_-]{20,}`, `AIza[0-9A-Za-z-_]{35}`, `-----BEGIN [A-Z ]+ PRIVATE KEY-----`) and abort the commit if any match is found.