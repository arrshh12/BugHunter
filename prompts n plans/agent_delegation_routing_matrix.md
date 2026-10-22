# Agent Delegation & Model Routing Matrix

This document defines two distinct delegation matrices:
1. **Build-Time Agent Delegation:** How Antigravity sub-agents divide responsibilities while building the project across Phases 1–7.
2. **Runtime Agent & Model Delegation:** How the running 24/7 Docker container delegates detection, patching, verification, and API key failover across deterministic tools and LLM endpoints.

---

## Part 1: Build-Time Agent Delegation (Inside Antigravity IDE)

| Agent Role | Assigned Phases | Core Responsibilities | Primary Files Owned |
| :--- | :--- | :--- | :--- |
| **1. Lead Systems Architect** | All Phases (1–7) | Coordinates phase progression, enforces `rules.md`, reviews cross-module interfaces, and signs off on phase verification gates. | `main.py`, `src/config.py`, `README.md` |
| **2. State & Resilience Engineer** | Phase 1 & Phase 2 | Builds the thread-safe SQLite WAL database engine, ring-buffer logger, and the Multi-Key LLM Pool Manager with exponential backoff circuit breaking. | `src/database.py`, `src/logger.py`, `src/key_manager.py`, `tests/test_key_manager.py` |
| **3. Git & Harness Integration Engineer** | Phase 3, Phase 4 & Phase 5 | Implements Git workspace syncing, `gh` CLI collision checks, Semgrep/Ruff static pre-filtering, OpenHands headless subprocess management, diff sanitization, and atomic PR creation. | `src/git_manager.py`, `src/static_scanner.py`, `src/openhands_runner.py`, `src/verifier.py`, `src/orchestrator.py`, `prompts/task_prompt.txt` |
| **4. Control Plane & UI Engineer** | Phase 6 | Builds the FastAPI backend API, live WebSocket log broadcaster, and the cyber-ops Mission Control Dashboard matching `ui.md`. | `src/web_server.py`, `src/templates/dashboard.html` |
| **5. DevOps & QA Verification Agent** | Phase 7 & Continuous Testing | Authors the `linux/arm64` Dockerfile, `docker-compose.yml`, Oracle Cloud setup script, and executes `pytest` suites after every phase. | `Dockerfile`, `docker-compose.yml`, `scripts/deploy_oracle_arm64.sh`, `tests/test_*.py` |

---

## Part 2: Runtime Task Delegation (Inside the 24/7 Container)

To maximize precision and prevent burning LLM tokens on trivial checks, runtime execution is divided into **4 specialized tiers**:

```text
[Tier 0: Deterministic Git & PR Guard]  --->  0 Tokens  ---> Filters unchanged SHA & open PR files
                 |
                 v
[Tier 1: Static AST & Security Scanner] --->  0 Tokens  ---> Ruff + Semgrep generate .static_findings.json
                 |
                 v
[Tier 2: OpenHands Autonomous Engineer] --->  LLM Pool  ---> Diagnoses 1 bug, writes minimal patch, runs tests
                 |
                 v
[Tier 3: Deterministic Diff Verifier]   --->  0 Tokens  ---> Validates diff bounds, blocks secrets, opens PR
```

### Runtime Tier Responsibilities

| Runtime Tier | Actor / Tool | Token Cost | Input | Output / Gate Decision |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 0: State & Collision Gate** | `src/git_manager.py` + SQLite + `gh pr list` | $0$ tokens | Target Repo Slug | Skips repo if `open_prs >= 5` or `HEAD` SHA is already `fully_exhausted`. Generates `.skip_files.txt`. |
| **Tier 1: Static Pre-Scanner** | `src/static_scanner.py` (`ruff`, `semgrep`) | $0$ tokens | Cloned Repo (excluding `.skip_files.txt`) | Produces `.static_findings.json` with exact file paths, line numbers, and rule violations. |
| **Tier 2: Autonomous Patch Agent** | `openhands --headless` + Active LLM Key | Dynamic (ScaleMax / Fallback Pool) | `task_prompt.txt` + `.static_findings.json` + `.skip_files.txt` | Applies minimal fix for **1 bug**, runs repo tests, outputs `.bug_fix_report.json`. |
| **Tier 3: Verification & PR Dispatcher** | `src/verifier.py` + `src/orchestrator.py` | $0$ tokens | Modified Git Working Tree + `.bug_fix_report.json` | Verifies diff is non-empty, touches $\le 3$ allowed files, contains zero secrets, pushes `fix/auto-*`, and runs `gh pr create`. |

---

## Part 3: Multi-Key LLM Failover Routing Matrix (`LLM_KEYS_POOL`)

The `KeyManager` routes OpenHands sessions across your configured keys in strict priority order:

| Priority Slot | Provider / Endpoint | Model Identifier | Trigger to Failover to Next Slot | Cooldown / Recovery Policy |
| :--- | :--- | :--- | :--- | :--- |
| **Slot 1 (Primary)** | ScaleMax OpenAI-Compatible API (`https://api.scalemax.ai/v1`) | `openai/claude-haiku-5.5` | `HTTP 429` (Rate Limit), `HTTP 402` (Quota), or $3\times$ consecutive timeout (`502/504`). | Exponential backoff: $60\text{s} \to 120\text{s} \to 240\text{s}$ (max $3600\text{s}$). Auto-recovers to Slot 1 once cooldown expires. |
| **Slot 2..N (Secondary ScaleMax Keys)** | ScaleMax OpenAI-Compatible API (`https://api.scalemax.ai/v1`) | `openai/claude-haiku-5.5` | Same as Slot 1. | Immediately takes over mid-cycle when Slot 1 enters `COOLDOWN`. |
| **Slot N+1..M (Free Tier Fallbacks)** | OpenRouter / Gemini / Groq OpenAI-Compatible Endpoints | `openai/deepseek/deepseek-chat:free`, `openai/qwen/qwen-2.5-coder-32b-instruct:free`, etc. | Activated when all primary ScaleMax keys are in `COOLDOWN` or `EXHAUSTED`. | Keeps the 24/7 container productive at $0$ cost while primary keys recover their rate-limit windows. |