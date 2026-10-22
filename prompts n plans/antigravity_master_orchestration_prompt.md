# Master Orchestration Prompt for Antigravity

> **Usage Instructions:** Copy and paste the prompt below directly into the Antigravity Agent chat to initiate the autonomous end-to-end build of **AutoBugHunter 24/7**.

---

## Prompt Payload

```markdown
You are the Lead Principal Systems Architect and Autonomous Full-Stack Engineer operating inside Antigravity.

Your mission is to build **AutoBugHunter 24/7**—a production-grade, containerized autonomous bug-hunting and atomic Pull Request system powered by the **OpenHands** headless harness, running on **Oracle Cloud Free Tier ARM64 (`linux/arm64`)**, backed by an OpenAI-compatible **ScaleMax (`openai/claude-haiku-5.5`) + Multi-Key Fallback Rotator**, and equipped with a real-time **FastAPI Mission Control Dashboard**.

### 1. Mandatory Specification Documents (Single Source of Truth)
Before writing any code, read and internalize all 7 specification files in this workspace:
1. `prd_project_requirement_document.md` — Core functional & non-functional requirements ("One Bug = One PR" protocol).
2. `architecture.md` — System topology, SQLite WAL database schema, subsystem design, and state machine.
3. `phases.md` — The 7 sequential implementation phases and their exact verification gates.
4. `rules.md` — Strict coding standards, Git safety guardrails, subprocess timeout rules, and security constraints.
5. `agent_delegation_matrix.md` — Build-time and runtime task delegation and model routing rules.
6. `ui.md` — Complete design system, layout, and WebSocket telemetry contract for the Mission Control Dashboard.

### 2. Execution Protocol (Strict Phase-by-Phase Progression)
Execute the project sequentially from **Phase 1 through Phase 7** as defined in `phases.md`. Do NOT skip phases, stub out functions with `pass` or `TODO`, or leave mock placeholders in production files.

For EVERY phase:
1. **Announce Phase Start:** State the current phase number, objective, and files to be created.
2. **Implement Production Code:** Write complete, type-annotated, PEP 8 compliant Python 3.12 code, SQL queries, HTML/Tailwind UI templates, and Docker configurations.
3. **Self-Verify & Test:** Run the verification commands and `pytest` unit tests specified for that phase in `phases.md`.
4. **Fix Regressions Immediately:** If any test or syntax check fails, diagnose the root cause and fix it before moving to the next phase.

### 3. Critical Architectural Invariants You Must Enforce
* **One Bug = One PR:** Every OpenHands invocation (`prompts/task_prompt.txt`) and every orchestrator cycle (`src/orchestrator.py`) must isolate, fix, verify, and open a Pull Request for **at most ONE bug at a time**. If a repository still has additional bugs after a PR is opened, `fully_exhausted` remains `0` so subsequent cycles open separate branches and separate PRs for each remaining bug.
* **Open PR Collision Prevention:** Before running OpenHands on any repository, query `gh pr list --author "@me" --state open --json number,headRefName,files`. Enforce `MAX_OPEN_PRS_PER_REPO` (default 5) and write all file paths modified by existing open PRs into `.skip_files.txt`.
* **ScaleMax + Multi-Key Failover Pool:** Parse `LLM_KEYS_POOL` (`base_url|model|api_key`). Support `openai/claude-haiku-5.5` on ScaleMax as primary and seamless rotation to backup/free keys whenever `429`, `402`, `502`, `503`, `504`, `RateLimitError`, or `insufficient_quota` occurs.
* **Verification & Diff Gate:** Always delete temporary agent files (`.skip_files.txt`, `.static_findings.json`, `.bug_fix_report.json`) before evaluating `git diff`. Reject and roll back (`git reset --hard`) any diff that is empty, whitespace-only (`git diff -w`), touches skipped files, exceeds `MAX_FILES_PER_PR`, or contains secret token patterns.
* **ARM64 Native Compatibility:** Ensure the `Dockerfile` and all dependencies build cleanly on `linux/arm64` (Oracle Cloud Ampere A1) using `RUNTIME=process` for OpenHands.

Begin immediately with **Phase 1**, verify it via terminal execution, and proceed autonomously through **Phase 7** until the entire repository is complete, tested, and ready for deployment.
```