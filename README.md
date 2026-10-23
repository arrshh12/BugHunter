---
title: AutoBugHunter 24/7
emoji: 🐞
colorFrom: indigo
colorTo: blue
sdk: docker
app_port: 7860
pinned: false
---

# AutoBugHunter 24/7

> **Autonomous Software Engineering Daemon**  
> Continuously monitors codebases, detects real bugs via static analysis pre-filters, executes headless AI agents for atomic fixes, validates test suites, and submits pull requests with strict safety bounds.

---

## ⚡ What is AutoBugHunter?

AutoBugHunter is a self-driving, containerized engineering daemon designed for 24/7 autonomous bug remediation. Instead of blindly letting LLMs roam entire repositories, AutoBugHunter enforces strict engineering discipline:

1. **Pre-Filters Before LLMs**: Scans code with Ruff and Semgrep OSS to surface concrete issues first.
2. **"One Bug = One PR" Rule**: Generates minimal atomic patches strictly bounded to $\le 3$ files and $\le 150$ lines.
3. **Automated Verification**: Runs project test suites to ensure zero regressions before touching Git branches.
4. **Resilient Key Routing**: Rotates multi-provider LLM pools with exponential backoff on `429/5xx` and circuit breakers.
5. **Zero-Trust Security**: Subprocess environment isolation, credential scrubbing in logs, and pre-commit sanitization.

---

## 🔄 How It Works

```
┌─────────────────┐      ┌─────────────────────────┐      ┌─────────────────────────┐
│  Target Repos   │ ───► │ Static Pre-Filter       │ ───► │ Resilient Key Router    │
│  (GitHub Sync)  │      │ (Ruff + Semgrep OSS)    │      │ (ScaleMax / OpenRouter) │
└─────────────────┘      └─────────────────────────┘      └────────────┬────────────┘
                                                                       │
┌─────────────────┐      ┌─────────────────────────┐                   ▼
│ Dispatch PR     │ ◄─── │ Verification Gate       │ ◄─── ┌─────────────────────────┐
│ (gh pr create)  │      │ (Diff Bounds, Tests,    │      │ OpenHands Headless      │
└────────┬────────┘      │  Secret Sanitization)   │      │ AI Agent (Atomic Fix)   │
         │               └─────────────────────────┘      └─────────────────────────┘
         ▼
┌──────────────────────────────────────────────────┐
│ Mission Control UI (FastAPI + Live WebSockets)   │
│ SQLite WAL Persistence & Audit Ledger            │
└──────────────────────────────────────────────────┘
```

1. **Repository Sync**: Clones/pulls target repositories and checks open PR collision guards.
2. **Static Pre-Scan**: Generates `.static_findings.json` targeting real code quality defects.
3. **Targeted Agent Execution**: Headless OpenHands AI agent attempts an isolated, minimal fix.
4. **Verification Gate**: Validates that changes do not exceed 3 files or 150 lines, removes temp artifacts, and verifies tests pass.
5. **Autonomous PR Dispatch**: Branches, commits, and opens a GitHub Pull Request via `gh` CLI.
6. **State & Telemetry**: Updates SQLite WAL database and streams live events to the web dashboard.

---

## 🚀 Quick Start

### 1. Clone & Configure
```bash
git clone https://github.com/bitxwolf/BugHunter.git
cd BugHunter
cp .env.example .env
```

Edit `.env` with your credentials:
```ini
GITHUB_TOKEN=your_github_personal_access_token
TARGET_REPOS=owner/repo1,owner/repo2
LLM_KEYS_POOL=https://api.scalemax.pro/v1|openai/gpt-6-luna|your_key_here
```

### 2. Run with Docker (Recommended)
```bash
docker compose up -d
```

### 3. Or Run Locally
```bash
pip install -r requirements.txt
python main.py
```
> Mission Control Dashboard is available at **http://localhost:7860** (or configured `DASHBOARD_PORT`).

---

## ⚙️ Configuration Reference

| Variable | Description | Default |
|---|---|---|
| `GITHUB_TOKEN` | GitHub PAT with repo & PR permissions | *Required* |
| `TARGET_REPOS` | Comma-separated list of `owner/repo` to monitor | `""` |
| `AUTO_DISCOVER_REPOS` | Automatically discover user repositories | `false` |
| `LLM_KEYS_POOL` | Pool format: `base_url\|model\|api_key,...` | *Required* |
| `MAX_FILES_PER_PR` | Hard file change limit per bug fix | `3` |
| `MAX_DIFF_LINES` | Hard line change limit per bug fix | `150` |
| `MAX_OPEN_PRS_PER_REPO`| Max concurrent bot PRs per repo | `7` |
| `SCAN_COOLDOWN_SECONDS`| Delay between repo scanning cycles | `60` |
| `DASHBOARD_PORT` | Mission Control Web UI port | `7860` |
| `DASHBOARD_API_KEY` | Optional auth token for remote dashboard access | `""` |

---

## 🛡️ Safety & Guardrails

- **Diff Limiter**: Rejects sprawling changes, hallucinations, or multi-feature drift.
- **Secret Redaction**: In-flight regex filters scrub tokens and private keys from logs, web streams, and process outputs.
- **Subprocess Isolation**: OpenHands agent runs in a sanitized environment without access to parent tokens.
- **Collision Prevention**: Skips files and repos with active open PRs to prevent duplicate work.

---

## 📁 Repository Layout

- `src/`
  - `orchestrator.py` — Master daemon loop & lifecycle control.
  - `static_scanner.py` — Ruff & Semgrep static analysis engine.
  - `openhands_runner.py` — Headless AI agent process runner.
  - `key_manager.py` — Multi-key pool rotation, health pings & cooldown circuits.
  - `verifier.py` — Safety gate enforcing diff boundaries and test suite integrity.
  - `git_manager.py` — Workspace syncing, branch isolation & `gh` integration.
  - `database.py` — SQLite WAL persistence for audit trails and state tracking.
  - `web_server.py` — FastAPI Mission Control server & WebSocket log broadcaster.
- `prompts/` — System prompts guiding OpenHands to perform atomic, verified fixes.
- `scripts/` — Deployment scripts, pre-commit hooks, and secret sanitizers.
- `tests/` — Comprehensive test suite covering security, concurrency, and verifier logic.

---

## 📄 License

MIT
