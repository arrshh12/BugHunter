---
title: AutoBugHunter 24/7
emoji: 🐞
colorFrom: indigo
colorTo: blue
sdk: docker
app_port: 7860
pinned: false
---

# AutoBugHunter 24/7 // Autonomous Engineering Daemon

Autonomous daemon running continuously to monitor repositories, isolate single bugs via static analysis pre-filters and autonomous agents, apply minimal atomic patches, verify test suites, and submit Pull Requests.

### Architecture & Key Features
- **Mission Control UI**: FastAPI dashboard + WebSocket live telemetry on port 7860.
- **State Persistence (Method A)**: Synchronizes SQLite snapshots with private GitHub state repository.
- **Pre-Filters & Scanners**: Ruff & Semgrep OSS pre-screening before invoking LLM agents.
- **PR Safety Guardrails**: Diff bounded to $\le 3$ files and $\le 150$ lines, zero credential leaks, collision guards.
