# Implementation Plan: AutoBugHunter 24/7 Remediation & QA Expansion

## Overview
A comprehensive, surgical remediation of 25 original operational bugs plus newly audited security vulnerabilities (token leakage, unauthenticated API access, ambient env leak, path traversal, CSWSH, fail-open remote auth, telemetry protection, container sandboxing, CSP) and QA coverage expansions.

## Architecture Decisions
- **Empty Tree Diff Base**: In `scripts/pre_commit_secret_sanitizer.py`, diff against empty tree `4b825dc642cb6eb9a060e54bf8d69288fbee4904` when unborn.
- **Secret-Free Git Auth**: In `src/git_manager.py`, pass token via `-c http.extraHeader` instead of embedding in git clone URL; scrub credentials from exceptions.
- **Subprocess Environment Whitelist**: In `src/openhands_runner.py`, construct explicit safe env whitelist omitting `GITHUB_TOKEN` and host credentials.
- **Fail-Closed Remote Auth**: In `src/web_server.py`, remote requests without `DASHBOARD_API_KEY` are rejected with HTTP 403 Forbidden. `/api/state` and `/ws/logs` are fully protected.
- **RingBuffer Secret Scrubbing**: In `src/logger.py`, automatically mask credentials matching known token regexes before storing, logging, or WebSocket broadcasting.
- **Repo Slug Validation**: Enforce strict regex `^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$` preventing path traversal and option injection.
- **Content-Security-Policy & Defensive Headers**: In `src/web_server.py`, attach CSP, `Referrer-Policy: strict-origin-when-cross-origin`, `X-Frame-Options: DENY`, and `X-Content-Type-Options: nosniff`.
- **Configurable Container Sandboxing**: In `src/openhands_runner.py` and `src/config.py`, support `OPENHANDS_RUNTIME=docker` vs `process`.

## Task List

### Phase 1: Security & Sanitizer Foundation
- [x] Task 1: Fix unborn `HEAD` bypass, quoted path detection, unquoted assignment regex in `scripts/pre_commit_secret_sanitizer.py`
- [x] Task 2: Fix escaped `\n` in `scripts/install_hooks.py` and sync `.gitignore`

### Phase 2: Process & Telemetry Concurrency
- [x] Task 3: Fix unbounded stdout iteration and recursive process cleanup in `src/openhands_runner.py`
- [x] Task 4: Fix FastAPI event-loop blocking in `src/web_server.py` and WebSocket loop registration in `src/logger.py`

### Phase 3: Configuration, Keys & Orchestrator Logic
- [x] Task 5: Fix comma delimiter in `src/config.py` and replace fallback key sentinel
- [x] Task 6: Fix `EXHAUSTED` key recovery in `src/key_manager.py`
- [x] Task 7: Fix repo auto-discovery in `main.py`, `.skip_files.txt` leak, and `--allow-empty` in `src/orchestrator.py`
- [x] Task 8: Fix PKCS#8 regex, changed lines calculation, and rename/quote parsing in `src/verifier.py`

### Phase 4: Packaging & Initial Verification
- [x] Task 9: Add `openhands-ai` and `semgrep` to `requirements.txt` and fix iptables rule
- [x] Task 10: Add regression tests for unborn `HEAD`, space-containing files, unquoted functions
- [x] Task 11: Run full test suite (188 tests passing)

### Phase 5: Security Hardening & Remediation
- [x] Task 12: Secret-free git clone and exception scrubbing in `src/git_manager.py`
- [x] Task 13: Automatic secret masking in `src/logger.py` ring buffer & broadcaster
- [x] Task 14: Subprocess environment whitelist in `src/openhands_runner.py`
- [x] Task 15: Configurable API authentication and security headers in `src/web_server.py` & `src/config.py`
- [x] Task 16: Path traversal and argument injection prevention in `src/web_server.py` and `src/git_manager.py`
- [x] Task 17: Origin header validation for `/ws/logs` in `src/web_server.py`

### Phase 6: QA Coverage & Extended Verification
- [x] Task 18: Add `tests/test_security_hooks.py` for `scripts/install_hooks.py` & `scripts/pre_commit_secret_sanitizer.py`
- [x] Task 19: Add boundary condition tests in `tests/test_verifier.py` (3 vs 4 files, 150 vs 151 lines)
- [x] Task 20: Add database concurrency stress test in `tests/test_database.py`
- [x] Task 21: Add security regression tests in `tests/test_web_server.py` and `tests/test_git_manager.py`
- [x] Task 22: Execute full regression test suite and verify 0 regressions across all tests (291 tests passing)

### Phase 7: Re-Audit Remediations & Production Lockdown
- [x] Task 23: Remote client 403 lockout when unconfigured & `/api/state` auth enforcement in `src/web_server.py`
- [x] Task 24: WebSocket token authentication & loopback restrictions in `src/web_server.py`
- [x] Task 25: Content-Security-Policy & Referrer-Policy headers in `src/web_server.py`
- [x] Task 26: API key management, localStorage caching, and request header forwarding in `src/templates/dashboard.html`
- [x] Task 27: OpenHands configurable container sandboxing (`OPENHANDS_RUNTIME=docker` vs `process`) in `src/openhands_runner.py` and `src/config.py`
- [x] Task 28: Synchronize `.env.example` and `docker-compose.yml` with `DASHBOARD_API_KEY` and loopback port binding
- [x] Task 29: Regression test verification across all 292 tests (100% pass rate)

## Risks and Mitigations
| Risk | Impact | Mitigation |
|------|--------|------------|
| Remote requests rejected without API key | Low | Fail-closed security design; loopback/testclient remains permitted without key |
| WebSocket connection without token | Low | Allowed for loopback clients; remote clients pass token via query parameter or header |
