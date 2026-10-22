# Task Checklist: AutoBugHunter 24/7 Bug Fixes & Security Hardening

## Phase 1: Security & Sanitizer Foundation
- [x] Task 1: Fix unborn HEAD, quoted paths, unquoted assignments, and duplicate regex in `scripts/pre_commit_secret_sanitizer.py`
- [x] Task 2: Fix literal `\n` in `scripts/install_hooks.py` and sync `.gitignore`

## Phase 2: Process & Telemetry Concurrency
- [x] Task 3: Fix unbounded stdout reading and recursive process termination in `src/openhands_runner.py`
- [x] Task 4: Fix non-blocking scan queuing in `src/web_server.py` and WebSocket event loop registration in `src/logger.py`

## Phase 3: Configuration, Keys & Orchestrator Logic
- [x] Task 5: Fix comma delimiter, fallback key sentinel, and dotenv parsing in `src/config.py`
- [x] Task 6: Fix `EXHAUSTED` key recovery in `src/key_manager.py`
- [x] Task 7: Fix repo discovery in `main.py`, `.skip_files.txt` leak, and `--allow-empty` in `src/orchestrator.py`
- [x] Task 8: Fix PKCS#8 regex, diff line counting, and git status parser in `src/verifier.py`

## Phase 4: Packaging & Regression Verification
- [x] Task 9: Add container dependencies to `requirements.txt` and fix iptables index in `scripts/deploy_oracle_arm64.sh`
- [x] Task 10: Add regression tests for newborn repo commit, files with spaces, unquoted functions, and key recovery
- [x] Task 11: Run full pytest suite across all tiers and unit tests (188 tests passed)

## Phase 5: Security Hardening & Remediation
- [x] Task 12: Secret-free git clone and exception scrubbing in `src/git_manager.py`
- [x] Task 13: Automatic secret masking in `src/logger.py` ring buffer & broadcaster
- [x] Task 14: Subprocess environment whitelist in `src/openhands_runner.py`
- [x] Task 15: Configurable API authentication and security headers in `src/web_server.py` & `src/config.py`
- [x] Task 16: Path traversal and argument injection prevention in `src/web_server.py` and `src/git_manager.py`
- [x] Task 17: Origin header validation for `/ws/logs` in `src/web_server.py`

## Phase 6: QA Coverage & Extended Verification
- [x] Task 18: Add `tests/test_security_hooks.py` for `scripts/install_hooks.py` & `scripts/pre_commit_secret_sanitizer.py`
- [x] Task 19: Add boundary condition tests in `tests/test_verifier.py` (3 vs 4 files, 150 vs 151 lines)
- [x] Task 20: Add database concurrency stress test in `tests/test_database.py`
- [x] Task 21: Add security regression tests in `tests/test_web_server.py` and `tests/test_git_manager.py`
- [x] Task 22: Execute full regression test suite and verify 0 regressions across all tests (291 tests passed)

## Phase 7: Re-Audit Remediations & Production Lockdown
- [x] Task 23: Remote client 403 lockout when unconfigured & `/api/state` auth enforcement in `src/web_server.py`
- [x] Task 24: WebSocket token authentication & loopback restrictions in `src/web_server.py`
- [x] Task 25: Content-Security-Policy & Referrer-Policy headers in `src/web_server.py`
- [x] Task 26: API key management, localStorage caching, and request header forwarding in `src/templates/dashboard.html`
- [x] Task 27: OpenHands configurable container sandboxing (`OPENHANDS_RUNTIME=docker` vs `process`) in `src/openhands_runner.py` and `src/config.py`
- [x] Task 28: Synchronize `.env.example` and `docker-compose.yml` with `DASHBOARD_API_KEY` and loopback port binding
- [x] Task 29: Regression test verification across all 292 tests (100% pass rate)
