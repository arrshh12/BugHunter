# AutoBugHunter 24/7 — Test Infrastructure Specification (`TEST_INFRA.md`)

## 1. Test Philosophy & Principles

The AutoBugHunter 24/7 test infrastructure follows an **opaque-box, requirement-driven testing philosophy**. The test suite is authored strictly against authoritative system requirements, architectural invariants, interface contracts, and operational guardrails rather than internal implementation details.

### Core Principles

1. **Opaque-Box Specification Verification**:
   - Tests assert observable behavior: exit codes, database state transitions, HTTP API payloads, Git commit and branch properties, sanitized diffs, and WebSocket telemetry streams.
   - Tests do not rely on private methods or internal state variables, ensuring zero refactoring fragility.

2. **Authoritative Expected Output Derivation**:
   - Expected outputs are derived mathematically (e.g. exponential cooldown formula $T = \min(3600, 60 \times 2^{F-1})$), from explicit protocol specifications (HTTP RFCs for 429/402/5xx), Git specifications (`git diff -w`, `git reset --hard`), or regex patterns for secret detection.
   - Non-deterministic values (such as ISO timestamps, generated branch UUIDs, process IDs, and temporary directory paths) are validated via structural pattern matching and regex invariants.

3. **Progressive Testability & Self-Containment**:
   - Each test is fully self-contained: it initializes its own isolated workspace, temporary SQLite database, and mock interfaces.
   - Tests do not require live external network calls, real GitHub API tokens, or actual cloud compute instances. All external boundaries (`gh` CLI, OpenAI-compatible ScaleMax endpoints, OpenHands headless CLI) are intercepted via high-fidelity test fixtures in `tests/e2e/conftest.py`.

4. **Zero Production Secret Leakage**:
   - All secret detection rules (`ghp_*`, `github_pat_*`, `sk-*`, `AIza*`, `BEGIN .* PRIVATE KEY`) are rigorously tested with simulated, synthetic tokens without embedding genuine production secrets in the repository.

---

## 2. Feature Inventory & Test Tier Mapping

The test suite covers all requirements across four progressive tiers:

| Requirement / Spec | Core Feature | Tier 1 (Features) | Tier 2 (Boundaries) | Tier 3 (Combinations) | Tier 4 (Workflows) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **R1. Open-Source Component Leverage** | Headless OpenHands, Ruff/Semgrep, LiteLLM/ScaleMax, GitHub `gh` CLI, FastAPI dashboard | `test_tier1_features.py` | `test_tier2_boundaries.py` | `test_tier3_combinations.py` | `test_tier4_scenarios.py` |
| **R2. Core Persistence & Resilient Routing** | SQLite WAL engine (4 tables), ring buffer logger (500 lines), multi-key circuit breaker | `test_tier1_features.py` | `test_tier2_boundaries.py` | `test_tier3_combinations.py` | `test_tier4_scenarios.py` |
| **R3. Git Workspace & Pre-Filter** | Git reset/sync, bot PR collision guard, `.skip_files.txt`, static pre-filter, process-tree isolation | `test_tier1_features.py` | `test_tier2_boundaries.py` | `test_tier3_combinations.py` | `test_tier4_scenarios.py` |
| **R4. Verification Gate & PR Dispatcher** | Atomic diff bounds ($\le 3$ files, $\le 150$ lines), non-empty `git diff -w`, secret sanitizer, `gh pr create` | `test_tier1_features.py` | `test_tier2_boundaries.py` | `test_tier3_combinations.py` | `test_tier4_scenarios.py` |
| **R5. Mission Control UI & Telemetry** | FastAPI endpoints (`/`, `/api/state`, `/api/control/*`), `/ws/logs` live streaming, dark theme | `test_tier1_features.py` | `test_tier2_boundaries.py` | `test_tier3_combinations.py` | `test_tier4_scenarios.py` |

---

## 3. Test Architecture & Runner Invocation

### Directory Layout

```
c:\antigravity\bughunter\
├── TEST_INFRA.md                          # Test infrastructure specification & mapping
├── TEST_READY.md                          # Test suite execution instructions & status
└── tests/
    └── e2e/
        ├── __init__.py
        ├── conftest.py                    # Mock fixtures, harness, environment isolation
        ├── test_tier1_features.py         # Tier 1: Functional coverage across R1–R5 (>= 5 per feature)
        ├── test_tier2_boundaries.py       # Tier 2: Boundary & stress conditions (>= 5 per domain)
        ├── test_tier3_combinations.py     # Tier 3: Cross-feature interactions & pairwise states
        └── test_tier4_scenarios.py        # Tier 4: Realistic end-to-end hunting workflow simulations
```

### Test Runner Commands

```bash
# Execute entire E2E test suite with verbose output
pytest tests/e2e/ -v

# Run individual test tiers
pytest tests/e2e/test_tier1_features.py -v
pytest tests/e2e/test_tier2_boundaries.py -v
pytest tests/e2e/test_tier3_combinations.py -v
pytest tests/e2e/test_tier4_scenarios.py -v

# Run with fail-fast on first failure
pytest tests/e2e/ -x -v

# Run with summary of test durations
pytest tests/e2e/ --durations=10
```

---

## 4. Test Fixtures & Mocking Architecture (`conftest.py`)

The test architecture relies on self-contained, isolated fixtures defined in `tests/e2e/conftest.py`:

1. **`temp_git_workspace`**:
   - Creates a temporary local Git repository initialized with `git init`.
   - Configures local test author identity (`git config user.name "Test Bot"`).
   - Generates initial commit on default branch (`main`).
   - Provides helper utilities for creating mock bug branches, unstaged files, and tracked diffs.

2. **`mock_db`**:
   - Initializes an isolated SQLite database in a temporary directory with `PRAGMA journal_mode=WAL` and `PRAGMA busy_timeout=10000`.
   - Automatically executes the 4 core schema tables (`repositories`, `pull_requests`, `api_key_status`, `scan_logs`) and indexes.
   - Cleans up and closes all connections at teardown.

3. **`mock_gh_cli`**:
   - Intercepts subprocess calls to `gh`.
   - Supports configurable responses for `gh pr list --author "@me"` and `gh pr create`.
   - Records all issued CLI invocations for assertion verification.

4. **`mock_llm_server`**:
   - Intercepts HTTP requests to the OpenAI-compatible ScaleMax `/v1/chat/completions` endpoint.
   - Simulates 200 OK responses, 429 Too Many Requests (rate-limit), 402 Payment Required (insufficient quota), and 503 Service Unavailable.

5. **`mock_openhands_runner`**:
   - Simulates the execution of headless OpenHands CLI (`openhands --headless`).
   - Emits realistic log lines into the log callback / ring buffer.
   - Generates valid `.bug_fix_report.json` artifacts or simulates timeout hangs and process tree signals.

6. **`fastapi_test_client`**:
   - Uses `starlette.testclient.TestClient` to test FastAPI routes (`/api/state`, `/api/control/*`, `/ws/logs`) without opening physical TCP ports.

7. **`contract_harness`**:
   - Provides a contract-compliant bridge that links test calls either to `src` modules when loaded or to the authoritative interface contracts defined in `PROJECT.md`.

---

## 5. Coverage Thresholds & Quality Gates

| Test Tier | Focus Area | Minimum Coverage Target | Actual Suite Target | Quality Gate |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1** | Core Functional Requirements (R1–R5) | $\ge 5$ test cases per feature category | $\ge 25$ test cases | 100% Pass |
| **Tier 2** | Boundary Values, Max Bounds, Secret Leaks | $\ge 5$ test cases per boundary domain | $\ge 25$ test cases | 100% Pass |
| **Tier 3** | Cross-Feature Interactions & Pairwise | $\ge 7$ pairwise interaction cases | $\ge 7$ test cases | 100% Pass |
| **Tier 4** | End-to-End Workflow Simulations | $\ge 5$ realistic workflow scenarios | $\ge 6$ test cases | 100% Pass |
| **Total** | **Comprehensive E2E Suite** | **$\ge 60$ test cases** | **$\ge 63$ test cases** | **100% Pass** |
