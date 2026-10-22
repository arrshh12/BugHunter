# UI Specification: AutoBugHunter 24/7 Mission Control (`ui.md`)

## 1. Overview & Purpose
Although **AutoBugHunter 24/7** runs headlessly inside Docker on an Oracle Cloud ARM64 VM, operators need instant visibility into what the agent is scanning, which API key is active, live terminal output from OpenHands, and a feed of every atomic Pull Request created.

The **Mission Control Dashboard** is a fast, zero-build single-page web interface served directly by FastAPI on port `8080` (`src/templates/dashboard.html`) using **Tailwind CSS (CDN)**, **Lucide Icons**, and **native WebSockets + Fetch API**.

---

## 2. Visual Direction & Design System ("Cyber-Ops Dark")

* **Theme Polarity:** Intentional Dark Mode (Carbon & Slate surfaces with high-contrast status indicators).
* **Color Palette:**
  * **Primary Canvas Background:** `#090D16` (Deep Obsidian)
  * **Elevated Card / Panel Surface:** `#111827` (Slate 900) with `1px solid #1F2937` (Slate 800) borders
  * **Interactive Hover Surface:** `#1E293B` (Slate 800)
  * **Primary Text:** `#F9FAFB` (Gray 50)
  * **Secondary / Muted Text:** `#9CA3AF` (Gray 400)
  * **Accent Primary (Active Agent / Indigo):** `#6366F1` (Indigo 500)
  * **Semantic Success (Healthy Key / PR Created):** `#10B981` (Emerald 500)
  * **Semantic Warning (Cooldown / Max PRs Reached):** `#F59E0B` (Amber 500)
  * **Semantic Danger (Exhausted Key / Error):** `#EF4444` (Red 500)
* **Typography:**
  * **UI & Headings:** `'Inter'`, system-ui, sans-serif
  * **Code, SHAs, Branches, & Terminal Logs:** `'JetBrains Mono'`, `'Fira Code'`, monospace (`tabular-nums`)

---

## 3. Layout Architecture (12-Column Responsive Grid)

```text
+--------------------------------------------------------------------------------------------------+
| [Pulse Icon] AUTOBUGHUNTER 24/7 // MISSION CONTROL     [Daemon: RUNNING] [Pause/Resume] [Re-Scan]|
+--------------------------------------------------------------------------------------------------+
| [KPI 1: Repos Monitored] | [KPI 2: Atomic PRs Opened] | [KPI 3: Active LLM Key] | [KPI 4: Uptime]|
+--------------------------------------------------------------------------------------------------+
|                                                        |                                         |
|  LEFT / CENTER COLUMN (7 Cols on Desktop)              |  RIGHT COLUMN (5 Cols on Desktop)       |
|                                                        |                                         |
|  +--------------------------------------------------+  |  +-----------------------------------+  |
|  | 20-REPOSITORY STATUS MATRIX                      |  |  | LIVE OPENHANDS TERMINAL STREAM    |  |
|  | [Search/Filter Repos...]                         |  |  | (WebSocket /ws/logs)              |  |
|  | Repo | SHA | Status | Open PRs | Total Fixes |Act|  |  | > [SYNC] Cloning user/repo1...    |  |
|  | ...  | ... | ...    | 2 / 5    | 7 PRs       |[>]|  |  | > [AGENT] Running OpenHands...    |  |
|  +--------------------------------------------------+  |  +-----------------------------------+  |
|                                                        |                                         |
|  +--------------------------------------------------+  |  +-----------------------------------+  |
|  | ATOMIC PULL REQUEST FEED (1 Bug = 1 PR)          |  |  | MULTI-KEY LLM POOL & FAILOVER     |  |
|  | #42 fix: prevent NoneType crash in auth.py       |  |  | #1 ScaleMax Haiku 5.5  [HEALTHY]  |  |
|  |     repo1 | fix/auto-a91f02 | 4m ago | [View PR] |  |  | #2 ScaleMax Haiku 5.5  [COOLDOWN] |  |
|  +--------------------------------------------------+  |  +-----------------------------------+  |
+--------------------------------------------------------------------------------------------------+
```

---

## 4. Component Specifications

### 4.1 Top Command Header
* **Left:** Animated emerald/indigo status dot + Title `AutoBugHunter 24/7` + Badge `OpenHands ARM64 Daemon`.
* **Right Action Bar:**
  * **Status Pill:** Shows `RUNNING (Scanning <repo>)`, `SLEEPING (Cooldown)`, or `PAUSED`.
  * **Pause / Resume Toggle Button:** Calls `POST /api/control/toggle-pause`.
  * **Reset Exhausted Cache Button:** Calls `POST /api/control/reset-exhausted` (allows re-scanning all 20 repos even if no new commits were pushed).

### 4.2 Top KPI Strip (4 Metric Cards)
1. **Repositories Tracked:** e.g., `20` (with sub-label showing `14 Exhausted (Clean) | 6 Active`).
2. **Atomic PRs Created:** Total lifetime PRs opened across all repos + count in the last $24\text{ hours}$.
3. **Active LLM Engine:** Displays currently active key ID & model (`ScaleMax • openai/claude-haiku-5.5`) and pool ratio (`3 / 4 Keys Healthy`).
4. **Cycle & Guard Status:** Displays `MAX_OPEN_PRS_PER_REPO` ceiling (e.g., `Max 5 Open PRs/Repo`) and total scan cycles completed.

### 4.3 20-Repository Status Matrix Table
* **Columns:**
  1. `Repository`: Clickable link to GitHub repo (`owner/repo`).
  2. `HEAD SHA`: Monospace 7-character commit badge (`a1b2c3d`).
  3. `Audit State`:
     * `SCANNING`: Pulsing indigo badge with spinner.
     * `CLEAN (EXHAUSTED)`: Emerald badge indicating all bugs on this commit SHA have been patched.
     * `MAX PRs PAUSED`: Amber badge when open bot PRs $\ge 5$.
     * `IDLE / QUEUED`: Slate badge.
  4. `Open Bot PRs`: Progress pill showing `2 / 5`.
  5. `Lifetime Fixes`: Count of PRs created for this repo.
  6. `Action`: `"Scan Now"` button (`POST /api/control/scan-now/{owner}/{repo}`) to prioritize that repo immediately.

### 4.4 Live OpenHands Terminal Stream
* **Visuals:** Monospace terminal window (`bg-[#05080F]`, height `340px`, auto-scrolling with a `"Lock Scroll"` toggle).
* **Behavior:** Connects to `ws://<host>:8080/ws/logs`. Color-codes log prefixes automatically:
  * `[PR CREATED]` $\to$ Emerald bold (`#10B981`)
  * `[KEY ROTATION]` / `[WARN]` $\to$ Amber (`#F59E0B`)
  * `[ERROR]` $\to$ Red (`#EF4444`)
  * `[AGENT]` / `[OPENHANDS]` $\to$ Indigo (`#818CF8`)

### 4.5 Multi-Key LLM Pool & Circuit Breaker Panel
* Lists every key configured in `LLM_KEYS_POOL` with:
  * Priority index (`#1`, `#2`, `#3`)
  * Provider & Model name (`openai/claude-haiku-5.5`)
  * Masked API key (`sk-sc...4f9a`)
  * Circuit State badge (`HEALTHY`, `COOLDOWN (114s left)`, or `EXHAUSTED`)
  * Success / Use counter (`42 / 43 runs`).

### 4.6 Atomic Pull Request Feed
* Chronological feed of every Pull Request created by the daemon.
* Each row shows: PR Title (`fix: ...`), Repository badge, Target File modified (`src/auth/token.py`), Branch name (`fix/auto-8f31c2`), Key ID used, Timestamp, and an external link button (`Open PR ↗`).

---

## 5. Backend-to-UI API Contract (`src/web_server.py`)

* **`GET /api/state`** returns:
  ```json
  {
    "daemon": {
      "paused": false,
      "current_repo": "owner/repo-3",
      "current_stage": "OPENHANDS_EXECUTION",
      "uptime_seconds": 84320
    },
    "kpis": {
      "total_repos": 20,
      "exhausted_repos": 12,
      "total_prs_created": 19,
      "healthy_keys": 3,
      "total_keys": 4
    },
    "repositories": [...],
    "keys": [...],
    "recent_prs": [...]
  }
  ```
* The frontend polls `GET /api/state` every $3\text{ seconds}$ for table/KPI updates while maintaining a persistent WebSocket connection to `/ws/logs` for sub-second terminal streaming.