"""
Main Application Entrypoint for AutoBugHunter 24/7.
Spawns FastAPI Mission Control in a background daemon thread and Orchestrator on the main thread.
"""

from __future__ import annotations

import logging
import signal
import sys
import threading
import time
from pathlib import Path

import uvicorn

from src.config import Config
from src.database import Database
from src.git_manager import GitManager
from src.key_manager import KeyManager
from src.logger import setup_logger
from src.openhands_runner import OpenHandsRunner
from src.orchestrator import Orchestrator
from src.static_scanner import StaticScanner
from src.verifier import Verifier
from src.web_server import create_app


def start_web_server(app, host: str, port: int):
    """Run uvicorn ASGI server in background thread."""
    uvicorn.run(app, host=host, port=port, log_level="warning")


def main():
    print("=" * 60)
    print("  AutoBugHunter 24/7 // Autonomous Engineering Daemon")
    print("=" * 60)

    # 1. Load configuration
    config = Config.load()
    print(f"[*] Workspace: {config.workspace_dir}")
    print(f"[*] Monitored Repositories: {len(config.target_repos)}")
    print(f"[*] LLM Keys Configured: {len(config.llm_keys)}")

    # 2. Setup database
    database = Database(config.db_path)

    # 3. Setup logger
    py_logger, ring_logger, broadcaster = setup_logger(
        name="autobughunter",
        log_file=config.log_file_path,
        capacity=config.log_ring_buffer_size,
    )
    ring_logger.log("INFO", "AutoBugHunter daemon initialization started.")

    # 4. Setup subsystems
    key_manager = KeyManager(config, database)
    git_manager = GitManager(config.workspace_dir, config.github_token, config.max_open_prs_per_repo)
    git_manager.configure_git_and_gh()

    if config.auto_discover_repos and not config.target_repos:
        discovered = git_manager.discover_or_load_repos("", auto_discover=True)
        config.target_repos = discovered
        ring_logger.log("INFO", f"Auto-discovered {len(discovered)} active repositories.")

    static_scanner = StaticScanner(config.static_scan_timeout_seconds)
    openhands_runner = OpenHandsRunner(config.agent_timeout_seconds)
    verifier = Verifier()

    orchestrator = Orchestrator(
        config=config,
        database=database,
        key_manager=key_manager,
        git_manager=git_manager,
        static_scanner=static_scanner,
        openhands_runner=openhands_runner,
        verifier=verifier,
        logger=ring_logger,
    )

    # 5. Initialize Web Server
    app = create_app(orchestrator, broadcaster)
    web_thread = threading.Thread(
        target=start_web_server,
        args=(app, config.dashboard_host, config.dashboard_port),
        daemon=True,
    )
    web_thread.start()
    ring_logger.log("INFO", f"Mission Control UI running on http://{config.dashboard_host}:{config.dashboard_port}")

    # 6. Signal handling
    def shutdown_handler(signum, frame):
        ring_logger.log("WARN", "Shutdown signal received. Stopping daemon loop cleanly...")
        orchestrator.stop()
        sys.exit(0)

    try:
        signal.signal(signal.SIGINT, shutdown_handler)
        signal.signal(signal.SIGTERM, shutdown_handler)
    except Exception:
        pass

    # 7. Main Orchestrator Loop
    ring_logger.log("INFO", "Starting 24/7 continuous autonomous scanning cycle...")
    try:
        while not orchestrator.stop_requested:
            try:
                orchestrator.run_cycle()
            except Exception as e:
                ring_logger.log("ERROR", f"Unhandled exception in daemon scan cycle: {e}")
            time.sleep(config.scan_cooldown_seconds)
    except KeyboardInterrupt:
        shutdown_handler(None, None)


if __name__ == "__main__":
    main()
