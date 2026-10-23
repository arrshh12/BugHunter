"""
Unit tests for main.py auto-discovery and startup subsystem wiring.
"""

from unittest.mock import MagicMock, patch
from pathlib import Path
import pytest
from src.config import Config, KeyConfig


def test_main_auto_discover_invoked_when_empty_targets():
    """Verify git_manager.discover_or_load_repos is invoked when auto_discover_repos is True and target_repos is empty."""
    k1 = KeyConfig("k1", "ScaleMax", "https://api.sm.ai/v1", "claude-haiku-5.5", "sk-123", "sk...123", 1)
    mock_config = Config(
        github_token="ghp_test",
        target_repos=[],
        auto_discover_repos=True,
        llm_keys=[k1],
    )

    with patch("main.Config.load", return_value=mock_config), \
         patch("main.Database"), \
         patch("main.setup_logger") as mock_setup_logger, \
         patch("main.KeyManager"), \
         patch("main.GitManager") as mock_git_mgr_cls, \
         patch("main.StaticScanner"), \
         patch("main.OpenHandsRunner"), \
         patch("main.Verifier"), \
         patch("main.Orchestrator") as mock_orch_cls, \
         patch("main.create_app"), \
         patch("main.threading.Thread"), \
         patch("main.signal.signal"):

        mock_logger = MagicMock()
        mock_setup_logger.return_value = (MagicMock(), mock_logger, MagicMock())
        mock_gm = MagicMock()
        mock_gm.discover_or_load_repos.return_value = ["auto/discovered-repo-1", "auto/discovered-repo-2"]
        mock_git_mgr_cls.return_value = mock_gm

        mock_orch = MagicMock()
        mock_orch.stop_requested = True  # Stop main loop immediately
        mock_orch_cls.return_value = mock_orch

        from main import main
        main()

        mock_gm.discover_or_load_repos.assert_called_once_with("", auto_discover=True)
        assert mock_config.target_repos == ["auto/discovered-repo-1", "auto/discovered-repo-2"]


def test_main_auto_discover_skipped_when_target_repos_present():
    """Verify git_manager.discover_or_load_repos is NOT invoked when target_repos is already populated."""
    k1 = KeyConfig("k1", "ScaleMax", "https://api.sm.ai/v1", "claude-haiku-5.5", "sk-123", "sk...123", 1)
    mock_config = Config(
        github_token="ghp_test",
        target_repos=["manual/specified-repo"],
        auto_discover_repos=True,
        llm_keys=[k1],
    )

    with patch("main.Config.load", return_value=mock_config), \
         patch("main.Database"), \
         patch("main.setup_logger") as mock_setup_logger, \
         patch("main.KeyManager"), \
         patch("main.GitManager") as mock_git_mgr_cls, \
         patch("main.StaticScanner"), \
         patch("main.OpenHandsRunner"), \
         patch("main.Verifier"), \
         patch("main.Orchestrator") as mock_orch_cls, \
         patch("main.create_app"), \
         patch("main.threading.Thread"), \
         patch("main.signal.signal"):

        mock_logger = MagicMock()
        mock_setup_logger.return_value = (MagicMock(), mock_logger, MagicMock())
        mock_gm = MagicMock()
        mock_git_mgr_cls.return_value = mock_gm

        mock_orch = MagicMock()
        mock_orch.stop_requested = True
        mock_orch_cls.return_value = mock_orch

        from main import main
        main()

        mock_gm.discover_or_load_repos.assert_not_called()
        assert mock_config.target_repos == ["manual/specified-repo"]


def test_main_run_once_mode_executes_cycles_and_skips_web_server(monkeypatch):
    """Verify that passing --once executes orchestrator cycles without launching FastAPI web server thread."""
    k1 = KeyConfig("k1", "ScaleMax", "https://api.sm.ai/v1", "claude-haiku-5.5", "sk-123", "sk...123", 1)
    mock_config = Config(
        github_token="ghp_test",
        target_repos=["org/repo-1"],
        auto_discover_repos=False,
        llm_keys=[k1],
        state_repo="org/state-repo",
    )

    monkeypatch.setattr("sys.argv", ["main.py", "--once", "--max-cycles", "2"])

    with patch("main.Config.load", return_value=mock_config), \
         patch("main.Database"), \
         patch("main.setup_logger") as mock_setup_logger, \
         patch("main.KeyManager"), \
         patch("main.GitManager"), \
         patch("main.StaticScanner"), \
         patch("main.OpenHandsRunner"), \
         patch("main.Verifier"), \
         patch("main.Orchestrator") as mock_orch_cls, \
         patch("main.StateSyncer") as mock_syncer_cls, \
         patch("main.create_app") as mock_create_app, \
         patch("main.threading.Thread") as mock_thread:

        mock_logger = MagicMock()
        mock_setup_logger.return_value = (MagicMock(), mock_logger, MagicMock())

        mock_orch = MagicMock()
        # First cycle produces PR, second cycle reports all repos at max PRs
        mock_orch.run_cycle.side_effect = [
            [{"outcome": "PR_CREATED", "repo_slug": "org/repo-1"}],
            [{"outcome": "SKIPPED_MAX_PRS", "repo_slug": "org/repo-1"}],
        ]
        mock_orch_cls.return_value = mock_orch

        mock_syncer = MagicMock()
        mock_syncer_cls.return_value = mock_syncer

        from main import main
        main()

        # Web server thread should NOT have been started
        mock_create_app.assert_not_called()
        mock_thread.assert_not_called()

        # Both restore and backup should have been invoked
        mock_syncer.restore_state.assert_called_once()
        mock_syncer.backup_state.assert_called()

        # Orchestrator ran cycles
        assert mock_orch.run_cycle.call_count == 2


def test_main_backup_state_flag(monkeypatch):
    """Verify --backup-state invokes backup_state and exits without starting orchestrator or server."""
    k1 = KeyConfig("k1", "ScaleMax", "https://api.sm.ai/v1", "claude-haiku-5.5", "sk-123", "sk...123", 1)
    mock_config = Config(
        github_token="ghp_test",
        target_repos=["org/repo-1"],
        auto_discover_repos=False,
        llm_keys=[k1],
        state_repo="org/state-repo",
    )

    monkeypatch.setattr("sys.argv", ["main.py", "--backup-state"])

    with patch("main.Config.load", return_value=mock_config), \
         patch("main.setup_logger") as mock_setup_logger, \
         patch("main.StateSyncer") as mock_syncer_cls, \
         patch("main.Orchestrator") as mock_orch_cls, \
         patch("main.create_app") as mock_create_app:

        mock_logger = MagicMock()
        mock_setup_logger.return_value = (MagicMock(), mock_logger, MagicMock())
        mock_syncer = MagicMock()
        mock_syncer.backup_state.return_value = True
        mock_syncer_cls.return_value = mock_syncer

        from main import main
        res = main()

        assert res == 0
        mock_syncer.backup_state.assert_called_once()
        mock_orch_cls.assert_not_called()
        mock_create_app.assert_not_called()

