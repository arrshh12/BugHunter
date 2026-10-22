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
