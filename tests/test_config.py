"""
Unit tests for src/config.py: Settings loading, environment variables, and key pool parsing.
"""

import json
from pathlib import Path
import pytest
from src.config import Config, KeyConfig, mask_key


def test_mask_key_various_lengths():
    """Verify mask_key utility handles empty, short, and long keys safely."""
    assert mask_key("") == "****"
    assert mask_key("short") == "****"
    assert mask_key("12345678") == "****"
    assert mask_key("123456789") == "1234...6789"
    assert mask_key("sk-scalemax-1234567890abcdef") == "sk-s...cdef"


def test_config_defaults(tmp_path: Path):
    """Verify default values and directory resolution."""
    config = Config.load(overrides={"workspace_dir": tmp_path})
    assert config.dashboard_port == 8080
    assert config.max_files_per_pr == 3
    assert config.max_diff_lines == 150
    assert config.scan_cooldown_seconds == 60
    assert config.repos_dir.exists()
    assert config.state_dir.exists()
    assert len(config.llm_keys) >= 1


def test_config_load_from_env_file(tmp_path: Path):
    """Verify loading from custom .env file."""
    env_file = tmp_path / ".env.test"
    env_content = """
GITHUB_TOKEN=ghp_test_token_1234567890
TARGET_REPOS=owner/repoA,owner/repoB
AUTO_DISCOVER_REPOS=true
MAX_OPEN_PRS_PER_REPO=7
MAX_FILES_PER_PR=2
MAX_DIFF_LINES=100
DASHBOARD_PORT=9000
LLM_KEYS_POOL=https://api.test.ai/v1|openai/test-model|sk-1234567890test
"""
    env_file.write_text(env_content, encoding="utf-8")

    config = Config.load(env_file=env_file, overrides={"workspace_dir": tmp_path})
    assert config.github_token == "ghp_test_token_1234567890"
    assert config.target_repos == ["owner/repoA", "owner/repoB"]
    assert config.auto_discover_repos is True
    assert config.max_open_prs_per_repo == 7
    assert config.max_files_per_pr == 2
    assert config.max_diff_lines == 100
    assert config.dashboard_port == 9000
    assert len(config.llm_keys) == 1
    assert config.llm_keys[0].base_url == "https://api.test.ai/v1"
    assert config.llm_keys[0].model == "openai/test-model"


def test_config_key_pool_pipe_formats(tmp_path: Path):
    """Verify parsing multiple pipe-separated keys (3-part and 4-part)."""
    pool_str = (
        "https://api.scalemax.ai/v1|openai/claude-haiku-5.5|sk-key1-1234567890;"
        "CustomProvider|https://api.openrouter.ai/v1|deepseek/v3|sk-key2-0987654321"
    )
    config = Config.load(overrides={"workspace_dir": tmp_path, "LLM_KEYS_POOL": pool_str})
    assert len(config.llm_keys) == 2
    k1 = config.llm_keys[0]
    assert k1.provider == "ScaleMax"
    assert k1.priority == 1
    assert k1.masked_key == "sk-k...7890"

    k2 = config.llm_keys[1]
    assert k2.provider == "CustomProvider"
    assert k2.priority == 2
    assert k2.masked_key == "sk-k...4321"


def test_config_key_pool_json_format(tmp_path: Path):
    """Verify parsing key pool from JSON array string."""
    json_keys = [
        {"id": "slot-1", "provider": "ScaleMax", "base_url": "https://api.sm.ai/v1", "model": "haiku", "api_key": "sk-111122223333", "priority": 1},
        {"id": "slot-2", "provider": "OpenAI", "base_url": "https://api.openai.com/v1", "model": "gpt-4o", "api_key": "sk-999988887777", "priority": 2}
    ]
    config = Config.load(overrides={"workspace_dir": tmp_path, "LLM_KEYS_POOL": json.dumps(json_keys)})
    assert len(config.llm_keys) == 2
    assert config.llm_keys[0].id == "slot-1"
    assert config.llm_keys[1].id == "slot-2"


def test_config_key_pool_list_override(tmp_path: Path):
    """Verify overriding key pool directly with KeyConfig objects."""
    keys = [
        KeyConfig("k1", "ScaleMax", "https://sm.ai", "model-1", "sk-123456789", "sk-1...6789", 1)
    ]
    config = Config.load(overrides={"workspace_dir": tmp_path, "LLM_KEYS_POOL": keys})
    assert len(config.llm_keys) == 1
    assert config.llm_keys[0].id == "k1"


def test_config_key_pool_comma_delimiter(tmp_path: Path):
    """Verify parsing key pool separated by commas."""
    pool_str = (
        "https://api.scalemax.ai/v1|openai/claude-haiku-5.5|sk-key1-1234567890,"
        "https://api.openrouter.ai/v1|deepseek/v3|sk-key2-0987654321"
    )
    config = Config.load(overrides={"workspace_dir": tmp_path, "LLM_KEYS_POOL": pool_str})
    assert len(config.llm_keys) == 2
    assert config.llm_keys[0].api_key == "sk-key1-1234567890"
    assert config.llm_keys[1].api_key == "sk-key2-0987654321"


def test_config_fallback_sentinel_key(tmp_path: Path):
    """Verify default fallback key uses non-secret sentinel string."""
    config = Config.load(overrides={"workspace_dir": tmp_path, "LLM_KEYS_POOL": ""})
    assert len(config.llm_keys) == 1
    fallback = config.llm_keys[0]
    assert fallback.api_key == "NO_LLM_KEY_CONFIGURED"
    assert fallback.masked_key == "NO_KEY"
    assert not fallback.api_key.startswith("sk-")

