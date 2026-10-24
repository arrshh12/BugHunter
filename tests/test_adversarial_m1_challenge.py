"""
Adversarial Stress Test Harness for Milestone 1: Model Shift & ScaleMax Configuration.
Author: challenger_m1_1
Purpose: Stress-test Config.load, key parsing, pool syntax, fallback mechanisms,
         conflicting environment variables, and subprocess environment propagation.
"""

from pathlib import Path

import pytest

from src.config import Config, KeyConfig, mask_key
from src.openhands_runner import OpenHandsRunner


@pytest.fixture
def empty_env_file(tmp_path: Path) -> Path:
    """Isolated empty .env file."""
    env_file = tmp_path / "empty.env"
    env_file.write_text("", encoding="utf-8")
    return env_file


class TestAdversarialKeyParsingAndPools:
    """Stress-test pool parsing with malformed, edge-case, and weird inputs."""

    def test_pool_empty_tokens_and_trailing_delimiters(self, tmp_path: Path, empty_env_file: Path):
        """Verify handling of empty tokens, leading/trailing delimiters, and whitespace."""
        pool_str = "  ,, ; ; \n  \n,  "
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": pool_str,
            "OPENAI_API_KEY": "sk-fallback-from-empty-tokens",
        })
        # Empty tokens should yield no valid keys from pool, falling back to OPENAI_API_KEY
        assert len(config.llm_keys) == 1
        assert config.llm_keys[0].api_key == "sk-fallback-from-empty-tokens"

    def test_pool_extra_whitespace_around_tokens(self, tmp_path: Path, empty_env_file: Path):
        """Tokens with excessive whitespace should be trimmed cleanly."""
        pool_str = "   sk-key-alpha   ,   \n\t  sk-key-beta  \t "
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": pool_str,
        })
        assert len(config.llm_keys) == 2
        assert config.llm_keys[0].api_key == "sk-key-alpha"
        assert config.llm_keys[0].base_url == "https://api.scalemax.pro/v1"
        assert config.llm_keys[0].model == "openai/gpt-6-luna"
        assert config.llm_keys[1].api_key == "sk-key-beta"

    def test_pool_incomplete_pipes_2_parts(self, tmp_path: Path, empty_env_file: Path):
        """Entries with exactly 2 pipe parts are incomplete and should not crash."""
        pool_str = "https://api.scalemax.pro/v1|sk-only-two-parts, sk-valid-single-key"
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": pool_str,
        })
        # The 2-part entry is skipped, 1-part entry is parsed
        assert len(config.llm_keys) == 1
        assert config.llm_keys[0].api_key == "sk-valid-single-key"

    def test_pool_more_than_4_parts(self, tmp_path: Path, empty_env_file: Path):
        """Entries with >= 4 parts take first 4 as provider, base_url, model, api_key."""
        pool_str = "ScaleMax|https://api.scalemax.pro/v1|openai/gpt-6-luna|sk-4plus|extra1|extra2"
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": pool_str,
        })
        assert len(config.llm_keys) == 1
        k = config.llm_keys[0]
        assert k.provider == "ScaleMax"
        assert k.base_url == "https://api.scalemax.pro/v1"
        assert k.model == "openai/gpt-6-luna"
        assert k.api_key == "sk-4plus"

    def test_pool_empty_fields_in_pipe_entry(self, tmp_path: Path, empty_env_file: Path):
        """Entries like '||' or '||sk-key' should not cause unhandled crashes."""
        pool_str = "||sk-empty-base-model, https://api.scalemax.pro/v1|openai/gpt-6-luna|sk-valid"
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": pool_str,
        })
        assert len(config.llm_keys) == 2
        assert config.llm_keys[0].api_key == "sk-empty-base-model"
        assert config.llm_keys[1].api_key == "sk-valid"

    def test_pool_unicode_and_special_chars(self, tmp_path: Path, empty_env_file: Path):
        """Keys containing unicode symbols, emojis, and special chars."""
        pool_str = "sk-üñîçødé-🔑-测试-123456789"
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": pool_str,
        })
        assert len(config.llm_keys) == 1
        assert config.llm_keys[0].api_key == "sk-üñîçødé-🔑-测试-123456789"
        assert config.openai_api_key == "sk-üñîçødé-🔑-测试-123456789"

    def test_pool_quoted_keys(self, tmp_path: Path, empty_env_file: Path):
        """Keys surrounded by single or double quotes."""
        pool_str = '"sk-quoted-double", \'sk-quoted-single\''
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": pool_str,
        })
        assert len(config.llm_keys) == 2
        # Quotes are preserved as part of the raw key token
        assert "sk-quoted-double" in config.llm_keys[0].api_key
        assert "sk-quoted-single" in config.llm_keys[1].api_key


class TestAdversarialJsonPoolParsing:
    """Stress-test JSON format parsing in LLM_KEYS_POOL."""

    def test_json_single_dict_instead_of_array(self, tmp_path: Path, empty_env_file: Path):
        """A single JSON object instead of a list."""
        json_obj = '{"api_key": "sk-single-dict", "model": "gpt-6-luna"}'
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": json_obj,
        })
        assert len(config.llm_keys) == 1
        k = config.llm_keys[0]
        assert k.api_key == "sk-single-dict"
        assert k.model == "gpt-6-luna"
        assert k.base_url == "https://api.scalemax.pro/v1"

    def test_json_missing_fields_defaults_to_scalemax(self, tmp_path: Path, empty_env_file: Path):
        """JSON entries missing base_url or model default to ScaleMax .pro and gpt-6-luna."""
        json_arr = '[{"api_key": "sk-only-key"}]'
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": json_arr,
        })
        assert len(config.llm_keys) == 1
        k = config.llm_keys[0]
        assert k.api_key == "sk-only-key"
        assert k.base_url == "https://api.scalemax.pro/v1"
        assert k.model == "openai/gpt-6-luna"
        assert k.provider == "ScaleMax"

    def test_json_null_values(self, tmp_path: Path, empty_env_file: Path):
        """JSON entries containing null values for base_url or model."""
        json_arr = '[{"api_key": "sk-nulls", "base_url": null, "model": null}]'
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": json_arr,
        })
        assert len(config.llm_keys) == 1
        k = config.llm_keys[0]
        assert k.api_key == "sk-nulls"
        assert k.base_url == "https://api.scalemax.pro/v1"
        assert k.model == "openai/gpt-6-luna"

    def test_json_malformed_string_falls_back(self, tmp_path: Path, empty_env_file: Path):
        """Malformed JSON string starting with '[' falls back gracefully to delimiter parsing."""
        bad_json = '[{"api_key": "sk-unclosed-json'
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": bad_json,
        })
        # Does not crash; parsed as raw string token
        assert len(config.llm_keys) >= 1


class TestConflictingEnvironmentVariables:
    """Stress-test precedence between conflicting environment variable names."""

    def test_openai_api_base_precedence_over_llm_base_url(self, tmp_path: Path, empty_env_file: Path):
        """OPENAI_API_BASE should take precedence over LLM_BASE_URL and OPENAI_BASE_URL."""
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "OPENAI_API_BASE": "https://api.primary.com/v1",
            "OPENAI_BASE_URL": "https://api.secondary.com/v1",
            "LLM_BASE_URL": "https://api.tertiary.com/v1",
        })
        assert config.openai_api_base == "https://api.primary.com/v1"
        assert config.llm_keys[0].base_url == "https://api.primary.com/v1"

    def test_openai_base_url_precedence_over_llm_base_url(self, tmp_path: Path, empty_env_file: Path):
        """OPENAI_BASE_URL takes precedence over LLM_BASE_URL when OPENAI_API_BASE is absent."""
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "OPENAI_BASE_URL": "https://api.secondary.com/v1",
            "LLM_BASE_URL": "https://api.tertiary.com/v1",
        })
        assert config.openai_api_base == "https://api.secondary.com/v1"
        assert config.llm_keys[0].base_url == "https://api.secondary.com/v1"

    def test_llm_model_precedence_over_openai_model(self, tmp_path: Path, empty_env_file: Path):
        """LLM_MODEL takes precedence over OPENAI_MODEL."""
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_MODEL": "openai/gpt-6-luna",
            "OPENAI_MODEL": "openai/gpt-4o",
        })
        assert config.llm_model == "openai/gpt-6-luna"
        assert config.llm_keys[0].model == "openai/gpt-6-luna"

    def test_openai_api_key_precedence_over_llm_api_key(self, tmp_path: Path, empty_env_file: Path):
        """OPENAI_API_KEY takes precedence over LLM_API_KEY for dynamic extraction."""
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "OPENAI_API_KEY": "sk-primary-openai-key",
            "LLM_API_KEY": "sk-secondary-llm-key",
        })
        assert config.openai_api_key == "sk-primary-openai-key"
        assert config.llm_keys[0].api_key == "sk-primary-openai-key"


class TestOpenHandsRunnerSubprocessEnvStress:
    """Stress-test subprocess environment construction with anomalous keys."""

    def test_subprocess_env_empty_base_url_heals(self, tmp_path: Path):
        """Empty string base_url in KeyConfig heals to ScaleMax .pro."""
        runner = OpenHandsRunner(timeout_seconds=60)
        key = KeyConfig("k", "ScaleMax", "", "openai/gpt-6-luna", "sk-test", "sk-t...test", 1)
        sub_env = runner._build_subprocess_env(tmp_path, key)
        assert sub_env["OPENAI_API_BASE"] == "https://api.scalemax.pro/v1"
        assert sub_env["OPENAI_BASE_URL"] == "https://api.scalemax.pro/v1"

    def test_subprocess_env_all_string_values(self, tmp_path: Path):
        """All values in subprocess environment dict must be str, never None or int."""
        runner = OpenHandsRunner(timeout_seconds=60)
        key = KeyConfig("k", "ScaleMax", "https://api.scalemax.pro/v1", "openai/gpt-6-luna", "sk-test", "sk-t...test", 1)
        sub_env = runner._build_subprocess_env(tmp_path, key)
        for k, v in sub_env.items():
            assert isinstance(k, str), f"Env key {k} is not str: {type(k)}"
            assert isinstance(v, str), f"Env value for {k} is not str: {type(v)}"


class TestMaskKeyEdgeCases:
    """Stress-test mask_key on edge-case inputs."""

    def test_mask_key_none_and_empty(self):
        assert mask_key("") == "****"
        assert mask_key(None) == "****"

    def test_mask_key_boundary_lengths(self):
        assert mask_key("1234567") == "****"
        assert mask_key("12345678") == "****"
        assert mask_key("123456789") == "1234...6789"
        assert mask_key("1234567890") == "1234...7890"

    def test_mask_key_unicode(self):
        masked = mask_key("🔑🔑🔑🔑secret🔑🔑🔑🔑")
        assert len(masked) > 0
        assert "..." in masked


# ==============================================================================
# EMPIRICAL BUG REPRODUCERS (XFAIL: Confirmed Edge Case Flaws in Milestone 1)
# ==============================================================================

class TestEmpiricalBugReproducers:
    """
    Empirical tests demonstrating remediated bugs in Milestone 1 key parsing and fallback.
    All 6 bugs identified by Challenger 1 have been remediated in src/config.py.
    """

    def test_bug_1_empty_key_in_pipe_blocks_fallback(self, tmp_path: Path, empty_env_file: Path):
        """
        When LLM_KEYS_POOL has empty key (e.g. 'base_url|model|' or '|||'),
        it should be discarded as invalid and fall back to OPENAI_API_KEY.
        """
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": "https://api.scalemax.pro/v1|openai/gpt-6-luna|",
            "OPENAI_API_KEY": "sk-valid-fallback-key",
        })
        # Desired behavior: empty pipe key discarded, OPENAI_API_KEY used
        assert config.llm_keys[0].api_key == "sk-valid-fallback-key"
        assert config.openai_api_key == "sk-valid-fallback-key"

    def test_bug_2_json_array_of_string_keys_corrupted(self, tmp_path: Path, empty_env_file: Path):
        """
        When LLM_KEYS_POOL is a JSON array of strings: '[\"sk-key-1\", \"sk-key-2\"]',
        it should parse as two clean keys without '[' or ']' or quotes.
        """
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": '["sk-key-1", "sk-key-2"]',
        })
        assert len(config.llm_keys) == 2
        assert config.llm_keys[0].api_key == "sk-key-1"
        assert config.llm_keys[1].api_key == "sk-key-2"

    def test_bug_3_list_of_strings_in_overrides_discarded(self, tmp_path: Path, empty_env_file: Path):
        """
        When LLM_KEYS_POOL is passed as a Python list of strings in overrides: ['sk-key-1', 'sk-key-2'],
        it should be accepted as raw keys.
        """
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": ["sk-key-1", "sk-key-2"],
        })
        assert len(config.llm_keys) == 2
        assert config.llm_keys[0].api_key == "sk-key-1"
        assert config.llm_keys[1].api_key == "sk-key-2"

    def test_bug_4_non_int_priority_raises_unhandled_value_error(self, tmp_path: Path, empty_env_file: Path):
        """
        When LLM_KEYS_POOL has a dict with priority='high' or invalid int,
        Config.load should not raise unhandled ValueError.
        """
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": [{"api_key": "sk-valid", "priority": "high"}],
        })
        assert len(config.llm_keys) == 1
        assert config.llm_keys[0].api_key == "sk-valid"

    def test_bug_5_whitespace_base_url_bypasses_fallback(self, tmp_path: Path, empty_env_file: Path):
        """
        When OPENAI_API_BASE is whitespace '   ',
        it should strip to empty and fall back to 'https://api.scalemax.pro/v1'.
        """
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "OPENAI_API_BASE": "   ",
            "LLM_KEYS_POOL": "",
        })
        assert config.openai_api_base == "https://api.scalemax.pro/v1"
        assert config.llm_keys[0].base_url == "https://api.scalemax.pro/v1"

    def test_bug_6_empty_model_in_pipe_does_not_fallback(self, tmp_path: Path, empty_env_file: Path):
        """
        When 3-part pipe has empty model: 'https://api.scalemax.pro/v1||sk-key',
        it should fall back to default_model ('openai/gpt-6-luna').
        """
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": "https://api.scalemax.pro/v1||sk-key",
        })
        assert config.llm_keys[0].model == "openai/gpt-6-luna"
