"""
Adversarial Deep Probe Test Suite for Milestone 1 Config Edge Cases.
Author: challenger_m1_3
Purpose: Thoroughly probe edge cases, corrupt payloads, mixed formats,
         and boundary conditions in src/config.py to verify complete resolution
         of all 6 Challenger 1 bugs and ensure zero residual failure modes.
"""

from pathlib import Path

import pytest

from src.config import Config, KeyConfig
from src.openhands_runner import OpenHandsRunner


@pytest.fixture
def empty_env_file(tmp_path: Path) -> Path:
    env_file = tmp_path / "empty.env"
    env_file.write_text("", encoding="utf-8")
    return env_file


class TestBug1ExhaustivePipeProbing:
    """Deep probe for Bug 1: Empty api_key in pipe formats."""

    @pytest.mark.parametrize("pipe_payload", [
        "https://api.scalemax.pro/v1|openai/gpt-6-luna|",
        "|||",
        "ScaleMax|https://api.scalemax.pro/v1|openai/gpt-6-luna|",
        "   |   |   |   ",
        "   |   |   ",
        "CustomProv|https://custom.org|custom-model|   ",
    ])
    def test_empty_api_key_pipes_fallback_to_openai_api_key(self, tmp_path: Path, empty_env_file: Path, pipe_payload: str):
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": pipe_payload,
            "OPENAI_API_KEY": "sk-fallback-confirmed",
        })
        assert len(config.llm_keys) == 1
        assert config.llm_keys[0].api_key == "sk-fallback-confirmed"
        assert config.openai_api_key == "sk-fallback-confirmed"

    def test_mixed_empty_and_valid_pipe_keys(self, tmp_path: Path, empty_env_file: Path):
        pool = "|||, https://api.scalemax.pro/v1||sk-valid-1, ||, ScaleMax|https://api.scalemax.pro/v1||sk-valid-2, |||"
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": pool,
            "OPENAI_API_KEY": "sk-should-not-be-used",
        })
        assert len(config.llm_keys) == 2
        assert config.llm_keys[0].api_key == "sk-valid-1"
        assert config.llm_keys[0].base_url == "https://api.scalemax.pro/v1"
        assert config.llm_keys[0].model == "openai/gpt-6-luna"
        assert config.llm_keys[1].api_key == "sk-valid-2"
        assert config.llm_keys[1].provider == "ScaleMax"
        assert config.llm_keys[1].model == "openai/gpt-6-luna"


class TestBug2ExhaustiveJsonArrayProbing:
    """Deep probe for Bug 2: JSON array handling and fall-through protection."""

    def test_json_mixed_strings_and_dicts(self, tmp_path: Path, empty_env_file: Path):
        json_payload = '[{"api_key": "sk-dict-key", "priority": 10}, "sk-str-key"]'
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": json_payload,
        })
        assert len(config.llm_keys) == 2
        assert config.llm_keys[0].api_key == "sk-dict-key"
        assert config.llm_keys[0].priority == 10
        assert config.llm_keys[1].api_key == "sk-str-key"
        assert config.llm_keys[1].base_url == "https://api.scalemax.pro/v1"
        assert config.llm_keys[1].model == "openai/gpt-6-luna"

    def test_json_array_all_empty_reaches_fallback(self, tmp_path: Path, empty_env_file: Path):
        json_payload = '[{"api_key": ""}, {"api_key": "   "}, "", "   "]'
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": json_payload,
            "OPENAI_API_KEY": "sk-fallback-from-json",
        })
        assert len(config.llm_keys) == 1
        assert config.llm_keys[0].api_key == "sk-fallback-from-json"

    def test_json_array_with_non_string_non_dict_elements(self, tmp_path: Path, empty_env_file: Path):
        json_payload = '[123, null, false, ["nested"], {"api_key": "sk-valid-json"}, "sk-valid-str"]'
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": json_payload,
        })
        assert len(config.llm_keys) == 2
        assert config.llm_keys[0].api_key == "sk-valid-json"
        assert config.llm_keys[1].api_key == "sk-valid-str"


class TestBug3ExhaustiveListOverrideProbing:
    """Deep probe for Bug 3: Programmatic list overrides."""

    def test_list_with_mixed_valid_types_and_empty_strings(self, tmp_path: Path, empty_env_file: Path):
        key_config_obj = KeyConfig("k-custom", "ScaleMax", "https://api.scalemax.pro/v1", "openai/gpt-6-luna", "sk-custom", "sk-c...stom", 1)
        list_payload = [
            "",
            "   ",
            key_config_obj,
            {"api_key": "sk-from-dict"},
            "sk-from-str",
            None,
            999,
        ]
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": list_payload,
        })
        assert len(config.llm_keys) == 3
        assert config.llm_keys[0] == key_config_obj
        assert config.llm_keys[1].api_key == "sk-from-dict"
        assert config.llm_keys[2].api_key == "sk-from-str"

    def test_list_all_empty_falls_back_to_openai_api_key(self, tmp_path: Path, empty_env_file: Path):
        list_payload = ["", "  ", {"api_key": ""}, {"api_key": "  "}]
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": list_payload,
            "OPENAI_API_KEY": "sk-list-fallback",
        })
        assert len(config.llm_keys) == 1
        assert config.llm_keys[0].api_key == "sk-list-fallback"


class TestBug4ExhaustivePriorityProbing:
    """Deep probe for Bug 4: Priority field variations."""

    @pytest.mark.parametrize("bad_priority", [
        "urgent",
        "high",
        "",
        "   ",
        None,
        {"nested": 1},
        [1, 2],
        3.14,
    ])
    def test_priority_in_dict_overrides_resilient(self, tmp_path: Path, empty_env_file: Path, bad_priority):
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": [{"api_key": "sk-safe-key", "priority": bad_priority}],
        })
        assert len(config.llm_keys) == 1
        assert config.llm_keys[0].api_key == "sk-safe-key"
        # In case bad priority is encountered, it safely defaults without throwing ValueError
        assert isinstance(config.llm_keys[0].priority, int)

    @pytest.mark.parametrize("bad_priority", [
        "urgent",
        "critical",
        "null",
        "",
    ])
    def test_priority_in_json_pool_resilient(self, tmp_path: Path, empty_env_file: Path, bad_priority):
        json_str = f'[{{"api_key": "sk-json-safe", "priority": "{bad_priority}"}}]'
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": json_str,
        })
        assert len(config.llm_keys) == 1
        assert config.llm_keys[0].api_key == "sk-json-safe"
        assert isinstance(config.llm_keys[0].priority, int)


class TestBug5ExhaustiveWhitespaceDefaultsProbing:
    """Deep probe for Bug 5: Whitespace in base URL and model defaults."""

    @pytest.mark.parametrize("ws_url", ["   ", "\t", "\r\n", "   \t\n  "])
    def test_whitespace_base_urls_fall_back(self, tmp_path: Path, empty_env_file: Path, ws_url: str):
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "OPENAI_API_BASE": ws_url,
            "OPENAI_BASE_URL": ws_url,
            "LLM_BASE_URL": ws_url,
            "OPENAI_API_KEY": "sk-probe",
        })
        assert config.openai_api_base == "https://api.scalemax.pro/v1"
        assert config.llm_keys[0].base_url == "https://api.scalemax.pro/v1"

    @pytest.mark.parametrize("ws_model", ["   ", "\t", "\r\n", "   \t\n  "])
    def test_whitespace_models_fall_back(self, tmp_path: Path, empty_env_file: Path, ws_model: str):
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_MODEL": ws_model,
            "OPENAI_MODEL": ws_model,
            "OPENAI_API_KEY": "sk-probe",
        })
        assert config.llm_model == "openai/gpt-6-luna"
        assert config.llm_keys[0].model == "openai/gpt-6-luna"

    def test_whitespace_keys_fall_back_to_sentinel(self, tmp_path: Path, empty_env_file: Path):
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": "   ",
            "OPENAI_API_KEY": "   ",
            "LLM_API_KEY": "   ",
        })
        assert len(config.llm_keys) == 1
        assert config.llm_keys[0].api_key == "NO_LLM_KEY_CONFIGURED"
        assert config.openai_api_key == ""


class TestBug6ExhaustiveEmptyModelPipesProbing:
    """Deep probe for Bug 6: Empty model in 3-part and 4-part pipe syntax."""

    def test_pipe_3_part_empty_model(self, tmp_path: Path, empty_env_file: Path):
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": "https://api.scalemax.pro/v1||sk-p3",
        })
        assert len(config.llm_keys) == 1
        assert config.llm_keys[0].base_url == "https://api.scalemax.pro/v1"
        assert config.llm_keys[0].model == "openai/gpt-6-luna"
        assert config.llm_keys[0].api_key == "sk-p3"

    def test_pipe_4_part_empty_model(self, tmp_path: Path, empty_env_file: Path):
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": "ScaleMax|https://api.scalemax.pro/v1||sk-p4",
        })
        assert len(config.llm_keys) == 1
        assert config.llm_keys[0].provider == "ScaleMax"
        assert config.llm_keys[0].base_url == "https://api.scalemax.pro/v1"
        assert config.llm_keys[0].model == "openai/gpt-6-luna"
        assert config.llm_keys[0].api_key == "sk-p4"

    def test_pipe_4_part_all_empty_except_key(self, tmp_path: Path, empty_env_file: Path):
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": "|||sk-p4-all-empty",
        })
        assert len(config.llm_keys) == 1
        assert config.llm_keys[0].provider == "ScaleMax"
        assert config.llm_keys[0].base_url == "https://api.scalemax.pro/v1"
        assert config.llm_keys[0].model == "openai/gpt-6-luna"
        assert config.llm_keys[0].api_key == "sk-p4-all-empty"


class TestSubprocessPropagationIntegration:
    """Verify that parsed KeyConfigs cleanly propagate into OpenHandsRunner."""

    def test_runner_receives_remediated_keys(self, tmp_path: Path, empty_env_file: Path):
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": "||sk-remediated-key",
        })
        runner = OpenHandsRunner(timeout_seconds=30)
        env = runner._build_subprocess_env(tmp_path, config.llm_keys[0])
        assert env["OPENAI_API_BASE"] == "https://api.scalemax.pro/v1"
        assert env["OPENAI_BASE_URL"] == "https://api.scalemax.pro/v1"
        assert env["OPENAI_API_KEY"] == "sk-remediated-key"
