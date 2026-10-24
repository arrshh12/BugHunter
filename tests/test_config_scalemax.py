"""
Unit tests for Milestone 1: Model Shift & ScaleMax Configuration (R3).

Verifies:
1. Default model shift to 'openai/gpt-6-luna' (and accepts 'gpt-6-luna').
2. Default base URL shift to 'https://api.scalemax.pro/v1'.
3. Dynamic key extraction from OPENAI_API_KEY / LLM_API_KEY when LLM_KEYS_POOL is omitted.
4. Parsing of raw single and multiple keys in LLM_KEYS_POOL.
5. Propagation of OPENAI_API_BASE, OPENAI_BASE_URL, and OPENAI_API_KEY in OpenHandsRunner subprocess environment.
6. Backward compatibility of LLM_BASE_URL, LLM_MODEL, and LLM_API_KEY.
7. Verification of zero remaining references to 'longcat-preview' in configuration and source.
"""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from src.config import Config, KeyConfig
from src.openhands_runner import OpenHandsRunner


@pytest.fixture
def empty_env_file(tmp_path: Path) -> Path:
    """Provide an isolated empty .env file so ambient .env does not pollute tests."""
    env_file = tmp_path / "empty.env"
    env_file.write_text("", encoding="utf-8")
    return env_file


class TestScaleMaxDefaultConfiguration:
    """Verify default endpoints, model names, and fallback keys for ScaleMax."""

    def test_default_base_url_and_model_sentinel(self, tmp_path: Path, empty_env_file: Path):
        """Default fallback key must point to ScaleMax .pro and openai/gpt-6-luna."""
        config = Config.load(env_file=empty_env_file, overrides={"workspace_dir": tmp_path})
        assert len(config.llm_keys) == 1
        default_key = config.llm_keys[0]

        assert default_key.base_url == "https://api.scalemax.pro/v1"
        assert default_key.model == "openai/gpt-6-luna"
        assert default_key.provider == "ScaleMax"
        assert default_key.api_key == "NO_LLM_KEY_CONFIGURED"
        assert default_key.masked_key == "NO_KEY"
        assert default_key.priority == 1

        # Check direct dataclass attributes
        assert config.openai_api_base == "https://api.scalemax.pro/v1"
        assert config.llm_model == "openai/gpt-6-luna"
        assert config.openai_api_key == ""

    def test_accepts_gpt_6_luna_without_prefix_via_env(self, tmp_path: Path, empty_env_file: Path):
        """Configuration accepts 'gpt-6-luna' without 'openai/' prefix when explicitly set."""
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_MODEL": "gpt-6-luna"
        })
        assert len(config.llm_keys) == 1
        assert config.llm_keys[0].model == "gpt-6-luna"
        assert config.llm_model == "gpt-6-luna"

    def test_accepts_gpt_6_luna_in_key_pool(self, tmp_path: Path, empty_env_file: Path):
        """Key pool entries with 'gpt-6-luna' are preserved."""
        pool_str = "https://api.scalemax.pro/v1|gpt-6-luna|sk-sm-test12345678"
        config = Config.load(env_file=empty_env_file, overrides={"workspace_dir": tmp_path, "LLM_KEYS_POOL": pool_str})
        assert len(config.llm_keys) == 1
        assert config.llm_keys[0].model == "gpt-6-luna"
        assert config.llm_keys[0].base_url == "https://api.scalemax.pro/v1"
        assert config.llm_keys[0].provider == "ScaleMax"
        assert config.llm_model == "gpt-6-luna"


class TestDynamicKeyExtraction:
    """Verify dynamic API key extraction when LLM_KEYS_POOL is omitted."""

    def test_dynamic_extraction_from_openai_api_key(self, tmp_path: Path, empty_env_file: Path):
        """When LLM_KEYS_POOL is omitted, extract key from OPENAI_API_KEY with ScaleMax defaults."""
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "OPENAI_API_KEY": "sk-sm-dynamic-key-1234567890",
        })
        assert len(config.llm_keys) == 1
        key = config.llm_keys[0]
        assert key.api_key == "sk-sm-dynamic-key-1234567890"
        assert key.base_url == "https://api.scalemax.pro/v1"
        assert key.model == "openai/gpt-6-luna"
        assert key.provider == "ScaleMax"
        assert key.masked_key == "sk-s...7890"
        assert key.priority == 1

        assert config.openai_api_key == "sk-sm-dynamic-key-1234567890"
        assert config.openai_api_base == "https://api.scalemax.pro/v1"
        assert config.llm_model == "openai/gpt-6-luna"

    def test_dynamic_extraction_from_openai_api_key_with_custom_base_and_model(self, tmp_path: Path, empty_env_file: Path):
        """Dynamic extraction respects OPENAI_API_BASE and LLM_MODEL overrides."""
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "OPENAI_API_KEY": "sk-custom-9876543210",
            "OPENAI_API_BASE": "https://api.custom.endpoint/v1",
            "LLM_MODEL": "gpt-6-luna",
        })
        assert len(config.llm_keys) == 1
        key = config.llm_keys[0]
        assert key.api_key == "sk-custom-9876543210"
        assert key.base_url == "https://api.custom.endpoint/v1"
        assert key.model == "gpt-6-luna"
        assert key.provider == "OpenAI"
        assert config.openai_api_base == "https://api.custom.endpoint/v1"
        assert config.llm_model == "gpt-6-luna"

    def test_dynamic_extraction_from_llm_api_key_fallback(self, tmp_path: Path, empty_env_file: Path):
        """When OPENAI_API_KEY is not set, extract from LLM_API_KEY."""
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_API_KEY": "sk-llm-fallback-11223344",
        })
        assert len(config.llm_keys) == 1
        key = config.llm_keys[0]
        assert key.api_key == "sk-llm-fallback-11223344"
        assert key.base_url == "https://api.scalemax.pro/v1"
        assert key.model == "openai/gpt-6-luna"
        assert key.provider == "ScaleMax"

    def test_dynamic_extraction_from_env_file_without_pool(self, tmp_path: Path):
        """Verify dynamic key loading when configured in a dedicated env file."""
        env_file = tmp_path / ".env.custom"
        env_file.write_text(
            "OPENAI_API_KEY=sk-sm-envfile-key-9999\n"
            "OPENAI_API_BASE=https://api.scalemax.pro/v1\n"
            "LLM_MODEL=openai/gpt-6-luna\n",
            encoding="utf-8"
        )
        config = Config.load(env_file=env_file, overrides={"workspace_dir": tmp_path})
        assert len(config.llm_keys) == 1
        key = config.llm_keys[0]
        assert key.api_key == "sk-sm-envfile-key-9999"
        assert key.base_url == "https://api.scalemax.pro/v1"
        assert key.model == "openai/gpt-6-luna"
        assert key.provider == "ScaleMax"


class TestRawKeyParsingInPool:
    """Verify parsing raw key strings in LLM_KEYS_POOL."""

    def test_single_raw_key_in_llm_keys_pool(self, tmp_path: Path, empty_env_file: Path):
        """A raw key string without pipes in LLM_KEYS_POOL is parsed using ScaleMax defaults."""
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": "sk-sm-rawkey-555566667777",
        })
        assert len(config.llm_keys) == 1
        key = config.llm_keys[0]
        assert key.api_key == "sk-sm-rawkey-555566667777"
        assert key.base_url == "https://api.scalemax.pro/v1"
        assert key.model == "openai/gpt-6-luna"
        assert key.provider == "ScaleMax"
        assert key.masked_key == "sk-s...7777"
        assert key.priority == 1

    def test_multiple_raw_keys_in_llm_keys_pool(self, tmp_path: Path, empty_env_file: Path):
        """Multiple raw keys separated by commas, semicolons, or newlines are parsed."""
        raw_pool = "sk-raw-key-11111111, sk-raw-key-22222222;\nsk-raw-key-33333333"
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": raw_pool,
        })
        assert len(config.llm_keys) == 3
        for idx, expected_key in enumerate(["sk-raw-key-11111111", "sk-raw-key-22222222", "sk-raw-key-33333333"], 1):
            k = config.llm_keys[idx - 1]
            assert k.id == f"key-{idx}"
            assert k.api_key == expected_key
            assert k.base_url == "https://api.scalemax.pro/v1"
            assert k.model == "openai/gpt-6-luna"
            assert k.priority == idx

    def test_mixed_raw_and_piped_keys_in_pool(self, tmp_path: Path, empty_env_file: Path):
        """A pool with both piped definitions and raw keys parses correctly."""
        mixed_pool = (
            "https://openrouter.ai/api/v1|deepseek/v3|sk-or-custom-key,"
            "sk-sm-raw-standalone-key"
        )
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": mixed_pool,
        })
        assert len(config.llm_keys) == 2
        k1 = config.llm_keys[0]
        assert k1.base_url == "https://openrouter.ai/api/v1"
        assert k1.model == "deepseek/v3"
        assert k1.api_key == "sk-or-custom-key"

        k2 = config.llm_keys[1]
        assert k2.base_url == "https://api.scalemax.pro/v1"
        assert k2.model == "openai/gpt-6-luna"
        assert k2.api_key == "sk-sm-raw-standalone-key"


class TestOpenHandsRunnerSubprocessEnvPropagation:
    """Verify OpenHandsRunner._build_subprocess_env propagates OpenAI variables."""

    def test_subprocess_env_openai_propagation(self, tmp_path: Path):
        """_build_subprocess_env must propagate OPENAI_API_BASE, OPENAI_BASE_URL, and OPENAI_API_KEY."""
        runner = OpenHandsRunner(timeout_seconds=60)
        key = KeyConfig(
            id="key-scalemax",
            provider="ScaleMax",
            base_url="https://api.scalemax.pro/v1",
            model="openai/gpt-6-luna",
            api_key="sk-sm-proc-test-key-9999",
            masked_key="sk-s...9999",
            priority=1,
        )

        sub_env = runner._build_subprocess_env(tmp_path, key)

        # Propagated ScaleMax / OpenAI variables
        assert sub_env["OPENAI_API_BASE"] == "https://api.scalemax.pro/v1"
        assert sub_env["OPENAI_BASE_URL"] == "https://api.scalemax.pro/v1"
        assert sub_env["OPENAI_API_KEY"] == "sk-sm-proc-test-key-9999"

        # Backwards compatible LLM_* variables
        assert sub_env["LLM_BASE_URL"] == "https://api.scalemax.pro/v1"
        assert sub_env["LLM_MODEL"] == "openai/gpt-6-luna"
        assert sub_env["LLM_API_KEY"] == "sk-sm-proc-test-key-9999"

        # Runtime and workspace
        assert sub_env["RUNTIME"] == "process"
        assert sub_env["WORKSPACE_BASE"] == str(tmp_path)

    def test_subprocess_env_fallback_when_base_url_empty(self, tmp_path: Path):
        """When key.base_url is empty, fallback to https://api.scalemax.pro/v1."""
        runner = OpenHandsRunner(timeout_seconds=60)
        key = KeyConfig(
            id="key-empty-base",
            provider="ScaleMax",
            base_url="",
            model="openai/gpt-6-luna",
            api_key="sk-test-key-1111",
            masked_key="sk-t...1111",
            priority=1,
        )

        sub_env = runner._build_subprocess_env(tmp_path, key)
        assert sub_env["OPENAI_API_BASE"] == "https://api.scalemax.pro/v1"
        assert sub_env["OPENAI_BASE_URL"] == "https://api.scalemax.pro/v1"
        assert sub_env["OPENAI_API_KEY"] == "sk-test-key-1111"

    def test_subprocess_env_security_isolation(self, tmp_path: Path):
        """Subprocess environment preserves secret scrubbing while propagating OpenAI credentials."""
        runner = OpenHandsRunner(timeout_seconds=60)
        key = KeyConfig(
            id="key-1",
            provider="ScaleMax",
            base_url="https://api.scalemax.pro/v1",
            model="openai/gpt-6-luna",
            api_key="sk-sm-test-key-safe",
            masked_key="sk-s...safe",
            priority=1,
        )

        host_env = {
            "GITHUB_TOKEN": "ghp_TopSecretGitHubToken12345",
            "GH_TOKEN": "ghp_CliToken12345",
            "DASHBOARD_API_KEY": "dash_key_secret_999",
            "AWS_SECRET_ACCESS_KEY": "aws_secret_key_888",
        }

        with patch.dict(os.environ, host_env, clear=False):
            sub_env = runner._build_subprocess_env(tmp_path, key)

        assert "GITHUB_TOKEN" not in sub_env
        assert "GH_TOKEN" not in sub_env
        assert "DASHBOARD_API_KEY" not in sub_env
        assert "AWS_SECRET_ACCESS_KEY" not in sub_env

        # Verified OpenAI credentials are safely present
        assert sub_env["OPENAI_API_BASE"] == "https://api.scalemax.pro/v1"
        assert sub_env["OPENAI_BASE_URL"] == "https://api.scalemax.pro/v1"
        assert sub_env["OPENAI_API_KEY"] == "sk-sm-test-key-safe"


class TestNoLongcatPreviewReferences:
    """Verify zero remaining references to 'longcat-preview' in configuration and source."""

    def test_zero_longcat_references_in_config_and_runner(self):
        """Source files and example configuration must contain zero references to longcat-preview."""
        repo_root = Path(__file__).resolve().parent.parent
        files_to_check = [
            repo_root / "src" / "config.py",
            repo_root / "src" / "openhands_runner.py",
            repo_root / ".env.example",
        ]

        for target_file in files_to_check:
            assert target_file.exists(), f"Expected file {target_file} does not exist"
            content = target_file.read_text(encoding="utf-8")
            assert "longcat-preview" not in content.lower(), (
                f"Found 'longcat-preview' in {target_file}"
            )
            assert "longcatpreview" not in content.lower(), (
                f"Found 'longcatpreview' in {target_file}"
            )

    def test_zero_longcat_references_in_all_src_files(self):
        """Scan all Python files in src/ for any longcat references."""
        repo_root = Path(__file__).resolve().parent.parent
        src_dir = repo_root / "src"
        for py_file in src_dir.glob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            assert "longcat-preview" not in content.lower(), (
                f"Found 'longcat-preview' in {py_file}"
            )
            assert "longcatpreview" not in content.lower(), (
                f"Found 'longcatpreview' in {py_file}"
            )


class TestConfigEdgeCaseRemediations:
    """Verify remediations for configuration edge cases in src/config.py."""

    def test_empty_api_key_in_pipe_does_not_suppress_openai_api_key(self, tmp_path: Path, empty_env_file: Path):
        """Empty key in 3-part or 4-part pipe syntax does not add invalid key and allows OPENAI_API_KEY fallback."""
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": "https://api.scalemax.pro/v1|openai/gpt-6-luna|, |||",
            "OPENAI_API_KEY": "sk-fallback-valid",
        })
        assert len(config.llm_keys) == 1
        assert config.llm_keys[0].api_key == "sk-fallback-valid"
        assert config.openai_api_key == "sk-fallback-valid"

    def test_empty_base_url_and_model_coalesce_in_pipe(self, tmp_path: Path, empty_env_file: Path):
        """Empty base URL and model in pipe syntax coalesce to ScaleMax defaults."""
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": "||sk-piped-key",
        })
        assert len(config.llm_keys) == 1
        assert config.llm_keys[0].base_url == "https://api.scalemax.pro/v1"
        assert config.llm_keys[0].model == "openai/gpt-6-luna"
        assert config.llm_keys[0].api_key == "sk-piped-key"

    def test_json_array_of_string_keys_parsed_cleanly(self, tmp_path: Path, empty_env_file: Path):
        """JSON array of string keys parses cleanly without brackets or quote corruption."""
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": '["sk-json-key-1", "sk-json-key-2"]',
        })
        assert len(config.llm_keys) == 2
        assert config.llm_keys[0].api_key == "sk-json-key-1"
        assert config.llm_keys[0].base_url == "https://api.scalemax.pro/v1"
        assert config.llm_keys[0].model == "openai/gpt-6-luna"
        assert config.llm_keys[1].api_key == "sk-json-key-2"

    def test_list_of_string_keys_in_overrides_parsed(self, tmp_path: Path, empty_env_file: Path):
        """Programmatic list of strings in overrides is parsed into valid KeyConfigs."""
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": ["sk-prog-key-1", "sk-prog-key-2"],
        })
        assert len(config.llm_keys) == 2
        assert config.llm_keys[0].api_key == "sk-prog-key-1"
        assert config.llm_keys[0].base_url == "https://api.scalemax.pro/v1"
        assert config.llm_keys[1].api_key == "sk-prog-key-2"

    def test_non_integer_priority_safe_fallback(self, tmp_path: Path, empty_env_file: Path):
        """Non-integer priority in dict safely falls back to index + 1 without ValueError."""
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "LLM_KEYS_POOL": [{"api_key": "sk-prio-safe", "priority": "urgent"}],
        })
        assert len(config.llm_keys) == 1
        assert config.llm_keys[0].api_key == "sk-prio-safe"
        assert config.llm_keys[0].priority == 1

    def test_whitespace_in_base_url_and_model_coalesce_to_defaults(self, tmp_path: Path, empty_env_file: Path):
        """Whitespace strings in OPENAI_API_BASE and LLM_MODEL coalesce cleanly to defaults."""
        config = Config.load(env_file=empty_env_file, overrides={
            "workspace_dir": tmp_path,
            "OPENAI_API_BASE": "   \t  ",
            "LLM_MODEL": "   \n  ",
            "LLM_KEYS_POOL": "",
        })
        assert config.openai_api_base == "https://api.scalemax.pro/v1"
        assert config.llm_model == "openai/gpt-6-luna"
        assert config.llm_keys[0].base_url == "https://api.scalemax.pro/v1"
        assert config.llm_keys[0].model == "openai/gpt-6-luna"

