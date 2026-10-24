"""
Adversarial Stress Test Suite for Milestone 1:
Subprocess Environment Propagation & Host Secret Leak Prevention in OpenHandsRunner.

Empirical verification harness by challenger_m1_2.

Tested Attack Vectors:
1. Hostile parent environment secret stripping (GITHUB_TOKEN, GH_TOKEN, DASHBOARD_API_KEY, AWS_*, etc.).
2. Case-insensitivity & case-variation hostile key stripping (lowercase, mixed case, extended prefixes).
3. Value-leak prevention: verifying secret strings do not leak as values in any environment key.
4. ScaleMax / OpenAI environment propagation (OPENAI_API_BASE, OPENAI_BASE_URL, OPENAI_API_KEY).
5. Host override resistance (hostile host OPENAI_API_KEY/BASE attempting to hijack subprocess).
6. Sneaky prefix / suffix / spoof variable exclusion via strict allowlisting.
7. Special characters, unicode, spaces in workspace path and API key.
8. End-to-end real subprocess execution verification (spawning python child process with sanitized env).
9. Immutability of parent os.environ during and after _build_subprocess_env.
10. Fallback handling for empty base_url, custom base_urls, and whitespace.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from src.config import Config, KeyConfig
from src.openhands_runner import OpenHandsRunner, SessionResult


@pytest.fixture
def test_key_entry() -> KeyConfig:
    return KeyConfig(
        id="key-scalemax-1",
        provider="ScaleMax",
        base_url="https://api.scalemax.pro/v1",
        model="openai/gpt-6-luna",
        api_key="sk-sm-testkey-1234567890abcdef",
        masked_key="sk-s...cdef",
        priority=1,
    )


@pytest.fixture
def runner() -> OpenHandsRunner:
    return OpenHandsRunner(timeout_seconds=60, runtime="process")


class TestHostileEnvironmentSecretStripping:
    """Stress-test that parent environment secrets are strictly stripped from subprocess environment."""

    def test_hostile_parent_secrets_strictly_stripped(self, runner: OpenHandsRunner, test_key_entry: KeyConfig, tmp_path: Path):
        """Simulate hostile parent environment containing tokens, dashboard keys, and cloud secrets."""
        hostile_env = {
            "GITHUB_TOKEN": "ghp_TopSecretGitHubToken12345",
            "GH_TOKEN": "gho_SecretCliToken54321",
            "GITHUB_PAT": "github_pat_SecretPersonalAccessToken999",
            "DASHBOARD_API_KEY": "admin123",
            "AWS_SECRET_ACCESS_KEY": "foo",
            "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
            "AWS_SESSION_TOKEN": "AQoDYXdzEJrHostileSessionToken",
            "AZURE_CLIENT_SECRET": "azure_secret_access_key_xyz",
            "AZURE_TENANT_ID": "azure_tenant_id_111",
            "OCI_AUTH_TOKEN": "oci_secret_auth_token_777",
            "GCP_SERVICE_ACCOUNT_KEY": '{"private_key": "gcp_secret_key"}',
            "SSH_AUTH_SOCK": "/tmp/ssh-agent-hostile.sock",
            "DATABASE_URL": "postgres://admin:pass@host:5432/main",
            "SECRET_KEY": "super_secret_django_flask_key",
        }

        with patch.dict(os.environ, hostile_env, clear=False):
            sub_env = runner._build_subprocess_env(tmp_path, test_key_entry)

        # 1. Assert explicitly denied / sensitive variables are stripped
        denied_keys = [
            "GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PAT", "DASHBOARD_API_KEY",
            "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN",
            "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
            "OCI_AUTH_TOKEN", "GCP_SERVICE_ACCOUNT_KEY",
            "SSH_AUTH_SOCK", "DATABASE_URL", "SECRET_KEY"
        ]
        for key in denied_keys:
            assert key not in sub_env, f"Security leak: '{key}' was not stripped from subprocess env"

        # 2. Assert none of the secret values appear anywhere in the env values
        all_sub_values = set(sub_env.values())
        for secret_name, secret_val in hostile_env.items():
            assert secret_val not in all_sub_values, (
                f"Security leak: Value of '{secret_name}' ('{secret_val}') leaked into subprocess env values"
            )

    def test_case_variation_and_prefix_stripping(self, runner: OpenHandsRunner, test_key_entry: KeyConfig, tmp_path: Path):
        """Verify that lowercase, mixed-case, and prefixed hostile keys are stripped."""
        hostile_case_variations = {
            "github_token": "ghp_lowercase_token_123",
            "GitHub_Token": "ghp_mixedcase_token_456",
            "gh_token": "gho_lowercase_token_789",
            "Gh_Token": "gho_mixedcase_token_012",
            "dashboard_api_key": "admin_lowercase_key",
            "Dashboard_Api_Key": "admin_mixedcase_key",
            "aws_secret_access_key": "aws_lowercase_secret",
            "Aws_Secret_Access_Key": "aws_mixedcase_secret",
            "GITHUB_ENTERPRISE_PAT": "ghp_ent_pat_999",
            "GH_ENTERPRISE_AUTH": "gho_ent_auth_888",
            "DASHBOARD_BACKDOOR_KEY": "backdoor_secret",
            "AWS_SECURITY_TOKEN": "aws_sec_tok",
            "AZURE_FEDERATED_CREDENTIAL": "azure_fed_cred",
            "OCI_PRIVATE_KEY_PEM": "-----BEGIN PRIVATE KEY-----",
            "GCP_CREDENTIALS_JSON": '{"key": "gcp"}',
        }

        with patch.dict(os.environ, hostile_case_variations, clear=False):
            sub_env = runner._build_subprocess_env(tmp_path, test_key_entry)

        for hostile_key, hostile_val in hostile_case_variations.items():
            # Check neither key nor case-insensitive matches exist
            for sub_k in sub_env.keys():
                assert sub_k.lower() != hostile_key.lower(), (
                    f"Case variation leak: '{sub_k}' matches hostile '{hostile_key}'"
                )
            assert hostile_val not in sub_env.values(), (
                f"Value leak: '{hostile_val}' found in subprocess env values"
            )

    def test_sneaky_prefix_and_spoof_variables_never_leak(self, runner: OpenHandsRunner, test_key_entry: KeyConfig, tmp_path: Path):
        """Variables attempting to bypass prefix checks (e.g. _GITHUB_TOKEN, X_AWS_KEY) are rejected by allowlist."""
        sneaky_hostile_vars = {
            "_GITHUB_TOKEN": "sneaky_token_1",
            "X_GITHUB_TOKEN": "sneaky_token_2",
            "MY_AWS_KEY": "sneaky_key_3",
            "NOT_PATH": "spoof_path_4",
            "SYSTEMROOT_SPOOF": "spoof_root_5",
            "CUSTOM_API_SECRET_KEY": "custom_secret_6",
            "AUTHORIZATION": "Bearer token_7",
            "HTTP_AUTHORIZATION": "Bearer token_8",
        }

        with patch.dict(os.environ, sneaky_hostile_vars, clear=False):
            sub_env = runner._build_subprocess_env(tmp_path, test_key_entry)

        for sneaky_k in sneaky_hostile_vars:
            assert sneaky_k not in sub_env, f"Allowlist bypass: '{sneaky_k}' entered subprocess env"

        for sneaky_v in sneaky_hostile_vars.values():
            assert sneaky_v not in sub_env.values(), f"Value leak: sneaky value '{sneaky_v}' found in sub_env"


class TestSubprocessOpenAIPropagation:
    """Verify ScaleMax and OpenAI environment variables propagate accurately."""

    def test_scalemax_openai_environment_propagation(self, runner: OpenHandsRunner, test_key_entry: KeyConfig, tmp_path: Path):
        """Verify OPENAI_API_BASE, OPENAI_BASE_URL, and OPENAI_API_KEY are properly propagated."""
        sub_env = runner._build_subprocess_env(tmp_path, test_key_entry)

        assert sub_env["OPENAI_API_BASE"] == "https://api.scalemax.pro/v1"
        assert sub_env["OPENAI_BASE_URL"] == "https://api.scalemax.pro/v1"
        assert sub_env["OPENAI_API_KEY"] == "sk-sm-testkey-1234567890abcdef"

        # Backwards compatible LLM_* variables
        assert sub_env["LLM_BASE_URL"] == "https://api.scalemax.pro/v1"
        assert sub_env["LLM_MODEL"] == "openai/gpt-6-luna"
        assert sub_env["LLM_API_KEY"] == "sk-sm-testkey-1234567890abcdef"

        # Runner configuration
        assert sub_env["RUNTIME"] == "process"
        assert sub_env["WORKSPACE_BASE"] == str(tmp_path)

    def test_host_override_resistance(self, runner: OpenHandsRunner, test_key_entry: KeyConfig, tmp_path: Path):
        """Hostile parent environment attempting to poison OPENAI_API_* is strictly overridden."""
        host_poisoning = {
            "OPENAI_API_BASE": "https://malicious-endpoint.phishing.attacker/v1",
            "OPENAI_BASE_URL": "https://malicious-endpoint.phishing.attacker/v1",
            "OPENAI_API_KEY": "sk-attacker-stolen-key-6666",
            "LLM_BASE_URL": "https://malicious-llm.attacker/v1",
            "LLM_MODEL": "rogue-malicious-model",
            "LLM_API_KEY": "sk-rogue-key-9999",
            "RUNTIME": "malicious_injected_runtime",
            "WORKSPACE_BASE": "/malicious/injected/workspace",
        }

        with patch.dict(os.environ, host_poisoning, clear=False):
            sub_env = runner._build_subprocess_env(tmp_path, test_key_entry)

        assert sub_env["OPENAI_API_BASE"] == "https://api.scalemax.pro/v1"
        assert sub_env["OPENAI_BASE_URL"] == "https://api.scalemax.pro/v1"
        assert sub_env["OPENAI_API_KEY"] == "sk-sm-testkey-1234567890abcdef"
        assert sub_env["LLM_BASE_URL"] == "https://api.scalemax.pro/v1"
        assert sub_env["LLM_MODEL"] == "openai/gpt-6-luna"
        assert sub_env["LLM_API_KEY"] == "sk-sm-testkey-1234567890abcdef"
        assert sub_env["RUNTIME"] == "process"
        assert sub_env["WORKSPACE_BASE"] == str(tmp_path)

        for poison_val in host_poisoning.values():
            assert poison_val not in sub_env.values()

    def test_empty_base_url_fallback(self, runner: OpenHandsRunner, tmp_path: Path):
        """When key_entry.base_url is empty, fallback to https://api.scalemax.pro/v1."""
        key = KeyConfig(
            id="key-no-base",
            provider="ScaleMax",
            base_url="",
            model="openai/gpt-6-luna",
            api_key="sk-test-key-fallback",
            masked_key="sk-t...back",
            priority=1,
        )

        sub_env = runner._build_subprocess_env(tmp_path, key)
        assert sub_env["OPENAI_API_BASE"] == "https://api.scalemax.pro/v1"
        assert sub_env["OPENAI_BASE_URL"] == "https://api.scalemax.pro/v1"
        assert sub_env["OPENAI_API_KEY"] == "sk-test-key-fallback"


class TestEmpiricalSubprocessExecution:
    """Execute real child processes using the generated environment to prove empirical safety."""

    def test_real_python_subprocess_environment_isolation(self, runner: OpenHandsRunner, test_key_entry: KeyConfig, tmp_path: Path):
        """Spawn an actual Python subprocess using the built environment and inspect child os.environ."""
        hostile_env = {
            "GITHUB_TOKEN": "ghp_RealChildSecretGitHubToken",
            "GH_TOKEN": "gho_RealChildSecretCliToken",
            "DASHBOARD_API_KEY": "RealChildSecretDashboardKey",
            "AWS_SECRET_ACCESS_KEY": "RealChildSecretAwsKey",
            "CUSTOM_HOSTILE_VAR": "HostileVarValue123",
        }

        with patch.dict(os.environ, hostile_env, clear=False):
            sub_env = runner._build_subprocess_env(tmp_path, test_key_entry)

        # Code to execute in child process: dump os.environ as JSON to stdout
        child_code = "import json, os; print(json.dumps(dict(os.environ)))"

        proc = subprocess.run(
            [sys.executable, "-c", child_code],
            env=sub_env,
            capture_output=True,
            text=True,
            check=True
        )

        child_env = json.loads(proc.stdout.strip())

        # 1. Verify child process received ScaleMax / OpenAI settings
        assert child_env.get("OPENAI_API_BASE") == "https://api.scalemax.pro/v1"
        assert child_env.get("OPENAI_BASE_URL") == "https://api.scalemax.pro/v1"
        assert child_env.get("OPENAI_API_KEY") == "sk-sm-testkey-1234567890abcdef"
        assert child_env.get("LLM_BASE_URL") == "https://api.scalemax.pro/v1"
        assert child_env.get("LLM_MODEL") == "openai/gpt-6-luna"
        assert child_env.get("LLM_API_KEY") == "sk-sm-testkey-1234567890abcdef"

        # 2. Verify child process does NOT have hostile tokens
        assert "GITHUB_TOKEN" not in child_env
        assert "GH_TOKEN" not in child_env
        assert "DASHBOARD_API_KEY" not in child_env
        assert "AWS_SECRET_ACCESS_KEY" not in child_env
        assert "CUSTOM_HOSTILE_VAR" not in child_env

        # 3. Verify no hostile values appear in any child env value
        for hostile_val in hostile_env.values():
            assert hostile_val not in child_env.values()

    def test_special_characters_and_paths_in_subprocess(self, runner: OpenHandsRunner, tmp_path: Path):
        """Stress-test paths with spaces, unicode characters, and complex keys in subprocess execution."""
        complex_workspace = tmp_path / "BugHunter Test Workspace 2026 #1 [Special]"
        complex_workspace.mkdir(parents=True, exist_ok=True)

        complex_key = KeyConfig(
            id="key-complex-chars",
            provider="ScaleMax",
            base_url="https://api.scalemax.pro/v1",
            model="openai/gpt-6-luna",
            api_key="sk-sm-complex!@#$%^&*()_+-=[]{}|;:,.<>?",
            masked_key="sk-s...<>?",
            priority=1,
        )

        sub_env = runner._build_subprocess_env(complex_workspace, complex_key)

        child_code = "import json, os; print(json.dumps({'base': os.environ.get('WORKSPACE_BASE'), 'key': os.environ.get('OPENAI_API_KEY')}))"

        proc = subprocess.run(
            [sys.executable, "-c", child_code],
            env=sub_env,
            capture_output=True,
            text=True,
            check=True
        )

        result = json.loads(proc.stdout.strip())
        assert result["base"] == str(complex_workspace)
        assert result["key"] == "sk-sm-complex!@#$%^&*()_+-=[]{}|;:,.<>?"

    def test_parent_os_environ_immutability(self, runner: OpenHandsRunner, test_key_entry: KeyConfig, tmp_path: Path):
        """Verify calling _build_subprocess_env produces zero side-effects on parent os.environ."""
        original_parent_env = dict(os.environ)

        runner._build_subprocess_env(tmp_path, test_key_entry)

        current_parent_env = dict(os.environ)
        assert original_parent_env == current_parent_env, (
            "Side effect detected: _build_subprocess_env mutated parent os.environ"
        )
