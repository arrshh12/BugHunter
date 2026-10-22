"""
Adversarial Stress Test Suite for Security Hardening (AutoBugHunter 24/7).
Empirical verification harness for Milestone 10 (challenger_m10_1).

Covers:
1. GitManager credential protection & repo slug validation.
2. RingBufferLogger, SanitizingFormatter & WebSocketBroadcaster secret redaction.
3. OpenHandsRunner subprocess environment sanitization.
4. WebServer API key authentication, defensive headers, and CSWSH origin checking.
"""

from __future__ import annotations

import asyncio
import base64
import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from src.config import Config, KeyConfig
from src.database import Database
from src.git_manager import GitManager, validate_repo_slug
from src.logger import RingBufferLogger, SanitizingFormatter, WebSocketBroadcaster, redact_secrets, setup_logger
from src.openhands_runner import OpenHandsRunner
from src.orchestrator import Orchestrator
from src.web_server import create_app


# =====================================================================
# 1. GITMANAGER CREDENTIAL PROTECTION & SLUG VALIDATION
# =====================================================================

class TestGitManagerCredentialProtectionAdversarial:
    """Stress-test credential scrubbing and slug validation in GitManager."""

    def test_repo_slug_validation_adversarial_matrix(self):
        """Reject path traversal, argument injection, and malformed repo slugs."""
        malicious_slugs = [
            "../../etc",
            "..\\windows\\system32",
            "owner/..",
            "../owner/repo",
            "owner/subdir/extra",
            "-flag/repo",
            "owner/-flag",
            "--upload-pack=evil/repo",
            "owner/repo;rm -rf /",
            "owner/repo$(whoami)",
            "owner/`id`",
            "owner/repo\nnewline",
            "owner/repo\rreturn",
            "owner/repo\x00null",
            "owner/",
            "/repo",
            "owner\\repo",
            "owner//repo",
            "owner/repo/extra/fourth",
            ".",
            "..",
            "owner/.",
            "owner/..",
            "owner/repo..extra",
            "owner/..secret",
            "",
            "   ",
        ]
        for slug in malicious_slugs:
            with pytest.raises(ValueError, match=r"(Invalid repository slug|Path traversal|Argument injection)"):
                validate_repo_slug(slug)

        # Non-string inputs
        for invalid_val in [None, 12345, ["owner/repo"], {"slug": "owner/repo"}]:
            with pytest.raises(ValueError, match=r"Invalid repository slug"):
                validate_repo_slug(invalid_val)  # type: ignore

        # Legitimate slugs should pass
        valid_slugs = [
            "octocat/Hello-World",
            "owner-name/repo.name_123",
            "1234/5678",
            "a/b",
            "AutoBugHunter/bughunter_daemon.v2",
        ]
        for slug in valid_slugs:
            validate_repo_slug(slug)

    def test_git_manager_sync_and_get_prs_rejects_bad_slugs(self, tmp_path):
        """GitManager public methods immediately reject invalid slugs before subprocess calls."""
        gm = GitManager(workspace_dir=tmp_path, github_token="ghp_testtoken12345678901234567890123456")
        
        with pytest.raises(ValueError):
            gm.sync_repository("../../etc/passwd")

        with pytest.raises(ValueError):
            gm.get_open_bot_prs("-rf/evil", tmp_path)

    def test_git_manager_scrubs_all_token_formats_from_text(self, tmp_path):
        """_scrub_credentials strips raw tokens, base64 variants, basic auth, and extraHeader flags."""
        token = "ghp_RealSecretTokenValue1234567890123456789"
        gm = GitManager(workspace_dir=tmp_path, github_token=token)

        # Raw token
        assert token not in gm._scrub_credentials(f"fatal: access denied for {token}")
        assert "[REDACTED]" in gm._scrub_credentials(f"fatal: access denied for {token}")

        # Base64 encoded token and basic auth header
        auth_bytes = f"x-access-token:{token}".encode("utf-8")
        auth_b64 = base64.b64encode(auth_bytes).decode("ascii")
        token_b64 = base64.b64encode(token.encode("utf-8")).decode("ascii")

        text_with_b64 = f"curl -H 'Authorization: basic {auth_b64}' with raw b64 {token_b64}"
        scrubbed = gm._scrub_credentials(text_with_b64)
        assert auth_b64 not in scrubbed
        assert token_b64 not in scrubbed
        assert "[REDACTED]" in scrubbed

        # ExtraHeader command line argument
        cmd_arg = f"http.https://github.com/.extraHeader=AUTHORIZATION: basic {auth_b64}"
        scrubbed_cmd = gm._scrub_credentials(cmd_arg)
        assert auth_b64 not in scrubbed_cmd
        assert "http.https://github.com/.extraHeader=[REDACTED]" in scrubbed_cmd

    def test_git_manager_called_process_error_scrubbing(self, tmp_path):
        """CalledProcessError during git operations must not leak tokens in cmd or stderr."""
        token = "ghp_SimulatedProcessLeakToken12345678901234"
        gm = GitManager(workspace_dir=tmp_path, github_token=token)

        # Simulate git clone failure raising CalledProcessError containing the raw token and b64 header
        auth_bytes = f"x-access-token:{token}".encode("utf-8")
        auth_b64 = base64.b64encode(auth_bytes).decode("ascii")

        leak_cmd = [
            "git",
            "-c", f"http.https://github.com/.extraHeader=AUTHORIZATION: basic {auth_b64}",
            "clone", f"https://github.com/owner/repo.git", str(tmp_path / "repos" / "owner__repo")
        ]
        leak_stderr = f"fatal: unable to access 'https://github.com/owner/repo.git/': Basic {auth_b64} invalid token {token}"

        error_to_raise = subprocess.CalledProcessError(
            returncode=128,
            cmd=leak_cmd,
            output="Starting clone...",
            stderr=leak_stderr
        )

        real_run = subprocess.run
        def mock_subprocess_run(cmd, *args, **kwargs):
            if isinstance(cmd, list) and len(cmd) > 1 and "clone" in cmd:
                raise error_to_raise
            return real_run(cmd, *args, **kwargs)

        with patch("subprocess.run", side_effect=mock_subprocess_run):
            # sync_repository catches CalledProcessError, scrubs it, and raises RuntimeError
            with pytest.raises(RuntimeError, match="Failed to clone repository owner/repo"):
                gm.sync_repository("owner/repo", allow_init=False)

            # Check that the exception object itself had cmd and stderr scrubbed
            assert auth_b64 not in str(error_to_raise.cmd)
            assert token not in str(error_to_raise.stderr)
            assert "[REDACTED]" in str(error_to_raise.cmd)
            assert "[REDACTED]" in str(error_to_raise.stderr)


# =====================================================================
# 2. LOGGER SECRET REDACTION ADVERSARIAL
# =====================================================================

class TestLoggerSecretRedactionAdversarial:
    """Stress-test secret scrubbing across memory ring buffer, disk log file, and WebSockets."""

    SECRET_TEST_VECTORS = [
        ("GitHub PAT classic", "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"),
        ("GitHub fine-grained PAT", "github_pat_11AAAAAAA01234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz12"),
        ("GitHub OAuth token", "gho_1234567890abcdefghijklmnopqrstuvwxyz12"),
        ("GitHub User token", "ghu_1234567890abcdefghijklmnopqrstuvwxyz12"),
        ("GitHub Server token", "ghs_1234567890abcdefghijklmnopqrstuvwxyz12"),
        ("Anthropic key standard", "sk-ant-api03-abcdef1234567890abcdef123456"),
        ("Anthropic key variant", "sk-ant-abcdef1234567890abcdef123456"),
        ("OpenAI project key", "sk-proj-abcdef1234567890abcdef1234567890"),
        ("OpenAI standard key", "sk-abcdef1234567890abcdef1234567890"),
        ("Google AIza key", "AIzaSy" + "A1234567890abcdef1234567890abcdef"),
        ("Bearer auth token", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M"),
        ("Basic auth token", "Basic dXNlcm5hbWU6cGFzc3dvcmRfZXhhbXBsZV8xMjM0NQ=="),
        ("Generic assignment quoted", 'api_key = "super_secret_production_credential_string_value_123"'),
        ("Generic assignment unquoted", "password: TopSecretPasswordStringValue12345"),
        ("Generic token assignment", "auth_token='secret_auth_token_value_9876543210'"),
        ("RSA private key multiline", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y1+2...\n-----END RSA PRIVATE KEY-----"),
        ("Generic private key multiline", "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD...\n-----END PRIVATE KEY-----"),
        ("Unclosed private key header", "-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA..."),
    ]

    @pytest.mark.parametrize("label,secret", SECRET_TEST_VECTORS)
    def test_redact_secrets_direct(self, label, secret):
        """Verify redact_secrets removes every secret payload without exception."""
        input_text = f"Context before {secret} and context after"
        scrubbed = redact_secrets(input_text)
        assert secret not in scrubbed, f"Failed to redact {label}"
        assert "[REDACTED]" in scrubbed

    def test_logger_all_output_channels(self, tmp_path):
        """Verify secrets are redacted in ring buffer, rotating file, and WebSocket broadcast."""
        log_file = tmp_path / "test_bughunter.log"
        broadcaster = WebSocketBroadcaster()

        received_broadcasts = []
        broadcaster.broadcast_sync = MagicMock(side_effect=lambda line: received_broadcasts.append(line))

        ring_logger = RingBufferLogger(capacity=100, log_file=log_file, broadcaster=broadcaster)

        test_payloads = [
            "Starting daemon with token ghp_VerySecretTokenValue1234567890123456789",
            "Loaded model key sk-ant-api03-MySuperSecretAnthropicKey999",
            "Authorization failed with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token123456789",
            "Loaded TLS key: -----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----",
        ]

        for payload in test_payloads:
            ring_logger.log("INFO", payload)

        ring_logger.close()

        # 1. Verify in-memory ring buffer
        recent = ring_logger.get_recent_logs(50)
        assert len(recent) == 4
        for line in recent:
            assert "ghp_VerySecretTokenValue" not in line
            assert "sk-ant-api03" not in line
            assert "eyJhbGciOi" not in line
            assert "MIIEvgIBADAN" not in line
            assert "[REDACTED]" in line

        # 2. Verify disk log file
        file_content = log_file.read_text(encoding="utf-8")
        assert "ghp_VerySecretTokenValue" not in file_content
        assert "sk-ant-api03" not in file_content
        assert "eyJhbGciOi" not in file_content
        assert "MIIEvgIBADAN" not in file_content
        assert "[REDACTED]" in file_content

        # 3. Verify WebSocket broadcast stream
        assert len(received_broadcasts) == 4
        for msg in received_broadcasts:
            assert "ghp_VerySecretTokenValue" not in msg
            assert "sk-ant-api03" not in msg
            assert "eyJhbGciOi" not in msg
            assert "MIIEvgIBADAN" not in msg
            assert "[REDACTED]" in msg


# =====================================================================
# 3. OPENHANDS RUNNER SUBPROCESS ENVIRONMENT SANITIZATION
# =====================================================================

class TestOpenHandsRunnerEnvSanitizationAdversarial:
    """Stress-test OpenHands subprocess environment whitelist and credential purging."""

    def test_ambient_secrets_strictly_purged(self, tmp_path):
        """Verify ambient tokens, cloud keys, and dashboard keys are completely excluded from subprocess env."""
        runner = OpenHandsRunner(timeout_seconds=60)
        repo_path = tmp_path / "test_repo"
        repo_path.mkdir()

        key = KeyConfig(
            id="key-1",
            provider="ScaleMax",
            base_url="https://api.scalemax.ai/v1",
            model="claude-haiku-5.5",
            api_key="sk-ant-runner-test-key-1234567890",
            masked_key="sk-a...7890",
            priority=1,
        )

        hostile_env = {
            "GITHUB_TOKEN": "ghp_AdversarialHostToken12345678901234567890",
            "GH_TOKEN": "ghp_AmbientCliToken12345678901234567890",
            "GITHUB_PAT": "github_pat_AmbientFineGrainedToken12345678901234567890",
            "DASHBOARD_API_KEY": "SuperSecretDashboardKey987654321",
            "DASHBOARD_SECRET": "internal_secret_token_12345",
            "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
            "AZURE_CLIENT_SECRET": "azure_client_secret_xyz123",
            "OCI_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----",
            "GCP_SERVICE_ACCOUNT_KEY": '{"type": "service_account"}',
            "CUSTOM_API_SECRET": "custom_secret_key_1234567890",
            "HOST_USER_CREDENTIALS": "password12345",
        }

        with patch.dict(os.environ, hostile_env, clear=False):
            sub_env = runner._build_subprocess_env(repo_path, key)

        # 1. Assert explicitly denied variables are purged
        assert "GITHUB_TOKEN" not in sub_env
        assert "GH_TOKEN" not in sub_env
        assert "GITHUB_PAT" not in sub_env
        assert "DASHBOARD_API_KEY" not in sub_env
        assert "DASHBOARD_SECRET" not in sub_env

        # 2. Assert cloud and custom secrets are not passed through
        assert "AWS_SECRET_ACCESS_KEY" not in sub_env
        assert "AWS_ACCESS_KEY_ID" not in sub_env
        assert "AZURE_CLIENT_SECRET" not in sub_env
        assert "OCI_PRIVATE_KEY" not in sub_env
        assert "GCP_SERVICE_ACCOUNT_KEY" not in sub_env
        assert "CUSTOM_API_SECRET" not in sub_env
        assert "HOST_USER_CREDENTIALS" not in sub_env

        # 3. Assert none of the secret values appear in the env dictionary values
        all_env_values = list(sub_env.values())
        for hostile_val in hostile_env.values():
            assert hostile_val not in all_env_values

        # 4. Assert necessary execution variables are properly populated
        assert sub_env["LLM_BASE_URL"] == "https://api.scalemax.ai/v1"
        assert sub_env["LLM_MODEL"] == "claude-haiku-5.5"
        assert sub_env["LLM_API_KEY"] == "sk-ant-runner-test-key-1234567890"
        assert sub_env["RUNTIME"] == "process"
        assert sub_env["WORKSPACE_BASE"] == str(repo_path)


# =====================================================================
# 4. WEBSERVER AUTHENTICATION & CSWSH ORIGIN CHECKING
# =====================================================================

class TestWebServerAuthAndCSWSHAdversarial:
    """Stress-test API authentication, security headers, and CSWSH origin verification."""

    @pytest.fixture
    def setup_app_and_orchestrator(self, tmp_path):
        db_path = tmp_path / "test.db"
        db = Database(db_path)
        db.init_db()

        log_file = tmp_path / "test.log"
        _, ring_logger, broadcaster = setup_logger(log_file=log_file)

        config = Config.load(overrides={
            "WORKSPACE_DIR": str(tmp_path),
            "DB_PATH": str(db_path),
            "LOG_FILE_PATH": str(log_file),
            "DASHBOARD_API_KEY": "UltraSecretKey_2026_Secure!",
            "DASHBOARD_HOST": "127.0.0.1",
        })

        orchestrator = MagicMock(spec=Orchestrator)
        orchestrator.config = config
        orchestrator.db = db
        orchestrator.logger = ring_logger
        orchestrator.paused = False
        orchestrator.force_queue = []
        orchestrator.toggle_pause.return_value = True

        app = create_app(orchestrator, broadcaster=broadcaster)
        client = TestClient(app)
        return app, client, orchestrator

    def test_defensive_http_headers_present(self, setup_app_and_orchestrator):
        """All HTTP responses must carry X-Frame-Options: DENY and X-Content-Type-Options: nosniff."""
        _, client, orchestrator = setup_app_and_orchestrator

        # GET /
        resp_root = client.get("/")
        assert resp_root.headers.get("X-Frame-Options") == "DENY"
        assert resp_root.headers.get("X-Content-Type-Options") == "nosniff"

        # GET /api/state
        resp_state = client.get("/api/state")
        assert resp_state.headers.get("X-Frame-Options") == "DENY"
        assert resp_state.headers.get("X-Content-Type-Options") == "nosniff"

        # 401 Unauthorized response
        resp_unauth = client.post("/api/control/toggle-pause")
        assert resp_unauth.status_code == 401
        assert resp_unauth.headers.get("X-Frame-Options") == "DENY"
        assert resp_unauth.headers.get("X-Content-Type-Options") == "nosniff"

    def test_api_authentication_adversarial_matrix(self, setup_app_and_orchestrator):
        """Exhaustively test valid and malicious auth attempts on control endpoints."""
        _, client, orchestrator = setup_app_and_orchestrator
        valid_key = "UltraSecretKey_2026_Secure!"

        # 1. Unauthenticated attempts -> 401
        res = client.post("/api/control/toggle-pause")
        assert res.status_code == 401

        # 2. Malicious / incorrect keys -> 401
        bad_headers = [
            {"X-API-Key": "ultrasecretkey_2026_secure!"},  # lower-case (case-sensitive check)
            {"X-API-Key": "UltraSecretKey_2026_Secure! "},  # trailing whitespace
            {"X-API-Key": " UltraSecretKey_2026_Secure!"},  # leading whitespace
            {"X-API-Key": "UltraSecretKey_2026_Secure!\x00"},  # null byte
            {"X-API-Key": "' OR '1'='1"},  # SQLi attempt
            {"X-API-Key": ""},  # empty string
            {"Authorization": "Bearer ultrasecretkey_2026_secure!"},  # case mismatch in Bearer
            {"Authorization": "Bearer wrong-key-string"},
            {"Authorization": "bearer UltraSecretKey_2026_Secure!"},  # lower-case 'bearer'
            {"Authorization": "Basic " + base64.b64encode(valid_key.encode()).decode()},
            {"Authorization": "Bearer "},  # empty bearer
            {"X-Custom-Key": valid_key},  # wrong header name
        ]
        for headers in bad_headers:
            r = client.post("/api/control/toggle-pause", headers=headers)
            assert r.status_code == 401, f"Expected 401 for headers: {headers}"

        # 3. Legitimate X-API-Key -> 200
        r_valid_x = client.post("/api/control/toggle-pause", headers={"X-API-Key": valid_key})
        assert r_valid_x.status_code == 200
        assert r_valid_x.json() == {"paused": True}

        # 4. Legitimate Authorization: Bearer -> 200
        r_valid_bearer = client.post("/api/control/toggle-pause", headers={"Authorization": f"Bearer {valid_key}"})
        assert r_valid_bearer.status_code == 200

        # 5. Authorization: Bearer with extra spaces around token -> 200 (strip supported)
        r_valid_bearer_spaces = client.post("/api/control/toggle-pause", headers={"Authorization": f"Bearer   {valid_key}  "})
        assert r_valid_bearer_spaces.status_code == 200

        # 6. Verify authentication is inactive if DASHBOARD_API_KEY is not configured
        orchestrator.config.dashboard_api_key = ""
        r_no_auth_needed = client.post("/api/control/toggle-pause")
        assert r_no_auth_needed.status_code == 200

    def test_scan_now_slug_validation_adversarial(self, setup_app_and_orchestrator):
        """Enforce strict slug validation on POST /api/control/scan-now/{owner}/{repo}."""
        _, client, orchestrator = setup_app_and_orchestrator
        headers = {"X-API-Key": "UltraSecretKey_2026_Secure!"}

        malicious_routes = [
            ("..", ".."),
            ("-flag", "repo"),
            ("owner", "-flag"),
            ("owner", "repo;rm"),
            ("owner", "repo$whoami"),
            ("owner", "repo..extra"),
        ]
        for owner, repo in malicious_routes:
            resp = client.post(f"/api/control/scan-now/{owner}/{repo}", headers=headers)
            assert resp.status_code in (400, 404), f"Expected rejection for {owner}/{repo}, got {resp.status_code}"

        # Legitimate slug
        resp_good = client.post("/api/control/scan-now/AutoBugHunter/bughunter", headers=headers)
        assert resp_good.status_code == 200
        assert resp_good.json()["status"] == "queued"

    def test_websocket_cswsh_origin_validation_adversarial(self, setup_app_and_orchestrator):
        """Cross-Site WebSocket Hijacking check: reject evil origins and accept authorized origins."""
        _, client, orchestrator = setup_app_and_orchestrator

        # 1. Evil origins must be rejected with 1008
        evil_origins = [
            "http://evil.com",
            "https://attacker.org",
            "http://localhost.evil.com",
            "http://127.0.0.1.attacker.com",
            "http://evil-localhost",
            "null",
            "http://192.168.1.50:8080",
            "http://10.0.0.1:8080",
        ]
        for origin in evil_origins:
            with pytest.raises(Exception):
                with client.websocket_connect("/ws/logs", headers={"Origin": origin}):
                    pass

        # 2. Legitimate origins must be accepted
        allowed_origins = [
            "http://localhost",
            "http://localhost:8080",
            "http://127.0.0.1",
            "http://127.0.0.1:8080",
            "http://testclient",
            "http://testserver",
        ]
        auth_token = orchestrator.config.dashboard_api_key
        for origin in allowed_origins:
            with client.websocket_connect(f"/ws/logs?token={auth_token}", headers={"Origin": origin}) as ws:
                assert ws is not None

        # 3. Missing origin (e.g. CLI client / python script) must be accepted
        with client.websocket_connect(f"/ws/logs?token={auth_token}") as ws:
            assert ws is not None

    def test_websocket_spoofed_subdomain_origins(self, setup_app_and_orchestrator):
        """Reject subdomains and tricked prefixes trying to impersonate localhost."""
        _, client, orchestrator = setup_app_and_orchestrator

        spoofed_subdomains = [
            "http://localhost.attacker.com",
            "http://127.0.0.1.attacker.com",
            "http://evil-localhost",
            "http://attacker-localhost.com",
            "http://evil127.0.0.1",
            "ws://localhost.evil.com",
            "http://fake.localhost.com:8080",
        ]
        for spoofed in spoofed_subdomains:
            with pytest.raises(Exception):
                with client.websocket_connect("/ws/logs", headers={"Origin": spoofed}):
                    pass


# =====================================================================
# 5. ADDITIONAL DEEP STRESS HARNESSES
# =====================================================================

class TestSecurityHardeningDeepStress:
    """Multi-vector stress verification across all R1 security hardening modules."""

    def test_multiple_secrets_in_single_entry(self):
        """Verify complex multi-secret entries are completely cleansed."""
        text = (
            "ERROR: Key sk-ant-api03-abcdef1234567890abcdef123456 failed while syncing "
            "with token ghp_1234567890abcdefghijklmnopqrstuvwxyz12 and "
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M"
        )
        scrubbed = redact_secrets(text)
        assert "sk-ant-api03" not in scrubbed
        assert "ghp_1234567890" not in scrubbed
        assert "eyJhbGciOi" not in scrubbed
        assert scrubbed.count("[REDACTED]") >= 3

    def test_git_push_scrubs_credentials_on_error(self, tmp_path):
        """push_atomic_branch scrubs credentials from CalledProcessError."""
        token = "ghp_PushFailureTokenValue1234567890123456"
        gm = GitManager(workspace_dir=tmp_path, github_token=token)
        repo_dir = tmp_path / "repos" / "test_repo"
        repo_dir.mkdir(parents=True)

        # Initialize local repo and branch
        subprocess.run(["git", "init", "-b", "main"], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "TestBot"], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo_dir, check=True, capture_output=True)
        (repo_dir / "README.md").write_text("test", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo_dir, check=True, capture_output=True)
        branch = gm.create_atomic_branch(repo_dir)

        auth_bytes = f"x-access-token:{token}".encode("utf-8")
        auth_b64 = base64.b64encode(auth_bytes).decode("ascii")

        push_error = subprocess.CalledProcessError(
            returncode=1,
            cmd=["git", "-c", f"http.https://github.com/.extraHeader=AUTHORIZATION: basic {auth_b64}", "push", "origin", branch],
            output="push error",
            stderr=f"fatal: remote rejected with token {token}"
        )

        real_run = subprocess.run
        def mock_push(cmd, *args, **kwargs):
            if isinstance(cmd, list) and len(cmd) > 1 and "push" in cmd:
                raise push_error
            return real_run(cmd, *args, **kwargs)

        with patch("subprocess.run", side_effect=mock_push):
            gm.push_atomic_branch(repo_dir, branch)

        assert auth_b64 not in str(push_error.cmd)
        assert token not in str(push_error.stderr)
        assert "[REDACTED]" in str(push_error.cmd)
        assert "[REDACTED]" in str(push_error.stderr)

    def test_openhands_env_completely_drops_ambient_case_insensitive(self, tmp_path):
        """Case variations in ambient env vars (e.g. Github_Token, gh_token) must never leak."""
        runner = OpenHandsRunner(timeout_seconds=60)
        repo_path = tmp_path / "test_repo"
        repo_path.mkdir()

        key = KeyConfig(
            id="key-1",
            provider="ScaleMax",
            base_url="https://api.scalemax.ai/v1",
            model="claude-haiku-5.5",
            api_key="sk-test-key-1234567890",
            masked_key="sk-t...7890",
            priority=1,
        )

        hostile_env = {
            "github_token": "leak_lowercase_github_token",
            "GITHUB_TOKEN": "leak_uppercase_github_token",
            "Gh_Token": "leak_mixedcase_gh_token",
            "Dashboard_Api_Key": "leak_mixedcase_dashboard_key",
            "AWS_SECRET": "leak_aws",
            "Azure_Secret": "leak_azure",
            "Oci_Key": "leak_oci",
        }

        with patch.dict(os.environ, hostile_env, clear=False):
            sub_env = runner._build_subprocess_env(repo_path, key)

        for leak_val in hostile_env.values():
            assert leak_val not in list(sub_env.values())
        for k in sub_env.keys():
            upper = k.upper()
            assert not any(upper.startswith(prefix) for prefix in ("GITHUB", "GH", "DASHBOARD", "AWS", "AZURE", "OCI", "GCP"))
