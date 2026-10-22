"""
Unit tests for src/web_server.py: Mission Control FastAPI endpoints, control actions, and WebSocket log streaming.
"""

from pathlib import Path
import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from src.config import Config, KeyConfig
from src.database import Database
from src.git_manager import GitManager
from src.key_manager import KeyManager
from src.logger import RingBufferLogger, WebSocketBroadcaster
from src.openhands_runner import OpenHandsRunner
from src.orchestrator import Orchestrator
from src.static_scanner import StaticScanner
from src.verifier import Verifier
from src.web_server import create_app


@pytest.fixture
def test_app(tmp_path: Path):
    db = Database(tmp_path / "web.sqlite")
    k1 = KeyConfig("k1", "ScaleMax", "https://api.sm.ai/v1", "claude-haiku-5.5", "sk-12345678", "sk-1...5678", 1)
    config = Config.load(overrides={"workspace_dir": tmp_path, "LLM_KEYS_POOL": [k1], "target_repos": ["owner/repo1"]})
    km = KeyManager(config, db)
    gm = GitManager(tmp_path)
    ss = StaticScanner()
    oh = OpenHandsRunner()
    vf = Verifier()
    rl = RingBufferLogger()

    # Pre-populate some logs
    rl.log("INFO", "Initial test log 1")
    rl.log("WARN", "Initial test log 2")

    orch = Orchestrator(config, db, km, gm, ss, oh, vf, rl)
    app = create_app(orch, rl.broadcaster)
    client = TestClient(app)
    return client, orch, db


def test_get_dashboard_html(test_app):
    """Verify GET / returns dashboard HTML."""
    client, _, _ = test_app
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "AutoBugHunter" in resp.text


def test_get_api_state(test_app):
    """Verify GET /api/state returns complete state JSON."""
    client, _, db = test_app
    db.upsert_repository("owner/test-repo", status="IDLE")

    resp = client.get("/api/state")
    assert resp.status_code == 200
    data = resp.json()

    assert "daemon" in data
    assert "kpis" in data
    assert "repositories" in data
    assert "keys" in data
    assert "recent_prs" in data
    assert data["daemon"]["paused"] is False
    assert data["kpis"]["total_repos"] == 1


def test_post_toggle_pause(test_app):
    """Verify POST /api/control/toggle-pause toggles pause flag."""
    client, orch, _ = test_app
    assert orch.paused is False

    resp = client.post("/api/control/toggle-pause")
    assert resp.status_code == 200
    assert resp.json()["paused"] is True
    assert orch.paused is True

    resp2 = client.post("/api/control/toggle-pause")
    assert resp2.json()["paused"] is False
    assert orch.paused is False


def test_post_reset_exhausted(test_app):
    """Verify POST /api/control/reset-exhausted resets exhausted cache."""
    client, _, db = test_app
    db.upsert_repository("owner/r1")
    db.record_scan_result("owner/r1", "sha1", fully_exhausted=1)
    assert db.get_stats()["kpis"]["exhausted_repos"] == 1

    resp = client.post("/api/control/reset-exhausted")
    assert resp.status_code == 200
    assert resp.json()["reset_count"] == 1
    assert db.get_stats()["kpis"]["exhausted_repos"] == 0


def test_post_scan_now(test_app):
    """Verify POST /api/control/scan-now/{owner}/{repo} enqueues scan without blocking."""
    client, orch, _ = test_app
    resp = client.post("/api/control/scan-now/owner/manual-repo")
    assert resp.status_code == 200
    data = resp.json()
    assert data["repo"] == "owner/manual-repo"
    assert data["status"] == "queued"
    assert data["scan_result"] == {"status": "queued"}
    assert "owner/manual-repo" in orch.force_queue


def test_websocket_logs_replay(test_app):
    """Verify WebSocket /ws/logs connects and replays recent logs."""
    client, _, _ = test_app
    with client.websocket_connect("/ws/logs") as websocket:
        line1 = websocket.receive_text()
        line2 = websocket.receive_text()
        assert "Initial test log 1" in line1
        assert "Initial test log 2" in line2


# =========================================================================
# Security Unit Tests for Mission Control
# =========================================================================

def test_web_server_api_key_auth(tmp_path: Path):
    """Verify API key authentication enforcement on /api/control/* endpoints."""
    # 1. Backward compatibility: dashboard_api_key="" (empty) allows unauthenticated requests
    db1 = Database(tmp_path / "auth_empty.sqlite")
    k1 = KeyConfig("k1", "ScaleMax", "https://api.sm.ai/v1", "claude-haiku-5.5", "sk-12345678", "sk-1...5678", 1)
    cfg_empty = Config.load(overrides={"workspace_dir": tmp_path, "LLM_KEYS_POOL": [k1], "dashboard_api_key": ""})
    orch_empty = Orchestrator(cfg_empty, db1, KeyManager(cfg_empty, db1), GitManager(tmp_path), StaticScanner(), OpenHandsRunner(), Verifier(), RingBufferLogger())
    client_empty = TestClient(create_app(orch_empty))

    resp = client_empty.post("/api/control/toggle-pause")
    assert resp.status_code == 200

    # 2. Configured dashboard_api_key="secret123" enforces authentication
    db2 = Database(tmp_path / "auth_configured.sqlite")
    cfg_auth = Config.load(overrides={"workspace_dir": tmp_path, "LLM_KEYS_POOL": [k1], "DASHBOARD_API_KEY": "secret123"})
    orch_auth = Orchestrator(cfg_auth, db2, KeyManager(cfg_auth, db2), GitManager(tmp_path), StaticScanner(), OpenHandsRunner(), Verifier(), RingBufferLogger())
    client_auth = TestClient(create_app(orch_auth))

    # Unauthenticated request -> 401
    resp_unauth = client_auth.post("/api/control/toggle-pause")
    assert resp_unauth.status_code == 401
    assert resp_unauth.json()["detail"] == "Unauthorized"

    # Invalid X-API-Key -> 401
    resp_bad_x = client_auth.post("/api/control/toggle-pause", headers={"X-API-Key": "wrong_key"})
    assert resp_bad_x.status_code == 401

    # Invalid Bearer token -> 401
    resp_bad_bearer = client_auth.post("/api/control/toggle-pause", headers={"Authorization": "Bearer wrong_key"})
    assert resp_bad_bearer.status_code == 401

    # Valid X-API-Key: secret123 -> 200
    resp_valid_x = client_auth.post("/api/control/toggle-pause", headers={"X-API-Key": "secret123"})
    assert resp_valid_x.status_code == 200

    # Valid Authorization: Bearer secret123 -> 200
    resp_valid_bearer = client_auth.post("/api/control/toggle-pause", headers={"Authorization": "Bearer secret123"})
    assert resp_valid_bearer.status_code == 200

    # GET /api/state with auth
    resp_state_unauth = client_auth.get("/api/state")
    assert resp_state_unauth.status_code == 401

    resp_state_auth = client_auth.get("/api/state", headers={"X-API-Key": "secret123"})
    assert resp_state_auth.status_code == 200
    assert "daemon" in resp_state_auth.json()

    # 3. Remote client without API key -> 403 Forbidden
    client_remote = TestClient(create_app(orch_empty), client=("192.168.1.100", 54321))
    resp_remote_pause = client_remote.post("/api/control/toggle-pause")
    assert resp_remote_pause.status_code == 403
    assert "Remote access requires DASHBOARD_API_KEY" in resp_remote_pause.json()["detail"]

    resp_remote_state = client_remote.get("/api/state")
    assert resp_remote_state.status_code == 403

    # 4. Remote client with configured API key providing valid header -> 200 OK
    client_remote_auth = TestClient(create_app(orch_auth), client=("192.168.1.100", 54321))
    resp_remote_auth_ok = client_remote_auth.post("/api/control/toggle-pause", headers={"X-API-Key": "secret123"})
    assert resp_remote_auth_ok.status_code == 200


def test_web_server_slug_validation_on_scan_now(test_app):
    """Verify repository slug validation and path traversal rejection on POST /api/control/scan-now/{owner}/{repo}."""
    client, _, _ = test_app

    # Valid slug -> 200
    resp_valid = client.post("/api/control/scan-now/valid-owner/valid-repo")
    assert resp_valid.status_code == 200
    assert resp_valid.json()["repo"] == "valid-owner/valid-repo"

    # Path traversal and invalid slugs -> 400
    invalid_slug_pairs = [
        ("%2E%2E", "%2E%2E"),
        ("%2E%2E", "etc"),
        ("owner", "%2E%2E"),
        ("..owner", "repo"),
        ("owner..", "repo"),
        ("owner", "repo.."),
        ("owner", "..repo"),
        ("owner%5Csubdir", "repo"),
        ("owner", "repo%5Csub"),
        ("-invalid_flag", "repo"),
        ("owner", "-invalid_flag"),
        ("owner!bad", "repo"),
    ]
    for owner, repo in invalid_slug_pairs:
        resp = client.post(f"/api/control/scan-now/{owner}/{repo}")
        assert resp.status_code == 400, f"Expected 400 for ({owner}, {repo}), got {resp.status_code}"
        assert resp.json()["detail"] == "Invalid repository slug"



def test_web_server_defensive_security_headers(test_app):
    """Verify responses contain X-Frame-Options: DENY, X-Content-Type-Options: nosniff, and Content-Security-Policy."""
    client, _, _ = test_app

    resp_root = client.get("/")
    assert resp_root.headers.get("x-frame-options") == "DENY"
    assert resp_root.headers.get("x-content-type-options") == "nosniff"
    assert "default-src 'self'" in resp_root.headers.get("content-security-policy", "")
    assert resp_root.headers.get("referrer-policy") == "strict-origin-when-cross-origin"

    resp_state = client.get("/api/state")
    assert resp_state.headers.get("x-frame-options") == "DENY"
    assert resp_state.headers.get("x-content-type-options") == "nosniff"
    assert "default-src 'self'" in resp_state.headers.get("content-security-policy", "")


def test_web_server_websocket_token_auth(tmp_path: Path):
    """Verify WebSocket /ws/logs enforces token parameter when DASHBOARD_API_KEY is configured."""
    db = Database(tmp_path / "ws_auth.sqlite")
    k1 = KeyConfig("k1", "ScaleMax", "https://api.sm.ai/v1", "claude-haiku-5.5", "sk-12345678", "sk-1...5678", 1)
    cfg_auth = Config.load(overrides={"workspace_dir": tmp_path, "LLM_KEYS_POOL": [k1], "DASHBOARD_API_KEY": "ws_secret_token"})
    rl = RingBufferLogger()
    rl.log("INFO", "Log entry before WS auth")
    orch_auth = Orchestrator(cfg_auth, db, KeyManager(cfg_auth, db), GitManager(tmp_path), StaticScanner(), OpenHandsRunner(), Verifier(), rl)
    client_auth = TestClient(create_app(orch_auth, rl.broadcaster))

    # 1. Remote client without token -> rejected 1008
    client_remote_auth = TestClient(create_app(orch_auth, rl.broadcaster), client=("192.168.1.100", 50000))
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client_remote_auth.websocket_connect("/ws/logs"):
            pass
    assert exc_info.value.code == 1008

    # 1b. Loopback client without token -> rejected 1008
    with pytest.raises(WebSocketDisconnect) as exc_info_lb:
        with client_auth.websocket_connect("/ws/logs"):
            pass
    assert exc_info_lb.value.code == 1008

    # 2. Invalid token -> rejected 1008
    with pytest.raises(WebSocketDisconnect) as exc_info2:
        with client_auth.websocket_connect("/ws/logs?token=wrong_key"):
            pass
    assert exc_info2.value.code == 1008

    # 3. Valid token query param -> accepted
    with client_auth.websocket_connect("/ws/logs?token=ws_secret_token") as ws:
        msg = ws.receive_text()
        assert "Log entry before WS auth" in msg

    # 4. Remote client without configured key -> rejected 1008
    cfg_empty = Config.load(overrides={"workspace_dir": tmp_path, "LLM_KEYS_POOL": [k1], "DASHBOARD_API_KEY": ""})
    orch_empty = Orchestrator(cfg_empty, db, KeyManager(cfg_empty, db), GitManager(tmp_path), StaticScanner(), OpenHandsRunner(), Verifier(), rl)
    client_remote = TestClient(create_app(orch_empty, rl.broadcaster), client=("192.168.1.100", 50000))
    with pytest.raises(WebSocketDisconnect) as exc_info3:
        with client_remote.websocket_connect("/ws/logs"):
            pass
    assert exc_info3.value.code == 1008


def test_web_server_websocket_origin_validation(test_app):
    """Verify WebSocket Origin validation accepts localhost and rejects foreign origins."""
    client, _, _ = test_app

    # 1. Missing Origin (None) -> accepted
    with client.websocket_connect("/ws/logs") as ws:
        msg = ws.receive_text()
        assert len(msg) > 0

    # 2. Localhost Origin -> accepted
    with client.websocket_connect("/ws/logs", headers={"Origin": "http://localhost:8080"}) as ws:
        msg = ws.receive_text()
        assert len(msg) > 0

    with client.websocket_connect("/ws/logs", headers={"Origin": "http://127.0.0.1:8080"}) as ws:
        msg = ws.receive_text()
        assert len(msg) > 0

    # 3. Foreign/malicious Origin -> rejected/closed with code 1008
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/ws/logs", headers={"Origin": "http://evil.com"}):
            pass
    assert exc_info.value.code == 1008

    with pytest.raises(WebSocketDisconnect) as exc_info2:
        with client.websocket_connect("/ws/logs", headers={"Origin": "https://attacker.org"}):
            pass
    assert exc_info2.value.code == 1008


def test_websocket_origin_matches_host_header(test_app):
    """Verify WebSocket /ws/logs accepts Origin matching client Host header."""
    client, _, _ = test_app
    with client.websocket_connect(
        "/ws/logs",
        headers={"Host": "bughunter.internal:8080", "Origin": "http://bughunter.internal:8080"}
    ) as ws:
        msg = ws.receive_text()
        assert len(msg) > 0


def test_websocket_origin_allowed_origins_env(test_app, monkeypatch):
    """Verify WebSocket /ws/logs accepts Origin configured via ALLOWED_ORIGINS env var."""
    client, _, _ = test_app
    monkeypatch.setenv("ALLOWED_ORIGINS", "https://dashboard.corp.net, http://remote-dev:3000")

    with client.websocket_connect(
        "/ws/logs",
        headers={"Origin": "https://dashboard.corp.net"}
    ) as ws:
        msg = ws.receive_text()
        assert len(msg) > 0

    with client.websocket_connect(
        "/ws/logs",
        headers={"Origin": "http://remote-dev:3000"}
    ) as ws:
        msg = ws.receive_text()
        assert len(msg) > 0

    # Malicious origin not in ALLOWED_ORIGINS and not matching Host is rejected
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/ws/logs", headers={"Origin": "http://evil-corp.com"}):
            pass
    assert exc_info.value.code == 1008


def test_websocket_origin_allowed_origins_collection(test_app, monkeypatch):
    """Verify WebSocket /ws/logs supports list/set/tuple for allowed origins."""
    client, orch, _ = test_app
    # Set allowed_origins directly on orchestrator config as list
    orch.config.allowed_origins = ["https://app1.internal", "https://app2.internal"]
    monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)

    with client.websocket_connect(
        "/ws/logs",
        headers={"Origin": "https://app1.internal"}
    ) as ws:
        msg = ws.receive_text()
        assert len(msg) > 0

    # Set as set
    orch.config.allowed_origins = {"https://set-origin.io"}
    with client.websocket_connect(
        "/ws/logs",
        headers={"Origin": "https://set-origin.io"}
    ) as ws:
        msg = ws.receive_text()
        assert len(msg) > 0


def test_websocket_loopback_auth_enforcement_when_api_key_configured(tmp_path: Path):
    """Verify WebSocket connection from loopback without token is rejected with 1008 when DASHBOARD_API_KEY is configured, and accepted with valid token."""
    db = Database(tmp_path / "ws_loopback.sqlite")
    k1 = KeyConfig("k1", "ScaleMax", "https://api.sm.ai/v1", "claude-haiku-5.5", "sk-12345678", "sk-1...5678", 1)
    cfg_auth = Config.load(overrides={"workspace_dir": tmp_path, "LLM_KEYS_POOL": [k1], "DASHBOARD_API_KEY": "secret_loopback_key"})
    rl = RingBufferLogger()
    rl.log("INFO", "Loopback auth test log")
    orch_auth = Orchestrator(cfg_auth, db, KeyManager(cfg_auth, db), GitManager(tmp_path), StaticScanner(), OpenHandsRunner(), Verifier(), rl)

    # 1. Loopback client (127.0.0.1) without token -> rejected with 1008
    client_loopback = TestClient(create_app(orch_auth, rl.broadcaster), client=("127.0.0.1", 52000))
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client_loopback.websocket_connect("/ws/logs"):
            pass
    assert exc_info.value.code == 1008

    # 2. Loopback client (::1) without token -> rejected with 1008
    client_ipv6 = TestClient(create_app(orch_auth, rl.broadcaster), client=("::1", 52000))
    with pytest.raises(WebSocketDisconnect) as exc_info_ipv6:
        with client_ipv6.websocket_connect("/ws/logs"):
            pass
    assert exc_info_ipv6.value.code == 1008

    # 3. Default testclient without token -> rejected with 1008
    client_default = TestClient(create_app(orch_auth, rl.broadcaster))
    with pytest.raises(WebSocketDisconnect) as exc_info_default:
        with client_default.websocket_connect("/ws/logs"):
            pass
    assert exc_info_default.value.code == 1008

    # 4. Loopback client with valid token query param -> accepted
    with client_loopback.websocket_connect("/ws/logs?token=secret_loopback_key") as ws:
        msg = ws.receive_text()
        assert "Loopback auth test log" in msg

    # 5. Loopback client with valid X-API-Key header -> accepted
    with client_loopback.websocket_connect("/ws/logs", headers={"X-API-Key": "secret_loopback_key"}) as ws:
        msg = ws.receive_text()
        assert "Loopback auth test log" in msg

    # 6. Loopback client with valid Bearer token -> accepted
    with client_loopback.websocket_connect("/ws/logs", headers={"Authorization": "Bearer secret_loopback_key"}) as ws:
        msg = ws.receive_text()
        assert "Loopback auth test log" in msg



