"""
Unit tests for src/key_manager.py: Multi-key circuit breaker, exponential backoff, 24h exhaustion, and preflight pings.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from src.config import Config, KeyConfig
from src.database import Database
from src.key_manager import KeyManager


@pytest.fixture
def test_setup(tmp_path: Path):
    db_file = tmp_path / "keys_test.sqlite"
    db = Database(db_file)
    k1 = KeyConfig("k1", "ScaleMax", "https://api.sm.ai/v1", "claude-haiku-5.5", "sk-sm-11111111", "sk-s...1111", 1)
    k2 = KeyConfig("k2", "ScaleMax", "https://api.sm.ai/v1", "claude-haiku-5.5", "sk-sm-22222222", "sk-s...2222", 2)
    k3 = KeyConfig("k3", "OpenRouter", "https://openrouter.ai/api/v1", "deepseek/v3", "sk-or-33333333", "sk-o...3333", 3)
    config = Config.load(overrides={"workspace_dir": tmp_path, "LLM_KEYS_POOL": [k1, k2, k3]})
    km = KeyManager(config, db)
    return km, db, config


def test_key_manager_init_and_priority_selection(test_setup):
    """Verify keys are synced to DB and selected by priority order."""
    km, db, _ = test_setup
    key = km.get_next_healthy_key()
    assert key is not None
    assert key.id == "k1"
    assert key.priority == 1


def test_cooldown_calculation(test_setup):
    """Verify exponential backoff formula: min(3600, 60 * 2^(F-1))."""
    km, _, _ = test_setup
    assert km.calculate_cooldown_seconds(0) == 60
    assert km.calculate_cooldown_seconds(1) == 60
    assert km.calculate_cooldown_seconds(2) == 120
    assert km.calculate_cooldown_seconds(3) == 240
    assert km.calculate_cooldown_seconds(4) == 480
    assert km.calculate_cooldown_seconds(10) == 3600  # capped


def test_key_failover_on_429(test_setup):
    """Verify key is tripped to COOLDOWN on 429 and next priority key is selected."""
    km, db, _ = test_setup
    k1 = km.get_next_healthy_key()
    assert k1.id == "k1"

    # Report 429 failure
    km.report_key_failure("k1", "Rate limit reached", status_code=429)

    with db.get_connection() as conn:
        row = conn.execute("SELECT state, consecutive_failures, cooldown_until FROM api_key_status WHERE key_id='k1'").fetchone()
        assert row["state"] == "COOLDOWN"
        assert row["consecutive_failures"] == 1
        assert row["cooldown_until"] is not None

    # Next key should be k2
    k2 = km.get_next_healthy_key()
    assert k2 is not None
    assert k2.id == "k2"


def test_quota_exhaustion_on_402(test_setup):
    """Verify key is disabled for 24 hours (EXHAUSTED) on HTTP 402 or insufficient_quota."""
    km, db, _ = test_setup
    km.report_key_failure("k1", "insufficient_quota: balance is 0", status_code=402)

    with db.get_connection() as conn:
        row = conn.execute("SELECT state, cooldown_until FROM api_key_status WHERE key_id='k1'").fetchone()
        assert row["state"] == "EXHAUSTED"
        cd = datetime.fromisoformat(row["cooldown_until"])
        now = datetime.now(timezone.utc)
        # Should be roughly 24 hours in the future
        diff_hours = (cd - now).total_seconds() / 3600
        assert 23.5 <= diff_hours <= 24.5


def test_cooldown_recovery(test_setup):
    """Verify expired cooldown keys are automatically promoted back to HEALTHY."""
    km, db, _ = test_setup
    # Manually place k1 into COOLDOWN with timestamp in the past
    past_iso = (datetime.now(timezone.utc) - timedelta(seconds=100)).isoformat()
    db.update_api_key_status("k1", state="COOLDOWN", consecutive_failures=1, cooldown_until=past_iso)

    # get_next_healthy_key should promote k1 and return it
    key = km.get_next_healthy_key()
    assert key is not None
    assert key.id == "k1"

    with db.get_connection() as conn:
        row = conn.execute("SELECT state, cooldown_until FROM api_key_status WHERE key_id='k1'").fetchone()
        assert row["state"] == "HEALTHY"
        assert row["cooldown_until"] is None


def test_preflight_check_simulation(test_setup):
    """Verify preflight check passes on 200 and trips circuit breaker on errors."""
    km, db, _ = test_setup
    k1 = km.config.llm_keys[0]

    assert km.preflight_check(k1, simulated_response_code=200) is True

    # 429
    assert km.preflight_check(k1, simulated_response_code=429) is False
    with db.get_connection() as conn:
        assert conn.execute("SELECT state FROM api_key_status WHERE key_id='k1'").fetchone()["state"] == "COOLDOWN"

    # Reset k1
    db.update_api_key_status("k1", state="HEALTHY", consecutive_failures=0, cooldown_until=None)

    # 402
    assert km.preflight_check(k1, simulated_response_code=402) is False
    with db.get_connection() as conn:
        assert conn.execute("SELECT state FROM api_key_status WHERE key_id='k1'").fetchone()["state"] == "EXHAUSTED"


def test_all_keys_exhausted_returns_none(test_setup):
    """Verify None is returned when all keys in pool are in COOLDOWN or EXHAUSTED."""
    km, _, _ = test_setup
    km.report_key_failure("k1", "429", status_code=429)
    km.report_key_failure("k2", "429", status_code=429)
    km.report_key_failure("k3", "402", status_code=402)

    assert km.get_next_healthy_key() is None


def test_report_key_success(test_setup):
    """Verify report_key_success resets consecutive failures and increments counters."""
    km, db, _ = test_setup
    db.update_api_key_status("k1", state="HEALTHY", consecutive_failures=3, cooldown_until=None)
    km.report_key_success("k1")

    with db.get_connection() as conn:
        row = conn.execute("SELECT total_uses, total_successes, consecutive_failures FROM api_key_status WHERE key_id='k1'").fetchone()
        assert row["total_uses"] == 1
        assert row["total_successes"] == 1
        assert row["consecutive_failures"] == 0


def test_exhausted_key_recovery(test_setup):
    """Verify expired EXHAUSTED keys are automatically promoted back to HEALTHY when cooldown elapses."""
    km, db, _ = test_setup
    past_iso = (datetime.now(timezone.utc) - timedelta(seconds=100)).isoformat()
    db.update_api_key_status("k1", state="EXHAUSTED", consecutive_failures=1, cooldown_until=past_iso)

    key = km.get_next_healthy_key()
    assert key is not None
    assert key.id == "k1"

    with db.get_connection() as conn:
        row = conn.execute("SELECT state, cooldown_until FROM api_key_status WHERE key_id='k1'").fetchone()
        assert row["state"] == "HEALTHY"
        assert row["cooldown_until"] is None


def test_unexpired_exhausted_key_remains_ineligible(test_setup):
    """Verify EXHAUSTED key with future cooldown timestamp is NOT promoted and remains EXHAUSTED."""
    km, db, _ = test_setup
    future_iso = (datetime.now(timezone.utc) + timedelta(seconds=86400)).isoformat()
    db.update_api_key_status("k1", state="EXHAUSTED", consecutive_failures=1, cooldown_until=future_iso)

    # Next key should skip k1 and return k2
    key = km.get_next_healthy_key()
    assert key is not None
    assert key.id == "k2"

    with db.get_connection() as conn:
        row = conn.execute("SELECT state, cooldown_until FROM api_key_status WHERE key_id='k1'").fetchone()
        assert row["state"] == "EXHAUSTED"
        assert row["cooldown_until"] is not None


