"""
Multi-Key Circuit Breaker and Key Rotator for AutoBugHunter 24/7.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional
import requests

from src.config import Config, KeyConfig
from src.database import Database


class KeyManager:
    """Manages LLM API key pools with pre-flight ping, exponential cooldown, and 24h quota exhaustion."""

    def __init__(self, config: Config, database: Database):
        self.config = config
        self.database = database
        self._sync_keys_to_db()

    def _sync_keys_to_db(self) -> None:
        """Synchronize configured keys into the database ledger."""
        for k in self.config.llm_keys:
            self.database.upsert_api_key(
                key_id=k.id,
                provider=k.provider,
                model=k.model,
                base_url=k.base_url,
                masked_key=k.masked_key,
                state="HEALTHY"
            )

    @staticmethod
    def mask_key(api_key: str) -> str:
        """Mask API key showing only first 4 and last 4 characters."""
        if not api_key:
            return "****"
        if len(api_key) <= 8:
            return "****"
        return f"{api_key[:4]}...{api_key[-4:]}"

    def calculate_cooldown_seconds(self, consecutive_failures: int) -> int:
        """Calculate exponential backoff cooldown: T = min(3600, 60 * 2^(F-1))."""
        if consecutive_failures <= 0:
            return 60
        power = max(0, consecutive_failures - 1)
        val = 60 * (2 ** power)
        return min(3600, val)

    def get_next_healthy_key(self) -> Optional[KeyConfig]:
        """Promote expired cooldown keys to HEALTHY and return highest priority healthy key."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.database.get_connection() as conn:
            # Promote expired cooldown and exhausted keys
            conn.execute("""
                UPDATE api_key_status
                SET state = 'HEALTHY', cooldown_until = NULL
                WHERE state IN ('COOLDOWN', 'EXHAUSTED') AND cooldown_until IS NOT NULL AND cooldown_until <= ?
            """, (now_iso,))

            healthy_rows = conn.execute(
                "SELECT key_id FROM api_key_status WHERE state = 'HEALTHY'"
            ).fetchall()
            healthy_ids = {row["key_id"] for row in healthy_rows}

        # Return the key with lowest priority number (1 is primary)
        for k in sorted(self.config.llm_keys, key=lambda x: x.priority):
            if k.id in healthy_ids:
                return k
        return None

    def preflight_check(self, key: KeyConfig, simulated_response_code: Optional[int] = None) -> bool:
        """Send a 1-token /v1/chat/completions request with 5s timeout to verify key viability."""
        if simulated_response_code is not None:
            if simulated_response_code == 200:
                return True
            elif simulated_response_code == 429:
                self.report_key_failure(key.id, "Rate limit exceeded (HTTP 429)", status_code=429)
                return False
            elif simulated_response_code == 402:
                self.report_key_failure(key.id, "Insufficient quota (HTTP 402)", status_code=402)
                return False
            else:
                self.report_key_failure(
                    key.id,
                    f"Upstream error HTTP {simulated_response_code}",
                    status_code=simulated_response_code
                )
                return False

        url = f"{key.base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {key.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": key.model,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1
        }

        try:
            resp = requests.post(
                url,
                headers=headers,
                json=payload,
                timeout=self.config.preflight_timeout_seconds
            )
            if resp.status_code == 200:
                return True
            elif resp.status_code == 429:
                self.report_key_failure(key.id, f"Rate limit exceeded (HTTP 429): {resp.text[:100]}", status_code=429)
                return False
            elif resp.status_code == 402 or "insufficient_quota" in resp.text.lower():
                self.report_key_failure(key.id, f"Insufficient quota (HTTP 402): {resp.text[:100]}", status_code=402)
                return False
            else:
                self.report_key_failure(
                    key.id,
                    f"Upstream HTTP {resp.status_code}: {resp.text[:100]}",
                    status_code=resp.status_code
                )
                return False
        except requests.exceptions.Timeout:
            self.report_key_failure(key.id, "Preflight ping timeout (5s)", status_code=504)
            return False
        except requests.exceptions.RequestException as e:
            self.report_key_failure(key.id, f"Connection error: {str(e)[:100]}", status_code=500)
            return False

    def report_key_failure(self, key_id: str, error_message: str, status_code: Optional[int] = None) -> None:
        """Trip circuit breaker to COOLDOWN (exponential backoff) or EXHAUSTED (24h for 402)."""
        with self.database.get_connection() as conn:
            row = conn.execute(
                "SELECT consecutive_failures FROM api_key_status WHERE key_id = ?",
                (key_id,)
            ).fetchone()
            curr_fail = (row["consecutive_failures"] if row else 0) + 1

        is_quota = (status_code == 402) or ("insufficient_quota" in error_message.lower())
        if is_quota:
            state = "EXHAUSTED"
            cd_until = (datetime.now(timezone.utc) + timedelta(seconds=86400)).isoformat()
        else:
            state = "COOLDOWN"
            cd_secs = self.calculate_cooldown_seconds(curr_fail)
            cd_until = (datetime.now(timezone.utc) + timedelta(seconds=cd_secs)).isoformat()

        self.database.update_api_key_status(key_id, state, curr_fail, cd_until, error_message)

    def report_key_success(self, key_id: str) -> None:
        """Record successful key usage and reset consecutive failures."""
        self.database.record_api_key_usage(key_id, success=True)
