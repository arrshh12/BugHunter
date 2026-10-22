"""
Configuration loader and typed settings for AutoBugHunter 24/7.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from dotenv import dotenv_values


@dataclass
class KeyConfig:
    id: str
    provider: str
    base_url: str
    model: str
    api_key: str
    masked_key: str
    priority: int = 1


def mask_key(api_key: str) -> str:
    """Mask an API key showing only first 4 and last 4 characters, or **** if <= 8 chars."""
    if not api_key:
        return "****"
    if len(api_key) <= 8:
        return "****"
    return f"{api_key[:4]}...{api_key[-4:]}"


@dataclass
class Config:
    github_token: str
    target_repos: list[str] = field(default_factory=list)
    auto_discover_repos: bool = False
    llm_keys: list[KeyConfig] = field(default_factory=list)
    max_open_prs_per_repo: int = 5
    max_files_per_pr: int = 3
    max_diff_lines: int = 150
    scan_cooldown_seconds: int = 60
    agent_timeout_seconds: int = 1200
    static_scan_timeout_seconds: int = 90
    git_timeout_seconds: int = 120
    preflight_timeout_seconds: int = 5
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8080
    dashboard_api_key: str = ""
    openhands_runtime: str = "process"
    workspace_dir: Path = field(default_factory=Path.cwd)
    repos_dir: Path = field(default_factory=lambda: Path.cwd() / "repos")
    state_dir: Path = field(default_factory=lambda: Path.cwd() / "state")
    db_path: Path = field(default_factory=lambda: Path.cwd() / "state" / "bughunter.sqlite")
    log_file_path: Path = field(default_factory=lambda: Path.cwd() / "state" / "bughunter.log")
    log_ring_buffer_size: int = 500

    @classmethod
    def load(
        cls,
        env_file: Optional[Path] = None,
        overrides: Optional[dict[str, Any]] = None,
    ) -> "Config":
        """Load configuration from .env file, environment variables, and programmatic overrides."""
        env_vars: dict[str, str] = {}

        # 1. Load from .env file if available
        target_env = env_file if env_file else (Path.cwd() / ".env")
        if target_env.exists() and target_env.is_file():
            try:
                loaded_env = dotenv_values(dotenv_path=target_env)
                for k, v in loaded_env.items():
                    if k is not None and v is not None:
                        env_vars[k] = str(v)
            except Exception:
                pass

        # 2. Merge with OS environment variables (os.environ takes precedence over .env file)
        for k, v in os.environ.items():
            env_vars[k] = v

        # 3. Apply programmatic overrides (highest precedence)
        if overrides:
            for k, v in overrides.items():
                env_vars[k] = v

        def get_val(key: str, default: Any = None) -> Any:
            return env_vars.get(key, default)

        # Workspace and directory resolution
        ws_raw = get_val("WORKSPACE_DIR", Path.cwd())
        workspace_dir = Path(ws_raw).resolve()

        repos_raw = get_val("REPOS_DIR", workspace_dir / "repos")
        repos_dir = Path(repos_raw).resolve()
        repos_dir.mkdir(parents=True, exist_ok=True)

        state_raw = get_val("STATE_DIR", workspace_dir / "state")
        state_dir = Path(state_raw).resolve()
        state_dir.mkdir(parents=True, exist_ok=True)

        db_raw = get_val("DB_PATH", state_dir / "bughunter.sqlite")
        db_path = Path(db_raw).resolve()

        log_raw = get_val("LOG_FILE_PATH", state_dir / "bughunter.log")
        log_file_path = Path(log_raw).resolve()

        # Parse LLM Keys pool
        keys_pool_val = get_val("LLM_KEYS_POOL", "")
        parsed_keys: list[KeyConfig] = []

        if isinstance(keys_pool_val, list):
            for idx, item in enumerate(keys_pool_val):
                if isinstance(item, KeyConfig):
                    parsed_keys.append(item)
                elif isinstance(item, dict):
                    k_api = item.get("api_key", "")
                    parsed_keys.append(KeyConfig(
                        id=item.get("id", f"key-{idx+1}"),
                        provider=item.get("provider", "ScaleMax" if "scalemax" in item.get("base_url", "").lower() else "OpenAI"),
                        base_url=item.get("base_url", ""),
                        model=item.get("model", ""),
                        api_key=k_api,
                        masked_key=item.get("masked_key", mask_key(k_api)),
                        priority=int(item.get("priority", idx + 1)),
                    ))
        elif isinstance(keys_pool_val, str) and keys_pool_val.strip():
            raw_str = keys_pool_val.strip()
            # Check if JSON string
            if raw_str.startswith("[") or raw_str.startswith("{"):
                try:
                    loaded = json.loads(raw_str)
                    if isinstance(loaded, dict):
                        loaded = [loaded]
                    for idx, item in enumerate(loaded):
                        k_api = item.get("api_key", "")
                        parsed_keys.append(KeyConfig(
                            id=item.get("id", f"key-{idx+1}"),
                            provider=item.get("provider", "ScaleMax" if "scalemax" in item.get("base_url", "").lower() else "OpenAI"),
                            base_url=item.get("base_url", ""),
                            model=item.get("model", ""),
                            api_key=k_api,
                            masked_key=item.get("masked_key", mask_key(k_api)),
                            priority=int(item.get("priority", idx + 1)),
                        ))
                except Exception:
                    pass

            if not parsed_keys:
                # Semicolon, comma, or newline separated
                delimiters = [";", "\n", ","]
                entries = [raw_str]
                for d in delimiters:
                    new_entries = []
                    for e in entries:
                        new_entries.extend(e.split(d))
                    entries = new_entries

                for entry in entries:
                    entry = entry.strip()
                    if not entry:
                        continue
                    parts = [p.strip() for p in entry.split("|")]
                    k_idx = len(parsed_keys) + 1
                    if len(parts) == 3:
                        b_url, mdl, k_api = parts[0], parts[1], parts[2]
                        provider = "ScaleMax" if "scalemax" in b_url.lower() or "scalemax" in mdl.lower() else "OpenAI"
                        parsed_keys.append(KeyConfig(
                            id=f"key-{k_idx}",
                            provider=provider,
                            base_url=b_url,
                            model=mdl,
                            api_key=k_api,
                            masked_key=mask_key(k_api),
                            priority=k_idx,
                        ))
                    elif len(parts) >= 4:
                        provider, b_url, mdl, k_api = parts[0], parts[1], parts[2], parts[3]
                        parsed_keys.append(KeyConfig(
                            id=f"key-{k_idx}",
                            provider=provider,
                            base_url=b_url,
                            model=mdl,
                            api_key=k_api,
                            masked_key=mask_key(k_api),
                            priority=k_idx,
                        ))

        # Default fallback key if none provided
        if not parsed_keys:
            parsed_keys.append(KeyConfig(
                id="key-1",
                provider="ScaleMax",
                base_url="https://api.scalemax.ai/v1",
                model="openai/claude-haiku-5.5",
                api_key="NO_LLM_KEY_CONFIGURED",
                masked_key="NO_KEY",
                priority=1,
            ))

        # Target repositories
        target_repos_val = get_val("TARGET_REPOS", "")
        if isinstance(target_repos_val, list):
            target_repos = [str(r).strip() for r in target_repos_val if str(r).strip()]
        else:
            target_repos = [r.strip() for r in str(target_repos_val).split(",") if r.strip()]

        # Booleans
        auto_discover_val = get_val("AUTO_DISCOVER_REPOS", False)
        if isinstance(auto_discover_val, str):
            auto_discover = auto_discover_val.lower() in ("true", "1", "yes")
        else:
            auto_discover = bool(auto_discover_val)

        return cls(
            github_token=str(get_val("GITHUB_TOKEN", "")),
            target_repos=target_repos,
            auto_discover_repos=auto_discover,
            llm_keys=parsed_keys,
            max_open_prs_per_repo=int(get_val("MAX_OPEN_PRS_PER_REPO", 5)),
            max_files_per_pr=int(get_val("MAX_FILES_PER_PR", 3)),
            max_diff_lines=int(get_val("MAX_DIFF_LINES", 150)),
            scan_cooldown_seconds=int(get_val("SCAN_COOLDOWN_SECONDS", 60)),
            agent_timeout_seconds=int(get_val("AGENT_TIMEOUT_SECONDS", 1200)),
            static_scan_timeout_seconds=int(get_val("STATIC_SCAN_TIMEOUT_SECONDS", 90)),
            git_timeout_seconds=int(get_val("GIT_TIMEOUT_SECONDS", 120)),
            preflight_timeout_seconds=int(get_val("PREFLIGHT_TIMEOUT_SECONDS", 5)),
            dashboard_host=str(get_val("DASHBOARD_HOST", "127.0.0.1")),
            dashboard_port=int(get_val("DASHBOARD_PORT", 8080)),
            dashboard_api_key=str(get_val("DASHBOARD_API_KEY", "")),
            openhands_runtime=str(get_val("OPENHANDS_RUNTIME", get_val("RUNTIME", "process"))),
            workspace_dir=workspace_dir,
            repos_dir=repos_dir,
            state_dir=state_dir,
            db_path=db_path,
            log_file_path=log_file_path,
            log_ring_buffer_size=int(get_val("LOG_RING_BUFFER_SIZE", 500)),
        )
