"""
Configuration loader and typed settings for AutoBugHunter 24/7.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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


DEFAULT_CURATED_REPOS: list[str] = [
    "bitxwolf/Airllm-tui",             # Priority 1
    "bitxwolf/orb",                    # Priority 2
    "bitxwolf/worldof3js",             # Priority 3
    "bitxwolf/medical-for-non-medics", # Priority 4
    # Priority 5: Dynamic non-fork repos created >= 2026-10-23
    "bitxwolf/BugHunter",              # Priority 6 (scanned last)
]


@dataclass
class Config:
    github_token: str
    target_repos: list[str] = field(default_factory=list)
    auto_discover_repos: bool = False
    llm_keys: list[KeyConfig] = field(default_factory=list)
    max_open_prs_per_repo: int = 7
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
    state_repo: str = ""
    openhands_runtime: str = "process"
    workspace_dir: Path = field(default_factory=Path.cwd)
    repos_dir: Path = field(default_factory=lambda: Path.cwd() / "repos")
    state_dir: Path = field(default_factory=lambda: Path.cwd() / "state")
    db_path: Path = field(default_factory=lambda: Path.cwd() / "state" / "bughunter.sqlite")
    log_file_path: Path = field(default_factory=lambda: Path.cwd() / "state" / "bughunter.log")
    log_ring_buffer_size: int = 500
    openai_api_base: str = "https://api.scalemax.pro/v1"
    openai_api_key: str = ""
    llm_model: str = "openai/gpt-6-luna"
    bot_github_user: str = "arrshh12"
    main_github_user: str = "bitxwolf"
    enable_auto_merge: bool = False

    @classmethod
    def load(
        cls,
        env_file: Path | None = None,
        overrides: dict[str, Any] | None = None,
    ) -> Config:
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
                env_vars[k.upper()] = v
                env_vars[k.lower()] = v

        def get_val(key: str, default: Any = None) -> Any:
            if key in env_vars:
                return env_vars[key]
            if key.lower() in env_vars:
                return env_vars[key.lower()]
            if key.upper() in env_vars:
                return env_vars[key.upper()]
            return default

        # Workspace and directory resolution
        ws_in_overrides = bool(overrides and any(k.lower() == "workspace_dir" for k in overrides))
        repos_in_overrides = bool(overrides and any(k.lower() == "repos_dir" for k in overrides))
        state_in_overrides = bool(overrides and any(k.lower() == "state_dir" for k in overrides))

        ws_raw = get_val("WORKSPACE_DIR", Path.cwd())
        workspace_dir = Path(ws_raw).resolve()

        if ws_in_overrides and not repos_in_overrides:
            repos_dir = (workspace_dir / "repos").resolve()
        else:
            repos_raw = get_val("REPOS_DIR", workspace_dir / "repos")
            repos_dir = Path(repos_raw).resolve()
        repos_dir.mkdir(parents=True, exist_ok=True)

        if ws_in_overrides and not state_in_overrides:
            state_dir = (workspace_dir / "state").resolve()
        else:
            state_raw = get_val("STATE_DIR", workspace_dir / "state")
            state_dir = Path(state_raw).resolve()
        state_dir.mkdir(parents=True, exist_ok=True)

        db_raw = get_val("DB_PATH", state_dir / "bughunter.sqlite")
        db_path = Path(db_raw).resolve()

        log_raw = get_val("LOG_FILE_PATH", state_dir / "bughunter.log")
        log_file_path = Path(log_raw).resolve()

        # Defaults for base_url and model
        default_base_url = (
            str(get_val("OPENAI_API_BASE") or "").strip()
            or str(get_val("OPENAI_BASE_URL") or "").strip()
            or str(get_val("LLM_BASE_URL") or "").strip()
            or "https://api.scalemax.pro/v1"
        )
        default_model = (
            str(get_val("LLM_MODEL") or "").strip()
            or str(get_val("OPENAI_MODEL") or "").strip()
            or "openai/gpt-6-luna"
        )

        # Parse LLM Keys pool
        keys_pool_val = get_val("LLM_KEYS_POOL", "")
        parsed_keys: list[KeyConfig] = []

        if isinstance(keys_pool_val, list):
            for idx, item in enumerate(keys_pool_val):
                if isinstance(item, KeyConfig):
                    parsed_keys.append(item)
                elif isinstance(item, dict):
                    k_api = str(item.get("api_key") or "").strip()
                    if not k_api:
                        continue
                    b_url = str(item.get("base_url") or "").strip() or default_base_url
                    mdl = str(item.get("model") or "").strip() or default_model
                    prov = item.get("provider") or ("ScaleMax" if "scalemax" in b_url.lower() or "scalemax" in mdl.lower() else "OpenAI")
                    try:
                        prio_raw = item.get("priority")
                        prio = int(prio_raw) if prio_raw is not None else (idx + 1)
                    except Exception:
                        prio = idx + 1
                    k_idx = len(parsed_keys) + 1
                    parsed_keys.append(KeyConfig(
                        id=item.get("id", f"key-{k_idx}"),
                        provider=prov,
                        base_url=b_url,
                        model=mdl,
                        api_key=k_api,
                        masked_key=item.get("masked_key", mask_key(k_api)),
                        priority=prio,
                    ))
                elif isinstance(item, str):
                    k_api = item.strip()
                    if not k_api:
                        continue
                    k_idx = len(parsed_keys) + 1
                    prov = "ScaleMax" if "scalemax" in default_base_url.lower() or "scalemax" in default_model.lower() else "OpenAI"
                    parsed_keys.append(KeyConfig(
                        id=f"key-{k_idx}",
                        provider=prov,
                        base_url=default_base_url,
                        model=default_model,
                        api_key=k_api,
                        masked_key=mask_key(k_api),
                        priority=k_idx,
                    ))
        elif isinstance(keys_pool_val, str) and keys_pool_val.strip():
            raw_str = keys_pool_val.strip()
            is_json = False
            # Check if JSON string
            if raw_str.startswith("[") or raw_str.startswith("{"):
                try:
                    loaded = json.loads(raw_str)
                    is_json = True
                    if isinstance(loaded, dict):
                        loaded = [loaded]
                    if isinstance(loaded, list):
                        for idx, item in enumerate(loaded):
                            if isinstance(item, dict):
                                k_api = str(item.get("api_key") or "").strip()
                                if not k_api:
                                    continue
                                b_url = str(item.get("base_url") or "").strip() or default_base_url
                                mdl = str(item.get("model") or "").strip() or default_model
                                prov = item.get("provider") or ("ScaleMax" if "scalemax" in b_url.lower() or "scalemax" in mdl.lower() else "OpenAI")
                                try:
                                    prio_raw = item.get("priority")
                                    prio = int(prio_raw) if prio_raw is not None else (idx + 1)
                                except Exception:
                                    prio = idx + 1
                                k_idx = len(parsed_keys) + 1
                                parsed_keys.append(KeyConfig(
                                    id=item.get("id", f"key-{k_idx}"),
                                    provider=prov,
                                    base_url=b_url,
                                    model=mdl,
                                    api_key=k_api,
                                    masked_key=item.get("masked_key", mask_key(k_api)),
                                    priority=prio,
                                ))
                            elif isinstance(item, str):
                                k_api = item.strip()
                                if not k_api:
                                    continue
                                k_idx = len(parsed_keys) + 1
                                prov = "ScaleMax" if "scalemax" in default_base_url.lower() or "scalemax" in default_model.lower() else "OpenAI"
                                parsed_keys.append(KeyConfig(
                                    id=f"key-{k_idx}",
                                    provider=prov,
                                    base_url=default_base_url,
                                    model=default_model,
                                    api_key=k_api,
                                    masked_key=mask_key(k_api),
                                    priority=k_idx,
                                ))
                except Exception:
                    pass

            if not parsed_keys and not is_json:
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
                    if len(parts) == 1 and parts[0]:
                        k_api = parts[0]
                        k_idx = len(parsed_keys) + 1
                        provider = "ScaleMax" if "scalemax" in default_base_url.lower() or "scalemax" in default_model.lower() else "OpenAI"
                        parsed_keys.append(KeyConfig(
                            id=f"key-{k_idx}",
                            provider=provider,
                            base_url=default_base_url,
                            model=default_model,
                            api_key=k_api,
                            masked_key=mask_key(k_api),
                            priority=k_idx,
                        ))
                    elif len(parts) == 3:
                        b_url = parts[0].strip() or default_base_url
                        mdl = parts[1].strip() or default_model
                        k_api = parts[2].strip()
                        if not k_api:
                            continue
                        k_idx = len(parsed_keys) + 1
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
                        prov = parts[0].strip()
                        b_url = parts[1].strip() or default_base_url
                        mdl = parts[2].strip() or default_model
                        k_api = parts[3].strip()
                        if not k_api:
                            continue
                        k_idx = len(parsed_keys) + 1
                        provider = prov or ("ScaleMax" if "scalemax" in b_url.lower() or "scalemax" in mdl.lower() else "OpenAI")
                        parsed_keys.append(KeyConfig(
                            id=f"key-{k_idx}",
                            provider=provider,
                            base_url=b_url,
                            model=mdl,
                            api_key=k_api,
                            masked_key=mask_key(k_api),
                            priority=k_idx,
                        ))

        # Check OPENAI_API_KEY / LLM_API_KEY if no keys were parsed from pool
        if not parsed_keys:
            single_key = (
                str(get_val("OPENAI_API_KEY") or "").strip()
                or str(get_val("LLM_API_KEY") or "").strip()
            )
            if single_key and single_key != "NO_LLM_KEY_CONFIGURED":
                provider = "ScaleMax" if "scalemax" in default_base_url.lower() or "scalemax" in default_model.lower() else "OpenAI"
                parsed_keys.append(KeyConfig(
                    id="key-1",
                    provider=provider,
                    base_url=default_base_url,
                    model=default_model,
                    api_key=single_key,
                    masked_key=mask_key(single_key),
                    priority=1,
                ))

        # Default fallback key if none provided
        if not parsed_keys:
            parsed_keys.append(KeyConfig(
                id="key-1",
                provider="ScaleMax",
                base_url=default_base_url,
                model=default_model,
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

        primary_key = parsed_keys[0].api_key if parsed_keys else ""
        primary_base = parsed_keys[0].base_url if parsed_keys else default_base_url
        primary_model = parsed_keys[0].model if parsed_keys else default_model

        # RULE-NO-AUTOMERGE validation: Auto-merging is strictly prohibited
        auto_merge_val = get_val("ENABLE_AUTO_MERGE", False)
        if isinstance(auto_merge_val, str) and auto_merge_val.strip().lower() in ("true", "1", "yes"):
            raise ValueError("RULE-NO-AUTOMERGE Violation: Auto-merging is strictly prohibited. Merging is reserved solely for human @bitxwolf.")
        if auto_merge_val is True:
            raise ValueError("RULE-NO-AUTOMERGE Violation: Auto-merging is strictly prohibited. Merging is reserved solely for human @bitxwolf.")

        bot_token = str(get_val("BOT_GITHUB_TOKEN") or get_val("GITHUB_TOKEN") or "")
        bot_user = str(get_val("BOT_GITHUB_USER", "arrshh12")).strip() or "arrshh12"
        main_user = str(get_val("MAIN_GITHUB_USER", "bitxwolf")).strip() or "bitxwolf"

        return cls(
            github_token=bot_token,
            target_repos=target_repos,
            auto_discover_repos=auto_discover,
            llm_keys=parsed_keys,
            max_open_prs_per_repo=int(get_val("MAX_OPEN_PRS_PER_REPO", 7)),
            max_files_per_pr=int(get_val("MAX_FILES_PER_PR", 3)),
            max_diff_lines=int(get_val("MAX_DIFF_LINES", 150)),
            scan_cooldown_seconds=int(get_val("SCAN_COOLDOWN_SECONDS", 60)),
            agent_timeout_seconds=int(get_val("AGENT_TIMEOUT_SECONDS", 1200)),
            static_scan_timeout_seconds=int(get_val("STATIC_SCAN_TIMEOUT_SECONDS", 90)),
            git_timeout_seconds=int(get_val("GIT_TIMEOUT_SECONDS", 120)),
            preflight_timeout_seconds=int(get_val("PREFLIGHT_TIMEOUT_SECONDS", 5)),
            dashboard_host=str(get_val("DASHBOARD_HOST", "0.0.0.0" if (os.getenv("SPACE_ID") or os.getenv("PORT")) else "127.0.0.1")),
            dashboard_port=int(get_val("DASHBOARD_PORT", get_val("PORT", 8080))),
            dashboard_api_key=str(get_val("DASHBOARD_API_KEY", "")),
            state_repo=str(get_val("STATE_REPO", "")).strip(),
            openhands_runtime=str(get_val("OPENHANDS_RUNTIME", get_val("RUNTIME", "process"))),
            workspace_dir=workspace_dir,
            repos_dir=repos_dir,
            state_dir=state_dir,
            db_path=db_path,
            log_file_path=log_file_path,
            log_ring_buffer_size=int(get_val("LOG_RING_BUFFER_SIZE", 500)),
            openai_api_base=primary_base,
            openai_api_key=primary_key if primary_key != "NO_LLM_KEY_CONFIGURED" else "",
            llm_model=primary_model,
            bot_github_user=bot_user,
            main_github_user=main_user,
            enable_auto_merge=False,
        )


Config.DEFAULT_CURATED_REPOS = DEFAULT_CURATED_REPOS

