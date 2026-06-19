"""Config loader — merges defaults + hydrasight.json + env vars + .env file."""
import os
import json
import logging
from pathlib import Path
from typing import Any

from hydrasight.config.defaults import DEFAULT_CONFIG, _CONFIG_ALLOWED_KEYS

log = logging.getLogger("hydrasight")

# Optional python-dotenv support
try:
    from dotenv import load_dotenv as _load_dotenv
    _DOTENV_OK = True
except ImportError:
    _DOTENV_OK = False


def load_config(config_path: str = "hydrasight.json") -> dict[str, Any]:
    """
    Build runtime config dict in priority order (highest wins):
      env vars  >  .env file  >  hydrasight.json  >  DEFAULT_CONFIG
    """
    cfg: dict[str, Any] = dict(DEFAULT_CONFIG)

    # 1. .env file (if python-dotenv installed)
    if _DOTENV_OK:
        env_file = Path(".env")
        if env_file.exists():
            _load_dotenv(env_file, override=False)

    # 2. JSON config file
    cfg_path = Path(config_path)
    if cfg_path.exists():
        try:
            raw = json.loads(cfg_path.read_text(encoding="utf-8"))
            for k, v in raw.items():
                if k in _CONFIG_ALLOWED_KEYS:
                    cfg[k] = v
        except json.JSONDecodeError as exc:
            print(f"[!] {config_path} invalid: {exc}")
        except OSError as exc:
            print(f"[!] config read error: {exc}")

    # 3. Environment variables
    env_map: list[tuple[str, str, type]] = [
        ("HYDRA_OLLAMA_URL", "ollama_url",   str),
        ("HYDRA_KALI_URL",   "kali_api_url", str),
        ("HYDRA_MODEL",      "model",        str),
        ("HYDRA_VERBOSITY",  "verbosity",    int),
        ("HYDRA_LPORT",      "lport",        int),
        ("HYDRA_OUTPUT_DIR", "output_dir",   str),
        ("HYDRA_LOG_FILE",   "log_file",     str),
    ]
    for env, key, cast in env_map:
        val = os.environ.get(env)
        if val:
            try:
                cfg[key] = cast(val)
            except (ValueError, TypeError):
                log.warning("invalid env var %s=%s", env, val)

    # 4. Ensure output dir exists
    try:
        Path(cfg["output_dir"]).mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError) as exc:
        print(f"[!] cannot create output dir: {exc}")
        cfg["output_dir"] = "."

    # 5. Write defaults back on first run
    if not cfg_path.exists():
        try:
            cfg_path.write_text(
                json.dumps(cfg, indent=2), encoding="utf-8"
            )
        except OSError:
            pass

    return cfg
