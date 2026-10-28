from __future__ import annotations

import json
import os
from pathlib import Path

__version__ = "0.1.0"

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _config_file() -> Path:
    configured = os.environ.get("IPINTEL_CONFIG")
    if configured:
        candidate = Path(configured).expanduser().resolve()
        if candidate.exists():
            return candidate

    for candidate in (_REPO_ROOT / "ipintel.json", _REPO_ROOT / ".ipintel.json"):
        if candidate.exists():
            return candidate

    return _REPO_ROOT / "ipintel.json"


def load_config() -> dict:
    config = {
        "offline": True,
        "no_third_party": False,
        "skip_icloud": False,
        "mmdb": None,
        "no_sources": False,
    }

    path = _config_file()
    if not path.exists():
        try:
            path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        except OSError:
            pass
        return config

    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return config

    if isinstance(loaded, dict):
        config.update({k: v for k, v in loaded.items() if v is not None})

    if "online" in loaded and "offline" not in loaded:
        config["offline"] = not bool(loaded["online"])
    if "offline" in loaded:
        config["offline"] = bool(loaded["offline"])

    return config
