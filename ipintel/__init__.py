from __future__ import annotations

from pathlib import Path
import json
import os

__version__ = "0.1.0"

_repo_root = Path(__file__).resolve().parent.parent
_legacy_root = _repo_root / "ip-intel"
if _legacy_root.exists():
    __path__.append(str(_legacy_root))


def _config_file() -> Path:
    configured = os.environ.get("IPINTEL_CONFIG")
    if configured:
        candidate = Path(configured).expanduser().resolve()
        if candidate.exists():
            return candidate

    for candidate in (_repo_root / "ipintel.json", _repo_root / ".ipintel.json"):
        if candidate.exists():
            return candidate

    return _repo_root / "ipintel.json"


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
