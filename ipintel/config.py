from __future__ import annotations

from . import load_config


def get_config() -> dict:
    return load_config()


def get_runtime_settings() -> dict:
    config = get_config()
    return {
        "offline": bool(config.get("offline", True)),
        "no_third_party": bool(config.get("no_third_party", False)),
        "skip_icloud": bool(config.get("skip_icloud", False)),
        "mmdb": config.get("mmdb"),
        "no_sources": bool(config.get("no_sources", False)),
    }
