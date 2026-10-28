"""Tiny HTTP + cache helpers (stdlib only)."""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

USER_AGENT = "ip-intel/0.1 (one-off fraud research tool)"
CACHE_DIR = Path(os.environ.get("IPINTEL_CACHE", Path.home() / ".cache" / "ip-intel"))
TIMEOUT = 10


def get(url: str, headers: dict | None = None) -> tuple[bytes, str]:
    """Return (body, final_url_after_redirects)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    for attempt in (1, 2):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return resp.read(), resp.geturl()
        except urllib.error.HTTPError:
            raise
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            if attempt == 2:
                raise
            time.sleep(1)


def get_json(url: str, headers: dict | None = None) -> tuple[dict, str]:
    body, final = get(url, headers)
    return json.loads(body), final


def get_cached(url: str, ttl_seconds: int) -> bytes:
    """Download a bulk list and cache it on disk. Used for Tor and cloud range lists."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = CACHE_DIR / hashlib.sha1(url.encode()).hexdigest()
    if path.exists() and time.time() - path.stat().st_mtime < ttl_seconds:
        return path.read_bytes()
    body, _ = get(url)
    path.write_bytes(body)
    return body
