# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Config file and token management for rhorizon CLI."""

import os
from pathlib import Path

import tomlkit

CONFIG_DIR = Path(os.environ.get("RH_CONFIG_DIR", "~/.config/rhorizon")).expanduser()
CONFIG_FILE = CONFIG_DIR / "config.toml"


def _ensure_dir():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)


def load_config() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    return tomlkit.loads(CONFIG_FILE.read_text())


def save_config(cfg: dict):
    _ensure_dir()
    CONFIG_FILE.write_text(tomlkit.dumps(cfg))
    os.chmod(CONFIG_FILE, 0o600)


def get_profile(name: str = "default") -> dict:
    cfg = load_config()
    return cfg.get(name, {})


def set_profile(name: str, url: str):
    cfg = load_config()
    cfg[name] = {"url": url}
    save_config(cfg)


def save_token(token: str, profile: str = "default"):
    _ensure_dir()
    token_path = CONFIG_DIR / f"token.{profile}"
    token_path.write_text(token)
    os.chmod(token_path, 0o600)


def load_token(profile: str = "default") -> str | None:
    """Load the auth token. Resolution order:
    1. RH_TOKEN env var (or legacy HKV_TOKEN)
    2. RH_TOKEN_STDIN=1 -> read one line from stdin (for CI / piped tokens
       that should never touch disk)
    3. ~/.config/rhorizon/token.<profile>
    """
    import sys

    env_token = os.environ.get("RH_TOKEN") or os.environ.get("HKV_TOKEN")
    if env_token:
        return env_token

    if os.environ.get("RH_TOKEN_STDIN") == "1":
        if sys.stdin.isatty():
            return None  # Don't block waiting for input on a TTY
        return sys.stdin.readline().strip() or None

    token_path = CONFIG_DIR / f"token.{profile}"
    if token_path.exists():
        return token_path.read_text().strip()
    return None


def get_url(profile: str = "default") -> str | None:
    # RH_ADDR/RH_URL are canonical; HKV_ADDR kept as a legacy alias (matches
    # load_token, which accepts RH_TOKEN then legacy HKV_TOKEN).
    env_url = (
        os.environ.get("RH_ADDR")
        or os.environ.get("RH_URL")
        or os.environ.get("HKV_ADDR")
    )
    if env_url:
        return env_url
    return get_profile(profile).get("url")
