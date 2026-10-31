"""Load and validate config.yaml. Secrets never live here, only in the environment."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

SOURCE_TYPES = {"rss", "cisa_kev", "vulncheck_kev", "nvd", "hn"}
CATEGORIES = {"vulnerabilities", "security", "tech", "world"}


class ConfigError(Exception):
    pass


def load_config(path: str | os.PathLike = "config.yaml") -> dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"config file not found: {p}")
    with p.open(encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    validate(cfg)
    return cfg


def validate(cfg: Any) -> None:
    if not isinstance(cfg, dict):
        raise ConfigError("config root must be a mapping")
    for key in ("settings", "scoring", "sources", "watchlist", "keywords"):
        if key not in cfg:
            raise ConfigError(f"config is missing section: {key}")
    names: set[str] = set()
    for src in cfg["sources"]:
        name = src.get("name")
        if not name:
            raise ConfigError(f"source without a name: {src}")
        if name in names:
            raise ConfigError(f"duplicate source name: {name}")
        names.add(name)
        if src.get("type") not in SOURCE_TYPES:
            raise ConfigError(f"{name}: unknown type {src.get('type')!r}")
        if src.get("category") not in CATEGORIES:
            raise ConfigError(f"{name}: unknown category {src.get('category')!r}")
        url = src.get("url", "")
        if not url.startswith(("https://", "http://")):
            raise ConfigError(f"{name}: url must be http(s)")


def source_active(src: dict[str, Any], env: dict[str, str] | None = None) -> bool:
    """A source runs when enabled and its required secret, if any, is present."""
    env = os.environ if env is None else env
    if not src.get("enabled", True):
        return False
    secret = src.get("requires_secret")
    return not secret or bool(env.get(secret))


def active_sources(cfg: dict[str, Any], env: dict[str, str] | None = None) -> list[dict[str, Any]]:
    return [s for s in cfg["sources"] if source_active(s, env)]
