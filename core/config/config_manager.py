"""Layered configuration for Tusk.

Resolution order (lowest to highest precedence):
    1. built-in defaults
    2. TOML file at ~/.config/tusk/config.toml (or a custom path)
    3. environment variables (TUSK_<KEY>, upper-cased)
    4. CLI flags passed in at runtime

Each layer only overrides keys it actually sets; unset keys fall through
to the layer below.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib


DEFAULT_CONFIG_PATH = Path.home() / ".config" / "tusk" / "config.toml"

ENV_PREFIX = "TUSK_"

DEFAULTS: Dict[str, Any] = {
    "threads": 100,
    "port_timeout": 0.5,
    "banner_timeout": 2.0,
    "cve_timeout": 10.0,
    "cve_workers": 10,
    "nvd_api_key": "",
    "ruleset_path": "rulesets/default",
}

_TYPE_CASTERS = {
    "threads": int,
    "port_timeout": float,
    "banner_timeout": float,
    "cve_timeout": float,
    "cve_workers": int,
    "nvd_api_key": str,
    "ruleset_path": str,
}


class ConfigManager:
    """Resolves Tusk configuration values across the layered sources above."""

    def __init__(
        self,
        config_path: Optional[Path] = None,
        cli_overrides: Optional[Dict[str, Any]] = None,
    ):
        self.config_path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH

        self._values: Dict[str, Any] = dict(DEFAULTS)
        self._apply_file()
        self._apply_env()
        self._apply_cli(cli_overrides or {})

    def _apply_file(self) -> None:
        if not self.config_path.exists():
            return

        try:
            with open(self.config_path, "rb") as f:
                data = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError):
            return

        for key in DEFAULTS:
            if key in data:
                self._values[key] = data[key]

    def _apply_env(self) -> None:
        for key in DEFAULTS:
            env_key = f"{ENV_PREFIX}{key.upper()}"
            if env_key not in os.environ:
                continue

            raw = os.environ[env_key]
            caster = _TYPE_CASTERS.get(key, str)
            try:
                self._values[key] = caster(raw)
            except (TypeError, ValueError):
                self._values[key] = raw

    def _apply_cli(self, overrides: Dict[str, Any]) -> None:
        for key, value in overrides.items():
            if key in DEFAULTS and value is not None:
                self._values[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        """Return the resolved value for `key`, or `default` if unknown."""
        if key not in DEFAULTS:
            return default
        return self._values.get(key, default)

    def as_dict(self) -> Dict[str, Any]:
        return dict(self._values)


def write_default_config(path: Optional[Path] = None) -> Path:
    """Write a default TOML config file, creating parent directories as needed."""
    target = Path(path) if path else DEFAULT_CONFIG_PATH
    target.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Tusk configuration file",
        "#",
        "# Resolution order: defaults -> this file -> TUSK_* env vars -> CLI flags",
        "",
        f"threads = {DEFAULTS['threads']}",
        f"port_timeout = {DEFAULTS['port_timeout']}",
        f"banner_timeout = {DEFAULTS['banner_timeout']}",
        f"cve_timeout = {DEFAULTS['cve_timeout']}",
        f"cve_workers = {DEFAULTS['cve_workers']}",
        f'nvd_api_key = "{DEFAULTS["nvd_api_key"]}"',
        f'ruleset_path = "{DEFAULTS["ruleset_path"]}"',
        "",
    ]

    target.write_text("\n".join(lines), encoding="utf-8")
    return target
