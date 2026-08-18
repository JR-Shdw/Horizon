# SPDX-License-Identifier: AGPL-3.0-or-later
"""Apache-style loader for the closed set of built-in dynamic engines."""

import configparser
from importlib import import_module
from pathlib import Path

from .base import DynamicEngine

# Values are fixed relative module names, never operator-controlled imports.
# The INI can reduce the loaded set but cannot execute an arbitrary Python path.
BUILTIN_MODULES = {
    "postgresql": "postgresql",
    "mysql": "mysql",
    "ldap": "ldap",
    "redis": "redis",
    "cassandra": "cassandra",
}
BUILTIN_METADATA = {
    "postgresql": {
        "display_name": "PostgreSQL",
        "driver_module": "asyncpg",
    },
    "mysql": {
        "display_name": "MySQL / MariaDB",
        "driver_module": "aiomysql",
    },
    "ldap": {
        "display_name": "LDAP",
        "driver_module": "bonsai",
    },
    "redis": {
        "display_name": "Redis",
        "driver_module": "redis.asyncio",
    },
    "cassandra": {
        "display_name": "Apache Cassandra",
        "driver_module": "cassandra",
    },
}
_ENABLED_VALUES = {"1", "enabled", "on", "true", "yes"}
_DISABLED_VALUES = {"0", "disabled", "off", "false", "no"}


def configured_modules(config_path: str) -> tuple[str, ...]:
    """Parse the hard operator allow-list without importing a backend."""
    path = Path(config_path)
    if not path.is_file():
        raise RuntimeError(f"dynamic engine module config not found: {path}")

    parser = configparser.ConfigParser(interpolation=None)
    try:
        with path.open(encoding="utf-8") as handle:
            parser.read_file(handle)
    except (OSError, configparser.Error) as exc:
        raise RuntimeError(f"cannot read dynamic engine module config: {path}") from exc

    if set(parser.sections()) != {"modules"} or parser.defaults():
        raise RuntimeError(
            "dynamic engine config must contain only an explicit [modules] section"
        )

    unknown = set(parser["modules"]) - set(BUILTIN_MODULES)
    if unknown:
        raise RuntimeError(
            "unknown dynamic engine modules: " + ", ".join(sorted(unknown))
        )

    configured = []
    for engine_type, value in parser["modules"].items():
        state = value.strip().lower()
        if state in _DISABLED_VALUES:
            continue
        if state not in _ENABLED_VALUES:
            raise RuntimeError(
                f"invalid state for dynamic module {engine_type!r}: {value!r}"
            )
        configured.append(engine_type)
    return tuple(configured)


def load_engines(
    config_path: str,
    enabled_modules: set[str],
) -> dict[str, DynamicEngine]:
    """Import only modules allowed by INI and enabled by cluster state."""
    configured = configured_modules(config_path)
    enabled = set(enabled_modules)
    outside_boundary = enabled - set(configured)
    if outside_boundary:
        raise RuntimeError(
            "dynamic modules are not allowed by the INI: "
            + ", ".join(sorted(outside_boundary))
        )

    engines: dict[str, DynamicEngine] = {}
    for engine_type in configured:
        if engine_type not in enabled:
            continue
        module = import_module(f".{BUILTIN_MODULES[engine_type]}", package=__package__)
        engine = getattr(module, "ENGINE", None)
        if not isinstance(engine, DynamicEngine) or engine.engine_type != engine_type:
            raise RuntimeError(
                f"dynamic module {engine_type!r} exported an invalid ENGINE"
            )
        metadata = BUILTIN_METADATA[engine_type]
        if (
            engine.support.display_name != metadata["display_name"]
            or engine.support.driver_module != metadata["driver_module"]
        ):
            raise RuntimeError(
                f"dynamic module {engine_type!r} metadata does not match its ENGINE"
            )
        engines[engine_type] = engine
    return engines
