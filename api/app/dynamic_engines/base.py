# SPDX-License-Identifier: AGPL-3.0-or-later
"""Stable contract shared by dynamic-secret engine modules."""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from importlib.util import find_spec
from unicodedata import category

ENGINE_CONNECT_TIMEOUT = 10
GENERATED_USERNAME_MAX_LENGTH = 32
GENERATED_USERNAME_SUFFIX_BYTES = 8
_GENERATED_USERNAME = re.compile(r"rh_[a-z0-9_]+_[0-9a-f]{16}")
_LEGACY_GENERATED_USERNAME = re.compile(r"rh_[a-z0-9_]+_[0-9a-f]{8}")


def is_generated_username(value: str, *, allow_legacy: bool = False) -> bool:
    if not isinstance(value, str) or len(value) > GENERATED_USERNAME_MAX_LENGTH:
        return False
    if _GENERATED_USERNAME.fullmatch(value) is not None:
        return True
    return allow_legacy and _LEGACY_GENERATED_USERNAME.fullmatch(value) is not None


@dataclass(frozen=True)
class EngineSupport:
    display_name: str
    driver_module: str
    validated_targets: tuple[str, ...]
    implementation_targets: tuple[str, ...]
    creation_example: str
    revocation_example: str


@dataclass(frozen=True)
class EngineProbe:
    product: str
    server_version: str | None

    def __post_init__(self) -> None:
        product = self._normalize(self.product, "product", 128, required=True)
        version = self._normalize(
            self.server_version,
            "server_version",
            256,
            required=False,
        )
        object.__setattr__(self, "product", product)
        object.__setattr__(self, "server_version", version)

    @staticmethod
    def _normalize(
        value: str | None,
        field_name: str,
        maximum: int,
        *,
        required: bool,
    ) -> str | None:
        if value is None:
            if required:
                raise ValueError(f"engine probe {field_name} must not be empty")
            return None
        if not isinstance(value, str):
            raise ValueError(f"engine probe {field_name} must be a string")
        normalized = value.strip()
        if not normalized:
            if required:
                raise ValueError(f"engine probe {field_name} must not be empty")
            return None
        if len(normalized) > maximum:
            raise ValueError(f"engine probe {field_name} is too long")
        if any(
            category(character) in {"Cc", "Cf", "Zl", "Zp"} for character in normalized
        ):
            raise ValueError(f"engine probe {field_name} contains control characters")
        return normalized


class DynamicEngine(ABC):
    """Contract implemented by one isolated backend module."""

    engine_type: str
    support: EngineSupport

    @abstractmethod
    async def provision(self, conn_url: str, rendered: str) -> str | None:
        """Create a credential from a fully rendered operator template."""
        raise NotImplementedError

    @abstractmethod
    async def revoke(self, conn_url: str, rendered: str) -> None:
        """Idempotently revoke a credential from a rendered operator template.

        An already-absent credential is success. Implementations must still
        raise connection, authorization, syntax and other target errors.
        """
        raise NotImplementedError

    def validate_conn(self, conn_url: str) -> None:
        """Optionally reject a malformed connection description without I/O."""
        return None

    def validate_role_templates(self, creation: str, revocation: str) -> None:
        """Optionally reject backend templates without I/O."""
        return None

    @abstractmethod
    async def probe(self, conn_url: str) -> EngineProbe:
        """Connect and inspect the target without modifying it."""
        raise NotImplementedError

    def compatibility_status(self, probe: EngineProbe) -> str:
        """Unknown versions stay usable but are never presented as validated."""
        return "connected_unvalidated"


def driver_available(module_name: str) -> bool:
    # Resolving a dotted name with find_spec() may import its parent package.
    # Checking the fixed top-level package keeps capability reporting passive.
    top_level = module_name.partition(".")[0]
    try:
        return find_spec(top_level) is not None
    except (ModuleNotFoundError, ValueError):
        return False


def engine_capability(engine: DynamicEngine) -> dict:
    support = engine.support
    return {
        "engine_type": engine.engine_type,
        "display_name": support.display_name,
        "driver_module": support.driver_module,
        "driver_installed": driver_available(support.driver_module),
        "validated_targets": list(support.validated_targets),
        "implementation_targets": list(support.implementation_targets),
        "creation_example": support.creation_example,
        "revocation_example": support.revocation_example,
    }


def first_version_number(version: str | None) -> int | None:
    if not version:
        return None
    match = re.search(r"\d+", version)
    return int(match.group()) if match else None


def mariadb_major_version(version: str | None) -> int | None:
    """Handle both native and MySQL-compat-prefixed MariaDB versions."""
    if not version:
        return None
    match = re.search(r"(?:^|-)(\d+)\.\d+(?:\.\d+)?-MariaDB", version, re.IGNORECASE)
    return int(match.group(1)) if match else first_version_number(version)
