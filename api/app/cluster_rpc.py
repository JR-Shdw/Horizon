# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Master RPC for crypto-ops delegation.

Workers without sub-keys delegate each crypto operation to the master
process via a Unix domain socket. The master's process is the only one
that holds master_key + sub-keys in RAM; workers hold zero plaintext
key material.

Wire format:
    Request:  4-byte BE length || JSON {"op": str, "args": dict}
    Response: 4-byte BE length || JSON {"result": str} or {"error": str}

`result` is hex-encoded for binary outputs (HMAC signatures, AES-GCM
ciphertext) and plain string for already-string outputs (audit signatures).
The caller knows what to expect per op.

Failure modes (all fail-closed):
    - Connect refused / file not found  -> MasterUnreachable
    - Foreign UID detected via peer_cred -> connection rejected
    - Master raises an exception -> wrapped in {"error": ...}, raised as RpcError
    - Read/write timeout -> MasterUnreachable

Transport:
    The master accepts connections on a filesystem-path Unix socket
    (default `/run/rhorizon/crypto-ops-{HOSTNAME}.sock`, see
    socket_paths.py for the resolution chain). The socket directory and
    the socket file are 0700 mode, owned by the rhorizon UID - combined
    with the peer-UID check, that's defence in depth against local
    impersonation. The path is portable across Linux, macOS and BSD;
    it replaced the Linux-only abstract-namespace path (\\0name) in
    2026-05.
"""

import asyncio
import json
import logging
import os
import stat
import struct
import time
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .config import settings
from .peer_cred import read_peer_cred as _read_peer_cred
from .socket_paths import (
    acquire_socket_path,
    cleanup_socket,
    crypto_ops_socket_path,
    post_bind_chmod,
)

if TYPE_CHECKING:
    from rhorizon_crypto import ShamirShare

    from .vault_state import VaultState

log = logging.getLogger("rhorizon.cluster_rpc")

# Per-call crypto-op deadline, operator-tunable (see config.Settings).
# Must exceed cluster_master_timeout_secs -- enforced there -- or a
# stalled-but-alive master fails every in-flight request before the
# cluster has decided whether it is gone.
DEFAULT_TIMEOUT_SECS = settings.cluster_rpc_timeout_secs
MAX_PAYLOAD = 3 * 1024 * 1024  # 1 MB secret encoded as hex plus JSON overhead

# Valid RPC ops -- the only strings allowed to become a metric label value
# (op is request-controlled ; keep in sync with MasterRpcServer._dispatch).
_OPS = frozenset(
    {
        "hmac_sha512",
        "hmac_sha512_prev",
        "aesgcm_encrypt",
        "aesgcm_decrypt",
        "secret_encrypt",
        "secret_decrypt",
        "secret_reencrypt",
        "audit_sign",
        "audit_sign_identity",
        "audit_sign_raw",
        "ha_wrap_encrypt",
        "ha_wrap_decrypt",
        "pki_wrap_encrypt",
        "pki_wrap_decrypt",
        "ha_password_hmac",
        "wrap_node_key_for_joiner",
        "wrap_server_key_for_joiner",
    }
)

_CUSTODIAN_CONTROL_OPS = frozenset(
    {
        "accept_reshare",
        "accept_topology_reshare",
        "clear_ha_password",
        "clear_prev_hmac",
        "clear_prev_hmac_if_envelope",
        "clear_share",
        "commit_share",
        "finalize_share",
        "generate_audit_identity",
        "generate_reshare",
        "generate_topology_reshare",
        "install_audit_identity",
        "install_ha_password",
        "install_prev_hmac",
        "install_share",
        "prepare_share",
        "replace_ha_password",
        "rollback_share",
        "seal",
        "set_ha_password_from_plain",
        "share_contribution",
        "unseal",
    }
)
_MIN_CONTROL_CAPABILITY_BYTES = 32
_MAX_CONTROL_CAPABILITY_BYTES = 256
_MAX_CONTROL_CAPABILITY_FILE_BYTES = _MAX_CONTROL_CAPABILITY_BYTES + 2
_ASCII_WHITESPACE = frozenset(b" \t\n\r\x0b\x0c")


class MasterUnreachable(Exception):
    """Raised when the master RPC server cannot be contacted."""


class RpcError(Exception):
    """Wrapper for errors returned by the master."""


# =====================================================================
# Client (worker side)
# =====================================================================


class MasterRpcClient:
    """Thin per-call client. No connection pooling - each call opens a
    fresh Unix socket connection (~100us cost), simpler reasoning."""

    def __init__(self, socket_name: str, timeout: float = DEFAULT_TIMEOUT_SECS):
        # `socket_name` is now a filesystem path (e.g.
        # /run/rhorizon/crypto-ops-host.sock). Reject empty / clearly invalid
        # values; full validation happens at connect() time.
        if not socket_name:
            raise ValueError("socket_name must be a non-empty filesystem path")
        self.socket_name = socket_name
        self.timeout = timeout

    async def call(self, op: str, args: dict) -> str:
        """Send one request, return the `result` string from the master.

        Raises:
            MasterUnreachable : connect/timeout/UID mismatch
            RpcError          : master returned an error response
        """
        return await self._call(op, args, capability=None)

    async def _call(self, op: str, args: dict, *, capability: str | None) -> str:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self.socket_name),
                timeout=self.timeout,
            )
        except (FileNotFoundError, ConnectionRefusedError, OSError) as e:
            raise MasterUnreachable(f"connect to master failed: {e}") from e
        except asyncio.TimeoutError as e:
            raise MasterUnreachable("connect to master timed out") from e

        try:
            sock = writer.get_extra_info("socket")
            # Fail closed (mirror server): missing socket or unreadable cred.
            ucred = _read_peer_cred(sock) if sock is not None else None
            if ucred is None or ucred[1] != os.getuid():
                peer = ucred[1] if ucred else None
                raise MasterUnreachable(
                    f"master uid check failed: peer={peer} ours={os.getuid()}"
                )

            request = {"op": op, "args": args}
            if capability is not None:
                request["capability"] = capability
            req_buf = json.dumps(request).encode()
            writer.write(struct.pack(">I", len(req_buf)) + req_buf)
            await writer.drain()

            len_buf = await asyncio.wait_for(
                reader.readexactly(4), timeout=self.timeout
            )
            resp_len = struct.unpack(">I", len_buf)[0]
            if resp_len == 0 or resp_len > MAX_PAYLOAD:
                raise MasterUnreachable(f"invalid response length: {resp_len}")
            resp_buf = await asyncio.wait_for(
                reader.readexactly(resp_len), timeout=self.timeout
            )
            resp = json.loads(resp_buf)

            if "error" in resp:
                raise RpcError(resp["error"])
            return resp["result"]
        except asyncio.IncompleteReadError as e:
            raise MasterUnreachable(f"master closed connection: {e}") from e
        except asyncio.TimeoutError as e:
            raise MasterUnreachable("master response timeout") from e
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


def _read_control_capability(path: str) -> bytearray:
    """Read one private capability without following a final symlink.

    The returned buffer belongs to the caller and must be wiped. Leading and
    trailing ASCII whitespace is ignored, matching the Rust daemon loader.
    """
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    read_buffer = bytearray(_MAX_CONTROL_CAPABILITY_FILE_BYTES + 1)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError("custodian control token is not a regular file")
        if info.st_uid != os.getuid():
            raise RuntimeError("custodian control token owner must match client UID")
        if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise RuntimeError(
                "custodian control token must not be group/world accessible"
            )
        with os.fdopen(descriptor, "rb", buffering=0, closefd=True) as token_file:
            descriptor = -1
            count = token_file.readinto(read_buffer)
        if count > _MAX_CONTROL_CAPABILITY_FILE_BYTES:
            raise RuntimeError("custodian control token is too large")
        start = 0
        while start < count and read_buffer[start] in _ASCII_WHITESPACE:
            start += 1
        end = count
        while end > start and read_buffer[end - 1] in _ASCII_WHITESPACE:
            end -= 1
        length = end - start
        if not _MIN_CONTROL_CAPABILITY_BYTES <= length <= _MAX_CONTROL_CAPABILITY_BYTES:
            raise RuntimeError("custodian control token must contain 32..256 bytes")
        return bytearray(memoryview(read_buffer)[start:end])
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        from rhorizon_crypto import secure_zero

        secure_zero(read_buffer)


class CustodianRpcClient(MasterRpcClient):
    """RPC client that authenticates only state-changing custodian calls."""

    def __init__(
        self,
        socket_name: str,
        control_token_file: str,
        timeout: float = DEFAULT_TIMEOUT_SECS,
    ):
        super().__init__(socket_name, timeout)
        if not control_token_file:
            raise ValueError("control_token_file must be a non-empty filesystem path")
        self.control_token_file = control_token_file

    async def call(self, op: str, args: dict) -> str:
        if op in _CUSTODIAN_CONTROL_OPS:
            return await self.call_control(op, args)
        return await super().call(op, args)

    async def call_control(self, op: str, args: dict) -> str:
        if op not in _CUSTODIAN_CONTROL_OPS:
            raise ValueError(f"operation is not a custodian control operation: {op}")
        capability = _read_control_capability(self.control_token_file)
        try:
            try:
                encoded_capability = capability.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise RuntimeError(
                    "custodian control token must be valid UTF-8"
                ) from exc
            return await self._call(op, args, capability=encoded_capability)
        finally:
            from rhorizon_crypto import secure_zero

            secure_zero(capability)


class CustodianPoolUnavailable(RuntimeError):
    """No fixed-slot custodian can currently assemble a quorum."""


class CustodianPoolController:
    """Coordinate encrypted contributions across fixed Rust custodian slots.

    This controller never accepts or returns a plaintext Shamir share. Share
    installation is a separate native-Rust transfer boundary; this class only
    asks already-provisioned donors for recipient-bound encrypted envelopes.
    """

    def __init__(
        self,
        socket_names: Mapping[int, str],
        control_token_file: str,
        threshold: int,
    ) -> None:
        slots = sorted(socket_names)
        if slots != list(range(1, len(slots) + 1)):
            raise ValueError("custodian slots must be contiguous from 1")
        if len(slots) < 3:
            raise ValueError("custodian pool requires at least three slots")
        if threshold < 2 or threshold > len(slots):
            raise ValueError("custodian threshold must be between 2 and slot count")
        self.threshold = threshold
        self._socket_names = dict(socket_names)
        self._control_token_file = control_token_file
        self._clients = {
            slot: CustodianRpcClient(socket_names[slot], control_token_file)
            for slot in slots
        }
        self._active_slot: int | None = None

    def _validate_share_map(
        self, shares: Mapping[int, "ShamirShare"], generation: int
    ) -> None:
        if isinstance(generation, bool) or generation < 1:
            raise ValueError("custodian share generation must be positive")
        if sorted(shares) != list(self._clients):
            raise ValueError(
                "opaque shares must cover every custodian slot exactly once"
            )
        for slot, share in shares.items():
            if share.x != slot:
                raise ValueError(
                    "opaque share coordinate does not match custodian slot"
                )

    async def install_shares(
        self, shares: Mapping[int, "ShamirShare"], generation: int
    ) -> dict[int, str]:
        """Install a complete opaque generation without exposing share bytes."""
        self._validate_share_map(shares, generation)
        outcomes: dict[int, str] = {}
        for slot, share in shares.items():
            try:
                outcome = await asyncio.to_thread(
                    share.install_into_custodian,
                    self._socket_names[slot],
                    self._control_token_file,
                    generation,
                    self.threshold,
                    len(self._clients),
                )
            except Exception as exc:
                raise CustodianPoolUnavailable(
                    f"opaque share installation failed for slot {slot}: {exc}"
                ) from exc
            if outcome not in {"installed", "already-installed"}:
                raise CustodianPoolUnavailable(
                    f"custodian slot {slot} returned invalid install outcome"
                )
            outcomes[slot] = outcome
        return outcomes

    async def prepare_shares(
        self, shares: Mapping[int, "ShamirShare"], generation: int
    ) -> dict[int, str]:
        """Stage one complete opaque generation while the old one stays active."""
        self._validate_share_map(shares, generation)
        outcomes: dict[int, str] = {}
        for slot, share in shares.items():
            try:
                outcome = await asyncio.to_thread(
                    share.prepare_into_custodian,
                    self._socket_names[slot],
                    self._control_token_file,
                    generation,
                    self.threshold,
                    len(self._clients),
                )
            except Exception as exc:
                raise CustodianPoolUnavailable(
                    f"opaque share preparation failed for slot {slot}: {exc}"
                ) from exc
            if outcome not in {
                "prepared",
                "already-prepared",
                "already-committed",
            }:
                raise CustodianPoolUnavailable(
                    f"custodian slot {slot} returned invalid prepare outcome"
                )
            outcomes[slot] = outcome
        return outcomes

    async def prepare_native_reshare(
        self,
        generation: int,
        coordinator_slot: int | None = None,
    ) -> dict[int, str]:
        """Relay only encrypted reshare deliveries from one unsealed custodian."""
        if isinstance(generation, bool) or generation < 1:
            raise ValueError("custodian share generation must be positive")
        coordinator_slot = (
            self._active_slot if coordinator_slot is None else coordinator_slot
        )
        if coordinator_slot not in self._clients:
            raise ValueError("native reshare requires an active coordinator slot")
        try:
            generated = await self._clients[coordinator_slot].call_control(
                "generate_reshare", {"generation": generation}
            )
        except (MasterUnreachable, RpcError, RuntimeError) as exc:
            raise CustodianPoolUnavailable(
                f"custodian slot {coordinator_slot} could not generate reshare: {exc}"
            ) from exc
        if (
            not isinstance(generated, dict)
            or generated.get("generation") != generation
            or not isinstance(generated.get("deliveries"), list)
        ):
            raise CustodianPoolUnavailable(
                f"custodian slot {coordinator_slot} returned invalid reshare"
            )

        deliveries: dict[int, str] = {}
        for delivery in generated["deliveries"]:
            if not isinstance(delivery, dict):
                raise CustodianPoolUnavailable("custodian returned invalid delivery")
            slot = delivery.get("slot")
            envelope = delivery.get("envelope")
            if (
                isinstance(slot, bool)
                or not isinstance(slot, int)
                or slot == coordinator_slot
                or slot not in self._clients
                or slot in deliveries
                or not isinstance(envelope, str)
                or not envelope
            ):
                raise CustodianPoolUnavailable("custodian returned invalid delivery")
            deliveries[slot] = envelope
        expected = set(self._clients) - {coordinator_slot}
        if set(deliveries) != expected:
            raise CustodianPoolUnavailable(
                "native reshare deliveries do not cover every remote slot"
            )

        outcomes = {coordinator_slot: "prepared-or-cached"}
        failures: list[str] = []
        for slot, envelope in deliveries.items():
            try:
                outcome = await self._clients[slot].call_control(
                    "accept_reshare",
                    {"envelope": envelope, "generation": generation},
                )
                if outcome not in {
                    "prepared",
                    "already-prepared",
                    "already-committed",
                }:
                    raise RuntimeError("invalid accept outcome")
                outcomes[slot] = outcome
            except (MasterUnreachable, RpcError, RuntimeError) as exc:
                failures.append(f"slot {slot}: {exc}")
        if failures:
            raise CustodianPoolUnavailable(
                "native custodian reshare preparation incomplete: "
                + "; ".join(failures)
            )
        return outcomes

    async def generate_topology_reshare(
        self,
        generation: int,
        *,
        threshold: int,
        slots: int,
        peer_keys: dict[int, str],
        coordinator_slot: int | None = None,
    ) -> dict[int, str]:
        """Split the runtime bundle for a shape this pool does not run.

        Returns one opaque envelope per TARGET slot, the coordinator's own
        included: no fixed slot accepts a share of another topology, so every
        one of them has to cross the operator restart encrypted. Nothing is
        delivered here -- the recipients do not exist yet.
        """
        if isinstance(generation, bool) or generation < 1:
            raise ValueError("custodian share generation must be positive")
        if set(peer_keys) != set(range(1, slots + 1)):
            raise ValueError("topology reshare needs a key for every target slot")
        coordinator_slot = (
            self._active_slot if coordinator_slot is None else coordinator_slot
        )
        if coordinator_slot not in self._clients:
            raise ValueError("topology reshare requires an active coordinator slot")
        if coordinator_slot > slots:
            raise ValueError("topology reshare coordinator must survive the target")
        try:
            generated = await self._clients[coordinator_slot].call_control(
                "generate_topology_reshare",
                {
                    "generation": generation,
                    "threshold": threshold,
                    "slots": slots,
                    "peer_keys": [
                        {"slot": slot, "key": peer_keys[slot]}
                        for slot in sorted(peer_keys)
                    ],
                },
            )
        except (MasterUnreachable, RpcError, RuntimeError) as exc:
            raise CustodianPoolUnavailable(
                f"custodian slot {coordinator_slot} could not generate a "
                f"topology reshare: {exc}"
            ) from exc
        if (
            not isinstance(generated, dict)
            or generated.get("generation") != generation
            or generated.get("threshold") != threshold
            or generated.get("slots") != slots
            or not isinstance(generated.get("deliveries"), list)
        ):
            raise CustodianPoolUnavailable(
                f"custodian slot {coordinator_slot} returned an invalid "
                "topology reshare"
            )

        deliveries: dict[int, str] = {}
        for delivery in generated["deliveries"]:
            if not isinstance(delivery, dict):
                raise CustodianPoolUnavailable("custodian returned invalid delivery")
            slot = delivery.get("slot")
            envelope = delivery.get("envelope")
            if (
                isinstance(slot, bool)
                or not isinstance(slot, int)
                or not 1 <= slot <= slots
                or slot in deliveries
                or not isinstance(envelope, str)
                or not envelope
            ):
                raise CustodianPoolUnavailable("custodian returned invalid delivery")
            deliveries[slot] = envelope
        if set(deliveries) != set(range(1, slots + 1)):
            raise CustodianPoolUnavailable(
                "topology reshare deliveries do not cover every target slot"
            )
        return deliveries

    async def deliver_topology_reshare(
        self, generation: int, deliveries: dict[int, str]
    ) -> dict[int, str]:
        """Install the recorded envelopes into a pool running the target shape.

        Every slot of THIS pool must be covered. A partial delivery is not a
        completed transition: the durable decision may only be closed once
        each target slot holds its share, and the envelope for a missing one
        is still on record, so a retry finishes what a repair reshare would
        otherwise have to guess at.
        """
        if isinstance(generation, bool) or generation < 1:
            raise ValueError("custodian share generation must be positive")
        if set(deliveries) != set(self._clients):
            raise ValueError("topology reshare must cover every custodian slot")
        outcomes: dict[int, str] = {}
        failures: list[str] = []
        for slot, envelope in sorted(deliveries.items()):
            try:
                outcome = await self._clients[slot].call_control(
                    "accept_topology_reshare",
                    {"envelope": envelope, "generation": generation},
                )
                if outcome not in {"installed", "already-installed"}:
                    raise RuntimeError("invalid accept outcome")
                outcomes[slot] = outcome
            except (MasterUnreachable, RpcError, RuntimeError) as exc:
                failures.append(f"slot {slot}: {exc}")
        if failures:
            raise CustodianPoolUnavailable(
                "custodian topology reshare delivery incomplete: " + "; ".join(failures)
            )
        return outcomes

    @property
    def active_slot(self) -> int | None:
        return self._active_slot

    def coordinator_client(self) -> "CustodianRpcClient | None":
        """The client for the elected coordinator, or None if none is elected.

        Read-only: callers that need to ASK the quorum something (rather than
        move share material) go through this instead of reaching into the
        private client map.
        """
        if self._active_slot is None:
            return None
        return self._clients.get(self._active_slot)

    @property
    def active_client(self) -> CustodianRpcClient | None:
        if self._active_slot is None:
            return None
        return self._clients[self._active_slot]

    async def unsealed_coordinator(self, generation: int) -> CustodianRpcClient | None:
        """Find a live coordinator already serving ``generation``, read-only.

        This exists so a disposable API worker can reach the quorum without
        performing leader-grade work. ``unseal`` would make donors emit share
        contributions and reconstruct the bundle again; ``status`` only reports
        whether a slot is open and which runtime generation it holds, so this
        moves no share material, takes no orchestration lock, and cannot change
        the custody generation.

        The generation is checked rather than trusted: adopting a coordinator
        on a different generation would hash tokens and unwrap DEKs under keys
        no stored row can match.
        """
        if isinstance(generation, bool) or generation < 1:
            raise ValueError("custodian share generation must be positive")
        for slot, client in self._clients.items():
            try:
                status = await client.call("status", {})
            except (MasterUnreachable, RpcError):
                continue
            if not isinstance(status, dict):
                continue
            if status.get("state") != "unsealed":
                continue
            if status.get("generation") != generation:
                continue
            self._active_slot = slot
            return client
        return None

    async def statuses(self) -> dict[int, dict[str, Any]]:
        result: dict[int, dict[str, Any]] = {}
        for slot, client in self._clients.items():
            try:
                status = await client.call("status", {})
            except (MasterUnreachable, RpcError) as exc:
                raise CustodianPoolUnavailable(
                    f"custodian slot {slot} status unavailable: {exc}"
                ) from exc
            if not isinstance(status, dict):
                raise CustodianPoolUnavailable(
                    f"custodian slot {slot} returned invalid status"
                )
            result[slot] = status
        return result

    async def availability_statuses(self) -> dict[int, dict[str, Any] | None]:
        """Best-effort status for monitoring; unavailable slots remain visible."""

        async def _probe(slot: int, client: CustodianRpcClient):
            try:
                status = await client.call("status", {})
            except (MasterUnreachable, RpcError):
                return slot, None
            if not isinstance(status, dict):
                return slot, None
            return slot, status

        observed = await asyncio.gather(
            *(_probe(slot, client) for slot, client in self._clients.items())
        )
        return dict(observed)

    async def share_statuses(self) -> dict[int, dict[str, Any]]:
        result: dict[int, dict[str, Any]] = {}
        for slot, client in self._clients.items():
            try:
                status = await client.call("share_status", {})
            except (MasterUnreachable, RpcError) as exc:
                raise CustodianPoolUnavailable(
                    f"custodian slot {slot} share status unavailable: {exc}"
                ) from exc
            if not isinstance(status, dict) or status.get("slot") != slot:
                raise CustodianPoolUnavailable(
                    f"custodian slot {slot} returned invalid share status"
                )
            result[slot] = status
        return result

    async def clear_shares_all(self) -> None:
        failures: list[str] = []
        for slot, client in self._clients.items():
            try:
                await client.call_control("clear_share", {})
            except (MasterUnreachable, RpcError, RuntimeError) as exc:
                failures.append(f"slot {slot}: {exc}")
        if failures:
            raise CustodianPoolUnavailable(
                "custodian share rollback incomplete: " + "; ".join(failures)
            )

    async def _transition_generation_all(
        self, operation: str, generation: int, accepted: set[str]
    ) -> dict[int, str]:
        if isinstance(generation, bool) or generation < 1:
            raise ValueError("custodian share generation must be positive")
        outcomes: dict[int, str] = {}
        failures: list[str] = []
        for slot, client in self._clients.items():
            try:
                outcome = await client.call_control(
                    operation, {"generation": generation}
                )
                if not isinstance(outcome, str) or outcome not in accepted:
                    raise RuntimeError("invalid transition outcome")
                outcomes[slot] = outcome
            except (MasterUnreachable, RpcError, RuntimeError) as exc:
                failures.append(f"slot {slot}: {exc}")
        if failures:
            raise CustodianPoolUnavailable(
                f"custodian {operation} incomplete: " + "; ".join(failures)
            )
        return outcomes

    async def commit_generation_all(self, generation: int) -> dict[int, str]:
        return await self._transition_generation_all(
            "commit_share", generation, {"committed", "already-committed"}
        )

    async def rollback_generation_all(self, generation: int) -> dict[int, str]:
        return await self._transition_generation_all(
            "rollback_share", generation, {"rolled-back", "already-rolled-back"}
        )

    async def finalize_generation_all(self, generation: int) -> dict[int, str]:
        return await self._transition_generation_all(
            "finalize_share", generation, {"finalized", "already-finalized"}
        )

    async def unseal(
        self,
        preferred_slot: int | None = None,
        generation: int | None = None,
    ) -> CustodianRpcClient:
        if preferred_slot is not None and preferred_slot not in self._clients:
            raise ValueError("preferred custodian slot does not exist")
        if generation is not None and (isinstance(generation, bool) or generation < 1):
            raise ValueError("custodian share generation must be positive")
        candidates = list(self._clients)
        if preferred_slot is not None:
            candidates.remove(preferred_slot)
            candidates.insert(0, preferred_slot)

        failures: list[str] = []
        for coordinator_slot in candidates:
            contributions: list[str] = []
            for donor_slot, donor in self._clients.items():
                if donor_slot == coordinator_slot:
                    continue
                try:
                    contribution_args = {"recipient_slot": coordinator_slot}
                    if generation is not None:
                        contribution_args["generation"] = generation
                    envelope = await donor.call_control(
                        "share_contribution",
                        contribution_args,
                    )
                except (MasterUnreachable, RpcError) as exc:
                    failures.append(f"donor slot {donor_slot}: {exc}")
                    continue
                if not isinstance(envelope, str) or not envelope:
                    failures.append(f"donor slot {donor_slot}: invalid contribution")
                    continue
                contributions.append(envelope)
                if len(contributions) == self.threshold - 1:
                    break
            if len(contributions) != self.threshold - 1:
                failures.append(
                    f"coordinator slot {coordinator_slot}: incomplete quorum"
                )
                continue
            try:
                unseal_args: dict[str, Any] = {"contributions": contributions}
                if generation is not None:
                    unseal_args["generation"] = generation
                result = await self._clients[coordinator_slot].call_control(
                    "unseal", unseal_args
                )
            except (MasterUnreachable, RpcError) as exc:
                failures.append(f"coordinator slot {coordinator_slot}: {exc}")
                continue
            if (
                not isinstance(result, dict)
                or result.get("state") not in {"unsealed", "already-unsealed"}
                or (generation is not None and result.get("generation") != generation)
            ):
                failures.append(
                    f"coordinator slot {coordinator_slot}: invalid unseal response"
                )
                continue
            self._active_slot = coordinator_slot
            return self._clients[coordinator_slot]

        self._active_slot = None
        detail = "; ".join(failures) if failures else "no candidates"
        raise CustodianPoolUnavailable(f"custodian quorum unavailable: {detail}")

    async def seal_all(self) -> None:
        self._active_slot = None
        failures: list[str] = []
        for slot, client in self._clients.items():
            try:
                await client.call_control("seal", {})
            except (MasterUnreachable, RpcError, RuntimeError) as exc:
                failures.append(f"slot {slot}: {exc}")
        if failures:
            raise CustodianPoolUnavailable(
                "custodian seal incomplete: " + "; ".join(failures)
            )


# =====================================================================
# Server (master side)
# =====================================================================


class MasterRpcServer:
    """Master-side RPC server. Started post-unseal in the lifespan; stopped
    on seal or shutdown. Only one instance per process."""

    def __init__(self, socket_name: str, vault: "VaultState"):
        if not socket_name:
            raise ValueError("socket_name must be a non-empty filesystem path")
        self.socket_name = socket_name
        self.vault = vault
        self._server: asyncio.base_events.Server | None = None

    async def start(self):
        if self._server is not None:
            log.warning("MasterRpcServer.start called twice - ignoring")
            return
        # Clean up any stale socket from a crashed previous instance, refuse
        # to start if a live process is already bound at this path.
        path = Path(self.socket_name)
        acquire_socket_path(path)
        self._server = await asyncio.start_unix_server(
            self._handle_client,
            path=self.socket_name,
        )
        post_bind_chmod(path)
        log.info("MasterRpcServer started on %s", self.socket_name)

    async def stop(self):
        if self._server is None:
            return
        self._server.close()
        try:
            await asyncio.wait_for(self._server.wait_closed(), timeout=2.0)
        except asyncio.TimeoutError:
            log.warning("MasterRpcServer.stop: wait_closed timed out")
        self._server = None
        cleanup_socket(Path(self.socket_name))
        log.info("MasterRpcServer stopped")

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        sock = writer.get_extra_info("socket")
        # Fail closed: no socket object means no peer cred to verify.
        ucred = _read_peer_cred(sock) if sock is not None else None
        if ucred is None or ucred[1] != os.getuid():
            log.warning(
                "MasterRpcServer: rejected peer ucred=%s our_uid=%d", ucred, os.getuid()
            )
            writer.close()
            return

        try:
            len_buf = await asyncio.wait_for(
                reader.readexactly(4), timeout=DEFAULT_TIMEOUT_SECS
            )
            req_len = struct.unpack(">I", len_buf)[0]
            if req_len == 0 or req_len > MAX_PAYLOAD:
                raise ValueError(f"invalid request length: {req_len}")
            req_buf = await asyncio.wait_for(
                reader.readexactly(req_len), timeout=DEFAULT_TIMEOUT_SECS
            )
            req = json.loads(req_buf)

            op = req.get("op")
            args = req.get("args", {})
            # op is request-controlled : only a known op may become a label
            # value, else cardinality is unbounded. Unknowns collapse to one
            # bucket (and still get dispatched -> a clean "unknown op" error).
            op_label = op if op in _OPS else "unknown"

            # Saturation visibility: the master is the one process that does not
            # scale with workers ; these series flag when you've outgrown it.
            from . import metrics as _m

            _m.master_rpc_inflight.inc()
            _t0 = time.monotonic()
            try:
                result = self._dispatch(op, args)
                resp = {"result": result}
            except Exception as e:
                log.warning("MasterRpcServer: op=%s failed: %s", op_label, e)
                resp = {"error": f"{type(e).__name__}: {e}"}
                _m.master_rpc_errors.labels(op=op_label).inc()
            finally:
                _m.master_rpc_duration.labels(op=op_label).observe(
                    time.monotonic() - _t0
                )
                _m.master_rpc_inflight.dec()

            resp_buf = json.dumps(resp).encode()
            writer.write(struct.pack(">I", len(resp_buf)) + resp_buf)
            await writer.drain()
        except (asyncio.IncompleteReadError, asyncio.TimeoutError) as e:
            log.debug("MasterRpcServer: client read failed: %s", e)
        except Exception as e:
            log.warning("MasterRpcServer: client handling error: %s", e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _dispatch(self, op: str, args: dict) -> str:
        """Map RPC ops to vault local methods. Returns a string (hex for
        binary outputs, plain str for audit signatures).

        Gated on SEALED (in the ``_local`` methods) but deliberately NOT on
        FROZEN, which was considered and rejected.

        node_uuid is read from a file on disk, so every worker on a host shares
        it, heartbeats the same ``vault_cluster_nodes`` row, and derives its
        authority deadline from the same PostgreSQL reads. They freeze and
        unfreeze together. In the failure FROZEN exists for -- the database is
        unreachable -- the *callers* are frozen too and refuse at
        ``require_unsealed()`` long before reaching this socket, so a frozen
        gate here would never fire.

        Where it WOULD fire is the divergent case: one worker's heartbeat task
        died while its siblings are healthy and PostgreSQL still names this
        node primary. Refusing there would convert a single dead task into a
        host-wide outage, and the callers would be right and the refusal
        wrong -- their view of authority is the one backed by the database.
        That fault is handled where it belongs, by ``main._supervised``, which
        replaces the process rather than having its peers work around it.
        """
        if op == "hmac_sha512":
            msg = bytes.fromhex(args["message"])
            return self.vault._hmac_sha512_hex_local(msg)
        if op == "hmac_sha512_prev":
            msg = bytes.fromhex(args["message"])
            r = self.vault._hmac_sha512_hex_prev_local(msg)
            return r if r is not None else ""
        if op == "aesgcm_encrypt":
            plain = bytes.fromhex(args["plaintext"])
            aad = bytes.fromhex(args["aad"])
            ct, nonce = self.vault._aesgcm_encrypt_local(plain, aad)
            return nonce.hex() + ct.hex()  # 24 hex chars nonce || ct
        if op == "aesgcm_decrypt":
            ct = bytes.fromhex(args["ciphertext"])
            nonce = bytes.fromhex(args["nonce"])
            aad = bytes.fromhex(args["aad"])
            plain = self.vault._aesgcm_decrypt_local(ct, nonce, aad)
            return plain.hex()
        if op == "secret_encrypt":
            result = self.vault._secret_encrypt_local(
                bytes.fromhex(args["plaintext"]),
                bytes.fromhex(args["dek_aad"]),
                bytes.fromhex(args["secret_aad"]),
            )
            encrypted_dek, dek_nonce, ciphertext, secret_nonce = result
            return (dek_nonce + encrypted_dek + secret_nonce + ciphertext).hex()
        if op == "secret_decrypt":
            plaintext = self.vault._secret_decrypt_local(
                bytes.fromhex(args["encrypted_dek"]),
                bytes.fromhex(args["dek_nonce"]),
                bytes.fromhex(args["dek_aad"]),
                bytes.fromhex(args["ciphertext"]),
                bytes.fromhex(args["secret_nonce"]),
                bytes.fromhex(args["secret_aad"]),
            )
            try:
                return plaintext.hex()
            finally:
                from rhorizon_crypto import secure_zero

                secure_zero(plaintext)
        if op == "secret_reencrypt":
            result = self.vault._secret_reencrypt_local(
                bytes.fromhex(args["old_encrypted_dek"]),
                bytes.fromhex(args["old_dek_nonce"]),
                bytes.fromhex(args["old_dek_aad"]),
                bytes.fromhex(args["old_ciphertext"]),
                bytes.fromhex(args["old_secret_nonce"]),
                bytes.fromhex(args["old_secret_aad"]),
                bytes.fromhex(args["new_dek_aad"]),
                bytes.fromhex(args["new_secret_aad"]),
            )
            encrypted_dek, dek_nonce, ciphertext, secret_nonce = result
            return (dek_nonce + encrypted_dek + secret_nonce + ciphertext).hex()
        if op == "audit_sign":
            payload = args["payload"]
            prev = args.get("prev_signature", "")
            return self.vault._audit_sign_local(payload, prev)
        if op == "audit_sign_identity":
            payload = args["payload"]
            prev = args.get("prev_signature", "")
            return self.vault._audit_sign_identity_local(payload, prev)
        if op == "ha_wrap_encrypt":
            # Follower-routed cluster routes (eg /cluster/init) delegate the
            # ha_wrap_key wrap via this op; only the master holds
            # vault._ha_wrap_enc.
            plain = bytes.fromhex(args["plaintext"])
            aad = bytes.fromhex(args["aad"])
            return self.vault._ha_wrap_encrypt_local(plain, aad).hex()
        if op == "ha_wrap_decrypt":
            wrapped = bytes.fromhex(args["wrapped"])
            aad = bytes.fromhex(args["aad"])
            plaintext = self.vault._ha_wrap_decrypt_local(wrapped, aad)
            try:
                return plaintext.hex()
            finally:
                from rhorizon_crypto import secure_zero

                secure_zero(plaintext)
        if op == "pki_wrap_encrypt":
            # Follower-routed PKI routes (eg /pki/issue) delegate the CA-key
            # wrap via this op; only the master holds vault._pki_wrap_enc.
            plain = bytes.fromhex(args["plaintext"])
            aad = bytes.fromhex(args["aad"])
            return self.vault._pki_wrap_encrypt_local(plain, aad).hex()
        if op == "pki_wrap_decrypt":
            wrapped = bytes.fromhex(args["wrapped"])
            aad = bytes.fromhex(args["aad"])
            plaintext = self.vault._pki_wrap_decrypt_local(wrapped, aad)
            try:
                return plaintext.hex()
            finally:
                from rhorizon_crypto import secure_zero

                secure_zero(plaintext)
        if op == "ha_password_hmac":
            # Followers delegate the JOIN-proof HMAC because only the master
            # holds the wrapped ha_password buffer. Same wire shape as
            # `hmac_sha512`.
            msg = bytes.fromhex(args["message"])
            return self.vault._ha_password_hmac_local(msg)
        if op == "wrap_node_key_for_joiner":
            # Lets /cluster/join succeed on a follower. The
            # HKDF(ha_password, info=node_uuid) wrap of the joiner's
            # freshly-minted node-key needs ``vault._ha_password_enc`` which
            # only the master holds. Lazy import keeps ha_password off the
            # module-level graph (ha_password imports vault_state ; circular
            # otherwise).
            from . import ha_password as _hap

            node_key_pem = bytes.fromhex(args["node_key_pem"])
            node_uuid = args["node_uuid"]
            return _hap.wrap_node_key_for_joiner(node_key_pem, node_uuid).hex()
        if op == "wrap_server_key_for_joiner":
            # Same rationale for the server-cert private key minted at JOIN
            # time. Distinct HKDF info / AAD domain enforced by the local
            # primitive.
            from . import ha_password as _hap

            server_key_pem = bytes.fromhex(args["server_key_pem"])
            node_uuid = args["node_uuid"]
            return _hap.wrap_server_key_for_joiner(server_key_pem, node_uuid).hex()
        raise ValueError(f"unknown op: {op}")


def crypto_socket_name(container_id: str | None = None) -> str:
    """Default socket path for the master crypto-ops RPC.

    Returns a filesystem path under the rhorizon runtime directory
    (default `/run/rhorizon/`, see socket_paths.runtime_dir). The
    container_id segment lets multiple rhorizon containers on the same
    host coexist (rare - usually one per host)."""
    return str(crypto_ops_socket_path(container_id))
