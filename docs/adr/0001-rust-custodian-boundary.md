# ADR 0001: Rust owns long-lived custody

Date: 2026-08-10
Status: accepted, implementation in progress

## Context

Rhorizon currently has two process layouts. Embedded mode couples API workers
to key custody. Separated mode keeps a fixed Python custodian pool beside a
disposable API pool. Separated mode fixes worker depletion under load, but each
custodian still starts the Python application and carries its memory cost.

The existing Rust extension already implements secure buffers, Shamir sharing,
crypto operations, Unix peer checks, and the master RPC dispatcher. The missing
piece is a small standalone process that owns custody without importing the HTTP
application.

## Decision

FastAPI and Uvicorn remain the public HTTP layer. Long-lived Shamir shares and
master-key operations move to `rhorizon-custodian`, a Rust daemon reachable only
through authenticated local sockets.

Rust code is split into three packages:

- `rhorizon-custody-core`: portable protocol, quorum rules, Shamir and crypto
  code with no PyO3 dependency;
- `rhorizon_crypto`: the current Python extension and compatibility adapter;
- `rhorizon-custodian`: the standalone daemon.

Custodians have fixed logical slots. Process replacement does not consume a new
share or change the key generation. A topology or threshold change uses an
explicit transactional reshare. Every share-bearing message identifies its
generation and slot; mixed generations fail closed.

The first production topology is 2-of-3. Larger configurable topologies remain
supported. Losing one 2-of-3 custodian keeps the vault available; losing two
seals it.

## Compatibility

This decision does not change encrypted database rows, AAD, key epochs, backup
formats, public HTTP routes, or the operator's memory-lock policy. The current
Python backend remains available during rollout. Switching backends requires a
seal, restart, and unseal, but no database migration.

## Security boundary

- API workers never retain Shamir shares or the reconstructed master key.
- Socket permissions and peer credentials fail closed.
- Share generation and slot are validated before reconstruction.
- Secret allocations are zeroized; memory locking follows best-effort or
  required mode as selected by the operator.
- Each fixed slot persists active, prepared, and rollback generations as one
  fixed-size authenticated encrypted record. Updates use file and directory
  fsync followed by atomic replacement; malformed, exposed, or tampered state
  prevents that custodian from starting.
- Reshare uses prepare, durable metadata commit, and custodian commit. Failure
  must leave exactly one complete generation usable.

## Rollout

1. Add the pure-Rust core while leaving runtime behavior unchanged.
2. Run one Rust custodian against the existing Python RPC client.
3. Add fixed-slot quorum, replacement, and transactional reshare.
4. Move seal, unseal, rotation, and key loading to a control socket.
5. Add Compose, Kubernetes, systemd, BSD rc.d, and macOS launchd adapters.
6. Canary behind an explicit backend setting and retain Python rollback.
7. Make Rust the default only after failure, load, memory, security, and
   platform gates pass.

## Required evidence

- Replacing 100 API workers leaves custody slots and generation unchanged.
- Replacing custodians repeatedly does not exhaust spare shares.
- Quorum loss, interrupted reshare, stale generations, and malformed frames
  fail safely.
- K7 passes under high request load and temporary 1-2 GiB disk pressure.
- Three idle Rust custodians target no more than 128 MiB RSS combined.
- amd64 and arm64 pass; BSD and macOS pass native socket smoke tests.
- Clippy, Miri where applicable, protocol fuzzing, and dependency gates pass.

## Consequences

The API can scale and restart independently of custody with substantially less
custodian memory. The cost is a versioned local protocol, transactional reshare
logic, and platform-specific service packaging that must be tested before the
backend becomes the default.
