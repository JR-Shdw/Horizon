# Key custody and worker pools

rhorizon supports two local process layouts.

`embedded` is the compatibility layout. API workers also form the Shamir
quorum. One worker holds the active subkeys and serves crypto RPC; the others
hold one share each.

`separated` uses two pools inside the API container:

- a fixed, Unix-socket-only custodian pool owns the Shamir shares and elects
  the local crypto master;
- public API workers hold no share, do not register in `vault_workers`, and
  delegate crypto to the elected custodian over the existing Rust RPC socket.

The second layout makes API workers disposable. A request worker may be killed,
replaced, or scaled without changing the Shamir generation. Key lifecycle
operations such as unseal, seal, password rotation, DEK rotation, and restore
cross a private control socket. Ordinary secret traffic stays in the public
pool and uses native crypto RPC.

Separated mode currently has two implementations. `python` remains the default.
The explicit `rust` canary runs fixed standalone daemons, restarts a failed
logical slot with its persistent transport identity, and transactionally
repairs an empty slot when the current quorum survives. Each slot saves its
active and in-flight generations in an authenticated encrypted file, so a full
container restart preserves the quorum while leaving runtime keys sealed. It
starts sealed unless an existing migrated generation has durable unsealed
intent.

The normal password and second-factor ceremony drives both entry paths. Against
an empty pool it activates: bootstrap and audit state commit first, the five
runtime subkeys move as opaque native shares, and the API copy is wiped before
it attaches to Rust. Against a pool that already holds a generation -- after a
manual seal, or after the automatic post-restore seal -- the same ceremony
reopens that generation from the shares the custodians kept. Nothing is
resplit, because a new split would use a different polynomial, and the unsealed
intent is recorded only once the daemons answered: the reverse order would
leave the maintenance leader chasing a generation no quorum can assemble.
Either path then recomputes `master_check` through the attached custodian
before the vault accepts the attachment. That is the only proof that the bundle
the pool holds is the one the password just verified; a mismatch reseals the
daemons, the API view, and the durable decision. Reopening also refuses a slot
count or threshold that no longer matches the durable generation, because
changing the topology is a reshare, not an unseal.
Master-password and `dek_key` rotation stage a complete opaque replacement
generation, commit the database rewrap and roll-forward decision together, then
switch the pool. A `dek_key` rotation replaces only that subkey, so the staged
bundle keeps the live HMAC, audit, HA-wrap, and PKI-wrap keys. A pre-commit
failure restores the old generation and reinstalls the envelopes the seal
dropped; post-commit recovery can only finish the new one.

A logical backup restore keeps the runtime bundle: `argon2_salt`,
`master_check`, and `dek_key_version` all stay current, so the custodians keep
the generation they already hold and no reshare happens. What the restore does
own is the post-restore seal, and under this canary that is a durable decision
committed in the same transaction as the restored rows. The restore takes the
custody orchestration lock for its whole transaction, so it cannot interleave
with a generation transition or with the maintenance leader's repair. If the
process dies between that commit and the daemon seal, the recorded decision
already says sealed and the maintenance loop finishes the seal. The restore
never imports the backup's own custody rows: `rust_custody_generation_state`
and `rust_custody_activation_state` describe the pool of the vault the backup
came from, and adopting that generation counter would point recovery at a
generation no local slot has.

Shamir administration remains blocked in this canary; there is no fallback that
silently moves an active generation back into Python.

## Enable it

Docker Compose or Podman:

```env
RH_CUSTODY_MODE=separated
RH_CUSTODY_BACKEND=python
RH_WORKERS=5
RH_CUSTODIAN_WORKERS=3
```

Helm:

```yaml
api:
  custodyMode: separated
  workers: 5
  custodianWorkers: 3
```

The standalone Rust canary supports password-based activation and reopening.
Enable it
only for testing until the remaining key-lifecycle routes and rollout gates are
complete:

```env
RH_CUSTODY_MODE=separated
RH_CUSTODY_BACKEND=rust
RH_RUST_CUSTODIAN_SLOTS=3
RH_RUST_CUSTODIAN_THRESHOLD=0
```

Transport identities and encrypted share state persist in
`/var/lib/rhorizon/custody`; runtime sockets and the control capability stay
under `/run/rhorizon`. Protect the persistent volume as key material. The share
files are encrypted with keys derived from the transport identities, so copying
the whole directory copies both the ciphertext and the keys needed to open it.

Custodian counts are restricted to 3, 5, 7, or 9. The automatic threshold is
a majority: 2-of-3, 3-of-5, 4-of-7, or 5-of-9. Eight extra shares are reserved
by default for replacement custodians. Extra shares do not raise the quorum.

Separated mode starts more processes. Size memory for both pools:

```text
(API workers + custodian workers) x steady worker memory
+ one Argon2id unseal allocation
+ database pools and runtime headroom
```

Do not enable it under the default memory limit without recalculating that
limit. Three custodians are the practical small-host setting. Five tolerate a
larger simultaneous custody loss.

## Boundary

The control socket and its capability file are created under
`/run/rhorizon`, with group and world access removed. The custodian listener
does not bind TCP. Requests without the capability are rejected before route
dispatch. The original client address is restored only after that check so
rate limits and audit records keep the public identity.

Custodians and API workers currently run under the same container UID. The
boundary prevents accidental network access and removes Shamir state from API
worker lifecycle, but it is not an OS-user isolation boundary. A later native
daemon can enforce peer credentials between separate service accounts without
changing the API-to-RPC design.

## Check it

`GET /api/v1/vault/status` reports:

- `custody_mode`;
- expected and live custodian counts;
- quorum threshold;
- whether exactly one live custody master exists.

The repository smoke test starts both pools, unseals the vault, creates a
secret, crashes the custody master, verifies quorum reconstruction and
custodian replacement, then kills a public API worker and verifies that its
replacement does not change the custodian PID set:

```bash
tools/custody-smoke.sh
```
