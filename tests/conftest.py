import json
import os
from pathlib import Path

import asyncpg
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

os.environ.setdefault(
    "RHORIZON_DATABASE_URL",
    os.environ.get(
        "TEST_DATABASE_URL",
        "postgresql+asyncpg://rhorizon_test:rhorizon_test@localhost:55434/rhorizon_test",
    ),
)
# Test PostgreSQL has no TLS
os.environ.setdefault("RHORIZON_DATABASE_SSL", "false")

# Override prod paths that are not writable locally (containerized CI is fine,
# dev box is not root). Tests that touch audit_dir / authfail_log would hit
# PermissionError otherwise.
import tempfile as _tf

_test_audit_dir = Path(_tf.gettempdir()) / "rhorizon-test-audit"
_test_audit_dir.mkdir(exist_ok=True)
os.environ.setdefault("RHORIZON_AUDIT_DIR", str(_test_audit_dir))
os.environ.setdefault("RHORIZON_AUTHFAIL_LOG", str(_test_audit_dir / "authfail.log"))

# same reasoning as RHORIZON_AUDIT_DIR: /var/lib/rhorizon is
# the prod container path (uid 1500 owns it). On a dev host it's
# root-owned, so lifespan would crash at first boot trying to create the
# parent dir. Redirect tests to a tmp file.
_test_node_uuid_dir = Path(_tf.gettempdir()) / "rhorizon-test-node-uuid"
_test_node_uuid_dir.mkdir(exist_ok=True)
os.environ.setdefault("RHORIZON_NODE_UUID_PATH", str(_test_node_uuid_dir / "node-uuid"))

# same volume override pattern for cluster cert
# paths. /cluster/init persists the primary's cert + key here, and the
# the auto-JOIN flow writes the joiner pair. Without a tmp
# redirect every cluster-init test would try to write to /var/lib/rhorizon
# which is root-owned on a dev host.
_test_cluster_cert_dir = Path(_tf.gettempdir()) / "rhorizon-test-cluster-cert"
_test_cluster_cert_dir.mkdir(exist_ok=True)
os.environ.setdefault(
    "RHORIZON_CLUSTER_CERT_PATH", str(_test_cluster_cert_dir / "cluster-cert.pem")
)
os.environ.setdefault(
    "RHORIZON_CLUSTER_CERT_KEY_PATH",
    str(_test_cluster_cert_dir / "cluster-cert.key"),
)

# Tests exercise dozens of namespace mutations under the same admin
# actor: bump the per-hour cap so the suite doesn't 429 itself.
os.environ.setdefault("RHORIZON_NAMESPACE_MUTATION_RATE_PER_HOUR", "10000")

# IPC bypass in tests:
#
# /unseal calls start_master_services which binds crypto-ops and key-sharing
# sockets in the runtime directory and spawns a Shamir share-serving task.
# The paths are host-stable, so repeated seal/unseal cycles inside one pytest
# session collide on the same socket files.
# Followers' attach_to_master would also poll the DB for a master row that
# never exists in single-worker tests.
#
# We install no-ops as an autouse fixture so the bypass is per-test and
# can be opted out by tests that exercise the real cluster_setup helpers
# (test_cluster_setup.py, test_cluster_rpc_more.py do their own setup).
import api.app.cluster_setup as _cs  # noqa: E402
from api.app.main import app  # noqa: E402

_ORIG_START_MASTER = _cs.start_master_services
_ORIG_STOP_MASTER = _cs.stop_master_services
_ORIG_ATTACH_TO_MASTER = _cs.attach_to_master


async def _noop_start_master_services(*args, **kwargs):
    return None


async def _noop_stop_master_services(*args, **kwargs):
    return None


async def _noop_attach_to_master(*args, **kwargs):
    # Followers in tests never attach, the test client process *is* the
    # master and never delegates.
    return False


@pytest.fixture(autouse=True)
def _bypass_cluster_ipc(request, monkeypatch):
    """Install no-op cluster_setup helpers for the duration of the test.

    Tests that need the real implementations (test_cluster_setup,
    test_cluster_rpc_more) carry the marker `cluster_real` to skip
    this bypass."""
    if "cluster_real" in request.keywords:
        return
    monkeypatch.setattr(_cs, "start_master_services", _noop_start_master_services)
    monkeypatch.setattr(_cs, "stop_master_services", _noop_stop_master_services)
    monkeypatch.setattr(_cs, "attach_to_master", _noop_attach_to_master)


@pytest_asyncio.fixture(autouse=True)
async def _reset_2fa_state(setup_db):
    """Clear any leaked 2FA state before each test so the suite is order-independent.

    2FA state lives in ``vault_config`` (second_factor / totp_secret /
    totp_pending / totp_last_counter)
    plus ``vault_yubikeys`` / ``vault_webauthn``. A test that enables TOTP leaves
    ``totp_secret`` behind; the next test's ``POST /totp/setup`` then returns 409
    ("TOTP already configured") and its ``r.json()["secret"]`` raises ``KeyError``.
    ``setup_db`` only wipes this once per session, which made the failure a latent,
    order-dependent flake. Reset per test instead.

    Uses asyncpg (already a core dependency, so present in the CI image) rather
    than a sync driver. Depends on ``setup_db`` so the schema exists. Also drops
    the vault singleton's in-memory 2FA status cache.
    """
    dsn = os.environ["RHORIZON_DATABASE_URL"].replace(
        "postgresql+asyncpg://", "postgresql://"
    )
    conn = await asyncpg.connect(dsn)
    try:
        await conn.execute(
            "DELETE FROM vault_config WHERE key IN "
            "('second_factor', 'totp_secret', 'totp_pending', "
            "'totp_last_counter')"
        )
        await conn.execute("TRUNCATE TABLE vault_yubikeys, vault_webauthn")
    finally:
        await conn.close()

    from api.app.vault_state import vault

    vault.invalidate_2fa_cache()
    yield


@pytest_asyncio.fixture(scope="session")
async def setup_db():
    """Apply schema.sql + wipe stale data + run lifespan migrations.

    The ASGITransport doesn't trigger FastAPI lifespan events in tests,
    so any post-schema migration logic has to be invoked explicitly
    here. Today this covers `_migrate_namespaces()`.

    Stale-data wipe : tests POST hardcoded names (e.g. `sec-no-seal`,
    `honey-test`, ...) that are unique within a single session but
    collide across sessions because previous runs leave their rows
    behind. We TRUNCATE all data tables at session start to give every
    run a clean slate. `vault_config` is preserved - it holds the
    Argon2 salt and master_check that admin_token relies on.
    """
    raw_dsn = os.environ["RHORIZON_DATABASE_URL"].replace(
        "postgresql+asyncpg://", "postgresql://"
    )
    conn = await asyncpg.connect(raw_dsn)
    try:
        # Drop tables whose constraints evolved across sessions so the new
        # schema definition applies (CREATE TABLE IF NOT EXISTS is a no-op
        # on an existing table). Only those that depend on the new
        # UNIQUE(name, namespace) constraint on vault_secrets.
        await conn.execute(
            "DROP TABLE IF EXISTS vault_secret_versions, vault_secrets CASCADE"
        )
        schema = (Path(__file__).parent.parent / "schema.sql").read_text()
        await conn.execute(schema)
        # Wipe all data tables (CASCADE cleans up FK chains).
        # vault_config preserved : contains master_check + argon2_salt.
        # vault_dek preserved : wrapped under the same master, valid
        # across sessions and avoids an unnecessary re-rotation.
        # vault_cluster_config and
        # vault_join_idempotency added to the wipe list. Cross-file
        # ordering used to leave stale cluster_id / ha_password_encrypted
        # / cluster_ca_* rows that a downstream test's /cluster/init
        # surfaced as 409 cluster_already_initialised. Per-file
        # autouse fixtures only delete a hard-coded subset of keys, so
        # a missed key (eg cluster_ca_cert_prev from a rotation test)
        # would survive. Session-level TRUNCATE makes the first
        # cluster-related test in any file see an empty config.
        await conn.execute("""
            TRUNCATE TABLE
                vault_secrets,
                vault_secret_versions,
                vault_tokens,
                vault_audit,
                vault_audit_lite,
                vault_audit_mcp,
                vault_audit_verify_jobs,
                vault_audit_verification_anchors,
                vault_audit_key_archive,
                vault_audit_signer_certs,
                vault_audit_archive_seals,
                vault_audit_lite_archive_seals,
                vault_yubikeys,
                vault_webauthn,
                vault_challenges,
                vault_workers,
                vault_cluster_nodes,
                vault_cluster_config,
                vault_join_idempotency,
                vault_rate_limits,
                vault_groups,
                vault_group_members,
                vault_notification_channels,
                vault_dynamic_module_state,
                vault_dynamic_engines,
                vault_dynamic_roles,
                vault_leases,
                vault_namespaces,
                vault_pending_token_rotations,
                -- The PKI CA private key is wrapped under pki_wrap_key, an
                -- HKDF sub-key of the master key. A session does not inherit
                -- the previous session's salt (a rotate-password test leaves a
                -- new one behind), so a CA that outlives its session is
                -- wrapped under a master key nobody can re-derive. The next
                -- rotate-password then fails in rewrap_for_master_rotation
                -- with "Decryption failed", far from the test that leaked it.
                -- Production never hits this: the salt only moves through
                -- rotate-password, which re-wraps the CA in the same
                -- transaction. Tests that need a CA call /pki/init themselves.
                vault_pki_config,
                vault_pki_certs
            RESTART IDENTITY CASCADE
        """)
        # Also clear the post-restore review flag if it was left behind
        await conn.execute(
            "DELETE FROM vault_config "
            "WHERE key IN ('pending_restore_review', "
            "'pending_restore_bootstrap')"
        )
        # Bootstrap state isolation : if a previous run left behind a
        # master_check tied to a different password (interrupted rotation,
        # mid-test crash, or a stray first-boot with the wrong password),
        # every admin_token unseal in this session would 401 and cascade
        # into hundreds of opaque VaultSealedError + 503 + 429 errors.
        # Drop the bootstrap rows so the first admin_token call re-mints
        # them under the canonical test master password.
        await conn.execute(
            "DELETE FROM vault_config "
            "WHERE key IN ('master_check', 'argon2_salt', "
            "'vault_initialized', 'dek_key_version', 'prev_hmac_key', "
            "'prev_hmac_rotated_at', 'second_factor', 'totp_secret', "
            "'audit_identity_seed_enc', 'audit_identity_pub')"
        )
        # vault_dek rows wrapped under the old dek_key are unusable too.
        await conn.execute("DELETE FROM vault_dek")
    finally:
        await conn.close()

    # Run the same lifespan migrations the production lifespan does.
    from api.app.database import async_session
    from api.app.main import _migrate_namespaces
    from api.app.routes import dynamic

    await _migrate_namespaces()
    async with async_session() as db:
        await dynamic.initialize_engine_registry(db)


@pytest_asyncio.fixture(scope="session")
async def client(setup_db):
    """Async test client."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture(scope="session")
def master_password():
    return "test-master-password-2024"


@pytest_asyncio.fixture(scope="function")
async def admin_token(client, master_password):
    """Bootstrap an root token for tests - unseals vault if needed,
    and forces consistency between in-RAM dek_key and vault_config.

    Function-scoped (not session-scoped) since Bloc G : the dual-context
    /backup/restore wipes vault_tokens, so any test running after one
    that exercises restore would otherwise inherit an empty vault_tokens
    + sealed vault.

    Bloc G also exposed a latent test inconsistency : several tests in
    test_main_loops.py call `vs.unseal(derive_keys(mk))` directly with
    the default dek_key_version=1, while vault_config.dek_key_version
    may be at 2 (after test_dek_key_rotation bumps it). In production
    these are kept in sync by /admin/rotate-dek-key, but the test
    bypass desynchronises the runtime. Force a re-unseal via the API
    here (which reads vault_config.dek_key_version and threads it
    through derive_keys) so every test starts from a known-consistent
    state. Adds ~1s Argon2id per test but eliminates a whole class
    of flake.
    """
    from api.app.crypto import generate_token
    from api.app.database import async_session
    from api.app.vault_state import vault

    # Per-test isolation for the WHOLE audit subsystem. vault_audit is only
    # TRUNCATEd at session start, but the per-test rotations bump
    # vault_config['key_epoch'] and leave rows in vault_audit_key_archive (each
    # retired audit key wrapped under THAT test's dek_key). A later test's
    # rotate_audit_keyring then re-wraps a stale archive row whose dek_key no
    # longer matches -> InvalidTag (the intra-session rotation/audit-epoch
    # failures). And the chain + the keys/identity that verify it must reset
    # TOGETHER: clearing keys/certs while leaving prior tests' signed rows in
    # vault_audit makes a later full-chain /audit/verify fail (rows signed
    # under keys/identities that no longer exist). So reset the chain, its key
    # archive, the signer certs, the epoch counter, and the audit identity as
    # one unit -- every test starts from a clean, self-consistent chain.
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_audit_archive_seals"))
        await db.execute(text("DELETE FROM vault_audit_lite_archive_seals"))
        await db.execute(text("DELETE FROM vault_audit"))
        await db.execute(text("DELETE FROM vault_audit_lite"))
        await db.execute(text("DELETE FROM vault_audit_key_archive"))
        await db.execute(text("DELETE FROM vault_audit_verification_anchors"))
        await db.execute(text("DELETE FROM vault_audit_signer_certs"))
        await db.execute(
            text(
                "DELETE FROM vault_config WHERE key IN "
                "('key_epoch', 'audit_identity_seed_enc', 'audit_identity_pub')"
            )
        )
        await db.commit()

    # Always seal first then unseal, guarantees the in-RAM dek_key
    # matches the dek_key_version in vault_config (the API unseal
    # reads it correctly via _get_dek_key_version, unlike the
    # `vs.unseal(derive_keys(mk))` bypass used in some tests).
    if not vault.sealed:
        vault.seal()
    r = await client.post("/api/v1/vault/unseal", json={"password": master_password})
    # Fail loudly if unseal didn't take : a stale master_check (run
    # against a corrupted DB), a 429 rate-limit lockout, or a 2FA mode
    # left enabled by a previous test would otherwise cascade into 503
    # / VaultSealedError on every later assertion. Surfacing it here
    # turns 300+ opaque setup errors into one actionable failure.
    if r.status_code != 200 or vault.sealed:
        raise RuntimeError(
            "admin_token fixture: unseal did not produce an unsealed vault "
            f"(status={r.status_code}, sealed={vault.sealed}, body={r.text}). "
            "Likely a corrupted vault_config or rate-limit lockout from a "
            "prior run - drop the test DB or check vault_rate_limits."
        )

    raw_token = generate_token()
    token_hash = await vault.hmac_sha512_hex(raw_token)

    async with async_session() as db:
        # Per-test isolation for the in-window rotation guard: a prior test's
        # non-emergency rotation leaves prev_hmac_rotated_at in vault_config,
        # which would make THIS test's first rotation 409 as a "second rotation
        # in the window". Clear the prev_hmac trace so every test starts as if
        # no rotation has happened (the fixture already re-derived keys from the
        # canonical master_password via the seal+unseal above).
        await db.execute(
            text(
                "DELETE FROM vault_config "
                "WHERE key IN ('prev_hmac_key', 'prev_hmac_rotated_at')"
            )
        )
        await db.execute(
            text("""
                INSERT INTO vault_tokens
                    (name, token_hash, permissions, created_by)
                VALUES
                    ('test-admin', :hash,
                     CAST(:perms AS jsonb), 'bootstrap')
                ON CONFLICT (name) WHERE active DO UPDATE SET token_hash = :hash
            """),
            {
                "hash": token_hash,
                "perms": json.dumps({"admin": "rw"}),
            },
        )
        await db.commit()
    vault.clear_prev_hmac()

    return raw_token
