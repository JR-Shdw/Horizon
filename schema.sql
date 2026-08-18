-- DO NOT REMOVE: SPDX header + copyright are part of the AGPL-3.0 license terms.
-- Stripping or rewriting these notices on redistribution is a license violation.
-- Project: Resurgamus Horizon · Author: shdw <horizon@resurgamus.com> · License: AGPL-3.0-or-later
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
-- rhorizon, PostgreSQL 18 schema
-- Idempotent: safe to re-run (IF NOT EXISTS / CREATE OR REPLACE)

-- Métadonnées vault (non secret)
CREATE TABLE IF NOT EXISTS vault_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- Stocke: argon2_salt, version, auto_seal_minutes
-- Shamir: shamir_threshold, shamir_total, shamir_enabled

-- Data Encryption Keys (chiffrées par master key)
CREATE TABLE IF NOT EXISTS vault_dek (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    encrypted_key   BYTEA NOT NULL,       -- AES-256-GCM(DEK, dek_key)
    nonce           BYTEA NOT NULL,       -- 12 bytes (96 bits)
    active          BOOLEAN DEFAULT true,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Secrets chiffrés. Le couple (name, namespace) est unique : un meme name
-- peut coexister dans des namespaces distincts (forgejo/admin-password vs
-- gitea/admin-password). Le name seul n'est PAS unique.
CREATE TABLE IF NOT EXISTS vault_secrets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    namespace   TEXT NOT NULL DEFAULT 'default',
    ciphertext  BYTEA NOT NULL,           -- XChaCha20-Poly1305(secret, DEK)
    nonce       BYTEA NOT NULL,           -- 24 bytes (192 bits)
    aad_version SMALLINT NOT NULL DEFAULT 2 CHECK (aad_version IN (1, 2)),
    dek_id      UUID NOT NULL REFERENCES vault_dek(id),
    metadata    JSONB DEFAULT '{}',
    version     INTEGER NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW(),
    expires_at  TIMESTAMPTZ,
    created_by  TEXT NOT NULL,
    dek_rotated_at  TIMESTAMPTZ DEFAULT NOW(),  -- last DEK rotation timestamp
    is_honey BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (name, namespace)
);

-- Tokens d'accès au vault
CREATE TABLE IF NOT EXISTS vault_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,     -- HMAC-SHA512
    permissions JSONB NOT NULL DEFAULT '{}',
    active      BOOLEAN DEFAULT true,
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,              -- historique révocation
    allowed_ips TEXT,  -- comma-separated CIDRs (NULL/'' = no IP restriction)
    is_honey BOOLEAN NOT NULL DEFAULT FALSE,
    rotated_at TIMESTAMPTZ
);
-- Un seul token actif par nom (les révoqués gardent l'historique)
CREATE UNIQUE INDEX IF NOT EXISTS uq_vault_tokens_active_name
    ON vault_tokens (name) WHERE active;
-- Idempotent migration for existing DBs

-- Audit trail signé
CREATE TABLE IF NOT EXISTS vault_audit (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- clock_timestamp() (not NOW()): NOW returns transaction_timestamp,
    -- constant across all inserts in a single transaction. The audit chain
    -- requires the row order at READ time (ORDER BY timestamp ASC) to match
    -- the row insert sequence at WRITE time. When a honey_access alert runs
    -- in a dedicated session inside the same request, it commits BEFORE the
    -- request's own log_action, so its INSERT clock is later, but its
    -- transaction_timestamp would be earlier than the request session's
    -- transaction_timestamp. clock_timestamp gives wall-clock at INSERT
    -- time, which preserves the write order on the timestamp axis.
    timestamp   TIMESTAMPTZ DEFAULT clock_timestamp(),
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    target      TEXT,                     -- secret name (jamais la valeur)
    detail      JSONB DEFAULT '{}',
    ip_address  TEXT,
    signature   TEXT NOT NULL,  -- chained HMAC-SHA512 or Ed25519 signature
    key_epoch INT NOT NULL DEFAULT 0,
    sig_alg TEXT NOT NULL DEFAULT 'hmac',
    signer_fpr TEXT,
    -- v1 signs actor/action/target/detail only. New writers explicitly select
    -- v2, which binds every immutable stored field except signature itself.
    payload_version SMALLINT NOT NULL DEFAULT 1
);

ALTER TABLE vault_audit
    ADD COLUMN IF NOT EXISTS payload_version SMALLINT NOT NULL DEFAULT 1;
DO $$ BEGIN
    ALTER TABLE vault_audit ADD CONSTRAINT ck_vault_audit_payload_version
        CHECK (payload_version IN (1, 2));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$ BEGIN
    ALTER TABLE vault_audit ADD CONSTRAINT ck_vault_audit_v2_detail_object
        CHECK (payload_version <> 2 OR jsonb_typeof(detail) = 'object');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Migration: bring existing tables up to clock_timestamp() default.
-- Idempotent: ALTER COLUMN SET DEFAULT is safe on already-correct tables.
ALTER TABLE vault_audit ALTER COLUMN timestamp SET DEFAULT clock_timestamp();

-- Audit chain survives key rotation. Each entry is tagged with the
-- key generation whose audit_key SIGNED it. /audit/verify recomputes each
-- entry's HMAC with the matching key: the live in-RAM audit_key for the
-- current epoch, or the archived key (vault_audit_key_archive) for retired
-- epochs. Without this, a master-password rotation changes audit_key and the
-- whole chain false-breaks (chain_intact:false). Existing rows default to
-- epoch 0; the first rotation archives the epoch-0 audit_key so they stay
-- verifiable.

-- Audit chain : asymmetric (Ed25519) signing migration. New entries are signed
-- with a per-node Ed25519 identity (sig_alg='ed25519') and verified with the
-- PUBLIC key only -- so /audit/verify works while sealed and does not depend on
-- the master key generation (kills the per-epoch keyring false-break class).
-- `sig_alg` dispatches verification: existing rows default to 'hmac' and keep
-- using the key_epoch + vault_audit_key_archive path; 'ed25519' rows verify via
-- the signer cert in vault_audit_signer_certs keyed by `signer_fpr`. key_epoch
-- is retained (still drives the DEK-staleness fence) but is unused for ed25519
-- rows.

-- Public registry of every audit signer cert ever seen (current + rotated +
-- prev), so historical ed25519 entries stay verifiable across identity/CA
-- rotation. PUBLIC material only (cert + pubkey) -- safe at rest, no decryption
-- needed by verify. `fingerprint` = SHA-256 hex of the signer's Ed25519 public
-- key (matches vault_state.audit_identity_fpr); `public_key` is the raw 32-byte
-- key; `cert_pem` is the CA-signed (HA) or self-signed (standalone) cert when
-- issued (NULL until S6 cert provisioning). node_uuid attributes the signer.
CREATE TABLE IF NOT EXISTS vault_audit_signer_certs (
    fingerprint TEXT PRIMARY KEY,
    public_key  BYTEA       NOT NULL,
    cert_pem    TEXT,
    node_uuid   TEXT,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- Retired audit_keys, encrypted at rest under the CURRENT dek_key (re-wrapped
-- on every rotation, same lifecycle shape as the DEKs). One row per retired
-- epoch; the current epoch's key stays only in RAM. audit_key_enc = AES-256-GCM
-- nonce(12) || ciphertext. Lets /audit/verify check entries signed under keys
-- the master password no longer derives, preserving tamper-evidence across
-- rotations.
CREATE TABLE IF NOT EXISTS vault_audit_key_archive (
    key_epoch     INT PRIMARY KEY,
    audit_key_enc BYTEA       NOT NULL,
    archived_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    quarantined_at TIMESTAMPTZ
);
-- A4: a permanently-dead archive row (does not decrypt under the current
-- dek_key, e.g. a foreign row left by a DB restore) is quarantined on first
-- detection so rotation stops re-alarming it every cycle, and so the
-- "all rows fail" wrong-cipher tripwire in load_audit_keyring ignores it.

-- vault_audit_lite : append-only access log for high-frequency read
-- operations (get_secret, list_secrets, whoami…). Same schema as
-- vault_audit MINUS the signature column, and NO cluster-wide
-- advisory lock on insert. Periodic Merkle roots are signed into
-- vault_audit, so completed windows are tamper-evident without paying
-- per-read signature and serialization cost. The newest tail remains
-- explicitly unprotected until its checkpoint is written.
-- Splitting reads off the chain frees ~150 RPS of headroom on
-- read_secret (was the cluster's hot bottleneck per the 2026-05-08
-- bench).
CREATE TABLE IF NOT EXISTS vault_audit_lite (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp   TIMESTAMPTZ DEFAULT clock_timestamp(),
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    target      TEXT,                     -- secret/token name (no value)
    detail      JSONB DEFAULT '{}',
    ip_address  TEXT
    -- intentionally no `signature` column : reads are not chained
);

-- Archive seals. One row per completed audit archive day: the content digest,
-- entry count and chain endpoints of audit-YYYY-MM-DD.jsonl, plus the digest
-- of the previous day's seal so the SEQUENCE of days is pinned too.
--
-- Deliberately its OWN table rather than only a row in vault_audit. Seals are
-- attested in the chain when written (an audit event proves they were not
-- fabricated later), but the chain can only ever be pruned contiguously -- so
-- a seal that lived only in the chain would be deleted along with the rows it
-- attests, leaving archive files with nothing left to verify them against.
-- These rows outlive the pruned window; one per day is negligible.
CREATE TABLE IF NOT EXISTS vault_audit_archive_seals (
    day                    DATE PRIMARY KEY,
    file_name              TEXT NOT NULL,
    entry_count            BIGINT NOT NULL,
    content_digest         TEXT NOT NULL,
    first_signature        TEXT NOT NULL,
    last_signature         TEXT NOT NULL,
    previous_seal_digest   TEXT,
    -- The vault_audit row that attested this seal, so an operator can find the
    -- signed event even after that row's neighbours are gone.
    attested_by_audit_id   UUID,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- Immutable exports of checkpointed audit-lite prefixes. The signed seal is
-- written to vault_audit; this compact index survives main-chain pruning.
CREATE TABLE IF NOT EXISTS vault_audit_lite_archive_seals (
    id                     UUID PRIMARY KEY,
    file_name              TEXT NOT NULL UNIQUE,
    entry_count            BIGINT NOT NULL CHECK (entry_count > 0),
    content_digest         TEXT NOT NULL,
    seal_digest            TEXT NOT NULL,
    merkle_root            TEXT NOT NULL,
    first_timestamp        TIMESTAMPTZ NOT NULL,
    first_id               UUID NOT NULL,
    last_timestamp         TIMESTAMPTZ NOT NULL,
    last_id                UUID NOT NULL,
    previous_seal_digest   TEXT,
    attested_by_audit_id   UUID,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- Durable full-verification jobs. Full audit verification is O(N), so it must
-- not be coupled to a reverse-proxy request timeout. A partial unique index
-- permits exactly one pending/running verifier across the whole API cluster.
CREATE TABLE IF NOT EXISTS vault_audit_verify_jobs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'running', 'succeeded', 'failed')),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    started_at   TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ,
    requested_by TEXT NOT NULL,
    worker_host  TEXT,
    worker_pid   INTEGER,
    heartbeat_at TIMESTAMPTZ,
    result       JSONB,
    error        TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_vault_audit_verify_active
    ON vault_audit_verify_jobs ((1)) WHERE status IN ('pending', 'running');
CREATE INDEX IF NOT EXISTS idx_vault_audit_verify_requested
    ON vault_audit_verify_jobs (requested_at DESC);

-- Independently signed receipts for completed, stable, full evidence walks.
-- These are deliberately outside vault_audit: an incremental verifier must be
-- able to authenticate its starting point before trusting any chain row after
-- it. The payload contains the exact main/lite/archive high-water marks and is
-- signed directly by the cluster Ed25519 audit identity.
CREATE TABLE IF NOT EXISTS vault_audit_verification_anchors (
    id           UUID PRIMARY KEY,
    completed_at TIMESTAMPTZ NOT NULL,
    payload      JSONB NOT NULL,
    signature    TEXT NOT NULL CHECK (length(signature) = 128),
    signer_fpr   TEXT NOT NULL REFERENCES vault_audit_signer_certs(fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_vault_audit_verification_anchor_completed
    ON vault_audit_verification_anchors (completed_at DESC, id DESC);

-- MCP hub audit: a DEDICATED chained log for MCP tool calls (OPTIONAL feature).
-- The MCP hub (mcp-hub/, opt-in) emits one row per tool call carrying the calling
-- agent's identity (agent_token_id = vault_tokens.id). It is a SEPARATE hash chain
-- from vault_audit (its own advisory-lock lineage) so high-volume MCP traffic never
-- serializes behind secret/token CRUD. Same keyed signing as vault_audit
-- (ed25519-first, hmac fallback + key_epoch) so /audit/mcp/verify works while
-- sealed and survives key rotation. Rows appear in the Jets "MCP" tab. This table
-- stays empty unless a hub is deployed; it changes nothing about the standalone
-- stdio mcp/ server.
CREATE TABLE IF NOT EXISTS vault_audit_mcp (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp      TIMESTAMPTZ DEFAULT clock_timestamp(),
    agent_token_id UUID,                     -- vault_tokens.id of the calling agent
    actor          TEXT NOT NULL,            -- token username (from the bearer, not the body)
    hub            TEXT,                     -- originating hub app name (self-declared label, signed)
    backend        TEXT NOT NULL,            -- MCP backend prefix (e.g. rhorizon, docker)
    tool           TEXT NOT NULL,            -- tool name
    target         TEXT,                     -- secret/resource name (no value)
    decision       TEXT NOT NULL,            -- allowed | policy_denied | error
    detail         JSONB DEFAULT '{}',
    ip_address     TEXT,                     -- the hub host as seen by the vault
    signature      TEXT NOT NULL,
    key_epoch      INT NOT NULL DEFAULT 0,
    sig_alg        TEXT NOT NULL DEFAULT 'hmac',
    signer_fpr     TEXT
);

-- YubiKeys enregistrées (challenge-response HMAC-SHA1, slot 2)
-- hmac_secret: the 20-byte secret programmed into the YubiKey
-- stored server-side for verification (same as any 2FA server)
CREATE TABLE IF NOT EXISTS vault_yubikeys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    serial          TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL DEFAULT '',
    hmac_secret     BYTEA NOT NULL,           -- 20 bytes, programmed in slot 2
    registered_at   TIMESTAMPTZ DEFAULT NOW(),
    registered_by   TEXT NOT NULL
);
-- vault_config keys for 2FA:
--   second_factor: none | yubikey | totp | any
--   totp_secret: base32 encoded TOTP secret

-- YubiKey challenges (cross-worker safe, auto-expire)
CREATE TABLE IF NOT EXISTS vault_challenges (
    challenge   TEXT PRIMARY KEY,
    expires_at  TIMESTAMPTZ NOT NULL,
    purpose     TEXT NOT NULL DEFAULT 'unseal',
    node_uuid TEXT,
    source_ip TEXT,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- Idempotent migration for older DBs

-- /cluster/challenge binding columns.
-- node_uuid / source_ip stay NULLable because the unseal flow does
-- not populate them ; the application layer enforces NOT NULL for
-- rows with purpose='cluster_join'. issued_at defaults to NOW() so
-- existing unseal rows backfill cleanly at ALTER time.

CREATE INDEX IF NOT EXISTS idx_vault_challenges_purpose_expires
    ON vault_challenges (purpose, expires_at);

-- WebAuthn/FIDO2 credentials (browser-native security keys)
-- credential_data: serialized AttestedCredentialData (public key, NOT encrypted)
CREATE TABLE IF NOT EXISTS vault_webauthn (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id   BYTEA NOT NULL UNIQUE,
    credential_data BYTEA NOT NULL,
    sign_count      INTEGER NOT NULL DEFAULT 0,
    name            TEXT NOT NULL DEFAULT '',
    registered_at   TIMESTAMPTZ DEFAULT NOW(),
    registered_by   TEXT NOT NULL
);

-- Rate limiting (DB-backed, multi-worker safe)
CREATE TABLE IF NOT EXISTS vault_rate_limits (
    ip_address  TEXT PRIMARY KEY,
    fail_count  INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Secret version history (chiffrées, comme vault_secrets)
CREATE TABLE IF NOT EXISTS vault_secret_versions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id   UUID NOT NULL REFERENCES vault_secrets(id) ON DELETE CASCADE,
    version     INTEGER NOT NULL,
    ciphertext  BYTEA NOT NULL,
    nonce       BYTEA NOT NULL,
    aad_version SMALLINT NOT NULL DEFAULT 2 CHECK (aad_version IN (1, 2)),
    dek_id      UUID NOT NULL REFERENCES vault_dek(id),
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    created_by  TEXT,
    grace_until TIMESTAMPTZ,
    UNIQUE (secret_id, version)
);

-- Rotation grace window: a non-emergency value update sets grace_until on the
-- immediately-prior version so GET /{name}?previous=true serves it until then.
-- NULL = not in grace (the default and the post-emergency state).

-- Groups / RBAC
CREATE TABLE IF NOT EXISTS vault_groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT UNIQUE NOT NULL,
    permissions JSONB NOT NULL DEFAULT '{}',
    source      TEXT NOT NULL DEFAULT 'local',  -- 'local' or 'ldap'
    ldap_dn     TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vault_group_members (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id        UUID NOT NULL REFERENCES vault_groups(id) ON DELETE CASCADE,
    principal_type  TEXT NOT NULL CHECK (principal_type IN ('external', 'token')),
    external_id     TEXT,
    token_id        UUID REFERENCES vault_tokens(id) ON DELETE CASCADE,
    added_at        TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT vault_group_members_principal_shape CHECK (
        (principal_type = 'external'
         AND external_id IS NOT NULL AND token_id IS NULL)
        OR
        (principal_type = 'token'
         AND external_id IS NULL AND token_id IS NOT NULL)
    )
);

-- One-time migration from the former untyped `(group_id, username)` model.
-- A row whose name currently identifies an active API token is narrowed to
-- that token UUID. Other legacy strings become `legacy:<name>` external
-- principals: they fail closed until the operator re-adds a source-qualified
-- `ldap:<name>` or `proxy:<name>` identity. This never broadens old access.
ALTER TABLE vault_group_members
    ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid();
ALTER TABLE vault_group_members
    ADD COLUMN IF NOT EXISTS principal_type TEXT;
ALTER TABLE vault_group_members
    ADD COLUMN IF NOT EXISTS external_id TEXT;
ALTER TABLE vault_group_members
    ADD COLUMN IF NOT EXISTS token_id UUID REFERENCES vault_tokens(id) ON DELETE CASCADE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'vault_group_members'
          AND column_name = 'username'
    ) THEN
        EXECUTE '
            UPDATE vault_group_members AS m
            SET principal_type = ''token'', token_id = t.id
            FROM vault_tokens AS t
            WHERE m.principal_type IS NULL
              AND t.active = TRUE
              AND t.name = m.username
        ';
        EXECUTE '
            UPDATE vault_group_members
            SET principal_type = ''external'',
                external_id = ''legacy:'' || username
            WHERE principal_type IS NULL
        ';
        IF EXISTS (
            SELECT 1
            FROM pg_constraint
            WHERE conrelid = 'vault_group_members'::regclass
              AND contype = 'p'
              AND pg_get_constraintdef(oid) =
                  'PRIMARY KEY (group_id, username)'
        ) THEN
            ALTER TABLE vault_group_members
                DROP CONSTRAINT vault_group_members_pkey;
        END IF;
        ALTER TABLE vault_group_members DROP COLUMN username;
    END IF;
END
$$;

ALTER TABLE vault_group_members ALTER COLUMN id SET NOT NULL;
ALTER TABLE vault_group_members ALTER COLUMN principal_type SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'vault_group_members'::regclass AND contype = 'p'
    ) THEN
        ALTER TABLE vault_group_members
            ADD CONSTRAINT vault_group_members_pkey PRIMARY KEY (id);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'vault_group_members'::regclass
          AND conname = 'vault_group_members_principal_type_check'
    ) THEN
        ALTER TABLE vault_group_members
            ADD CONSTRAINT vault_group_members_principal_type_check
            CHECK (principal_type IN ('external', 'token'));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'vault_group_members'::regclass
          AND conname = 'vault_group_members_principal_shape'
    ) THEN
        ALTER TABLE vault_group_members
            ADD CONSTRAINT vault_group_members_principal_shape CHECK (
                (principal_type = 'external'
                 AND external_id IS NOT NULL AND token_id IS NULL)
                OR
                (principal_type = 'token'
                 AND external_id IS NULL AND token_id IS NOT NULL)
            );
    END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_vault_group_members_external
    ON vault_group_members (group_id, external_id)
    WHERE principal_type = 'external';
CREATE UNIQUE INDEX IF NOT EXISTS uq_vault_group_members_token
    ON vault_group_members (group_id, token_id)
    WHERE principal_type = 'token';

-- Namespaces (Phase A, RBAC ownership of secret containers).
-- Each namespace is owned by exactly one vault_groups row. Operating
-- on the namespace itself (change owner, upgrade RBAC, change deletion
-- mode, archive) requires admin + 2FA + rate-limit. Operating on
-- secrets WITHIN a namespace is gated by two per-namespace flags :
--
--   `enforce_membership`   bool, one-way ratchet
--     false (default+migration) : claim-based check (existing model)
--     true                      : live vault_group_members check on
--                                  every read AND write
--
--   `delete_protection`    enum {'free','soft','protected'}, one-way
--     'free' (default+migration) : hard DELETE (existing behavior)
--     'soft'                     : DELETE = soft-delete (deleted_at set),
--                                  reaper purges after retention window,
--                                  POST /{name}/restore un-deletes
--     'protected'                : DELETE requires admin + 2FA challenge,
--                                  always soft, extended retention, no
--                                  auto-purge by reaper
--
-- Both flags are ratcheted at the DB level, see trigger below.
CREATE TABLE IF NOT EXISTS vault_namespaces (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                TEXT UNIQUE NOT NULL,
    owner_group_id      UUID NOT NULL REFERENCES vault_groups(id) ON DELETE RESTRICT,
    enforce_membership  BOOLEAN NOT NULL DEFAULT false,
    delete_protection   TEXT NOT NULL DEFAULT 'free',
    archived_at         TIMESTAMPTZ,
    created_by          TEXT,
    created_at          TIMESTAMPTZ DEFAULT NOW()
);

-- Drop the deprecated transfers_blocked column if a previous deploy
-- created it (idempotent ; no-op on fresh installs).
ALTER TABLE vault_namespaces DROP COLUMN IF EXISTS transfers_blocked;

-- Add delete_protection column on existing tables (idempotent).

-- Enum-style CHECK constraint via DO block (PG has no IF NOT EXISTS
-- on ADD CONSTRAINT). Refuses unknown values.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_delete_protection'
    ) THEN
        ALTER TABLE vault_namespaces
            ADD CONSTRAINT chk_delete_protection
            CHECK (delete_protection IN ('free', 'soft', 'protected'));
    END IF;
END$$;

-- One-way ratchet : a compromised admin token must NOT be able to
-- relax security flags to exfiltrate. The DB trigger refuses
-- relaxing transitions on `enforce_membership` and on
-- `delete_protection` (free=0 < soft=1 < protected=2 ; new must be
-- >= old). Recovery from a wrong upgrade is by design heavy : create
-- a new namespace in agnostic mode, migrate secrets manually, archive
-- the old one.
CREATE OR REPLACE FUNCTION vault_namespaces_one_way_ratchet()
RETURNS TRIGGER AS $$
DECLARE
    old_rank INTEGER;
    new_rank INTEGER;
BEGIN
    IF OLD.enforce_membership = true AND NEW.enforce_membership = false THEN
        RAISE EXCEPTION 'enforce_membership is set-once: cannot be relaxed';
    END IF;
    old_rank := CASE OLD.delete_protection
        WHEN 'free'      THEN 0
        WHEN 'soft'      THEN 1
        WHEN 'protected' THEN 2
        ELSE -1
    END;
    new_rank := CASE NEW.delete_protection
        WHEN 'free'      THEN 0
        WHEN 'soft'      THEN 1
        WHEN 'protected' THEN 2
        ELSE -1
    END;
    IF new_rank < old_rank THEN
        RAISE EXCEPTION 'delete_protection is one-way (free->soft->protected): cannot be relaxed';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_vault_namespaces_ratchet ON vault_namespaces;
CREATE TRIGGER trg_vault_namespaces_ratchet
    BEFORE UPDATE ON vault_namespaces
    FOR EACH ROW EXECUTE FUNCTION vault_namespaces_one_way_ratchet();

-- vault_secrets : add FK to vault_namespaces (idempotent migration in
-- main.py populates the column) + soft-delete columns.
ALTER TABLE vault_secrets ADD COLUMN IF NOT EXISTS namespace_id UUID
        REFERENCES vault_namespaces(id) ON DELETE RESTRICT, ADD COLUMN IF NOT EXISTS deleted_at  TIMESTAMPTZ, ADD COLUMN IF NOT EXISTS purge_after TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_vault_secrets_purge
    ON vault_secrets (purge_after)
    WHERE deleted_at IS NOT NULL AND purge_after IS NOT NULL;
-- Drop the deprecated per-secret transfer_locked column.
ALTER TABLE vault_secrets DROP COLUMN IF EXISTS transfer_locked;

-- Notification channels
CREATE TABLE IF NOT EXISTS vault_notification_channels (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT UNIQUE NOT NULL,
    channel_type TEXT NOT NULL,  -- 'matrix', 'webhook', 'email'
    config      JSONB NOT NULL DEFAULT '{}',
    events      JSONB NOT NULL DEFAULT '[]',
    enabled     BOOLEAN DEFAULT true,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Dynamic secret modules: cluster-wide fine-grained activation under the hard
-- dynamic-engines.ini boundary. Missing rows mean enabled on first boot.
CREATE TABLE IF NOT EXISTS vault_dynamic_module_state (
    module_name TEXT PRIMARY KEY CHECK (
        module_name IN ('postgresql', 'mysql', 'ldap', 'redis', 'cassandra')
    ),
    enabled     BOOLEAN NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE vault_dynamic_module_state
    DROP CONSTRAINT IF EXISTS vault_dynamic_module_state_module_name_check;
ALTER TABLE vault_dynamic_module_state
    ADD CONSTRAINT vault_dynamic_module_state_module_name_check
    CHECK (module_name IN ('postgresql', 'mysql', 'ldap', 'redis', 'cassandra'));

-- Dynamic secret engines
CREATE TABLE IF NOT EXISTS vault_dynamic_engines (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT UNIQUE NOT NULL,
    namespace       TEXT NOT NULL DEFAULT 'default'
                    REFERENCES vault_namespaces(name) ON DELETE RESTRICT,
    engine_type     TEXT NOT NULL CHECK (
        engine_type IN ('postgresql', 'mysql', 'ldap', 'redis', 'cassandra')
    ),
    connection_url  BYTEA NOT NULL,   -- chiffré avec DEK
    nonce           BYTEA NOT NULL,
    dek_id          UUID REFERENCES vault_dek(id),
    max_ttl_seconds INTEGER NOT NULL DEFAULT 86400,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- A dynamic engine is unusable without its wrapped DEK. Refuse startup on an
-- invalid legacy row instead of allowing it to masquerade as a missing engine.
ALTER TABLE vault_dynamic_engines
    ALTER COLUMN dek_id SET NOT NULL;

-- Existing installations may predate namespace rows. NOT VALID immediately
-- protects all new writes while allowing the boot migration to adopt legacy
-- names; `_migrate_namespaces` then validates every existing engine row.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'vault_dynamic_engines_namespace_fkey'
          AND conrelid = 'vault_dynamic_engines'::regclass
    ) THEN
        ALTER TABLE vault_dynamic_engines
            ADD CONSTRAINT vault_dynamic_engines_namespace_fkey
            FOREIGN KEY (namespace)
            REFERENCES vault_namespaces(name)
            ON DELETE RESTRICT
            NOT VALID;
    END IF;
END$$;

-- Keep the persisted catalog wide enough for every built-in module. Runtime
-- enablement is narrower and controlled by dynamic-engines.ini.
ALTER TABLE vault_dynamic_engines
    DROP CONSTRAINT IF EXISTS vault_dynamic_engines_engine_type_check;
ALTER TABLE vault_dynamic_engines
    ADD CONSTRAINT vault_dynamic_engines_engine_type_check
    CHECK (engine_type IN ('postgresql', 'mysql', 'ldap', 'redis', 'cassandra'));
CREATE INDEX IF NOT EXISTS idx_vault_dynamic_engines_ns
    ON vault_dynamic_engines (namespace);

CREATE TABLE IF NOT EXISTS vault_dynamic_roles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engine_id       UUID NOT NULL REFERENCES vault_dynamic_engines(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    creation_sql    TEXT NOT NULL,
    revocation_sql  TEXT NOT NULL,
    default_ttl_seconds INTEGER NOT NULL DEFAULT 3600,
    max_ttl_seconds     INTEGER NOT NULL DEFAULT 86400,
    UNIQUE (engine_id, name)
);

CREATE TABLE IF NOT EXISTS vault_leases (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engine_id   UUID NOT NULL REFERENCES vault_dynamic_engines(id),
    role_name   TEXT NOT NULL,
    username    TEXT NOT NULL,
    revocation_sql TEXT,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN DEFAULT false,
    revocation_verified BOOLEAN NOT NULL DEFAULT false,
    revocation_attempted_at TIMESTAMPTZ,
    provisioning BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);
-- A lease must remain independently revocable after its role is changed or
-- removed. Existing installations receive the snapshot from the live role;
-- an unmatched legacy row stays NULL and fails closed during revocation.
ALTER TABLE vault_leases
    ADD COLUMN IF NOT EXISTS revocation_sql TEXT;
ALTER TABLE vault_leases
    ADD COLUMN IF NOT EXISTS revocation_verified BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE vault_leases
    ADD COLUMN IF NOT EXISTS revocation_attempted_at TIMESTAMPTZ;
ALTER TABLE vault_leases
    ADD COLUMN IF NOT EXISTS provisioning BOOLEAN NOT NULL DEFAULT false;
UPDATE vault_leases AS l
SET revocation_sql = r.revocation_sql
FROM vault_dynamic_roles AS r
WHERE l.revocation_sql IS NULL
  AND r.engine_id = l.engine_id
  AND r.name = l.role_name;

-- Cluster: per-worker state for the process-level cluster.
-- Each uvicorn worker registers (hostname, pid, worker_state) plus the
-- filesystem path of the socket it listens on. last_heartbeat is updated
-- every 1s while the worker is alive; rows whose heartbeat is older than
-- MASTER_TIMEOUT (5s) are considered dead.
-- Composite PK (hostname, pid): multi-host deployments (Swarm/K8s/multi-VM
-- replicas sharing one Patroni cluster) need pid scoped by host or two
-- containers with the same pid collide on UPSERT.
CREATE TABLE IF NOT EXISTS vault_workers (
    hostname            TEXT NOT NULL,                       -- $HOSTNAME at registration
    pid                 INTEGER NOT NULL,
    worker_state        TEXT NOT NULL DEFAULT 'sealed',      -- sealed | follower | candidate | master
    socket_name         TEXT,                                -- follower share-back socket path
    crypto_socket_name  TEXT,                                -- master crypto-ops RPC socket path
    last_heartbeat      TIMESTAMPTZ DEFAULT NOW(),
    started_at          TIMESTAMPTZ DEFAULT NOW(),
    node_uuid        TEXT,
    ha_state         TEXT,
    quarantine_until TIMESTAMPTZ,
    PRIMARY KEY (hostname, pid)
);
-- Idempotent upgrade path for instances created before the composite PK.
-- vault_workers is ephemeral. A process whose row disappears fail-closes its
-- local crypto state and exits for supervisor replacement on its next
-- heartbeat, so wiping pre-migration rows is safe and avoids backfill heuristics.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'vault_workers' AND column_name = 'hostname'
    ) THEN
        DELETE FROM vault_workers;
        ALTER TABLE vault_workers ADD COLUMN hostname TEXT NOT NULL;
        ALTER TABLE vault_workers DROP CONSTRAINT vault_workers_pkey;
        ALTER TABLE vault_workers ADD PRIMARY KEY (hostname, pid);
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_vault_workers_worker_state ON vault_workers (worker_state);
CREATE INDEX IF NOT EXISTS idx_vault_workers_heartbeat ON vault_workers (last_heartbeat);
CREATE INDEX IF NOT EXISTS idx_vault_workers_hostname ON vault_workers (hostname);

-- Separated custody, python backend: the HTTP socket this custodian listens on,
-- so the control plane can ADDRESS the elected master instead of re-dialling a
-- shared listener until the kernel happens to hand it over. NULL everywhere
-- else -- embedded workers and disposable API workers have no such socket, and
-- nothing reads the column outside the python custodian route.
ALTER TABLE vault_workers ADD COLUMN IF NOT EXISTS http_socket_name TEXT;
-- Which process this row is, in separated custody: 'custodian' holds key
-- material, 'api' is a disposable worker that holds none. NULL in embedded,
-- where the distinction does not exist. Read by /status so its custodian
-- counters count custodians.
ALTER TABLE vault_workers ADD COLUMN IF NOT EXISTS process_role TEXT;

-- HA cluster: cross-container coordination columns on vault_workers.
-- Nullable so single-node deploys (ha_enabled=false) keep working unchanged.
-- When HA is on, application code enforces non-null at write time.
-- See docs/HA-CLUSTER.md §6 for the full design.

-- Defense-in-depth CHECK on ha_state values (see §4). NULL allowed for
-- backward compat with single-node rows that never participate in HA.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'vault_workers_ha_state_check'
    ) THEN
        ALTER TABLE vault_workers
            ADD CONSTRAINT vault_workers_ha_state_check
            CHECK (ha_state IS NULL OR ha_state IN (
                'unjoined', 'joining', 'quarantine', 'secondary', 'primary'
            ));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_vault_workers_node_uuid ON vault_workers (node_uuid);
CREATE INDEX IF NOT EXISTS idx_vault_workers_ha_state ON vault_workers (ha_state);

-- HA cluster config: cluster-wide settings (cluster_id,
-- ha_password_encrypted, ha_enabled, primary_uuid, primary_since). The
-- single-row-per-key shape keeps schema migrations free of value-type
-- assumptions; the app layer decodes each key. See §6.1.
CREATE TABLE IF NOT EXISTS vault_cluster_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- inter-host HA cluster membership (one row per
-- container running rhorizon in an HA cluster). PK is node_uuid (the
-- per-container UUID materialized at /var/lib/rhorizon/node-uuid).
-- This table is the authoritative source for HA state -- the legacy
-- vault_workers.ha_state column is a deprecated reservation. The
-- (node_uuid, source_ip)
-- UNIQUE index is the DB-side guard against volume-wipe rejoin.
CREATE TABLE IF NOT EXISTS vault_cluster_nodes (
    node_uuid           TEXT        PRIMARY KEY,
    source_ip           INET        NOT NULL,
    ha_state            TEXT        NOT NULL,
    quarantine_until    TIMESTAMPTZ,
    joined_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cluster_version     TEXT        NOT NULL,
    cert_fingerprint    TEXT        NOT NULL,
    cert_not_after      TIMESTAMPTZ NOT NULL,
    last_heartbeat      TIMESTAMPTZ,
    role_changed_at     TIMESTAMPTZ,
    drain_deadline_at TIMESTAMPTZ,
    force_renew_at TIMESTAMPTZ,
    rekey_pub BYTEA,
    active_key_epoch INTEGER,
    CONSTRAINT vault_cluster_nodes_ha_state_check
        CHECK (ha_state IN ('joining','secondary','primary',
                            'draining','evicted','quarantined'))
);
-- Sprint 1.x -- auto-promote demotion cooldown. Stamped NOW() on every
-- ha_state transition (cluster_membership.transition_node + the
-- joining->secondary flip). _maybe_auto_promote holds a node out of the
-- election pool until it has dwelt in its current state for
-- cluster_auto_promote_cooldown_secs. NULL (pre-migration rows, the
-- /cluster/init primary) is treated as "no cooldown" (eligible).

CREATE UNIQUE INDEX IF NOT EXISTS vault_cluster_nodes_uuid_ip
    ON vault_cluster_nodes (node_uuid, source_ip);
-- Faille 12 (volume-wipe rejoin): at most one non-evicted row per source_ip.
-- A fresh node_uuid claiming an active node's IP fails atomically at INSERT --
-- this is the guarantee, NOT the (node_uuid, source_ip) index above (which is
-- redundant with the PK). Closes the TOCTOU the check_source_ip_unbound
-- pre-check leaves open. Evicted rows leave the index, releasing the IP.
CREATE UNIQUE INDEX IF NOT EXISTS vault_cluster_nodes_active_ip
    ON vault_cluster_nodes (source_ip) WHERE ha_state != 'evicted';
-- Split-brain guard: election code demotes the prior primary before promoting
-- its successor in the same transaction.  Keep the invariant at the database
-- layer too, so no alternate writer can ever commit two primary rows.
CREATE UNIQUE INDEX IF NOT EXISTS vault_cluster_nodes_single_primary
    ON vault_cluster_nodes (ha_state) WHERE ha_state = 'primary';
CREATE INDEX IF NOT EXISTS vault_cluster_nodes_ha_state
    ON vault_cluster_nodes (ha_state) WHERE ha_state != 'evicted';

-- per-row drain deadline. Populated by POST
-- /cluster/drain ; consumed by the cluster_ha_reaper_loop to bascule
-- draining -> evicted once NOW() > drain_deadline_at. NULL on non-
-- draining rows. Idempotent ALTER : the column is additive, no data
-- migration required.

-- per-row force-renew trigger. POST
-- /cluster/rotate-cert (admin:w) sets this column to NOW() on one or
-- all rows ; the per-node renewal loop polls
-- `cert_not_after - NOW < threshold_days OR (force_renew_at IS NOT
-- NULL AND force_renew_at <= NOW)` and refreshes the cert when either
-- branch fires. force_renew_at is cleared (set NULL) on successful
-- refresh. NULL on rows not currently flagged.

-- Per-node X25519 rekey public key.
-- Published by each host master at unseal (cluster_rekey / vault_state). The
-- rotating master seals the new-generation key bundle to this pubkey so a
-- live-but-stale peer rolls forward without an operator re-unseal. PUBLIC
-- material (32-byte X25519 pub) -- the matching private key is RAM-only,
-- mlock'd, never persisted (see docs/rekey-envelope). NULL until a node first
-- publishes ; a NULL-pub node is skipped at publish time and falls back to the
-- key_epoch fence (quarantine) on the next rotation it misses.

-- write-path guard -- the key generation this node's MASTER process
-- currently holds in RAM. Stamped by the master on every HA heartbeat
-- (cluster_ha_loops), so it tracks roll-forwards within one heartbeat. A
-- follower delegates every DEK wrap to that master, but cannot see its in-RAM
-- epoch ; it reads this column instead. When it lags vault_config.key_epoch the
-- host master is mid-convergence and a write would wrap a DEK under the OLD
-- dek_key (silently unreadable post-convergence), so the write guard returns
-- 503 + Retry-After until the master rolls forward. NULL on non-HA single-host
-- deployments (no cross-process wrap delegation -> nothing to fence).

-- /cluster/join idempotency cache. Bug D structural
-- fix for the case where a joiner's previous attempt succeeded
-- server-side but the wire response was lost ; replaying the same nonce
-- recovers the *identical* cert + wrapped-key payload instead of either
-- minting a fresh divergent pair or hitting 401 once the challenge row
-- has been consumed. node_uuid + source_ip are cross-checked at lookup
-- so a stolen nonce cannot be replayed by a different joiner. expires_at
-- bounds the replay window ; the reaper purges past-deadline rows.
CREATE TABLE IF NOT EXISTS vault_join_idempotency (
    nonce         TEXT        PRIMARY KEY,
    node_uuid     TEXT        NOT NULL,
    source_ip     TEXT        NOT NULL,
    response_json TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vault_join_idempotency_expires
    ON vault_join_idempotency (expires_at);

-- Signed, per-recipient sealed-box
-- envelope that lets live-but-stale peers roll forward to the new key
-- generation after a NON-emergency rotation, with no operator re-unseal and
-- no plaintext key ever on the wire or recoverable from the DB alone.
--
-- One epoch's envelope is a set of rows sharing key_epoch :
--   * one shared row  (node_uuid = '*')   carries the bulk-wrapped key bundle
--     (blob = AES-256-GCM(K, hmac||dek||audit||ha_wrap, AAD=cluster_id||epoch)),
--     the Ed25519 origin signature (sig) over H(cluster_id||epoch||blob), and
--     the master's CA-signed cert PEM (signer_cert) so the row is
--     self-describing -- a peer verifies sig against the cluster CA before
--     adopting anything. blob/sig/signer_cert are NULL on per-node rows.
--   * one per-node row per recipient   carries wrapped_k = crypto_box_seal(K,
--     recipient_x25519_pub) -- only that node's RAM-held private key opens it.
--     wrapped_k is NULL on the shared row.
--
-- TEMPORARY by design : a per-node row is DELETEd by its owner on confirmed
-- roll-forward (same txn as the epoch flip) ; the shared row + any straggler
-- per-node rows are superseded (DELETEd) by the next rotation and purged by
-- the reaper after token_migration_window. At steady state the table is
-- EMPTY -- a non-empty table means a rotation is mid-propagation or a node is
-- lagging (the fence surfaces the latter). See shared/plan-ha-rekey-envelope.md
-- "Envelope teardown" : retention is a forward-secrecy property, not hygiene.
--
-- Emergency rotations write NO envelope (the old->new link is severed on
-- purpose) ; peers quarantine via the fence and require operator re-unseal.
CREATE TABLE IF NOT EXISTS vault_rekey_envelope (
    key_epoch    INT         NOT NULL,
    node_uuid    TEXT        NOT NULL,   -- recipient uuid ; '*' = shared row
    wrapped_k    BYTEA,                  -- per-node : SealedBox(K) to node pub
    blob         BYTEA,                  -- shared   : nonce||ct of the bundle
    sig          BYTEA,                  -- shared   : Ed25519 over H(cid||ep||blob)
    signer_cert  TEXT,                   -- shared   : master CA-signed cert PEM
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (key_epoch, node_uuid)
);
CREATE INDEX IF NOT EXISTS idx_vault_rekey_envelope_age
    ON vault_rekey_envelope (created_at);

-- Backup/restore: stubs for tokens that must be rotated on-demand by an admin
-- after a restore (the OLD plaintexts were shown once at creation, the new
-- hmac_key derived post-restore cannot reproduce them). Rows live here until
-- an admin calls POST /tokens/pending/{id}/rotate (mint a fresh plaintext +
-- INSERT into vault_tokens + DELETE the stub) or DELETE /tokens/pending/{id}
-- (revoke without ever emitting an active token). The reaper purges rows
-- older than RHORIZON_RESTORE_ROTATION_GRACE_DAYS (default 30).
CREATE TABLE IF NOT EXISTS vault_pending_token_rotations (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          TEXT NOT NULL,
    namespace     TEXT NOT NULL DEFAULT 'default',
    permissions   JSONB NOT NULL,
    allowed_ips   TEXT,
    expires_at    TIMESTAMPTZ,
    is_honey      BOOLEAN NOT NULL DEFAULT FALSE,
    group_names   JSONB NOT NULL DEFAULT '[]'::jsonb,
    backup_origin TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (name, namespace)
);

ALTER TABLE vault_pending_token_rotations
    ADD COLUMN IF NOT EXISTS group_names JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE INDEX IF NOT EXISTS idx_vault_pending_token_rotations_age
    ON vault_pending_token_rotations (created_at);

-- Tokens minted by a restore rotation flow are tagged so the UI can render
-- a "NEW" badge while they are fresh (rotated_at < 7 days ago AND
-- last_used_at IS NULL).

-- Indexes
-- Existing installs used delimiter-joined v1 AAD. Add the column as v1 so old
-- ciphertext remains readable, then make collision-free v2 the default for all
-- future writes. Fresh tables already declare the column with DEFAULT 2.
ALTER TABLE vault_secrets
    ADD COLUMN IF NOT EXISTS aad_version SMALLINT NOT NULL DEFAULT 1;
ALTER TABLE vault_secrets ALTER COLUMN aad_version SET DEFAULT 2;
ALTER TABLE vault_secret_versions
    ADD COLUMN IF NOT EXISTS aad_version SMALLINT NOT NULL DEFAULT 1;
ALTER TABLE vault_secret_versions ALTER COLUMN aad_version SET DEFAULT 2;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'vault_secrets_aad_version_check'
    ) THEN
        ALTER TABLE vault_secrets
            ADD CONSTRAINT vault_secrets_aad_version_check
            CHECK (aad_version IN (1, 2));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'vault_secret_versions_aad_version_check'
    ) THEN
        ALTER TABLE vault_secret_versions
            ADD CONSTRAINT vault_secret_versions_aad_version_check
            CHECK (aad_version IN (1, 2));
    END IF;
END $$;

-- V1's delimiter encoding is safe only while its encoded identity is unique.
-- Refuse an ambiguous legacy dataset at migration instead of silently allowing
-- two rows whose authenticated identities are identical.
CREATE UNIQUE INDEX IF NOT EXISTS uq_vault_secrets_legacy_aad
    ON vault_secrets ((name || ':' || namespace))
    WHERE aad_version = 1;

-- Secrets: namespace filter + name sort (list_secrets), FK join (get_secret)
CREATE INDEX IF NOT EXISTS idx_vault_secrets_ns ON vault_secrets (namespace, name);
CREATE INDEX IF NOT EXISTS idx_vault_secrets_dek ON vault_secrets (dek_id);
CREATE INDEX IF NOT EXISTS idx_vault_secrets_expires ON vault_secrets (expires_at) WHERE expires_at IS NOT NULL;
DROP INDEX IF EXISTS idx_vault_secrets_rotate;
-- Versions: list by secret, ordered
CREATE INDEX IF NOT EXISTS idx_vault_versions_secret ON vault_secret_versions (secret_id, version DESC);
-- Tokens: O(1) lookup by HMAC hash (auth.py)
CREATE INDEX IF NOT EXISTS idx_vault_tokens_hash ON vault_tokens (token_hash) WHERE active;
-- Audit: chain verification (ASC), listing (DESC), filter by actor/action
CREATE INDEX IF NOT EXISTS idx_vault_audit_ts ON vault_audit (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_vault_audit_ts_id
    ON vault_audit (timestamp, id);
CREATE INDEX IF NOT EXISTS idx_vault_audit_actor ON vault_audit (actor);
CREATE INDEX IF NOT EXISTS idx_vault_audit_action ON vault_audit (action);
CREATE INDEX IF NOT EXISTS idx_vault_audit_lite_ts_id
    ON vault_audit_lite (timestamp, id);
-- vault_audit_lite indexes mirror vault_audit so the UI / API can query
-- both with the same patterns (timestamp DESC list, actor / action filters).
CREATE INDEX IF NOT EXISTS idx_vault_audit_lite_ts ON vault_audit_lite (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_vault_audit_lite_actor ON vault_audit_lite (actor);
CREATE INDEX IF NOT EXISTS idx_vault_audit_lite_action ON vault_audit_lite (action);
-- vault_audit_mcp: hub column for installs predating the first-class hub label.
-- Do NOT fold this into CREATE TABLE. It was folded in once (593ff83, "structure
-- identical") and that is true only for a FRESH database: an existing one never
-- gains the column, so the index below fails with `column "hub" does not exist`
-- and the whole idempotent apply aborts under ON_ERROR_STOP=1. Caught by an
-- upgrade of the HA lab cluster, which is exactly the case a fresh-install test
-- cannot see.
ALTER TABLE vault_audit_mcp ADD COLUMN IF NOT EXISTS hub TEXT;

-- vault_audit_mcp indexes: list (timestamp DESC) + filter by agent/backend/decision/hub.
CREATE INDEX IF NOT EXISTS idx_vault_audit_mcp_ts ON vault_audit_mcp (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_vault_audit_mcp_agent ON vault_audit_mcp (agent_token_id);
CREATE INDEX IF NOT EXISTS idx_vault_audit_mcp_backend ON vault_audit_mcp (backend);
CREATE INDEX IF NOT EXISTS idx_vault_audit_mcp_decision ON vault_audit_mcp (decision);
CREATE INDEX IF NOT EXISTS idx_vault_audit_mcp_hub ON vault_audit_mcp (hub);
-- Groups: member lookup
DROP INDEX IF EXISTS idx_vault_group_members;
DROP INDEX IF EXISTS idx_vault_group_members_username;
CREATE INDEX IF NOT EXISTS idx_vault_group_members_external_id
    ON vault_group_members (external_id) WHERE principal_type = 'external';
CREATE INDEX IF NOT EXISTS idx_vault_group_members_token_id
    ON vault_group_members (token_id) WHERE principal_type = 'token';
-- Namespaces: ownership lookup, archived filter, secret FK
CREATE INDEX IF NOT EXISTS idx_vault_namespaces_owner ON vault_namespaces (owner_group_id);
CREATE INDEX IF NOT EXISTS idx_vault_namespaces_archived ON vault_namespaces (archived_at) WHERE archived_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_vault_secrets_ns_id ON vault_secrets (namespace_id, name);
-- WebAuthn: credential lookup
CREATE INDEX IF NOT EXISTS idx_vault_webauthn_cred ON vault_webauthn (credential_id);
-- Leases: expiry reaper
CREATE INDEX IF NOT EXISTS idx_vault_leases_expires
    ON vault_leases (expires_at) WHERE NOT revoked;
CREATE INDEX IF NOT EXISTS idx_vault_leases_reaper_queue
    ON vault_leases (
        revocation_attempted_at NULLS FIRST,
        expires_at,
        id
    )
    WHERE NOT revoked OR NOT revocation_verified;

-- PKI secrets engine: one issuing CA per namespace (separate from the cluster
-- CA). See api/app/pki_ca.py + routes/pki.py. Keys are suffixed by namespace:
-- pki_ca_cert:<ns>, pki_ca_key:<ns> (wrapped under pki_wrap_key), pki_ca_pub:<ns>
-- (ml-dsa public key hex), pki_ca_algorithm:<ns>, pki_ca_cn:<ns>,
-- pki_ca_cert_prev:<ns> (rotation grace window), pki_ca_rotated_at:<ns>.
CREATE TABLE IF NOT EXISTS vault_pki_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Issued leaf certs (public material only -- private keys are returned once on
-- issue and never stored). algorithm = the CA's signature algorithm at issue.
CREATE TABLE IF NOT EXISTS vault_pki_certs (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    serial_number     TEXT NOT NULL UNIQUE,
    subject_cn        TEXT NOT NULL,
    san_ips           TEXT[],
    san_dns           TEXT[],
    cert_pem          TEXT NOT NULL,
    fingerprint       TEXT NOT NULL,
    algorithm         TEXT NOT NULL,
    namespace         TEXT NOT NULL DEFAULT 'default',
    not_before        TIMESTAMPTZ NOT NULL,
    not_after         TIMESTAMPTZ NOT NULL,
    issued_by         TEXT,
    issued_at         TIMESTAMPTZ DEFAULT NOW(),
    revoked_at        TIMESTAMPTZ,
    revocation_reason TEXT,
    subject_algorithm TEXT,
    kem_mode TEXT
);
-- KEM certificates (Workstream 2): the subject key is a KEM key, not a signature
-- key, so subject algorithm != signature algorithm. `algorithm` keeps its meaning
-- (the CA's SIGNATURE algorithm). For an ordinary signature cert both columns are
-- NULL; for a KEM cert subject_algorithm is the ML-KEM parameter set and kem_mode
-- names the KEM construction (Cut 1: 'ml-kem'; Cut 2 will add 'x25519-ml-kem').

CREATE INDEX IF NOT EXISTS idx_vault_pki_certs_fpr ON vault_pki_certs (fingerprint);
CREATE INDEX IF NOT EXISTS idx_vault_pki_certs_expiry ON vault_pki_certs (not_after);
CREATE INDEX IF NOT EXISTS idx_vault_pki_certs_cn ON vault_pki_certs (subject_cn);
CREATE INDEX IF NOT EXISTS idx_vault_pki_certs_ns ON vault_pki_certs (namespace);

-- Opaque share deliveries for one in-flight custodian TOPOLOGY change.
--
-- A topology reshare spans an operator restart: the unsealed coordinator that
-- splits the runtime bundle for the target shape is gone before any daemon of
-- that shape exists to receive it. Its deliveries therefore have to outlive
-- the process, and this is where they wait.
--
-- Each row is one target slot's share, sealed to THAT slot's transport key and
-- authenticated for the target topology and generation, so a row is inert to
-- anything but its own custodian running the target shape. It is still the new
-- generation at rest: a dump plus `threshold` transport keys reconstructs the
-- bundle. Rows are deleted the moment the transition resolves, either way, and
-- this table is deliberately absent from BACKUP_COVERAGE -- a backup carries
-- the pool of the vault it came from, which has no relationship to this one.
CREATE TABLE IF NOT EXISTS vault_custody_topology_reshare (
    slot        SMALLINT PRIMARY KEY,
    generation  BIGINT   NOT NULL,
    threshold   SMALLINT NOT NULL,
    slots       SMALLINT NOT NULL,
    envelope    TEXT     NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
