// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

/** Permission level on a scope. */
export type PermLevel = 'r' | 'w' | 'rw';

/** A token's permission shape. Matches `vault_tokens.permissions` JSONB. */
export interface Permissions {
  secrets?: PermLevel;
  tokens?: PermLevel;
  audit?: PermLevel;
  admin?: PermLevel;
  namespaces?: string[];
}

/** Vault sealed/unsealed status, `/api/v1/vault/status`. */
export interface VaultStatus {
  sealed: boolean;
  uptime: string | null;
  version: string;
  second_factor: 'none' | 'totp' | 'yubikey' | 'any';
  yubikeys_registered: number;
  totp_enabled: boolean;
  webauthn_registered: number;
  shamir_enabled: boolean;
  shamir_threshold: number;
  shamir_total: number;
  shamir_progress: number;
  memory_protection: 'mlock' | 'zeroize-only';
  process_memory_protection: 'mlock' | 'swappable' | 'disabled' | 'unsupported' | 'unknown';
  swap_protection: 'protected' | 'unencrypted' | 'unknown';
}

/** Body for `/unseal`. */
export interface UnsealRequest {
  password: string;
  /** Optional 2FA proof, depending on the vault's configured mode. */
  totp_code?: string;
  yubikey_response?: string;
  challenge?: string;
  webauthn_response?: Record<string, unknown>;
}

/** Response of `/unseal`. The `root_token` is only present on first unseal. */
export interface UnsealResponse {
  status: string;
  second_factor: string;
  root_token?: string;
  warning?: string;
}

/** A secret as stored, never includes the plaintext value in list views. */
export interface SecretMeta {
  id: string;
  name: string;
  namespace: string;
  version: number;
  created_at: string;
  updated_at: string;
  dek_rotated_at: string | null;
}

/** Secret with decrypted plaintext (returned by GET `/secrets/{name}`). */
export interface SecretValue {
  name: string;
  namespace: string;
  value: string;
  version: number;
}

/** Body for creating a secret. */
export interface SecretCreate {
  name: string;
  value: string;
  namespace?: string;
  metadata?: Record<string, unknown>;
  expires_at?: string;
  is_honey?: boolean;
}

/** Token as listed (no plaintext). */
export interface Token {
  id: string;
  name: string;
  permissions: Permissions;
  active: boolean;
  created_by: string;
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  allowed_ips: string | null;
  is_ephemeral: boolean;
}

/** A freshly minted token, plaintext shown ONCE. */
export interface TokenCreated {
  token: string;
  name: string;
  expires_at?: string;
  ttl_seconds?: number;
  allowed_ips: string | null;
}

/** Body for `/tokens/`. */
export interface TokenCreateRequest {
  name: string;
  permissions: Permissions;
  expires_at?: string;
  allowed_ips?: string;
  is_honey?: boolean;
}

/** Body for `/tokens/ephemeral`. */
export interface EphemeralCreateRequest {
  permissions: Permissions;
  ttl_seconds?: number;
  label?: string;
  allowed_ips?: string;
  inherit_group_membership?: boolean;
}

/** Namespace as exposed by the API. */
export interface Namespace {
  id: string;
  name: string;
  owner_group_id: string;
  enforce_membership: boolean;
  delete_protection: 'free' | 'soft' | 'protected';
  archived_at: string | null;
  created_by: string | null;
  created_at: string | null;
}

/** Body for `/namespaces/`. */
export interface NamespaceCreate {
  name: string;
  owner_group_id: string;
  enforce_membership?: boolean;
  delete_protection?: 'free' | 'soft' | 'protected';
  /** 2FA proof (when the vault has 2FA configured). */
  challenge?: string;
  totp_code?: string;
  yubikey_response?: string;
  webauthn_response?: Record<string, unknown>;
}

/** Audit log entry. */
export interface AuditEntry {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  target: string | null;
  detail: Record<string, unknown> | null;
  ip_address: string | null;
}

/** Token introspection, `/tokens/whoami`. */
export interface WhoamiResponse {
  id: string;
  name: string;
  permissions: Permissions;
  scopes: string[];
  namespaces: string[] | null;
  allowed_ips: string | null;
  active: boolean;
  created_by: string;
  created_at: string | null;
  last_used_at: string | null;
  expires_at: string | null;
  is_ephemeral: boolean;
}
