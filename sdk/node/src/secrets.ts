// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

import type { HttpClient, RequestOptions } from './http.js';
import type { SecretMeta, SecretValue, SecretCreate } from './types.js';

/**
 * Secrets sub-client. Endpoints under `/api/v1/vault/secrets/`.
 */
export class SecretsApi {
  constructor(private readonly http: HttpClient) {}

  /** POST /secrets/, create a new secret. Requires `secrets:w`. */
  async create(body: SecretCreate, opts?: RequestOptions): Promise<{ id: string; name: string; version: number }> {
    return this.http.post('/api/v1/vault/secrets/', body, opts);
  }

  /** GET /secrets/{name}, read decrypted plaintext. Requires `secrets:r`.
   *  Pass `namespace` to disambiguate same-name secrets across namespaces
   *  (the API returns 409 ambiguous otherwise). */
  async get(name: string, namespace?: string, opts?: RequestOptions): Promise<SecretValue> {
    return this.http.get(
      `/api/v1/vault/secrets/${encodeURIComponent(name)}${_nsQs(namespace)}`,
      opts,
    );
  }

  /**
   * GET /secrets/?namespace=, list secret metadata. Plaintext is
   * never included (use {@link get} for that). Filtered server-side
   * by the token's `permissions.namespaces` claim.
   */
  async list(namespace?: string, opts?: RequestOptions): Promise<SecretMeta[]> {
    const resp = await this.http.get<{ items: SecretMeta[] }>(
      `/api/v1/vault/secrets/${_nsQs(namespace)}`,
      opts,
    );
    return resp.items;
  }

  /** PUT /secrets/{name}, update value (mints a new DEK). Requires `secrets:w`.
   *  Pass `namespace` to disambiguate same-name secrets across namespaces. */
  async update(
    name: string,
    value: string,
    namespace?: string,
    opts?: RequestOptions,
  ): Promise<{ name: string; version: number }> {
    return this.http.put(
      `/api/v1/vault/secrets/${encodeURIComponent(name)}${_nsQs(namespace)}`,
      { value },
      opts,
    );
  }

  /**
   * DELETE /secrets/{name}, delete. Behaviour depends on the
   * namespace's `delete_protection` mode :
   *   free      → hard delete (irreversible)
   *   soft      → soft-delete + retention window + restore possible
   *   protected → admin + 2FA required + extended retention
   *
   * Pass 2FA fields in `body` when the target namespace is `protected`
   * AND the vault has 2FA configured. Pass `namespace` to disambiguate
   * same-name secrets across namespaces.
   */
  async delete(
    name: string,
    body?: {
      challenge?: string;
      totp_code?: string;
      yubikey_response?: string;
      webauthn_response?: Record<string, unknown>;
    },
    namespace?: string,
    opts?: RequestOptions,
  ): Promise<{ status: string; name: string; mode: string; retention_days?: number }> {
    return this.http.delete(
      `/api/v1/vault/secrets/${encodeURIComponent(name)}${_nsQs(namespace)}`,
      body,
      opts,
    );
  }

  /** POST /secrets/{name}/restore, un-delete within the retention window. */
  async restore(name: string, namespace?: string, opts?: RequestOptions): Promise<{ restored: boolean; name: string }> {
    return this.http.post(
      `/api/v1/vault/secrets/${encodeURIComponent(name)}/restore${_nsQs(namespace)}`,
      undefined,
      opts,
    );
  }

  /** POST /secrets/{name}/rotate, manual per-secret DEK rotation. */
  async rotate(name: string, namespace?: string, opts?: RequestOptions): Promise<{ rotated: boolean }> {
    return this.http.post(
      `/api/v1/vault/secrets/${encodeURIComponent(name)}/rotate${_nsQs(namespace)}`,
      undefined,
      opts,
    );
  }

  /** GET /secrets/{name}/versions, list version history. */
  async listVersions(name: string, namespace?: string, opts?: RequestOptions): Promise<{ items: Array<{ version: number; created_at: string }> }> {
    return this.http.get(
      `/api/v1/vault/secrets/${encodeURIComponent(name)}/versions${_nsQs(namespace)}`,
      opts,
    );
  }

  /** GET /secrets/{name}/versions/{n}, read a specific version. */
  async getVersion(name: string, version: number, namespace?: string, opts?: RequestOptions): Promise<SecretValue> {
    return this.http.get(
      `/api/v1/vault/secrets/${encodeURIComponent(name)}/versions/${version}${_nsQs(namespace)}`,
      opts,
    );
  }

  /** POST /secrets/{name}/rollback/{n}, restore an old version. */
  async rollback(name: string, version: number, namespace?: string, opts?: RequestOptions): Promise<{ rolled_back_to: number }> {
    return this.http.post(
      `/api/v1/vault/secrets/${encodeURIComponent(name)}/rollback/${version}${_nsQs(namespace)}`,
      undefined,
      opts,
    );
  }
}

function _nsQs(namespace?: string): string {
  return namespace ? `?namespace=${encodeURIComponent(namespace)}` : '';
}
