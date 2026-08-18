// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

import { HttpClient, type RequestOptions } from './http.js';
import { SecretsApi } from './secrets.js';
import { TokensApi } from './tokens.js';
import { NamespacesApi } from './namespaces.js';
import { AuditApi } from './audit.js';
import type { VaultStatus, UnsealRequest, UnsealResponse } from './types.js';

/** Options for instantiating a {@link RhorizonClient}. */
export interface ClientOptions {
  /** Vault base URL, e.g. `https://vault.example.com`. */
  address: string;
  /** Bearer token. Optional, can be set later via {@link setToken}. */
  token?: string;
  /**
   * Per-call default timeout in milliseconds. Defaults to 30s.
   * Override per call via `RequestOptions.timeoutMs`.
   */
  timeoutMs?: number;
}

/**
 * Top-level rhorizon client. Wraps the REST API in typed sub-clients :
 *
 * - `client.vault`, seal/unseal/status/challenge
 * - `client.secrets`, secrets CRUD + restore
 * - `client.tokens`, long-lived + ephemeral tokens
 * - `client.namespaces`, RBAC-owned namespaces (Phase A)
 * - `client.audit`, audit chain
 *
 * Example :
 *
 * ```ts
 * import { RhorizonClient } from '@rhorizon/client';
 *
 * const rh = new RhorizonClient({
 *   address: 'https://vault.example.com',
 *   token: process.env.RHORIZON_TOKEN,
 * });
 *
 * const s = await rh.secrets.get('claude/db-password');
 * console.log(s.value);
 * ```
 */
export class RhorizonClient {
  readonly http: HttpClient;
  readonly vault: VaultApi;
  readonly secrets: SecretsApi;
  readonly tokens: TokensApi;
  readonly namespaces: NamespacesApi;
  readonly audit: AuditApi;

  constructor(opts: ClientOptions) {
    this.http = new HttpClient(opts.address, opts.token, opts.timeoutMs);
    this.vault = new VaultApi(this.http);
    this.secrets = new SecretsApi(this.http);
    this.tokens = new TokensApi(this.http);
    this.namespaces = new NamespacesApi(this.http);
    this.audit = new AuditApi(this.http);
  }

  /** Swap the bearer token (e.g. after rotating an ephemeral). */
  setToken(token: string | undefined): void {
    this.http.setToken(token);
  }
}

/**
 * Vault lifecycle sub-client : status, challenge, unseal, seal.
 */
export class VaultApi {
  constructor(private readonly http: HttpClient) {}

  /** GET /status, unauthenticated. Safe for monitoring probes. */
  async status(opts?: RequestOptions): Promise<VaultStatus> {
    return this.http.get('/api/v1/vault/status', opts);
  }

  /**
   * POST /challenge?purpose=…, get a fresh DB-backed challenge for
   * YubiKey or WebAuthn auth flows. Single-use, TTL 60s.
   */
  async challenge(
    purpose: 'unseal' | 'namespace_mutation' | 'delete_protected_secret' = 'unseal',
    opts?: RequestOptions,
  ): Promise<{ challenge: string }> {
    return this.http.post(
      `/api/v1/vault/challenge?purpose=${encodeURIComponent(purpose)}`,
      undefined,
      opts,
    );
  }

  /**
   * POST /unseal, unseals the vault. The first ever call also sets
   * the master password and returns a one-shot `root_token`.
   */
  async unseal(body: UnsealRequest, opts?: RequestOptions): Promise<UnsealResponse> {
    return this.http.post('/api/v1/vault/unseal', body, opts);
  }

  /** POST /seal, zero keys in RAM. Requires admin:w. */
  async seal(opts?: RequestOptions): Promise<{ status: string }> {
    return this.http.post('/api/v1/vault/seal', undefined, opts);
  }

  /** GET /health, unauthenticated liveness probe. */
  async health(opts?: RequestOptions): Promise<{ status: string }> {
    return this.http.get('/health', opts);
  }
}
