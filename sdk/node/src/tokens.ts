// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

import type { HttpClient, RequestOptions } from './http.js';
import type {
  Token,
  TokenCreated,
  TokenCreateRequest,
  EphemeralCreateRequest,
  WhoamiResponse,
} from './types.js';

/** Tokens sub-client. Endpoints under `/api/v1/vault/tokens/`. */
export class TokensApi {
  constructor(private readonly http: HttpClient) {}

  /** POST /tokens/, mint a long-lived token. Plaintext shown ONCE. */
  async create(body: TokenCreateRequest, opts?: RequestOptions): Promise<TokenCreated> {
    return this.http.post('/api/v1/vault/tokens/', body, opts);
  }

  /** GET /tokens/, list (no plaintext, no hash). */
  async list(opts?: RequestOptions): Promise<Token[]> {
    const resp = await this.http.get<{ items: Token[] }>('/api/v1/vault/tokens/', opts);
    return resp.items;
  }

  /** GET /tokens/whoami, introspect the current token. */
  async whoami(opts?: RequestOptions): Promise<WhoamiResponse> {
    return this.http.get('/api/v1/vault/tokens/whoami', opts);
  }

  /** POST /tokens/{id}/revoke, deactivate a token. */
  async revoke(id: string, opts?: RequestOptions): Promise<{ revoked: boolean }> {
    return this.http.post(`/api/v1/vault/tokens/${encodeURIComponent(id)}/revoke`, undefined, opts);
  }

  /** POST /tokens/{id}/renew, extend expiry (does not rotate the value). */
  async renew(id: string, opts?: RequestOptions): Promise<{ expires_at: string }> {
    return this.http.post(`/api/v1/vault/tokens/${encodeURIComponent(id)}/renew`, undefined, opts);
  }

  /** DELETE /tokens/{id}, remove. */
  async delete(id: string, opts?: RequestOptions): Promise<void> {
    await this.http.delete(`/api/v1/vault/tokens/${encodeURIComponent(id)}`, undefined, opts);
  }

  /**
   * POST /tokens/ephemeral, mint a short-TTL token.
   *
   * Forces `secrets:r` if `permissions` doesn't include it ; admin
   * scope is forbidden (the API rejects with 403). Pass
   * `inherit_group_membership=true` so the new ephemeral token UUID
   * is attached to the caller's groups, required for strict-RBAC
   * namespaces.
   */
  async createEphemeral(
    body: EphemeralCreateRequest,
    opts?: RequestOptions,
  ): Promise<TokenCreated> {
    return this.http.post('/api/v1/vault/tokens/ephemeral', body, opts);
  }
}
