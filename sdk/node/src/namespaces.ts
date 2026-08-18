// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

import type { HttpClient, RequestOptions } from './http.js';
import type { Namespace, NamespaceCreate } from './types.js';

/**
 * Namespaces sub-client (Phase A RBAC).
 *
 * All mutations require admin:w + a fresh 2FA challenge (when the
 * vault has 2FA configured) + are subject to the per-actor rate
 * limit (default 10 / hour). Caller MUST provide 2FA fields in the
 * body when applicable.
 */
export class NamespacesApi {
  constructor(private readonly http: HttpClient) {}

  /** POST /namespaces/, create with chosen flags. */
  async create(body: NamespaceCreate, opts?: RequestOptions): Promise<Namespace> {
    return this.http.post('/api/v1/vault/namespaces/', body, opts);
  }

  /** GET /namespaces/, list visible. */
  async list(opts?: RequestOptions): Promise<Namespace[]> {
    const resp = await this.http.get<{ items: Namespace[] }>('/api/v1/vault/namespaces/', opts);
    return resp.items;
  }

  /** GET /namespaces/{name}, single namespace + secret count. */
  async get(
    name: string,
    opts?: RequestOptions,
  ): Promise<Namespace & { secret_count: number }> {
    return this.http.get(`/api/v1/vault/namespaces/${encodeURIComponent(name)}`, opts);
  }

  /**
   * PUT /namespaces/{name}, change owner / upgrade flags.
   *
   * Note : `name` is **immutable** post-creation. The flag upgrades
   * are one-way ratchets, the API rejects relax attempts with 423
   * Locked.
   */
  async update(
    name: string,
    body: {
      owner_group_id?: string;
      enforce_membership?: boolean;
      delete_protection?: 'free' | 'soft' | 'protected';
      challenge?: string;
      totp_code?: string;
      yubikey_response?: string;
      webauthn_response?: Record<string, unknown>;
    },
    opts?: RequestOptions,
  ): Promise<Namespace> {
    return this.http.put(`/api/v1/vault/namespaces/${encodeURIComponent(name)}`, body, opts);
  }

  /** DELETE /namespaces/{name}, soft archive. Refused if non-empty. */
  async archive(
    name: string,
    body?: {
      challenge?: string;
      totp_code?: string;
      yubikey_response?: string;
      webauthn_response?: Record<string, unknown>;
    },
    opts?: RequestOptions,
  ): Promise<{ archived: boolean; namespace: string }> {
    return this.http.delete(`/api/v1/vault/namespaces/${encodeURIComponent(name)}`, body, opts);
  }
}
