// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

import type { HttpClient, RequestOptions } from './http.js';
import type { AuditEntry } from './types.js';

/** Audit sub-client. Endpoints under `/api/v1/vault/audit/`. */
export class AuditApi {
  constructor(private readonly http: HttpClient) {}

  /**
   * GET /audit/, list entries with optional filters.
   *
   * @param filters Server-side filter parameters (actor, action,
   *                date range). Empty filter returns the latest N
   *                entries (server-side cap).
   */
  async list(
    filters?: {
      actor?: string;
      action?: string;
      from?: string;
      to?: string;
      limit?: number;
    },
    opts?: RequestOptions,
  ): Promise<{ items: AuditEntry[]; chain_intact: boolean }> {
    const params = new URLSearchParams();
    if (filters?.actor) params.set('actor', filters.actor);
    if (filters?.action) params.set('action', filters.action);
    if (filters?.from) params.set('from', filters.from);
    if (filters?.to) params.set('to', filters.to);
    if (filters?.limit) params.set('limit', String(filters.limit));
    const qs = params.toString() ? `?${params.toString()}` : '';
    return this.http.get(`/api/v1/vault/audit/${qs}`, opts);
  }

  /** GET /audit/verify, full chain integrity check. */
  async verify(
    opts?: RequestOptions,
  ): Promise<{ intact: boolean; verified_count: number; broken_at: string | null }> {
    return this.http.get('/api/v1/vault/audit/verify', opts);
  }

  /** GET /audit/files, list daily JSONL audit files. */
  async listFiles(opts?: RequestOptions): Promise<{ items: Array<{ date: string; size: number; compressed: boolean }> }> {
    return this.http.get('/api/v1/vault/audit/files', opts);
  }

  /** GET /audit/files/{date}, read one day. Server decompresses transparently. */
  async readFile(date: string, opts?: RequestOptions): Promise<{ entries: AuditEntry[] }> {
    return this.http.get(`/api/v1/vault/audit/files/${encodeURIComponent(date)}`, opts);
  }
}
