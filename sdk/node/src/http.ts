// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

import { errorForStatus, RhorizonError } from './errors.js';

/** Minimal options accepted by every API call. */
export interface RequestOptions {
  /** Override the default token for this single call. */
  token?: string;
  /** AbortSignal to cancel the call. */
  signal?: AbortSignal;
  /** Per-call timeout (ms). Defaults to the client's `timeout`. */
  timeoutMs?: number;
}

/**
 * Thin wrapper around `fetch` that handles auth + JSON + error mapping.
 *
 * - Joins the base URL + path.
 * - Adds `Authorization: Bearer <token>` if a token is set.
 * - Serialises the body as JSON when non-null.
 * - Parses the response as JSON when present, returning `null` for 204s.
 * - Maps non-2xx responses to typed errors via `errorForStatus`.
 *
 * The SDK is `fetch`-based so it works on Node ≥ 18, Deno, Bun, and
 * modern browsers without bundling a polyfill.
 */
export class HttpClient {
  private readonly baseUrl: string;
  // Mutable so `setToken` can swap at runtime (ephemeral rotation in
  // long-lived processes). Other fields stay readonly.
  private defaultToken?: string;
  private readonly defaultTimeoutMs: number;

  constructor(baseUrl: string, token?: string, timeoutMs = 30_000) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.defaultToken = token;
    this.defaultTimeoutMs = timeoutMs;
  }

  setToken(token: string | undefined): void {
    this.defaultToken = token;
  }

  async request<T>(
    method: string,
    path: string,
    body?: unknown,
    opts?: RequestOptions,
  ): Promise<T> {
    const url = `${this.baseUrl}${path.startsWith('/') ? path : `/${path}`}`;
    const headers: Record<string, string> = {
      Accept: 'application/json',
    };
    const token = opts?.token ?? this.defaultToken;
    if (token) headers.Authorization = `Bearer ${token}`;
    if (body !== undefined && body !== null) {
      headers['Content-Type'] = 'application/json';
    }

    const ac = new AbortController();
    const ms = opts?.timeoutMs ?? this.defaultTimeoutMs;
    const timer = setTimeout(() => ac.abort(), ms);
    if (opts?.signal) {
      opts.signal.addEventListener('abort', () => ac.abort(), { once: true });
    }

    let res: Response;
    try {
      res = await fetch(url, {
        method,
        headers,
        body: body === undefined || body === null ? undefined : JSON.stringify(body),
        signal: ac.signal,
      });
    } catch (e) {
      // Network error / timeout / aborted, surface as a 0-status RhorizonError
      // so callers don't need a separate catch for this.
      throw new RhorizonError(0, (e as Error).message ?? 'fetch failed');
    } finally {
      clearTimeout(timer);
    }

    // 204 No Content
    if (res.status === 204) return null as T;

    const contentType = res.headers.get('content-type') ?? '';
    let parsed: unknown = null;
    if (contentType.includes('application/json')) {
      parsed = await res.json().catch(() => null);
    } else {
      parsed = await res.text().catch(() => '');
    }

    if (!res.ok) {
      // Extract the FastAPI-style {"detail": "..."} field if present,
      // falling back through plain-text body, statusText, or a generic
      // marker. Parens around the ?? expression to satisfy TS5076.
      let detail = 'unknown';
      if (parsed && typeof parsed === 'object' && 'detail' in parsed) {
        detail = String((parsed as { detail: unknown }).detail);
      } else if (typeof parsed === 'string' && parsed) {
        detail = parsed;
      } else if (res.statusText) {
        detail = res.statusText;
      }
      throw errorForStatus(res.status, detail, parsed);
    }

    return parsed as T;
  }

  get<T>(path: string, opts?: RequestOptions): Promise<T> {
    return this.request<T>('GET', path, undefined, opts);
  }
  post<T>(path: string, body?: unknown, opts?: RequestOptions): Promise<T> {
    return this.request<T>('POST', path, body, opts);
  }
  put<T>(path: string, body?: unknown, opts?: RequestOptions): Promise<T> {
    return this.request<T>('PUT', path, body, opts);
  }
  delete<T>(path: string, body?: unknown, opts?: RequestOptions): Promise<T> {
    return this.request<T>('DELETE', path, body, opts);
  }
}
