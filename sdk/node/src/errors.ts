// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

/**
 * Base error for all SDK calls. The HTTP status + the API's `detail`
 * field are surfaced so callers can branch on either.
 */
export class RhorizonError extends Error {
  readonly status: number;
  readonly detail: string;
  readonly body: unknown;

  constructor(status: number, detail: string, body?: unknown) {
    super(`[rhorizon ${status}] ${detail}`);
    this.name = 'RhorizonError';
    this.status = status;
    this.detail = detail;
    this.body = body;
  }
}

/** Thrown on 401, token missing or invalid. */
export class AuthError extends RhorizonError {
  constructor(detail: string, body?: unknown) {
    super(401, detail, body);
    this.name = 'AuthError';
  }
}

/** Thrown on 403, token valid but lacks the scope / namespace / IP. */
export class ForbiddenError extends RhorizonError {
  constructor(detail: string, body?: unknown) {
    super(403, detail, body);
    this.name = 'ForbiddenError';
  }
}

/** Thrown on 404, resource not found (or hidden via deletion). */
export class NotFoundError extends RhorizonError {
  constructor(detail: string, body?: unknown) {
    super(404, detail, body);
    this.name = 'NotFoundError';
  }
}

/** Thrown on 409, duplicate / archived target / conflict. */
export class ConflictError extends RhorizonError {
  constructor(detail: string, body?: unknown) {
    super(409, detail, body);
    this.name = 'ConflictError';
  }
}

/** Thrown on 423, set-once flag rejected (one-way ratchet violated). */
export class LockedError extends RhorizonError {
  constructor(detail: string, body?: unknown) {
    super(423, detail, body);
    this.name = 'LockedError';
  }
}

/** Thrown on 429, rate limited. */
export class RateLimitedError extends RhorizonError {
  constructor(detail: string, body?: unknown) {
    super(429, detail, body);
    this.name = 'RateLimitedError';
  }
}

/** Thrown on 503, vault is sealed. */
export class SealedError extends RhorizonError {
  constructor(detail: string, body?: unknown) {
    super(503, detail, body);
    this.name = 'SealedError';
  }
}

/**
 * Map an HTTP status to the most specific error class. Callers can
 * catch the broader `RhorizonError` if they don't care about the
 * subclass.
 */
export function errorForStatus(status: number, detail: string, body?: unknown): RhorizonError {
  switch (status) {
    case 401: return new AuthError(detail, body);
    case 403: return new ForbiddenError(detail, body);
    case 404: return new NotFoundError(detail, body);
    case 409: return new ConflictError(detail, body);
    case 423: return new LockedError(detail, body);
    case 429: return new RateLimitedError(detail, body);
    case 503: return new SealedError(detail, body);
    default:  return new RhorizonError(status, detail, body);
  }
}
