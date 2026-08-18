// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

/**
 * @rhorizon/client, TypeScript SDK for Resurgamus Horizon.
 *
 * Public re-exports : the {@link RhorizonClient} class, every typed
 * sub-client, every error subclass, and every shared interface.
 *
 * @packageDocumentation
 */

export { RhorizonClient, VaultApi, type ClientOptions } from './client.js';
export { HttpClient, type RequestOptions } from './http.js';
export { SecretsApi } from './secrets.js';
export { TokensApi } from './tokens.js';
export { NamespacesApi } from './namespaces.js';
export { AuditApi } from './audit.js';
export {
  RhorizonError,
  AuthError,
  ForbiddenError,
  NotFoundError,
  ConflictError,
  LockedError,
  RateLimitedError,
  SealedError,
} from './errors.js';
export type {
  PermLevel,
  Permissions,
  VaultStatus,
  UnsealRequest,
  UnsealResponse,
  SecretMeta,
  SecretValue,
  SecretCreate,
  Token,
  TokenCreated,
  TokenCreateRequest,
  EphemeralCreateRequest,
  Namespace,
  NamespaceCreate,
  AuditEntry,
  WhoamiResponse,
} from './types.js';
