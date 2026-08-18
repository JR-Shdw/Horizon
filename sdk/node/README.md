# `@rhorizon/client`

TypeScript SDK for [Resurgamus Horizon](https://github.com/JR-Shdw/Horizon)
- a self-hosted secrets vault.

```bash
npm install @rhorizon/client
```

## Quickstart

```ts
import { RhorizonClient } from '@rhorizon/client';

const rh = new RhorizonClient({
  address: 'https://vault.example.com',
  token: process.env.RH_TOKEN,
});

// Read a secret
const s = await rh.secrets.get('claude/db-password');
console.log(s.value);

// Create one
await rh.secrets.create({
  name: 'mariadb-root',
  value: 'super-secret',
  namespace: 'prod',
});

// Mint a short-TTL ephemeral with inheritance
const eph = await rh.tokens.createEphemeral({
  permissions: { secrets: 'r' },
  ttl_seconds: 3600,
  inherit_group_membership: true,
});
```

## Sub-clients

| Property | Endpoints |
|----------|-----------|
| `client.vault` | `/health`, `/status`, `/challenge`, `/unseal`, `/seal` |
| `client.secrets` | secrets CRUD + restore + version history |
| `client.tokens` | long-lived + ephemeral tokens + whoami |
| `client.namespaces` | RBAC-owned namespaces |
| `client.audit` | log + chain verify + file mirror |

## Error handling

Every non-2xx response throws a typed error subclass - catch the
broader `RhorizonError` if you don't care about the subclass :

```ts
import {
  RhorizonError,
  AuthError,
  ForbiddenError,
  NotFoundError,
  SealedError,
} from '@rhorizon/client';

try {
  await rh.secrets.get('missing');
} catch (e) {
  if (e instanceof NotFoundError) {
    return null;
  }
  if (e instanceof SealedError) {
    console.error('vault is sealed - operator must unseal');
    return;
  }
  throw e;
}
```

| Status | Class |
|--------|-------|
| 401 | `AuthError` |
| 403 | `ForbiddenError` |
| 404 | `NotFoundError` |
| 409 | `ConflictError` |
| 423 | `LockedError` (one-way ratchet violated) |
| 429 | `RateLimitedError` |
| 503 | `SealedError` |
| 0 | `RhorizonError` (network failure / timeout) |

## Token rotation pattern

For long-running services that periodically swap their bearer (e.g.
mirroring rh-watch's ephemeral rotation in JS), use `setToken` :

```ts
const rh = new RhorizonClient({
  address: 'https://vault.example.com',
  token: bootstrap,
});

setInterval(async () => {
  const eph = await rh.tokens.createEphemeral({
    permissions: { secrets: 'r' },
    ttl_seconds: 3600,
    inherit_group_membership: true,
  });
  rh.setToken(eph.token);
}, 30 * 60 * 1000); // every 30 min - TTL/2
```

## Per-call options

Every method takes an optional last argument with `token`, `signal`,
and `timeoutMs` :

```ts
const ac = new AbortController();
setTimeout(() => ac.abort(), 5_000);

await rh.secrets.list('prod', {
  signal: ac.signal,
  timeoutMs: 5_000,
  token: 'rh_temporary_override',
});
```

## Build / test

```bash
cd sdk/node
npm install
npm run build
npm run test
npm run typecheck
```

## License

AGPL-3.0-or-later - same as the rhorizon server. If you ship a
service that exposes this SDK over a network interface, you must
make your modified source available to the users of that service.
