// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//
// Runs on Node's built-in test runner (node:test + node:assert), so the SDK
// needs no third-party test framework. `npm test` compiles this with tsc into
// .test-build/ and runs `node --test` over the output.

import { describe, it, beforeEach, afterEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import {
  RhorizonClient,
  RhorizonError,
  AuthError,
  ForbiddenError,
  NotFoundError,
  ConflictError,
  LockedError,
  SealedError,
} from '../src/index.js';

const ADDR = 'https://vault.test';

let fetchMock: ReturnType<typeof mock.fn>;

beforeEach(() => {
  fetchMock = mock.fn();
  globalThis.fetch = fetchMock as unknown as typeof fetch;
});

afterEach(() => {
  mock.restoreAll();
});

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/** Queue one response for the next fetch call. */
function replyOnce(status: number, body: unknown): void {
  fetchMock.mock.mockImplementationOnce(() => Promise.resolve(jsonResponse(status, body)));
}

/** Answer every fetch call with the same response. */
function replyAlways(status: number, body: unknown): void {
  fetchMock.mock.mockImplementation(() => Promise.resolve(jsonResponse(status, body)));
}

/** Arguments the Nth fetch call received. */
function callArgs(n: number): [string, RequestInit] {
  const args = fetchMock.mock.calls[n].arguments;
  return [args[0] as string, args[1] as RequestInit];
}

describe('RhorizonClient, constructor + token swap', () => {
  it('strips trailing slash from address', async () => {
    replyOnce(200, { sealed: false });
    const rh = new RhorizonClient({ address: 'https://vault.test/' });
    await rh.vault.status();
    const [url] = callArgs(0);
    assert.equal(url, 'https://vault.test/api/v1/vault/status');
  });

  it('sends Authorization header when token is provided', async () => {
    replyOnce(200, { sealed: false });
    const rh = new RhorizonClient({ address: ADDR, token: 'rh_abc' });
    await rh.vault.status();
    const [, init] = callArgs(0);
    assert.equal((init.headers as Record<string, string>).Authorization, 'Bearer rh_abc');
  });

  it('omits Authorization when no token', async () => {
    replyOnce(200, { sealed: false });
    const rh = new RhorizonClient({ address: ADDR });
    await rh.vault.status();
    const [, init] = callArgs(0);
    assert.equal((init.headers as Record<string, string>).Authorization, undefined);
  });

  it('setToken swaps the default bearer at runtime', async () => {
    replyAlways(200, { sealed: false });
    const rh = new RhorizonClient({ address: ADDR, token: 'rh_old' });
    rh.setToken('rh_new');
    await rh.vault.status();
    const [, init] = callArgs(0);
    assert.equal((init.headers as Record<string, string>).Authorization, 'Bearer rh_new');
  });
});

describe('Error mapping', () => {
  // Subclass constructors take (detail, body?); the base takes (status, ...).
  // `never[]` keeps this assignable for every subclass without widening.
  const cases: Array<[number, new (...a: never[]) => RhorizonError]> = [
    [401, AuthError],
    [403, ForbiddenError],
    [404, NotFoundError],
    [409, ConflictError],
    [423, LockedError],
    [503, SealedError],
  ];

  for (const [status, klass] of cases) {
    it(`maps ${status} to ${klass.name}`, async () => {
      replyOnce(status, { detail: 'nope' });
      const rh = new RhorizonClient({ address: ADDR });
      await assert.rejects(rh.vault.status(), klass);
    });
  }

  it('includes detail in the error message', async () => {
    replyOnce(403, { detail: 'Missing scope: secrets' });
    const rh = new RhorizonClient({ address: ADDR });
    await assert.rejects(rh.secrets.get('foo'), /Missing scope: secrets/);
  });

  it('falls back to generic RhorizonError for unmapped status', async () => {
    replyOnce(418, { detail: 'teapot' });
    const rh = new RhorizonClient({ address: ADDR });
    await assert.rejects(rh.vault.status(), (e: unknown) => {
      assert.ok(e instanceof RhorizonError);
      assert.equal((e as RhorizonError).status, 418);
      return true;
    });
  });
});

describe('Sub-clients, request shapes', () => {
  it('secrets.create posts JSON body', async () => {
    replyOnce(201, { id: 'u', name: 'k', version: 1 });
    const rh = new RhorizonClient({ address: ADDR, token: 'rh_x' });
    await rh.secrets.create({ name: 'k', value: 'v', namespace: 'ns' });
    const [, init] = callArgs(0);
    assert.equal(init.method, 'POST');
    assert.equal(init.body, JSON.stringify({ name: 'k', value: 'v', namespace: 'ns' }));
  });

  it('secrets.get URL-encodes the secret name', async () => {
    replyOnce(200, { name: 'k', namespace: 'ns', value: 'v', version: 1 });
    const rh = new RhorizonClient({ address: ADDR, token: 'rh_x' });
    await rh.secrets.get('claude/with space');
    const [url] = callArgs(0);
    assert.equal(url, `${ADDR}/api/v1/vault/secrets/claude%2Fwith%20space`);
  });

  it('secrets.list unwraps {items}', async () => {
    replyOnce(200, {
      items: [
        {
          id: '1',
          name: 'k1',
          namespace: 'ns',
          version: 1,
          created_at: '',
          updated_at: '',
          dek_rotated_at: null,
        },
      ],
    });
    const rh = new RhorizonClient({ address: ADDR, token: 'rh_x' });
    const items = await rh.secrets.list('ns');
    assert.ok(Array.isArray(items));
    assert.equal(items.length, 1);
    assert.equal(items[0].name, 'k1');
  });

  it('tokens.list returns the items array', async () => {
    replyOnce(200, { items: [] });
    const rh = new RhorizonClient({ address: ADDR, token: 'rh_x' });
    const items = await rh.tokens.list();
    assert.deepEqual(items, []);
  });

  it('tokens.createEphemeral passes inherit_group_membership through', async () => {
    replyOnce(201, {
      token: 'rh_eph',
      name: 'eph-aaa',
      expires_at: '',
      ttl_seconds: 3600,
      allowed_ips: null,
    });
    const rh = new RhorizonClient({ address: ADDR, token: 'rh_boot' });
    await rh.tokens.createEphemeral({
      permissions: { secrets: 'r' },
      ttl_seconds: 3600,
      inherit_group_membership: true,
    });
    const [, init] = callArgs(0);
    const body = JSON.parse(init.body as string);
    assert.equal(body.inherit_group_membership, true);
  });

  it('namespaces.update sends PUT to the right URL', async () => {
    replyOnce(200, {
      id: 'u',
      name: 'prod',
      owner_group_id: 'g',
      enforce_membership: true,
      delete_protection: 'soft',
      archived_at: null,
      created_by: null,
      created_at: null,
    });
    const rh = new RhorizonClient({ address: ADDR, token: 'rh_x' });
    await rh.namespaces.update('prod', { enforce_membership: true });
    const [url, init] = callArgs(0);
    assert.equal(url, `${ADDR}/api/v1/vault/namespaces/prod`);
    assert.equal(init.method, 'PUT');
  });

  it('audit.verify hits the right path', async () => {
    replyOnce(200, { intact: true, verified_count: 100, broken_at: null });
    const rh = new RhorizonClient({ address: ADDR, token: 'rh_x' });
    const r = await rh.audit.verify();
    assert.equal(r.intact, true);
    assert.equal(r.verified_count, 100);
  });
});

describe('Network errors', () => {
  it('wraps fetch failures as RhorizonError(0)', async () => {
    fetchMock.mock.mockImplementationOnce(() =>
      Promise.reject(new TypeError('connect ECONNREFUSED')),
    );
    const rh = new RhorizonClient({ address: ADDR });
    await assert.rejects(rh.vault.status(), (e: unknown) => {
      assert.ok(e instanceof RhorizonError);
      assert.equal((e as RhorizonError).status, 0);
      return true;
    });
  });
});
