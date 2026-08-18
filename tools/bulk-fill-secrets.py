#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Fill a vault with N secrets, for load-shaped smoke runs.

Only the O(N) paths care: dek_key rotation re-wraps one row per DEK, and
backup/restore walk every secret. Custody migration does not -- it splits a
fixed-size sub-key bundle -- so this changes the shape of the slow phases
without changing the migration itself.
"""

import asyncio
import json
import sys
import urllib.request

NAMESPACES = ("prod", "staging", "ci", "apps")


def create(port: str, token: str, index: int) -> None:
    body = json.dumps(
        {
            "name": f"bulk-secret-{index:05d}",
            "value": f"value-{index:05d}-" + "x" * 64,
            "namespace": NAMESPACES[index % len(NAMESPACES)],
        }
    ).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/v1/vault/secrets/",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    urllib.request.urlopen(request, timeout=60).read()


async def main() -> int:
    port, token, count = sys.argv[1], sys.argv[2], int(sys.argv[3])
    loop = asyncio.get_running_loop()
    # Bounded: the point is to fill the vault, not to benchmark the API.
    semaphore = asyncio.Semaphore(8)

    async def one(index: int) -> None:
        async with semaphore:
            await loop.run_in_executor(None, create, port, token, index)

    await asyncio.gather(*(one(i) for i in range(count)))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
