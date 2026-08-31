# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""TLS contexts for outbound HA calls.

The public/system trust store remains the default. Deployments using a private
or self-signed HTTPS certificate can pin its CA through
``RH_HA_SERVER_CA_FILE`` without weakening verification globally.
"""

import ssl

from .config import settings


def server_context(
    *, client_cert: str | None = None, client_key: str | None = None
) -> ssl.SSLContext:
    context = ssl.create_default_context(
        cafile=settings.ha_server_ca_file or None,
    )
    if client_cert or client_key:
        if not client_cert or not client_key:
            raise ValueError("both HA client certificate and key are required")
        context.load_cert_chain(certfile=client_cert, keyfile=client_key)
    return context
