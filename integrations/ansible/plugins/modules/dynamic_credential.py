# SPDX-License-Identifier: AGPL-3.0-or-later
"""Mint one leased Horizon dynamic credential."""

from urllib.parse import quote

from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible_collections.resurgamus.rhorizon.plugins.module_utils import (
    rhorizon_client,
)

DOCUMENTATION = r"""
---
module: dynamic_credential
short_description: Mint a leased Resurgamus Horizon credential
description:
  - Creates one dynamic credential through an existing Horizon engine role.
  - The target password is returned once and must be protected with C(no_log).
options:
  address:
    description: Base URL of the Horizon API.
    type: str
    required: true
  token:
    description: Horizon bearer token with C(secrets:w).
    type: str
    required: true
  engine_id:
    description: UUID of the configured dynamic engine.
    type: str
    required: true
  role_name:
    description: Name of the configured dynamic role.
    type: str
    required: true
  ttl_seconds:
    description: Requested TTL, capped by the role maximum.
    type: int
  ca_cert:
    description: Path to the CA certificate used to verify Horizon.
    type: path
  validate_certs:
    description: Verify the Horizon TLS certificate.
    type: bool
    default: true
  timeout:
    description: API timeout in seconds.
    type: int
    default: 10
author:
  - shdw
"""

EXAMPLES = r"""
- name: Mint a PostgreSQL credential on the controller
  resurgamus.rhorizon.dynamic_credential:
    address: "{{ rhorizon_address }}"
    token: "{{ rhorizon_token }}"
    engine_id: "{{ pg_engine_id }}"
    role_name: readonly
    ttl_seconds: 900
    ca_cert: /etc/rhorizon/ca.pem
  delegate_to: localhost
  no_log: true
  register: pg_lease
"""

RETURN = r"""
credential:
  description: One-time credential and its lease metadata.
  type: dict
  returned: success
"""


def main():
    module = AnsibleModule(
        argument_spec={
            "address": {
                "type": "str",
                "required": True,
                "fallback": (env_fallback, ["RHORIZON_ADDR"]),
            },
            "token": {
                "type": "str",
                "required": True,
                "no_log": True,
                "fallback": (env_fallback, ["RHORIZON_TOKEN"]),
            },
            "engine_id": {"type": "str", "required": True},
            "role_name": {"type": "str", "required": True},
            "ttl_seconds": {"type": "int"},
            "ca_cert": {"type": "path"},
            "validate_certs": {"type": "bool", "default": True},
            "timeout": {"type": "int", "default": 10},
        },
        supports_check_mode=False,
    )
    params = module.params
    body = {}
    if params["ttl_seconds"] is not None:
        body["ttl_seconds"] = params["ttl_seconds"]
    path = (
        "/api/v1/vault/dynamic/engines/"
        + quote(params["engine_id"], safe="")
        + "/creds/"
        + quote(params["role_name"], safe="")
    )
    try:
        credential = rhorizon_client.request_json(
            params["address"],
            params["token"],
            "POST",
            path,
            body=body,
            ca_cert=params["ca_cert"],
            validate_certs=params["validate_certs"],
            timeout=params["timeout"],
        )
    except rhorizon_client.HorizonClientError as exc:
        module.fail_json(msg=str(exc))
    password = credential.get("password")
    if password:
        module.no_log_values.add(password)
    module.exit_json(changed=True, credential=credential)


if __name__ == "__main__":
    main()
