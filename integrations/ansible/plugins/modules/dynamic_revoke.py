# SPDX-License-Identifier: AGPL-3.0-or-later
"""Revoke one Horizon dynamic-credential lease."""

from urllib.parse import quote

from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible_collections.resurgamus.rhorizon.plugins.module_utils import (
    rhorizon_client,
)

DOCUMENTATION = r"""
---
module: dynamic_revoke
short_description: Revoke a Resurgamus Horizon dynamic credential
description:
  - Revokes the target-side credential and marks its Horizon lease revoked.
options:
  address:
    description: Base URL of the Horizon API.
    type: str
    required: true
  token:
    description: Horizon bearer token with C(admin:w).
    type: str
    required: true
  lease_id:
    description: UUID of the lease returned by C(dynamic_credential).
    type: str
    required: true
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
- name: Revoke the credential after the protected task
  resurgamus.rhorizon.dynamic_revoke:
    address: "{{ rhorizon_address }}"
    token: "{{ rhorizon_admin_token }}"
    lease_id: "{{ pg_lease.credential.lease_id }}"
    ca_cert: /etc/rhorizon/ca.pem
  delegate_to: localhost
  no_log: true
"""

RETURN = r"""
lease_id:
  description: Revoked lease UUID.
  type: str
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
            "lease_id": {"type": "str", "required": True},
            "ca_cert": {"type": "path"},
            "validate_certs": {"type": "bool", "default": True},
            "timeout": {"type": "int", "default": 10},
        },
        supports_check_mode=False,
    )
    params = module.params
    lease_id = params["lease_id"]
    try:
        rhorizon_client.request_json(
            params["address"],
            params["token"],
            "POST",
            "/api/v1/vault/dynamic/leases/" + quote(lease_id, safe="") + "/revoke",
            body={},
            ca_cert=params["ca_cert"],
            validate_certs=params["validate_certs"],
            timeout=params["timeout"],
        )
    except rhorizon_client.HorizonClientError as exc:
        module.fail_json(msg=str(exc))
    module.exit_json(changed=True, lease_id=lease_id, revoked=True)


if __name__ == "__main__":
    main()
