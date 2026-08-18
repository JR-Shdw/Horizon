# Resurgamus Horizon Ansible collection

This collection consumes an existing Horizon dynamic engine. It is deliberately
separate from the API process and adds no Ansible dependency to the vault.

Build and install it from the repository:

```sh
cd integrations/ansible
ansible-galaxy collection build
ansible-galaxy collection install resurgamus-rhorizon-0.1.0.tar.gz
```

Run both modules on the controller with `delegate_to: localhost`. Always put
`no_log: true` on tasks that mint, register, use, or revoke a credential:
Ansible variables remain in controller memory for the play, and an unprotected
registered result can expose the one-time password in logs or callback output.
Use a short TTL as the final fallback if the play is interrupted before the
explicit revoke task.

```yaml
- block:
    - name: Mint a short-lived credential
      resurgamus.rhorizon.dynamic_credential:
        address: "{{ rhorizon_address }}"
        token: "{{ rhorizon_token }}"
        engine_id: "{{ dynamic_engine_id }}"
        role_name: readonly
        ttl_seconds: 900
        ca_cert: /etc/rhorizon/ca.pem
      delegate_to: localhost
      no_log: true
      register: dynamic_lease

    - name: Use the credential
      ansible.builtin.debug:
        msg: "Replace this task with the target operation"
      no_log: true
  always:
    - name: Revoke it immediately
      resurgamus.rhorizon.dynamic_revoke:
        address: "{{ rhorizon_address }}"
        token: "{{ rhorizon_admin_token }}"
        lease_id: "{{ dynamic_lease.credential.lease_id }}"
        ca_cert: /etc/rhorizon/ca.pem
      when: dynamic_lease is defined
      delegate_to: localhost
      no_log: true
```

TLS certificate validation is on by default. Plain HTTP is rejected except for
loopback development. Tokens may come from `RHORIZON_TOKEN`; do not place them
in inventory files or command-line arguments.
