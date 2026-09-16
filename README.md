<!--
-----------------------------------------------------------------------------
Resurgamus Horizon - (c) 2024-2026 shdw <horizon@resurgamus.com> - AGPL-3.0
Self-hosted secrets vault
Source: https://github.com/JR-Shdw/Horizon
-----------------------------------------------------------------------------
-->

<h1>
  <img src="docs/img/icon.png" alt="" height="40" valign="middle">
  Resurgamus Horizon
</h1>

**A self-hosted secrets vault for AI agents and automation.**

Give each agent, application or workflow access to the credentials it needs.
Horizon stores your secrets encrypted, controls access through scoped tokens,
and records their use in an audit trail. You can revoke access when the job is done.

Connect AI assistants through MCP, supply credentials to CI jobs and containers,
or call the HTTP API from your own scripts. Run it on your infrastructure, with
no SaaS dependency or telemetry. All features are available in the open-source edition.

[AI quickstart](docs/QUICKSTART-AI.md) · [Automation examples](docs/USE-CASES.md) · [Français](docs/fr/README.md)

## What can you do with Horizon?

- **Connect your AI tools.** Use the native MCP server with Cursor, Cline,
  Claude Desktop or opencode. MCP Hub brings multiple MCP backends together.
- **Keep API keys out of prompts.** For configured API integrations, let an
  agent make authenticated requests through Horizon without receiving the
  underlying credential.
- **Supply secrets to your workflows.** Fetch or inject credentials when a
  script, CI job, container or n8n workflow needs them.
- **Control each client's access.** Scope tokens to the required namespaces,
  set expiry times, review access and revoke tokens independently.

## Install in 5 minutes

Clone Horizon and start the installer:

```bash
git clone https://github.com/JR-Shdw/Horizon.git rhorizon
cd rhorizon
sh tools/install.sh
```

The installer detects Docker or Podman when available, otherwise it uses a
native installation. Horizon configures HTTPS automatically and starts with
the vault sealed.

Open the URL displayed by the installer, verify the certificate fingerprint,
then initialize and unseal your vault. Keep your recovery credentials in a
password manager.

Installation options: [Docker & Podman](docs/DOCKER.md) · [Native](docs/INSTALL-NATIVE.md) · [Kubernetes](docs/K8S.md)

Need help? [Quickstart](docs/QUICKSTART.md) · [TLS setup](docs/TLS.md) · [Complete installation guide](docs/INSTALL.md)

### Using Horizon with AI agents?

Horizon provides a native MCP server, MCP Hub and scoped credentials.

[AI quickstart](docs/QUICKSTART-AI.md) · [AI-secure installation](docs/AI-INSTALL-GUIDE.md)

For coding agents with shell access, use the AI-secure installation to isolate
administrative and recovery credentials from the agent's account. The agent's
vault token and grants enforce its access limits; local MCP policy adds filtering.

## Put it to work

| Your workflow | Start here |
|---|---|
| AI assistants and coding agents | [MCP integration](docs/MCP.md) · [Agent prompts](docs/AI-PROMPTS.md) |
| Scripts, Ansible and CI/CD | [Practical examples](docs/USE-CASES.md) · [CLI](docs/CLI.md) · [HTTP API](docs/docs/reference/api.md) |
| Containers and Kubernetes | [Secret delivery patterns](docs/K8S.md) |
| n8n workflows | [n8n integration](docs/N8N.md) |
| Temporary database credentials | [Dynamic secrets](docs/DYNAMIC-SECRETS.md) |

## Security and deployment

Secrets are encrypted at rest, the vault starts sealed, and access is audited.
Signed releases include software bills of materials (SBOMs) and build provenance
so you can verify what you deploy.

- [Security model and limitations](docs/THREAT-MODEL.md)
- [Verify releases](docs/verifying-releases.md) and [container images](docs/verifying-images.md)
- [Supported platforms](docs/COMPATIBILITY.md) and [deployment guide](docs/DEPLOYMENT.md)
- [High availability](docs/HA-CLUSTER.md) and [backup and recovery](docs/DISASTER-RECOVERY.md)
- [Report a vulnerability](SECURITY.md)

## Project status and support

**Horizon is in beta.** See the [changelog](CHANGELOG.md) and
[roadmap](docs/ROADMAP.md) for changes and planned work.

Bug reports, documentation feedback and use cases are welcome. See
[how to contribute](CONTRIBUTING.md).

To support development, [sponsor the project](.github/FUNDING.yml).
For deployment help, training or a [commercial license](LICENSE-COMMERCIAL.md),
contact [horizon@resurgamus.com](mailto:horizon@resurgamus.com).

## License

> **License and trademark**
>
> - Licensed under **AGPL-3.0-or-later** ([LICENSE](LICENSE)). Modifications must remain AGPL.
> - **Closed-source relicensing prohibited.** A commercial license is available - see [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md).
> - **"Resurgamus Horizon" is a reserved project name.** The AGPL license covers the source code only, not the name or logo - it grants no trademark rights. Forks, derivatives, and commercial services built on this code may not use "Resurgamus Horizon" (or a confusingly similar name) to identify themselves without permission from Resurgamus.
