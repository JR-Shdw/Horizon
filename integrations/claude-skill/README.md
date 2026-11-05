# Horizon skill for Claude Code

This skill teaches Claude Code to get credentials from Horizon through the MCP
server, and to prefer `vault_call_api` so the value stays out of the conversation.

Set up the MCP server first: see [docs/MCP.md](../../docs/MCP.md).

## Install

For every project:

```bash
mkdir -p ~/.claude/skills
cp -r integrations/claude-skill/horizon ~/.claude/skills/
```

For one project, copy it to `.claude/skills/` in that repository instead.

## Use

Claude loads the skill when a task needs a credential. You can also run it with
`/horizon`.

Add your own vault addresses and secret names to your local copy.
