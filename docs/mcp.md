# Keyorix MCP server

`keyorix-mcp` gives an AI agent **read-only, least-privilege, audited** access to Keyorix
secrets over the [Model Context Protocol](https://modelcontextprotocol.io/) (MCP). Instead
of pasting a secret into a prompt or baking a broad token into an agent's environment, the
agent calls a tool and Keyorix serves the value *through* its normal controls — scoped
`secrets.read`, `max_reads`, suspension, and audit logging all apply (ADR-061).

It speaks MCP over **stdio** (JSON-RPC 2.0): the agent client spawns the binary and talks
to it over stdin/stdout. There is no network listener and no inbound surface.

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `keyorix_get_secret` | `ref` — `project/environment/name` | The secret's current value (text). |
| `keyorix_list_secrets` | `environment` *(optional)* | The references the token can see (metadata only, **no values**). |

There are deliberately **no** write/rotate/delete tools — handing an agent the ability to
mutate secrets is out of scope for v1.

## Configure

The server needs two environment variables:

- `KEYORIX_URL` — the Keyorix server base URL (e.g. `https://keyorix.internal`).
- `KEYORIX_TOKEN` — a **least-privilege machine-identity token** (ADR-030) with
  `secrets.read` only for the secrets the agent should reach. Create one with
  `keyorix machine create …`. The token is read from the environment, never from a tool
  argument, so the model can't coax it out.

### Claude Desktop / Claude Code

Add it as an MCP server (e.g. in `claude_desktop_config.json`, or via
`claude mcp add` for Claude Code):

```json
{
  "mcpServers": {
    "keyorix": {
      "command": "keyorix-mcp",
      "env": {
        "KEYORIX_URL": "https://keyorix.internal",
        "KEYORIX_TOKEN": "kx_machine_…"
      }
    }
  }
}
```

Then ask the agent to e.g. *"list the production secrets in Keyorix"* or *"read
`app/production/db-password`"* — it will call the tools and Keyorix will authorize and
audit each read.

### Run from an image

```sh
docker run --rm -i \
  -e KEYORIX_URL=https://keyorix.internal \
  -e KEYORIX_TOKEN=kx_machine_… \
  ghcr.io/keyorixhq/keyorix-mcp:latest
```

(`-i` keeps stdin open for the stdio protocol; point the agent client's `command` at this
`docker run` invocation.)

## Security

- **Least-privilege by construction.** The agent can only reach what its
  `KEYORIX_TOKEN`'s machine identity is allowed to read. Revoke the identity to cut the
  agent off immediately.
- **Every read is audited.** Each `keyorix_get_secret` is an ordinary authorized Keyorix
  read — it appears in the audit log with the machine identity as actor, and counts
  against any `max_reads` cap.
- **No values are logged.** The server writes only diagnostics (to stderr); values flow
  solely into the tool result the agent requested.
- **No inbound surface.** stdio only — the binary is launched by the agent client, not a
  network service.
- **Read-only.** v1 exposes no mutating tools.

> Treat a secret returned to an agent as disclosed to that agent (and any model context it
> shares). Scope the token tightly and prefer secrets with a sensible `max_reads`.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Server exits immediately | `KEYORIX_URL` or `KEYORIX_TOKEN` unset (it logs which to stderr). |
| `not authorized (HTTP 403)` from a tool | The token's identity lacks `secrets.read` for that secret. |
| `not found` from `keyorix_get_secret` | No such `project/environment/name` (check `keyorix_list_secrets`). |
| `invalid request …` | `ref` is not a three-part `project/environment/name`. |
| Agent client shows no tools | The client didn't complete `initialize`/`tools/list` — check its MCP logs and that `command` points at the binary. |
