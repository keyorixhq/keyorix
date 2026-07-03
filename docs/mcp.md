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

- `KEYORIX_URL` — the Keyorix server base URL (e.g. `https://keyorix.internal`). Must be
  `https://` — `http://` is rejected unless the host is loopback (`localhost`/`127.0.0.1`/
  `::1`, for local development), since the bearer token and every secret value read
  through it would otherwise travel in cleartext.
- `KEYORIX_TOKEN` — a **least-privilege machine-identity token** (ADR-030) with
  `secrets.read` only for the secrets the agent should reach. Create one with
  `keyorix machine create …`. The token is read from the environment, never from a tool
  argument, so the model can't coax it out.

Two more are optional, opt-in **defense-in-depth on top of** (never instead of) the
token's own server-side RBAC scope — useful when an agent's task only needs a narrow
slice of what the token can technically reach:

- `KEYORIX_MCP_ALLOWED_REFS` — a comma-separated list of `project/environment/name`
  glob patterns (e.g. `app/production/*,app/staging/db-*`). When set, both tools refuse
  any ref that doesn't match at least one pattern — `keyorix_list_secrets` also omits
  non-matching refs from its output, so they're never even named to the agent.
- `KEYORIX_MCP_MAX_READS` — a positive integer capping how many `keyorix_get_secret`
  calls this server process will serve for its whole session. Once reached, every
  further read is refused (a fresh MCP server process — e.g. the next agent session —
  gets a fresh budget). See "Prompt injection" below for why this exists.

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
- **HTTPS enforced.** `KEYORIX_URL` must be `https://` (loopback `http://` allowed for
  local dev) — the bearer token and every returned value would otherwise be sent/received
  in cleartext.
- **Every read is audited.** Each `keyorix_get_secret` is an ordinary authorized Keyorix
  read — it appears in the audit log with the machine identity as actor, and counts
  against any `max_reads` cap.
- **No values are logged.** The server writes only diagnostics (to stderr); values flow
  solely into the tool result the agent requested.
- **No inbound surface.** stdio only — the binary is launched by the agent client, not a
  network service.
- **Read-only.** v1 exposes no mutating tools.
- **Generic tool errors.** A failed read or list never echoes the underlying reason
  (permission-denied vs. not-found, HTTP status, transport detail) into the tool result —
  only a generic message. The real reason is logged to stderr for an operator. This closes
  an existence/permission oracle: without it, an agent could learn *which* refs exist but
  are merely out of scope versus which don't exist at all, from tool-result text alone.

### Prompt injection

> Treat a secret returned to an agent as disclosed to that agent (and any model context it
> shares). A secret's *value* is attacker-controllable content to anyone who can write it —
> nothing stops it from containing text crafted to steer the agent (e.g. an instruction to
> read every other ref it can see). Once returned, that text is in the agent's context like
> any other tool result; this server cannot detect or block the agent *acting* on it.

`KEYORIX_MCP_ALLOWED_REFS` and `KEYORIX_MCP_MAX_READS` (see Configure) are the available
mitigations: an allowlist bounds *which* refs a manipulated agent could reach at all, and a
read cap bounds *how many* it can sweep even within the allowlist, before this server
process refuses further reads for the rest of its session. Neither replaces scoping the
`KEYORIX_TOKEN` itself tightly and preferring secrets with a sensible `max_reads` — those
remain the primary controls.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Server exits immediately | `KEYORIX_URL` or `KEYORIX_TOKEN` unset, `KEYORIX_URL` is not https (and not loopback), or `KEYORIX_MCP_MAX_READS` is not a positive integer — it logs which to stderr. |
| `could not read the requested secret` from `keyorix_get_secret` | The token lacks `secrets.read` for that ref, the ref doesn't exist, the ref is outside `KEYORIX_MCP_ALLOWED_REFS`, or the per-process read cap is exhausted — check stderr for the specific reason. |
| `could not list secrets` | The token's `ListSecrets` call failed — check stderr for the specific reason. |
| `invalid request …` | `ref` is not a three-part `project/environment/name`. |
| Agent client shows no tools | The client didn't complete `initialize`/`tools/list` — check its MCP logs and that `command` points at the binary. |
