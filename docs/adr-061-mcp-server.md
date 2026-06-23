# ADR-061: Model Context Protocol (MCP) server

## Status

Accepted.

## Context

AI agents (Claude Desktop/Code, IDE assistants, automation) increasingly need access to
secrets to do real work — call an API, connect to a database — but the usual paths are
bad: paste a secret into a prompt, bake it into the agent's environment, or give the
agent a broad token. The Model Context Protocol (MCP) is the emerging standard for giving
an agent scoped, declarative access to external capabilities via **tools**.

Keyorix already has the right primitives for a safe answer: least-privilege
**machine-identity tokens** (ADR-030), a **by-reference value read** endpoint (ADR-059),
and per-read **scoped permission / `max_reads` / suspension / audit** enforcement. What's
missing is an MCP front door so an agent can read a secret *through* Keyorix —
authenticated, least-privilege, and audited — instead of around it.

## Decision

Add a small **MCP server** (`keyorix-mcp`) that exposes read-only Keyorix access to an
agent over stdio.

- **Transport: stdio JSON-RPC 2.0.** The standard for locally-launched MCP servers; the
  agent's client spawns the binary and speaks newline-delimited JSON over stdin/stdout.
  No network listener, no inbound attack surface.
- **Dependency-minimal, hand-rolled.** The protocol surface is small (`initialize`,
  `tools/list`, `tools/call`); it is implemented over the standard library rather than
  pulling an MCP SDK, mirroring how `keyorix-k8s-sync` hand-rolls a thin REST client
  instead of importing `client-go`. Logic lives in `internal/mcp`; the binary is
  `cmd/keyorix-mcp`.
- **Auth.** The server reads `KEYORIX_URL` and `KEYORIX_TOKEN` (a least-privilege machine
  identity) from the environment — never from a tool argument, so a token can't be
  coaxed out of the model. Every Keyorix call carries that bearer token.
- **Read-only tools.**
  - `keyorix_get_secret({ ref })` — returns a secret's value, resolved by a
    `project/environment/name` reference through the by-reference endpoint (ADR-059).
  - `keyorix_list_secrets({ environment })` — lists secret references in an environment
    (metadata only, **no values**) for discovery.
  There are deliberately **no** write/rotate/delete tools: handing an agent the ability
  to mutate secrets is a different, higher-risk decision, out of scope for v1.
- **Enforcement is server-side and unchanged.** Each tool call is an ordinary authorized
  Keyorix API request: the machine identity's scoped `secrets.read`, `max_reads`,
  suspension, and audit logging all apply. The MCP server adds no new trust — it is a
  thin, audited proxy. It never logs secret values.

## Alternatives considered

- **Use an MCP SDK** (official Go SDK / community libraries). Rejected for v1: adds a
  dependency and supply-chain surface for a three-method protocol the standard library
  handles cleanly; the hand-rolled server is small and matches house style. Revisit if we
  need resources/prompts/sampling or streaming transports.
- **HTTP/SSE transport.** Rejected for v1: stdio is what local agent clients expect and
  has no inbound surface. A remote transport can be added later behind the same tool
  layer.
- **Expose write tools** (set/rotate). Rejected for v1: read access is the high-value,
  low-risk starting point; mutation by an agent warrants its own approval/guardrail
  design.
- **Embed MCP in the server process.** Rejected: an agent client launches a local stdio
  process; a separate tiny binary is the right packaging (and keeps the server free of
  MCP concerns).

## Consequences

- A new `keyorix-mcp` binary (and image) ships alongside the CLI/agent. Users add it to
  their agent client config with a `KEYORIX_URL` + a scoped `KEYORIX_TOKEN`.
- Agent secret access becomes least-privilege and audited by construction: revoke the
  machine identity to cut the agent off; read it back in the audit log.
- v1 is read-only; write tools and non-stdio transports are deliberate future decisions.
