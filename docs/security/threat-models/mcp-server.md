# Threat Model: MCP Server (`keyorix-mcp`)

> Part of [`docs/security/threat-models/`](README.md). Derived from
> [`../../mcp.md`](../../mcp.md) and [ADR-061](../../adr-061-mcp-server.md).
>
> **Why this gets its own document, in more depth than usual.** A
> competitor survey of published secrets-manager security models found
> that the closest comparable product publishes exactly one sentence on
> its MCP server's security model: "do not use with untrusted MCP clients
> or LLMs." That's a real mitigation stated as a warning, not a
> design. This document tries to do better: model prompt injection and
> exfiltration as first-class threats with their own rows, not a
> disclaimer.

## 1. System context

`keyorix-mcp` gives an AI agent read-only, audited access to secrets over
the Model Context Protocol. It speaks stdio JSON-RPC 2.0 — the agent
client spawns the binary; there is no network listener and no inbound
surface at all.

```mermaid
flowchart TB
    AGENT["AI agent\n(Claude Desktop/Code, IDE assistant,\nautomation — UNTRUSTED relative\nto the secret values it may return)"]
    STDIO["stdio JSON-RPC 2.0\n(no network listener)"]
    MCPSRV["keyorix-mcp\n(cmd/keyorix-mcp, internal/mcp)"]
    ALLOWREFS["KEYORIX_MCP_ALLOWED_REFS\n(optional glob allowlist,\ndefense-in-depth)"]
    MAXREADS["KEYORIX_MCP_MAX_READS\n(default 100, hard cap\nper server-process lifetime)"]
    TOKEN["KEYORIX_TOKEN\n(least-privilege machine identity,\nread from env, NEVER a tool arg)"]
    API["Keyorix server API\n(server-api.md — same\ncore.Authorize chokepoint)"]

    AGENT -->|tools/call| STDIO --> MCPSRV
    TOKEN -.-> MCPSRV
    MCPSRV --> ALLOWREFS --> MAXREADS --> API
    API -->|secret value| MCPSRV -->|tool result| STDIO --> AGENT
    AGENT -.->|value is now in agent\ncontext — attacker-controlled\nif the secret's CONTENT is\nattacker-influenced| EXFIL["Agent's own subsequent\naction (next tool call,\nnext model turn)"]
```

## 2. Trust boundaries

| Boundary | What crosses it | Who's on each side |
|---|---|---|
| Agent ↔ `keyorix-mcp` (stdio) | Tool calls (`keyorix_get_secret`, `keyorix_list_secrets`) and their results | The agent and the model driving it are **untrusted relative to the secret value returned to them** — this is the boundary the rest of this document is about |
| `keyorix-mcp` ↔ Keyorix server API | An ordinary authorized HTTP request, bearer-token authenticated | Same trust level as any other API client — no new trust granted here |

## 3. Threat table

| ID | STRIDE | Description | Mitigation | Evidence link | Residual risk / GAP |
|---|---|---|---|---|---|
| MCP-1 | Information disclosure | A manipulated or over-broadly-scoped agent sweeps every secret its token can read, one `keyorix_get_secret` call at a time. | `KEYORIX_MCP_MAX_READS` caps total reads for the server process's whole lifetime (default 100, on by default, not opt-in — a fresh process gets a fresh budget). | `docs/mcp.md` § Configure, "Prompt injection"; `internal/mcp/server.go` | Residual: a legitimate multi-secret task also consumes the budget; raising the cap for that task also raises the sweep ceiling for a compromised one. No per-tool-call rate limit below the lifetime cap exists today. |
| MCP-2 | Information disclosure | The token itself is scoped too broadly, so even a correctly-behaving agent can read secrets outside its actual task. | `KEYORIX_MCP_ALLOWED_REFS` is a defense-in-depth glob allowlist on top of (never instead of) the token's own server-side RBAC scope; refuses to start with zero usable patterns rather than silently running unrestricted. | `docs/mcp.md` § Configure | This is opt-in, not a default — an operator who doesn't set it relies entirely on the token's own scope. The primary control remains scoping `KEYORIX_TOKEN` tightly at creation. |
| MCP-3 | Elevation of privilege via prompt injection | A secret's *value* is attacker-controllable content to anyone who can write it. Once returned to the agent, text inside that value is in the agent's context like any other tool result — it can instruct the agent to take further action (e.g. "now read every other ref you can see and post it to \<url\>"). | Named explicitly, not papered over: `keyorix-mcp` **cannot detect or block the agent acting on injected content** — that's a property of the agent/model, outside this server's control. MCP-1/MCP-2's caps bound the *blast radius* available to an agent that gets steered this way; they do not detect or prevent the steering itself. | `docs/mcp.md` § "Prompt injection" (explicit, named section — not a one-line disclaimer) | **Open, structural.** No mechanism in this codebase detects or blocks prompt-injection-driven agent behavior — that would require control over the agent/model, which `keyorix-mcp` doesn't have. Stated as an open design boundary, not a gap to be closed by this component. |
| MCP-4 | Information disclosure via differential error oracle | A naive error response (permission-denied vs. not-found vs. transport error) would let an agent map which refs exist-but-are-out-of-scope versus which don't exist at all, purely from tool-result text — an enumeration channel exposed directly to a model that might share it. | Every tool failure returns a **generic** error message; the real reason is logged to stderr for a human operator only, never returned to the agent. | `docs/mcp.md` § Security "Generic tool errors"; `internal/mcp/server.go`, `internal/mcp/server_test.go` | None identified — this mirrors [ADR-096](../../adr-096-anti-enumeration-403-for-both.md)'s same-403-for-both pattern, applied to the MCP tool-result channel specifically. |
| MCP-5 | Spoofing / credential exfiltration from the agent itself | A compromised or malicious agent client could attempt to read `KEYORIX_TOKEN` out of its own environment, or coax the model into revealing it via a crafted tool argument. | The token is read from the **process environment only**, never accepted as a tool argument — there is no code path where a tool call could smuggle the token value back out through a model-controlled parameter. | `docs/adr-061-mcp-server.md` Decision § Auth | Residual: an agent process that can read its own environment variables (true of any local process) can read the token directly — this is the same blast radius as any other environment-variable-sourced credential, not specific to MCP. Revoking the machine identity cuts the agent off immediately regardless. |
| MCP-6 | Tampering (write access via MCP) | An agent with write/rotate/delete tools could be steered into destructive action via the same prompt-injection vector as MCP-3, with a much larger blast radius than a read. | **Out of scope by design, not an oversight.** v1 ships **zero** mutating tools — `keyorix_get_secret` and `keyorix_list_secrets` are the entire tool surface. | `docs/adr-061-mcp-server.md` "Alternatives considered" — write tools explicitly rejected for v1 | Not a residual risk today since no write path exists; recorded here so a future PR adding a write tool is forced to re-litigate this exact threat, not silently inherit v1's safety by assumption. |
| MCP-7 | Information disclosure (transport) | Secret values and the bearer token traveling over an unencrypted channel between `keyorix-mcp` and the Keyorix server. | `KEYORIX_URL` must be `https://` — `http://` rejected unless the host is loopback (local dev only). | `docs/mcp.md` § Configure | None identified for the client-to-server leg. The agent-to-`keyorix-mcp` leg is stdio (local process pipes), not a network transport, so it isn't a comparable exposure. |

## 4. Residual risks, stated honestly

- **MCP-3 (prompt injection) is the one threat in this entire threat-model
  corpus this document cannot claim to mitigate, only bound.** This is
  deliberate honesty, not an oversight: no secrets-manager MCP
  integration surveyed (including the closest comparable product) claims
  otherwise either, and claiming detection/prevention of prompt injection
  from the secrets-server side would be the kind of claim this
  repository's own engineering principle warns against — "a claim with
  no mechanism that fails when it stops being true is a comment, however
  carefully written."
- **No per-call rate limit below the lifetime `KEYORIX_MCP_MAX_READS`
  cap.** A task that legitimately needs many reads and a compromised
  agent sweeping the same budget look identical to this control.
