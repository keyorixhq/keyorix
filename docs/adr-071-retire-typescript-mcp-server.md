# ADR-071: Retire the TypeScript MCP server

## Status

Accepted.

## Context

ADR-061 added a Model Context Protocol (MCP) server so an AI agent can read Keyorix
secrets through the platform's own controls — least-privilege machine-identity tokens
(ADR-030), scoped `secrets.read`, `max_reads`, suspension, and audit logging — instead of
around them. That server lives in this repo (`internal/mcp`, binary `cmd/keyorix-mcp`,
image `ghcr.io/keyorixhq/keyorix-mcp`) and exposes exactly two tools: `keyorix_get_secret`
and `keyorix_list_secrets`. Both are read-only by design; ADR-061 explicitly rejected
write/rotate/delete tools for v1.

A second, independent MCP server implementation exists at `github.com/keyorixhq/keyorix-mcp`
— a TypeScript/Node package (`@modelcontextprotocol/sdk`), publishable via `npm`/`npx`
(`package.json` declares a `bin` entry and no `"private": true"`). It advertises itself
under the same `keyorix-mcp` name and predates ADR-061's Go implementation: its first
commit is 2026-04-25, and its final tagged release, `v0.2.1`, is 2026-06-03. ADR-061 and
the Go implementation landed three weeks later, 2026-06-23 (`cc20d05a`, #433) — the
TypeScript server predates ADR-061 and was superseded by it, but retirement never
followed that supersession: the superseded implementation remained published under the
org for roughly six weeks afterward, until this ADR. The process lesson is that
superseding an implementation needs an explicit retirement step, not just a new ADR for
the replacement. Same name, two codebases, two different security models.

## Problem

The TypeScript server's tool surface is far wider than ADR-061's decision: `src/index.ts`
registers eight tools — `list_secrets`, `get_secret`, `create_secret`, `delete_secret`,
`list_environments`, `get_stats`, `list_audit_events`, `list_users` — against the Go
server's two. Concretely, it exposes:

- **Write and destructive tools.** `create_secret` and `delete_secret` let an agent
  mutate and destroy secrets outright. ADR-061 considered this and deliberately excluded
  it: "handing an agent the ability to mutate secrets is a different, higher-risk
  decision, out of scope for v1." The TypeScript server made that decision anyway, for
  every user who installed it.
- **User enumeration.** `list_users` returns the full user list — information that has
  nothing to do with secrets access and expands what a compromised or prompt-injected
  agent session can learn about the deployment.
- **Audit-log access.** `list_audit_events` exposes the audit trail itself to the agent,
  the same audit trail ADR-061 treats as the enforcement backstop, not something to also
  read back through the tool it's meant to be watching.

Separately, and more fundamentally, the TypeScript server's authentication model
undermines ADR-061's actual security guarantee — though not by bypassing audit itself.
Its `main()` reads `KEYORIX_TOKEN` if set, but falls back to `KEYORIX_USERNAME` +
`KEYORIX_PASSWORD`, POSTs them to `/auth/login`, and uses the returned **session token**
— a human user's full session, with that user's full permissions — for every subsequent
call. Scoped `secrets.read` permission, `max_reads`, and account suspension are genuinely
inapplicable to a session token: it carries the full permission set of whatever user
authenticated it, not a narrow scope, and none of the machine-identity-specific controls
(ADR-030) apply to it.

Audit is not one of those bypassed controls — verified directly from source, not assumed.
Every secret read produces an `AuditEvent` regardless of which credential type
authenticated the request (`internal/core/audit.go`, `server/middleware/auth.go`); audit
event creation does not distinguish machine tokens from session tokens, and both produce
a row. What differs is **attribution**. A machine token (ADR-030, `kx_`-prefixed) resolves
to a `UserContext` with `ActorType: core.ActorTypeMachine` and the specific
`MachineIdentityID` (`server/middleware/auth.go`'s `machineUserContext`) — a
Go-server-initiated read is tagged and traceable to a specific, revocable machine
identity, distinguishable from any human's own activity. A session token (from
`/auth/login` — the TypeScript server's `KEYORIX_USERNAME`+`KEYORIX_PASSWORD` fallback)
resolves to `ActorType: core.ActorTypeUser` and `UserID` set to that human's own ID
(same file, `validateToken`'s session branch) — indistinguishable in the audit trail from
that user's own direct action. The Go server's documented configuration only ever uses a
machine identity token; the TypeScript server is the one that offers a human-credential
path at all. When that fallback is used, reads an agent initiated and reads the human
initiated themselves become indistinguishable in the audit trail — for a product sold on
audit quality, that is a sharper defect than "no audit," not a lesser one.

The TypeScript repository has no LICENSE file, no tests, and no CI — nothing verifying
its own behavior, let alone verifying it against ADR-061's model, because it was never
built to that model in the first place.

## Decision

The Go implementation in `internal/mcp` (binary `cmd/keyorix-mcp`, image
`ghcr.io/keyorixhq/keyorix-mcp`) is the **only supported MCP server**. The TypeScript
repository (`github.com/keyorixhq/keyorix-mcp`) is retired and deleted — not archived —
with its full history preserved as a git bundle (see "Disposition of published
artifacts" below).

Nothing in this repo needs to change to enforce that in practice: a repo-wide search
(`git grep -in "keyorix-mcp"`, plus a separate check of `web/src`) found zero references
to the npm package, `npx`, or the TypeScript repo anywhere in `keyorix` — every existing
mention (`docs/mcp.md`, `docs/adr-061-mcp-server.md`, `CHANGELOG.md`,
`docker-publish.yml`, `cmd/keyorix-mcp/`) already refers to the Go binary/image. The
ambiguity was external — a same-named package sitting on npm/GitHub next to this repo's
own binary — not something this repo's own documentation ever pointed users toward.

## Distribution note

The plausible reason a TypeScript version existed at all is `npx` convenience: `npx
keyorix-mcp` needs no local build, no Go toolchain, nothing beyond Node — a real ergonomic
advantage the Go binary/container distribution doesn't offer. That advantage is real, but
it does not justify a second implementation of tool logic, security enforcement, and
auth handling running against Keyorix from scratch, drifting from ADR-061 the moment
nobody's specifically keeping the two in sync — which is exactly what happened here.

If `npx`-style convenience is wanted later, the correct shape is a **thin npm wrapper**
that downloads and executes the signed `ghcr.io/keyorixhq/keyorix-mcp` Go binary for the
host platform (verifying its signature/checksum before exec), the same pattern many Go
CLI tools use to ship an `npx`-installable front door without reimplementing anything.
The wrapper would carry no tool logic, no auth logic, and no security decisions of its
own — it would just fetch and run the one real implementation. **This is the trigger for
reopening this decision**: a proposal to add `npx` convenience is welcome, but only in
that shape. A proposal that reimplements MCP tool handling in TypeScript again is the
same mistake this ADR retires.

## Disposition of published artifacts

Archiving or deleting the GitHub repository does nothing to a published npm package —
they are separate distribution surfaces, and an ADR read during a customer security
review needs to answer for both, not just the one that's convenient to close out.

- **GitHub (`keyorixhq/keyorix-mcp`)**: deleted, 2026-08-04 — not archived. Zero forks,
  zero stars, no inbound links, so there is no fork-network-root risk of the kind
  archiving exists to guard against (contrast `keyorix-go`, ADR-072, which has one fork
  and is archived rather than deleted for exactly that reason). Full branch and tag
  history is preserved as a verified `git bundle --all` archive in
  `keyorix-private/archive/keyorix-mcp.bundle` (`git bundle verify` passing, every ref
  cross-checked against `git ls-remote` on the source repo before deletion; restore via
  `git clone keyorix-mcp.bundle keyorix-mcp`), rather than relying on GitHub's continued
  hosting of a repo with no external dependents. This remains a retirement of the
  implementation, not an erasure of it — the history is just no longer browsable
  directly on GitHub.
- **npm (`keyorix-mcp`)**: no action required. `package.json` has a `bin` entry and no
  `"private": true"`, so nothing in the repo itself prevented publication, but the package
  was **never published**. Verified 2026-08-04: `npm view keyorix-mcp` returns HTTP 404
  from `registry.npmjs.org` — the name has no corresponding registry entry. There is
  nothing to deprecate or unpublish, and no deprecation notice is possible (or needed)
  against a name that was never claimed.
- **Security advisory (GHSA)**: **not warranted.** Determined 2026-08-04, on this basis:
  the implementation was never distributed through any package registry (see npm finding
  above); its sole distribution channel was the public GitHub source repository, which
  carried 0 stars and 0 forks at the time of retirement; and there is no evidence of any
  downstream consumer having installed or run it. Against the criteria this ADR set out
  to apply — actual registry publication, duration/volume of availability, and evidence
  of real-world use — none are met. This determination is not permanent: it would change
  if evidence of use elsewhere emerged (a fork with commits, an issue/discussion
  referencing it from outside the org, a security report). Recorded here so the reasoning
  is auditable later, not just the conclusion.

## Consequences

- The `keyorix-mcp` name collision is resolved: one implementation, one security model,
  one place (`docs/mcp.md`, ADR-061) that describes it.
- `list_environments` — the TypeScript server's ability to enumerate environments, which
  the Go server's `keyorix_get_secret`/`keyorix_list_secrets` pair has no equivalent for
  (`internal/mcp/keyorix.go`'s reader interface has no environment-listing method) — is a
  genuine, in-scope read-only capability gap. It moves to `BACKLOG.md` against the Go
  server rather than being lost with the TypeScript repo. `get_stats`, `list_audit_events`,
  and `list_users` are read-only in a narrow technical sense but belong to a different
  permission class than "read a secret" (deployment analytics, audit visibility, user
  enumeration) and are not carried forward as gaps.
- Disposition of the two published artifacts is recorded in "Disposition of published
  artifacts" above: npm requires no action (the name was never published) and no GHSA
  advisory is warranted (no registry distribution, 0 stars/forks, no evidence of use).
  The GitHub repository is deleted, not archived, with its history preserved as a
  verified git bundle rather than left browsable on GitHub itself.
