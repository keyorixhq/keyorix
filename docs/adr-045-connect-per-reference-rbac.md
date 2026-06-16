# ADR-045: Per-reference RBAC for Keyorix Connect

## Status

Accepted.

## Context

Keyorix Connect (ADR-043) proxies authorized, audited read-through to external secret
stores. Until now a federated read was bounded by exactly two controls:

1. the global **`connect.read`** permission (ADR-044) — a caller either may use Connect
   or may not; and
2. the operator-configured per-connector **`allowed_refs`** prefix allowlist — a
   *uniform* bound that applies identically to every caller.

There was no way to say "role A may read `metrics/*` from this connector, but only
role B may read `db/*`." Any holder of `connect.read` could read every reference the
connector's backend identity (and `allowed_refs`) permitted — too coarse for a
deployment where different teams share one connector but should see different secrets.

## Decision

Add **per-reference grants**: a `(role, connector, ref_prefix)` allowlist that refines
`connect.read`, enforced in `ReadFederatedSecret` before the backend call.

- A grant authorizes a `ref` for holders of the role when the grant's pattern matches.
  A pattern with **no** glob metacharacters (`*`, `?`, `[`) matches as a **prefix** (an
  empty pattern = all refs on that connector); a pattern **containing** a metacharacter
  matches as a shell-style **glob** via `path.Match`, where `*` does not cross `/`. So
  `metrics/` grants everything under `metrics/`, `metrics/*` grants exactly one further
  path segment, and `prod/*/db` matches `prod/<env>/db`. A malformed glob matches
  nothing (fails closed).
- Enforcement is **deny-by-default, but only for connectors that have at least one
  grant**:
  - a connector with **no** grants is governed exactly as before — `connect.read` plus
    `allowed_refs` (fully backward compatible, opt-in);
  - once a connector has **any** grant, a read is permitted only if one of the caller's
    roles holds a matching grant. A principal whose roles do not match — including one
    with no resolvable roles — is denied.
- A caller holding several roles is allowed if **any** of them matches (union).
- Denied reads are audited as `connect.secret_read` with a `DENIED by per-reference
  policy` description, so an attempted out-of-scope read is visible.

Grants are managed over HTTP: `GET /connect/ref-grants` (gated `roles.read`),
`POST /connect/ref-grants` and `DELETE /connect/ref-grants/{id}` (gated `roles.write`)
— they are role-authorization configuration, so they reuse the role-management
permissions rather than `connect.read`. Create/delete are audited
(`connect.ref_grant_create` / `connect.ref_grant_delete`). A grant for an unknown
(typo'd) connector is rejected, so an operator cannot believe they scoped a connector
that is in fact still unscoped.

Enforcement lives in the core layer (`ReadFederatedSecret`), so it protects **every**
transport uniformly — HTTP and the gRPC `ConnectService` alike. The caller's roles are
resolved exactly as canonical authorization resolves them, so the per-reference policy
is consistent with the rest of RBAC: a user's **effective** roles — direct assignments
**plus group-derived roles** — and, for a machine identity, its `machine_identity_roles`
(at global scope, since Connect is a global surface). Resolving only direct roles would
wrongly deny a user whose granted role comes via a group even though `connect.read`
itself honors it. **Group-based scoping therefore works out of the box**: grant a
ref-prefix to a role and manage who holds it through group membership.

## The deny-by-default footgun (documented)

Defining the first grant on a connector flips it to deny-by-default: roles without a
matching grant immediately lose access to it. This is the point of the feature, but it
can surprise an operator who expected admins to retain blanket access. To keep an admin
role's broad access while scoping others, grant that role an **empty-prefix** grant on
the connector (which matches every ref). This is explicit and auditable rather than an
implicit admin bypass.

## Alternatives considered

- **Regex ref patterns**: rejected as too sharp an edge for an allowlist (catastrophic
  backtracking, hard to reason about for least-privilege). Shell-style globs via
  `path.Match` were instead added **additively** on top of prefixes (a plain pattern
  stays a prefix, so existing grants are unchanged; a pattern with `*`/`?`/`[` matches
  as a glob), which covers mid-path wildcards (`prod/*/db`) without the regex hazards.
  The coarse connector-level `allowed_refs` guardrail remains prefix-only for now.
- **User-scoped (not role-scoped) grants**: rejected — Keyorix authorization is
  role-based throughout; per-user grants would fork the model and not compose with
  groups.
- **An implicit admin bypass** (a privileged permission that ignores ref-grants):
  rejected — it would reintroduce the coarse "sees everything" behavior the feature
  exists to remove. An explicit empty-prefix grant expresses the same intent visibly.

## Consequences

- Connect access can now be scoped per team without splitting one external store into
  many connectors.
- Backward compatible: existing deployments (no grants) are unaffected; the policy is
  opt-in per connector.
- Out of scope here (possible follow-ups): gRPC/CLI/web management surfaces for grants
  (enforcement already covers all read transports); group-scoped grants;
  caching (still cautioned for stale-secret reasons).
