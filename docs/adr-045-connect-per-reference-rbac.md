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

- A grant authorizes any `ref` whose value begins with `ref_prefix` (an empty prefix =
  all refs on that connector) for holders of the role.
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
resolved from the correct identity store for the actor kind — `user_roles` for users,
`machine_identity_roles` for machine identities — so the policy is enforceable for both
human and machine principals (at global scope, since Connect is a global surface).

## The deny-by-default footgun (documented)

Defining the first grant on a connector flips it to deny-by-default: roles without a
matching grant immediately lose access to it. This is the point of the feature, but it
can surprise an operator who expected admins to retain blanket access. To keep an admin
role's broad access while scoping others, grant that role an **empty-prefix** grant on
the connector (which matches every ref). This is explicit and auditable rather than an
implicit admin bypass.

## Alternatives considered

- **Glob / regex ref patterns** instead of prefixes: more expressive but inconsistent
  with the existing `allowed_refs` prefix semantics and harder to reason about for
  least-privilege. Prefix matching covers the hierarchical-path naming every supported
  backend uses; revisit if a real need for mid-path wildcards appears.
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
