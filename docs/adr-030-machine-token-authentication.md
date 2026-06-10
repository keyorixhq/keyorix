# ADR-030: Machine-token authentication + machine RBAC

**Status:** Accepted
**Date:** 2026-06-10
**Context:** ADR-023 introduced machine identities (a `machine_identities` table,
a lifecycle state machine, CLI, audit `actor_type`) but deferred the actual
**authentication** path every time: a machine identity exists as a record but
cannot sign in or call the API. This ADR closes that gap.

## Context

Human principals authenticate with session tokens or personal access tokens
(ADR-027); a bearer token is hashed, looked up, and resolved to a `UserContext`
carrying the user's roles, and `core.Authorize(userID, permission, scope)`
gates every protected operation. Machine identities have none of this — no
credential, no validation path, no way to be authorized.

Two machine-auth modes are worth supporting:

1. **Opaque bearer tokens** — issued by Keyorix, presented as `Authorization:
   Bearer kx_machine_…`, validated by hash lookup. Mirrors the PAT path. Works
   anywhere, no external dependency.
2. **OIDC / Kubernetes projected service-account tokens** — a workload presents
   a cluster-issued JWT, verified against the issuer's JWKS and mapped to a
   machine identity by `(issuer, subject)`. No long-lived secret to distribute.

**This ADR delivers mode 1 (opaque tokens) plus the machine-RBAC foundation
both modes need.** Mode 2 (OIDC federation) is a follow-up (ADR-031) that reuses
this foundation — it only adds a different way to *resolve a request to a
machine principal*; issuance/authorization/audit are identical.

## Decision

### Credentials — `machine_identity_credentials`

A new table holds hashed machine tokens (never plaintext), mirroring
`personal_access_tokens`: `machine_identity_id`, `token_hash` (SHA-256 hex,
unique), `token_prefix` (display, e.g. `kx_machine_ab12cd`), `expires_at`
(nullable = non-expiring), `revoked`, `last_used_at`, `created_at`. Raw tokens
are `kx_machine_` + base64url(32 random bytes), shown once at issuance. A machine
may hold several active credentials (rotation).

Issuance requires the machine to be in state `active`. Validation requires the
credential to be un-revoked + unexpired **and** the machine still `active`, so
suspending/revoking the identity instantly disables all its tokens.

### Authorization — `machine_identity_roles` + actor-aware authorize

Roles cannot be keyed to `user_id` for machines (id spaces overlap). A parallel
grant table `machine_identity_roles` mirrors `user_roles`:
`(machine_identity_id, role_id, project_id, environment_id)` composite PK, same
0-sentinel global scope.

Authorization is generalized to a **principal**: `AuthorizePrincipal(ctx,
actorType, principalID, permission, scope)`. For `user` it is the existing
logic; for `machine_identity` it resolves `machine_identity_roles` at scope
(admin-role bypass deliberately does **not** apply to machines — a machine is
never a global admin). `Authorize(userID, …)` is kept as a thin wrapper
(`AuthorizePrincipal(ActorTypeUser, …)`) so every existing user call site is
unchanged. The ~7 call sites that gate operations (the two permission
middlewares + a handful of in-handler checks) switch to the principal form,
reading actor type + principal id from the request context.

### Request principal

`UserContext` gains `ActorType` and `MachineIdentityID *uint`. For a machine
request `UserID` is 0, `MachineIdentityID` is set, `Roles` carries the machine's
granted roles, and the middleware tags the context `WithActorType(machine_identity)`
so every audit event the request produces is correctly actored (ADR-023 plumbing,
now finally exercised).

### Middleware hook

`validateToken` routes by prefix: `kx_machine_` → `ValidateMachineToken`
(the new path), `kx_pat_` → PAT, else session. The machine path builds a
machine `UserContext`. The token cache keys on the SHA-256 of the bearer, same
as the others.

### HTTP surface (under the existing project-scoped machine-identity group)

- `POST   /projects/{id}/machine-identities/{machineId}/tokens` — issue (returns the raw token once)
- `GET    /projects/{id}/machine-identities/{machineId}/tokens` — list (metadata only; never the token)
- `DELETE /projects/{id}/machine-identities/{machineId}/tokens/{tokenId}` — revoke
- `POST   /projects/{id}/machine-identities/{machineId}/roles` — grant a role at the project scope
- `DELETE /projects/{id}/machine-identities/{machineId}/roles/{roleId}` — remove

Issuance/role-management require `roles.assign` at the project scope (the same
gate as human role assignment). Every mutation is audited
(`machine_identity.token_issued` / `…token_revoked` / `…role_granted` /
`…role_removed`).

## Consequences

- A CI/automation/K8s workload can now hold a Keyorix identity, be granted a
  least-privilege project role (e.g. `project_viewer` to read deploy secrets),
  and authenticate — the core ADR-023 promise, finally usable.
- Machines get **no admin bypass** and are project-scoped by construction, so a
  leaked machine token is bounded to its grants.
- Suspending/revoking a machine identity disables all its tokens immediately
  (validation re-checks machine state every request; the token cache TTL bounds
  the window).
- Blast radius is contained: `Authorize` stays source-compatible; only the gate
  call sites become principal-aware.
- **Out of scope (follow-up ADR-031):** OIDC/Kubernetes-JWT federation —
  verifying an external cluster token against JWKS and mapping `(iss, sub)` to a
  machine identity. It builds directly on this foundation (same credentials are
  unnecessary; same `machine_identity_roles` + `AuthorizePrincipal` authorize
  it; same audit actoring), so it is additive, not a rework.
