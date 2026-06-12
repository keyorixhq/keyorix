# ADR-042: Personal access token permission scoping (least privilege)

**Status:** Accepted
**Date:** 2026-06-12

## Context

A personal access token (PAT, ADR-027) authenticates an API request **as its
owning user**, inheriting that user's *full* permission set — there is no way to
mint a token that does less than its owner. In practice a PAT is most often handed
to automation: a CI job that only needs to **read** one project's secrets, a
backup script, a third-party integration. Giving each of those the owner's entire
authority — frequently a project- or system-admin's authority — is a textbook
least-privilege violation. If such a token leaks, the blast radius is the whole
account, not the one capability the job actually used.

Least privilege for non-interactive credentials is a core control in the
certification frames Keyorix targets — NIS2 Art. 21(2) (access control,
least-functionality), ISO 27001:2022 A.5.15 / A.5.18 / A.8.2 (access rights and
privileged access), ENS `op.acc.4` (least privilege). Machine identities (ADR-030)
already get bounded, explicitly-granted permissions with **no admin bypass**; PATs
were the remaining over-privileged credential.

## Decision

A PAT may carry an optional **least-privilege restriction** fixed at creation: a
**permission allowlist** and/or a **single-project confinement**. The restriction
is a **filter that only ever narrows** the token below its owner — it can never
grant a permission the owner does not hold, because the owner's live RBAC still
runs. An existing token, or one created without a restriction, is unaffected
(full inheritance — the back-compatible default).

- **Model** (`PersonalAccessToken`, additive columns, ADR-042):
  - `Scopes` — JSON-encoded `[]string` permission allowlist. Empty/null = inherit
    the owner's full set. An entry is an exact permission (`secrets.read`), the
    catch-all `*`, or a prefix wildcard (`secrets.*`).
  - `ProjectScope uint` — when non-zero, the token may act **only** within that
    project's scope; `0` = any scope the owner can reach (mirrors the `0 = global`
    sentinel used throughout RBAC). A project-scoped token is therefore denied at
    global/system scope — it is not a system-wide credential.
  - Defaults leave existing rows unrestricted. On an existing DB the columns are
    added via the GORM `Migrator` (never a full `AutoMigrate` on the live table —
    the same pgx prepared-statement hazard the invitations/notifications blocks
    avoid).

- **Enforcement is at the single authorization chokepoint, not the HTTP layer.**
  The restriction is carried on the request `context.Context`
  (`core.WithPATRestriction`, tagged in the auth middleware's
  `buildRequestContext` for PAT requests only) and read back inside
  **`core.Authorize` and `core.AuthorizePrincipal`** — the two functions every
  authorization decision funnels through (HTTP middleware `RequireScopedPermission`
  / `RequirePermission`, the in-handler authorizers for secret-create /
  dynamic-secrets / rotation-create, and gRPC). The filter is applied **first,
  before role resolution and before the admin bypass**, so it bounds even a
  global admin's own token. Because it sits at the chokepoint rather than at N
  call sites, every present and future authorization path is constrained
  automatically — there is no route to forget to wire (the failure mode ADR-037's
  pre-merge review caught for per-project MFA).

- **It is a filter, never an escalation.** `Authorize` still resolves the owner's
  live roles after the restriction passes. A token listing `secrets.write` whose
  owner has since lost that permission grants nothing. This is why creation does
  **not** need to validate that the requested scopes are a subset of the owner's
  permissions: the runtime intersection makes over-broad scopes harmless, and the
  owner's permission set is scope-dependent and changes over time anyway.

- **API.** `POST /api/v1/auth/tokens` accepts optional `scopes` (`[]string`) and
  `project_scope` (`uint`). The list/create DTO surfaces both read-only — a
  token's scope is immutable after creation (to change it, revoke and re-mint).
  The raw token is still returned exactly once.

## Consequences

- A user — including an admin — can mint a token that is strictly weaker than
  themselves: a CI read-only token for one project, a rotation-only token, etc.
  Leak blast radius shrinks to the granted capability.
- Enforcement is uniform and centrally provable: the four-case core test plus the
  real-RBAC end-to-end test show a `secrets.read`-scoped token on a **global
  admin** is denied `secrets.write`, and a project-3 token is denied in project 4
  and at global scope — surviving the real admin bypass.
- No behavioural change for existing tokens or unrestricted new ones.

## Alternatives considered

- **Enforce in HTTP middleware (like ADR-037 per-project MFA).** Rejected: PAT
  authority must hold for *every* authorization path including gRPC and in-handler
  authorizers; the ctx-at-the-chokepoint approach covers them all without
  per-site wiring. (Per-project MFA had to be at the HTTP layer because it keys on
  request interactivity, which `Authorize` cannot see; a PAT restriction is pure
  authorization data and belongs at the authorization function.)
- **Validate scopes ⊆ owner at creation.** Rejected as unnecessary: the runtime
  intersection already prevents escalation, and owner permissions are
  scope-dependent and mutable, so a creation-time check would be both
  redundant and frequently wrong later.
- **Separate scoped-credential type.** Rejected: machine identities (ADR-030)
  already serve the "first-class non-human principal" need; this is the lighter
  "narrow a token I already trust myself to hold" case.

## Deferred

- **Per-environment confinement** (a token bound to `prod` only) — `Scope` already
  carries an environment axis; the model/filter can extend to it when needed.
- **Frontend (My Account) UI** to pick scopes/project when creating a token — the
  API and storage are complete; the keyorix-web token-creation dialog is the
  remaining surface.
- **Scope presets** (e.g. a "read-only" macro expanding to the read permissions).
- **CLI `--scope` / `--project` flags** on token creation.
