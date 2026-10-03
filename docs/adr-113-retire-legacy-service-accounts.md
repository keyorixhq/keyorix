# ADR-113: Retire legacy service accounts in favour of machine identities

**Status:** Accepted (retroactive — the engineering decision was taken
2026-07-03 in #552; this ADR records it and closes the last remaining piece,
the dead web UI)
**Date:** 2026-10-03
**Related:** ADR-027 (Personal Access Tokens), ADR-030 (machine-token
authentication), ADR-070 (web repo merge)

## Context

2026-05-10, f2b62e2b ("RBAC phase 1") introduced admin-managed **service
accounts**: an `APIClient` (a named credential holder with a hashed
`client_secret`) plus `APIToken`s issued under it, managed through
`server/http/handlers/service_accounts_handler.go` and the
`internal/core/service_accounts.go` business logic, with admin-only issuance/
rotation/revocation routes under `/api/v1/service-accounts`.

ADR-030 (2026-06-10) then introduced **machine identities**: a project-scoped,
RBAC-integrated, fully-audited non-human principal with its own hashed-bearer-
token credential type (`machine_identity_credentials`) and role grants
(`machine_identity_roles`), authorized through the same `AuthorizePrincipal`
path as every other request.

2026-07-03, #552 (f81997af) found that the service-account credential type
was **never actually wired into authentication**:
`server/middleware/auth.go`'s `validateToken` had no branch that ever accepted
an `APIClient`/`APIToken` secret — every service-account token that had ever
been issued was, and always had been, rejected by every protected endpoint. A
credential type nothing can authenticate with is not a reduced-functionality
feature; it is dead code with a UI in front of it. #552 removed the issuance/
management routes and their `internal/core` logic outright, named machine
identities (already shipped, already wired) as the intended replacement, and
deliberately **kept** the `APIClient`/`APIToken` GORM models and the KEK-
rotation sweep code (`internal/encryption/sweep_auth.go`'s `sweepAPIClients`/
`sweepAPITokens`) so that an already-deployed database with legacy rows in
those tables would not break on `admin migrate` or on a key-rotation sweep.

2026-08-03, ADR-070 merged the separate web frontend repository into this one
as `web/`. The merge brought its `ServiceAccountsPage` along — built against
the routes #552 had, by that point, already deleted two months earlier in the
Go backend's own history, but the two repositories' histories were
independent until the merge, so the web UI was never updated to match.
2026-09-15, #1888 noticed the page was non-functional and slapped an "under
construction" banner on it rather than removing it.

Issue #2486 (filed by the QA-2 session building a static web-call-vs-
`openapi.yaml` contract test) made the gap precise: `web/src/services/
serviceAccounts.ts` calls 7 endpoints —
`GET/POST /api/v1/service-accounts`,
`PUT/DELETE /api/v1/service-accounts/{id}`,
`GET/POST /api/v1/service-accounts/{id}/tokens`,
`DELETE /api/v1/tokens/{id}` —
none of which exist anywhere in `server/http/router.go`. This is not a docs
gap; the backend genuinely has no handler for any of them, and never will,
per the decision below.

A second, related defect surfaced while tracing this ADR's own scope:
`web/src/pages/admin/OIDCFederationSection.tsx` (a tab on the same
`ServiceAccountsPage`) calls a THIRD non-existent surface,
`/api/v1/oidc/trust`, to bind an OIDC trust configuration to a legacy
`service_account_id`. The real OIDC/Kubernetes-JWT federation feature shipped
under ADR-031, machine-identity-scoped
(`POST /projects/{id}/machine-identities/{machineId}/oidc-bindings`,
`machine_identity_oidc_bindings`) — a different API shape entirely, and one
`web/` never grew a UI for. `OIDCFederationSection` is not a "Kubernetes
service account" (a distinct, real concept this ADR does not touch) — it is
dead UI for the same retired credential type, and is retired alongside it in
the companion PR.

## Decision

**Service accounts (`APIClient`/`APIToken`) are retired as a product
feature.** Machine identities (ADR-030/ADR-031) are the one non-human
identity model going forward.

- **No service-account API.** `server/http/handlers/service_accounts_handler.go`
  and its routes stay deleted (#552); no replacement is planned.
  `TestServiceAccountRoutesRemoved` (`server/http/integration_test.go`) is the
  standing guard — it fails if any of the 5 issuance/management routes is ever
  re-registered.
- **The web UI is removed**, not fixed: `ServiceAccountsPage`,
  `APITokensPage` (which showed only service-account tokens — no PAT or
  machine-identity content existed on that page to preserve), and
  `OIDCFederationSection` (dead UI for the pre-ADR-031 API shape), plus their
  service/hook/type layers (`services/serviceAccounts.ts`,
  `types/serviceAccounts.ts`, `features/admin/useServiceAccounts.ts`) and
  tests. See the companion PR for the full file list. The old
  `/admin/service-accounts` and `/admin/api-tokens` URLs redirect to
  `/admin/machine-identities` rather than 404ing for anyone with an old
  bookmark or link.
- **What remains, and why:** the `APIClient`/`APIToken` GORM models
  (`internal/storage/models/models.go`) and the KEK-rotation sweep code
  (`internal/encryption/sweep_auth.go`) stay. Deleting them outright would
  break `admin migrate` and key-rotation on any already-deployed,
  self-hosted database that still has legacy rows in those tables — Keyorix
  does not control when or whether an operator upgrades, so "no production
  system has these rows" cannot be verified centrally the way it could for a
  hosted service. Keeping dead-but-harmless columns and a sweep function is a
  strictly safer failure mode than a migration that silently drops rows or a
  sweep that crashes on a table it no longer expects.
- **A later purge is appropriate, but needs its own gate, not a date.**
  Filed as #2541: once a migration step can positively confirm zero rows
  remain in `api_clients`/`api_tokens` on a given install (the same
  "completion marker" pattern `ReconcileAlertsWriteRole`'s
  `alerts_write_role_backfill_v1` uses — see ADR-110), the models and sweep
  functions can be dropped in that release. Until that check exists and
  reports clean, the tables and sweep stay — removing them on a timeline
  instead of a verified-empty check would trade a loud, safe failure for a
  silent one on exactly the self-hosted, operator-upgraded deployments this
  ADR is trying to protect.

### ADR-027 cross-reference

ADR-027's "What this is not" section says "Not service accounts (those
remain admin-managed, see `service_accounts_handler.go`)" — written before
#552 deleted that handler. Updated in this PR to point here instead.

## Consequences

- One non-human identity model (machine identities) instead of two, one of
  which never worked.
- No `/api/v1/service-accounts*` or `/api/v1/oidc/trust` API, now or planned;
  `internal/core`/`server/http` carry no service-account business logic.
  `TestServiceAccountRoutesRemoved` keeps it that way.
- The web admin UI no longer has a page that always fails every action a
  user takes on it against a real backend (the defect issue #2486 reported).
- `APIClient`/`APIToken` DB models and the KEK-rotation sweep remain as
  dead-row-safe legacy support until #2541's verified-empty check lands and
  the next release after that drops them.
- Anyone who previously bookmarked `/admin/service-accounts` or
  `/admin/api-tokens` lands on Machine Identities instead of a 404.
