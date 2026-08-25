# G80 documented-exception re-verification sweep — findings pending GitHub filing

`gh` is broken in the working environment (invalid keyring token, plus a TLS
certificate error on the device-auth flow: `x509: OSStatus -26276`). The items
below are staged here so they can be pasted into GitHub once `gh auth` (or
manual web filing) is available. Do not let this doc substitute for the actual
issue/comment — file these for real as soon as possible.

## New issue: CleanupExpiredSessions is implemented but wired to no scheduler

**Confirmed**: `CleanupExpiredSessions` (`internal/core/storage/interface.go:1318`,
implemented in `internal/storage/store/local_auth.go:224` and
`internal/storage/store/remote_auth.go:83`) has zero callers anywhere in the
repo. `server/main.go:1187`'s `startSchedulers` registers 18 named background
schedulers (anomaly_detection, retention_purge, data_retention,
rotation_reminder, expiry_reminder, certificate_expiry, license_expiry,
auto_rotation, compliance_digest, recertification, evidence_delivery,
audit_checkpoint, jit_access_expiry, dynamic_secret_sweep,
login_attempt_prune, mfa_stepup_grant_prune, read_quota_alerts) — none of them
sweep expired sessions.

**Not a vulnerability**: `ValidateSessionToken` (`internal/core/auth.go:461`)
re-checks expiry and account state on every use, so an orphaned session row is
inert — it can never be used to authenticate once past its `ExpiresAt`.

**Why it still matters**: Keyorix is designed to run on-prem, unattended, for
years. With no sweep, the `sessions` table accumulates one dead row per login
forever — an unbounded-growth/table-bloat issue in a long-lived deployment,
not a security bypass.

**Suggested issue title**: "CleanupExpiredSessions has no scheduler — sessions
table grows unbounded in long-running deployments"

**Suggested body**: as the "Confirmed"/"Not a vulnerability"/"Why it still
matters" text above, with the four file:line references.

**Labels**: `tech-debt`, `ops`. Not `security` — validation already fails
closed on an expired/orphaned row.

---

## Correction: three handlers recorded FIXED were fixed on the wrong axis

**Context**: an independent verification session (2026-08-25) found that three
`/system` proxy handlers, each previously recorded FIXED (a PR reference or
this same sweep's own `rawStorageBypassAllowlist` entry
(`server/http/raw_storage_bypass_guard_test.go`)), were fixed against the
RAW-STORAGE-BYPASS shape (#1542: does an independently-gated core ceiling get
skipped) but NOT against a separate, orthogonal shape this doc had not yet
named: **wire-actor-identity forgery** — a handler authorizing or persisting
an actor identity (who performed this action) from a value the CALLER
supplied on the wire, instead of the AUTHENTICATED request context. All three
are now fixed on both axes as of this sweep (2026-08-25); recorded here so
the "FIXED" label on the original PRs/entries isn't read as covering ground
it never actually covered.

- **`CreateInvitationProxy`** (`server/http/handlers/invitations_proxy.go`).
  Recorded FIXED under #1558 (re-derives `requireAuthorityForRole`'s
  escalation-by-proxy ceiling). That fix did not touch this axis at all: the
  ceiling check itself, and the persisted `InvitedBy` field, both still read
  the wire body's `invited_by` — a caller holding only `system.write` could
  name a real administrator's ID in that field and clear the ceiling meant to
  require the ADMIN to have made the call, while also mis-attributing the
  invitation. Fixed by deriving both from `actorID(r)` (invitation authority
  is a human-only decision).
- **`UpdateAccessRequestProxy`** (`server/http/handlers/access_request_proxy.go`).
  Recorded FIXED under #1557 (re-derives maker≠checker + admin/role-grant
  authority). Same correction: the self-approval check and both authority
  checks read the wire body's `resolved_by`, not the authenticated caller —
  a system.write-only caller could name a real admin as `resolved_by` and
  approve access to a restricted secret. Fixed via
  `requestActorKindAndID(r)` (actor-kind aware — this check must work for
  both human and machine callers).
- **`RevokeBreakGlassActivationProxy`** (`server/http/handlers/break_glass_proxy.go`).
  Recorded FIXED in this same sweep's earlier pass ("actually revoke role" —
  the role-removal + audit-event gap, #1511-adjacent). That fix kept trusting
  the wire body's `revoked_by` for the role-removal actor, the persisted
  `RevokedBy` field, and the audit event — a non-repudiation break letting
  any `system.write` holder revoke an emergency access grant while
  attributing it, in both the activation record and the audit trail, to an
  arbitrary user ID. Fixed via `actorID(r)` (revocation authority is a human
  decision).

**Root cause, generalized**: a handler can be genuinely fixed against the
specific vulnerability an audit named, while an adjacent, differently-shaped
vulnerability in the same code survives untouched because it was never named
as a separate axis. "FIXED" in a PR title or an allowlist entry is a claim
about the axis that PR addressed, not a claim that the handler has no other
problems — worth remembering before trusting a FIXED label to mean "this
handler is now safe" rather than "this ONE finding is closed."

**Full sweep table** (every `/system` proxy handler and every handler with an
actor-shaped body field, checked — not just the hits; a sweep that reports
only hits is indistinguishable from one that didn't look):

| Handler | Wire field(s) | Used for | Status | Notes |
|---|---|---|---|---|
| `CreateInvitationProxy` | `invited_by` | auth check + persisted | FIXED | `actorID(r)` |
| `UpdateAccessRequestProxy` | `resolved_by` | auth check + persisted | FIXED | `requestActorKindAndID(r)` |
| `UpdateAccessReviewItemProxy` | `decided_by` | auth check (self-cert) + persisted | FIXED (new hit) | was comparing two wire values against each other |
| `CreateAccessRequestApprovalProxy` | `approver_id` | persisted, feeds dual-control count | FIXED (new hit) | no auth check existed at all; dual-control bypass |
| `RevokeBreakGlassActivationProxy` | `revoked_by` | role-removal actor + persisted + audit | FIXED (new hit) | already touched by this campaign, wrong axis |
| `CreateMachineIdentityProxy` | `created_by` | persisted only | FIXED (new hit) | ceiling check 2 lines above was already correct |
| `UpdateMachineIdentityProxy` / `TransitionMachineIdentityStateProxy` | `created_by` | persisted (full-row overwrite) | FIXED (new hit) | same field, reachable a second way |
| `CreateAccessReviewCampaignProxy` | `created_by` | persisted | FIXED (new hit) | audit event was already correct; only the row wasn't |
| `CreateMembershipProxy` | `invited_by` | persisted only | FIXED (new hit) | feeds notification routing + audit, no privilege by itself |
| `CreateSetupTokenProxy` | `created_by` | persisted, feeds audit actor | FIXED (new hit) | the route's own gating (users.write) was already correct |
| `CreateAccessRequestProxy` | `resolved_by` | persisted at creation, unused | FIXED (new hit) | cosmetic — state is always forced to pending |
| `CreateDynamicSecretConfigProxy` | `created_by` | persisted (display string) | **NOT FIXED, tracked** | low severity, no auth decision reads it back; see `wire_actor_identity_forgery_guard_test.go`'s own doc comment for why the guard structurally cannot see this one |
| `IngestAuditEventProxy` | full `AuditEvent` incl. actor fields | persisted (the audit record itself) | ACKNOWLEDGED, DEFERRED | pre-existing, explicitly documented, tracked separately ("Wave 4") |
| `CreateUserWithRoleGrantsProxy` | — | `actorID(r)` used correctly | CORRECT EXAMPLE | the positive pattern every fix above now matches |
| `DeleteProjectProxy` | — | `RequireScopedPermission` middleware, not a wire field | CORRECT EXAMPLE | fixed in this same session for a related but distinct finding (see the raw-storage-bypass triage doc) |
| groups/rbac-role-grants/risk-exceptions/most of machine-identities/users-credentials/legal-hold proxies | — | `actorID(r)`/`isMachineActor(r)`/context-derived throughout | CORRECT EXAMPLE (~20 handlers) | already using the right pattern before this sweep |
| ~115 remaining GET/List/Count/plain-CRUD `/system` routes | — | no actor-shaped field influences an auth decision or persisted attribution | NOT APPLICABLE | — |

**Guard added**: `server/http/wire_actor_identity_forgery_guard_test.go`
(`TestNoUnjustifiedActorIdentityForgery`) — same allowlist/known-unfixed
shape as `raw_storage_bypass_guard_test.go`, scanning every `/system` handler
for a wire-supplied actor-shaped field (`invited_by`, `resolved_by`,
`created_by`, `decided_by`, `approver_id`, `revoked_by`) read directly
instead of derived from the authenticated caller.

---

## Comment on #1511 (missing `/api/v1/rbac/remove-role` wire route)

**Context**: #1511 already tracks that `POST /api/v1/rbac/remove-role` and
`POST /api/v1/rbac/assign-role` are unregistered
(`internal/storage/store/remote_wire_route_coverage_test.go`'s
`knownMissingRoutes`). This was previously filed as a coverage gap. The G80
documented-exception re-verification sweep (2026-08-25) found it has now
caused a **confirmed live security failure**, not just a theoretical gap.

**Comment text to post**:

> Confirmed live impact, not just a coverage gap: `/api/v1/rbac/remove-role`
> being unregistered isn't only a theoretical wire-coverage hole — it broke a
> real security control. `RevokeBreakGlassActivationProxy`
> (`server/http/handlers/break_glass_proxy.go`) was documented as safe on the
> assumption that its offsetting role-removal effect travels through
> `core.RevokeBreakGlass`'s own separate call chain. It doesn't:
> `core.RevokeBreakGlass` (`internal/core/break_glass.go:272`) calls
> `RemoveUserRole` → `storage.RemoveRole` → `RemoteStorage.RemoveRole` →
> `POST /api/v1/rbac/remove-role`, which 404s because the route was never
> registered. Under `storage.type: remote`, this meant the legitimate
> break-glass revoke flow could never complete at all when a role grant was
> still live — and the raw storage proxy
> (`POST /api/v1/system/break-glass/{id}/revoke`), independently reachable by
> anyone holding `system.write`, was the only path that succeeded, doing so
> without removing the underlying role grant or writing an audit event.
>
> Fixed at the proxy layer directly (2026-08-25): it now performs the role
> removal and audit write itself, inline, rather than relying on the missing
> route. But the missing route itself is still open and affects every other
> project-scoped `RemoveUserRole` caller under `storage.type: remote` (SSO
> deprovisioning, project-member removal, access-review revocation,
> invitation cleanup, the direct RBAC handler, the gRPC role service) —
> recommend prioritizing `/api/v1/rbac/remove-role` (and its mirror-image gap
> `/api/v1/rbac/assign-role`) ahead of the rest of this backlog.

**Escalation note**: consider whether #1511's severity/priority label should
change given this is no longer purely theoretical.
