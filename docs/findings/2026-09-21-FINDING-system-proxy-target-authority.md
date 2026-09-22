# FINDING: `/api/v1/system` proxy routes missing the caller-authority ceiling their human-facing equivalents already require

**Date:** 2026-09-21
**Component:** `server/http/handlers/*.go` (the RemoteStorage `/system` proxy
layer, `server/http/router.go`'s `r.Route("/system", ...)` block),
`internal/core/*.go` (the reused/added authority-check wrappers).
**Status:** **10 of 11 findings fixed** on branch
`fix/system-proxy-target-authority` (based on `origin/main` `bb93b549`), each
with its own commit, a red-before/green-after regression test, and a control
case proving a properly-authorized caller still succeeds. One finding
(`MarkTOTPStepUsedProxy`) is **filed open, not fixed** — see its entry below
for why. Proving tests: `server/http/system_write_ceiling_walk_test.go`
(`TestSystemWriteOnlyCeilingWalk`, a `chi.Walk`-driven ratchet over every
mutating `/api/v1/system` route) plus a dedicated `TestSystemWriteCeiling_*`
row per finding, and (for F5)
`server/http/users_active_transition_proxy_ceiling_test.go`.

## Summary

Every route under `/api/v1/system` is gated by one blanket permission,
`system.write` (`server/http/router.go`: `r.Use(customMiddleware.RequirePermission(permSystemWrite))`).
That gate is deliberately broad by design — `system.write` is documented as
grantable to a narrow, unrelated custom role (audit checkpoints, legal holds,
risk exceptions, SoD policies, admin job triggers), not an admin-only
permission. The majority of `/system` routes correctly rely on that blanket
gate alone (confirmed route-by-route below and in the walk's own allowlist).
**Eleven routes did not**: their real, human-facing equivalent requires a
DIFFERENT, narrower permission (`users.write`, `roles.assign`, `secrets.write`
— always scoped to a specific project/environment/secret where the
human-facing route scopes it), and the `/system` proxy route silently
accepted the broader `system.write` alone as sufficient. A principal holding
`system.write` for its documented, narrow, unrelated purpose could reach
every one of these eleven routes and do something the human-facing RBAC
model never intended to grant it.

This was found by direct code comparison (human-facing route's real
middleware/core-level check vs. the `/system` proxy's actual check), not by
trusting either the proxy handlers' own doc comments or two pre-existing test
registries (`server/http/raw_storage_bypass_guard_test.go`,
`server/http/node_credential_route_classification_test.go`) that had
independently verified a DIFFERENT property (CAS/data-invariant correctness,
or non-repudiation/audit attribution) and worded their "no-independent-ceiling"
conclusions in a way that read as an authority-equivalence claim without
actually being one. Two of the eleven (`TransitionSecretStatusProxy`,
`RevokeBreakGlassActivationProxy`) were specifically caught this way, after
an initial pass trusted the existing registry text and missed them.

## Findings, by severity

### F5 — `UpdateUserIfActiveStateMatchesProxy` (Critical, FIXED)

`PUT /api/v1/system/users/{id}/active-transition`. No ceiling beyond blanket
`system.write`. Reproduced live against `origin/main` `bb93b549` before the
fix: a `system.write`-only caller rewrote a global admin's email in one HTTP
call (200, email actually changed). The human-facing authority path is
`users.write` at global scope (`RequirePermission(permUsersWrite)` on
`PUT /api/v1/users/{id}`) — `core.UpdateUser` itself performs no
caller-authority check of its own; the HTTP transport is the real ceiling,
and this route's transport was the wrong (too broad) one.
**Fix:** `core.RequireUsersWriteAuthority` (new exported wrapper around the
existing `requireUserCredentialsRevokeAuthority`), called in the handler
before any storage read.

### `CreateSecretDependencyExclusiveProxy` (Medium, FIXED)

`POST /api/v1/system/secret-dependencies/exclusive`. No authority check on
either endpoint of the dependency edge — a `system.write`-only caller could
link any two secrets within one project+environment with zero `secrets.write`
ACL on either, bypassing per-secret ACL scoping (#G32) entirely. The
handler's own doc justified this with "the caller already ran
`AddSecretDependency`'s checks itself" — the same downstream-node-relay-trust
reasoning ADR-085 already found cannot hold anywhere in this codebase
(`validateRemoteStorageNotServer` rejects `storage.type: remote` for any
server process, so no such relay topology can exist). Impact is bounded to
metadata (dependency edges carry no secret values) and to rotation-wave
ordering (an attacker-created edge can defer/block a target secret's
scheduled rotation) — not a disclosure primitive.
**Fix:** `core.AuthorizeSecretPrincipal` (existing, already used by the
human-facing path) re-derived on BOTH `DependentSecretID` and
`DependsOnSecretID` before the write. Relay-trust doc comments corrected, not
just silenced.

### `TransitionSecretStatusProxy` (Medium-High for resume, FIXED, both directions)

`PUT /api/v1/system/secrets/{id}/transition-status`. No ceiling beyond
blanket `system.write`; human-facing `POST /secrets/{id}/suspend` and
`/resume` both require `RequireScopedSecretPermission(permSecretsWrite,
"id")`. **Suspend direction:** deny-of-read-access DoS. **Resume direction is
more serious**: suspension is a deliberate incident-response control
(`internal/core/secret_suspend.go`'s own doc: freeze a suspected-compromised
secret's value reads without deleting it); a `system.write`-only caller could
silently un-suspend a secret an admin froze for exactly that reason, with no
real-time signal the containment was reversed — undoing a security decision,
not just denying access. Suspension blocks only direct value reads, not
rotation or Connect federated sync (verified: zero suspend-awareness in
either).
**Fix:** `core.AuthorizeSecretPrincipal` re-derived on the target secret
before either direction of the transition.

### `UpdateAccessReviewItemProxy` (Medium-High, FIXED)

`PUT /api/v1/system/access-review-campaigns/items/{itemID}`. Had an
attribution check (must be an identifiable human) and a self-certification
check, but no `roles.assign` — the human-facing decision route requires
`roles.assign` scoped to the project. Not merely a record-keeping gap: a
"revoke" decision here actually removes the underlying role grant
(`core.DecideAccessReviewItem`'s `applyAccessDecision`), so a
`system.write`-only caller could approve or revoke real ISO 27001 A.5.18
access-review decisions — including revoking someone's real access — in any
project.
**Fix:** `core.RequireRolesAssignAuthority`, scoped to the item's own
campaign's project (fetched from storage, not trusted off the wire).

### `RevokeBreakGlassActivationProxy` (Medium, FIXED)

`POST /api/v1/system/break-glass/{id}/revoke`. Had only an attribution check
(`revokedBy := actorID(r); if revokedBy == 0 { refuse }`) — proves the caller
is a human, not that they hold authority. Human-facing revoke requires
`roles.assign` scoped to the project. A `system.write`-only caller could
silently revoke any project's active emergency-access grant, undoing another
admin's break-glass decision. Verified separately: no `/system` route can
CREATE/activate/extend a break-glass grant at all (`CreateBreakGlassActivationProxy`
was already deleted, G80 liveness sweep) — this is a revoke-direction-only
finding, not an escalation path.
**Fix:** `core.RequireRolesAssignAuthority`, scoped to the activation's own
project.

### `CreateGroupProxy` / `UpdateGroupProxy` / `DeleteGroupProxy` / `RestoreGroupProxy` (Low-Medium, FIXED)

`POST/PUT/DELETE /api/v1/system/groups(/{id})`, `POST .../restore`. Create/
Update/Delete had no caller-authority check (`actorID` used only for audit);
human-facing requires `users.write`. Restore had an admin-tier-only check
(`requireGlobalAdminToReinstateAdminRoles`, a deliberate no-op for a group
holding no admin-tier role) where the human-facing route requires
`roles.assign` unconditionally. **Investigated and ruled out as an
escalation path**: binding a role to a group (`AssignRoleToGroupWithExpiryProxy`)
and joining an admin-tier group (`AddGroupMemberProxy`) both already
independently re-derive `requireGranterHoldsRolePermissions` — no chain of
`/system`-only calls reaches admin-tier authority via groups. Impact is
organizational-namespace vandalism/disruption (create/rename/delete/restore
any group), not privilege escalation.
**Fix:** `core.RequireUsersWriteAuthority` (Create/Update/Delete),
`core.RequireRolesAssignAuthority` at global scope (Restore, layered under
the existing admin-tier-specific check — left as-is, a known,
accepted over-restriction for the admin-tier case, not a gap).
gRPC unaffected: `GroupGRPCService.CreateGroup/UpdateGroup/DeleteGroup/
RestoreGroup` (`server/grpc/services/group_service.go`) already call
`authorizeGlobal(ctx, s.core, actor, permUsersWrite)` /
`permRolesAssign` themselves, matching the human-facing HTTP gate exactly —
this fix closes the `/system` proxy's own gap only.

### `UpdateWebAuthnCredentialProxy` (Low-Medium, FIXED)

`PUT /api/v1/system/webauthn/credentials/{id}`. No ownership check — a
`system.write`-only caller could disable any OTHER user's passkey.
Investigated precisely: disabling a user's only WebAuthn credential produces
**full lockout, not MFA bypass or fallback to a weaker factor** — `Login`
gates on the static `user.WebAuthnEnabled`/`MFAEnabled` flags (not live
credential count), and this route never touches those flags, so
`BeginWebAuthnLogin` then refuses outright ("no passkeys registered"); TOTP,
if separately enrolled, still works. Availability/DoS via missing ownership
check, not authentication bypass.
**Fix:** self-service allowed with no extra check when the caller's own
`actorID` equals `body.UserID` (mirroring the existing self-service `DELETE
/auth/webauthn/credentials/{id}` route, gated on authentication only);
otherwise both `core.RequireUsersWriteAuthority` AND
`core.RequireEqualOrGreaterAdminAuthority` (new exported wrapper around the
existing impersonation admin-rank ceiling) against the target user, so a
lower-privileged `users.write` holder can't lock out a higher-privileged
admin's MFA.

### `ExpireSetupTokenProxy` (Low, FIXED)

`POST /api/v1/system/setup-tokens/{id}/expire`. No ceiling beyond blanket
`system.write`; sibling `CreateSetupTokenProxy` (minting) already requires
`users.write`. A `system.write`-only caller could mass-invalidate any user's
outstanding setup/password-reset/invitation-accept link by ID —
invitation/onboarding-denial DoS, not takeover.
**Fix:** `core.RequireUsersWriteAuthority`, same ceiling as the sibling
Create route.

### `UpdateInvitationProxy` (Low, FIXED)

`PUT /api/v1/system/invitations/{id}`. No ceiling beyond blanket
`system.write`; human-facing revoke (`DELETE /projects/{id}/invitations/{id}`)
requires `roles.assign` scoped to the project. Investigated precisely: this
route is a pure DB row flip (State/AcceptedAt/RevokedAt); nothing reads
`ProjectInvitation.State` to trigger a grant anywhere in the codebase (grep
confirmed zero hits) — the real accept flow is driven entirely by setup-token
consumption, which independently requires `State == pending` as its own
precondition (`setup_consume.go:174`) before doing anything. Forcing the
state via this route just burns the invitation before the real invitee can
use it — invitation-poisoning DoS, not escalation.
**Fix:** `core.RequireRolesAssignAuthority`, scoped to the invitation's own
project.

### `CreateAccessReviewCampaignProxy` / `CreateAccessReviewItemsProxy` (Low, FIXED)

`POST /api/v1/system/access-review-campaigns`, `POST .../{id}/items`. Same
gate mismatch as `UpdateAccessReviewItemProxy` above (`system.write` vs.
`roles.assign` scoped to project), but a freshly-opened, empty campaign or a
pending item confers nothing by itself — the real lever was
`UpdateAccessReviewItemProxy`'s decision path, fixed above. Fixed anyway for
consistency between the two surfaces.
**Fix:** `core.RequireRolesAssignAuthority`, scoped to the target project
(campaign create) or the campaign's own project (items create, fetched from
storage).

### `MarkTOTPStepUsedProxy` (Low, **FILED OPEN, NOT FIXED**)

`POST /api/v1/system/mfa/totp-step-used`. No ceiling beyond blanket
`system.write`, and no human-facing route exists to compare against — every
real core caller (`ActivateMFA`/`VerifyMFACredentials`/`verifyMFAStepUpCode`)
marks the step used only after verifying the CALLER's own TOTP code. A
`system.write`-only caller can burn an arbitrary OTHER user's next TOTP step,
forcing their legitimate code to be rejected as a replay — self-healing (TOTP
steps keep advancing) but a real, low-severity, per-login denial-of-service.

**A "self-only" fix (`actorID == body.UserID`) was implemented, then
reverted.** `TestConformance_MarkTOTPStepUsed`
(`server/http/remote_storage_conformance_tranche4_auth_security_test.go`)
proved the real caller shape for this route is a MACHINE/node credential
(`h.rs` in that test, authenticated via `createNodeToken`) acting on an
ARBITRARY human's `user_id` — a legitimate relay of that human's
already-verified TOTP check on the spoke side, not a human self-action.
Restricting to `actorID == body.UserID` broke that legitimate relay call
identically to how it would block the attack, because the check cannot tell
them apart: both are "a caller acting on a `user_id` that isn't its own."
Unlike this finding's ten siblings, no ceiling was found that both closes the
gap and preserves the legitimate relay shape. Filed open rather than shipping
a fix that breaks real traffic to close a low-severity gap. Left classified
`ALLOW` (reviewed, not independently ceiling-checked) in
`system_write_ceiling_walk_test.go`'s route table, with a pointer to this
document — not a "known-open" comment describing the exploit mechanism
in-line.

### `CreateAccessReviewItemsProxy` accepts an item body with no `principal_type`/`principal_id` validation (Low, NOT FIXED — documented only)

Found during the collateral-test audit for this branch, not part of the
original 11: `CreateAccessReviewItemsProxy` (`POST
/api/v1/system/access-review-campaigns/{id}/items`) decodes its body with a
plain `json.NewDecoder(r.Body).Decode(&body)` — no `DisallowUnknownFields`,
no post-decode validation of the decoded `accessReviewItemProxyWire` fields
before calling `storage.CreateAccessReviewItems`. Confirmed directly in
`access_review_campaigns_proxy.go`'s `CreateAccessReviewItemsProxy` (lines
365-411) and `models.AccessReviewItem` (`internal/storage/models/models.go`):
no gorm `not null`/validation tag on `PrincipalType`/`PrincipalID`/`Source`,
and `LocalStorage.CreateAccessReviewItems` persists whatever it's given with
no field checks.

Concretely: a caller (now gated by `roles.assign` at the campaign's project
scope, per this branch's own fix above) that sends an item shaped like the
*pre-fix* form of this route's own now-corrected test fixture —
`{"items":[{"user_id":1,"role":"viewer","decision":"pending"}]}`, using field
names the real struct never had — decodes with `PrincipalType`/`Source` as
empty strings and `PrincipalID` as `0` (Go zero values for the unset real
fields); the unrecognized `user_id`/`role` keys are silently dropped. That row
persists exactly as sent (`Decision` is separately force-reset to `pending`
regardless, per `ARC-004`) and would appear in `ListAccessReviewItemsProxy`/
`CountPendingAccessReviewItemsProxy` output as a blank-principal item stuck
permanently pending.

**Not an authority or data-corruption escalation**: both decision paths a
reviewer could apply to it are independently guarded and refuse a malformed
row outright — `AttestAccessReviewGrant` requires `d.Source != ""`
(`internal/core/access_review_revoke.go:204`) and
`RevokeAccessReviewGrant`/`revokeRoleByPrincipalType`/`revokeReviewShare`
require `d.PrincipalID != 0` plus a recognized `d.Source` value
(`access_review_revoke.go:124-141`), so a malformed item can never be
attested or revoked into acting on the wrong (zero-value) principal — it can
only sit permanently `pending`, a compliance-report data-integrity nuisance
(an uncertifiable phantom item), not a privilege or data-safety bug. Also
bounded by the caller-inventory finding above: `CreateAccessReviewItemsProxy`
has zero real in-tree callers today, so this is latent, not exploitable
through any current legitimate or attacker-reachable path in this codebase.
**Not fixed here**, per instruction — documented for whoever next touches
this handler (e.g. the follow-up route-deletion branch, since this route is
itself a delete candidate per the caller inventory).

## Route classification methodology (`TestSystemWriteOnlyCeilingWalk`)

`server/http/system_write_ceiling_walk_test.go` replaces
`system_write_ceiling_table_test.go` and `system_write_ceiling_table_users_test.go`
(which covered only the machine-identities/credentials/oidc-bindings group
and two users-credentials routes) with a `chi.Walk` over the router's actual
registered routes — not a hand-copied list, per this repo's own #1511/#1524
lesson that only a test-enforced list survives drift. Every mutating
(`POST`/`PUT`/`DELETE`/`PATCH`) route under `/api/v1/system` must be
classified in exactly one of:

- **`systemCeilingReadOnly`** — registered as a mutating method but performs
  no state change (one entry: `GetActiveMFAStepUpGrantProxy`, a `POST` that's
  actually a read).
- **`systemCeilingAllowlist`** — `system.write` alone is the reviewed,
  sufficient ceiling, with a one-line reason (~45 routes: no human-facing
  equivalent exists, the route's own core-level check already re-derives the
  right authority, or the check is genuinely self-contained and unrelated to
  caller identity).
- **`systemCeilingDenyChecked`** — a dedicated `TestSystemWriteCeiling_*`
  function sends a request as a `system.write`-only caller and asserts it is
  refused (25 routes: the 10 fixes above, plus 15 already-fixed rows ported
  from the two replaced files, unchanged in spirit).

A route in none of the three fails the walk outright — that failure IS the
ratchet: a new `/system` route cannot silently ship unreviewed. F5 and every
fixed gap above are listed identically to every already-fixed row — no
"known-open" marker, no in-code comment naming which ones were currently
exploitable before their fix commit landed.

## Red-proof

Each of the 10 fixes was verified by reverting it individually (git-level,
one commit at a time) and confirming its `TestSystemWriteCeiling_*` row goes
red, then restoring. See the PR's own CI history / commit sequence for the
per-commit red-before/green-after pairing; not reproduced narratively here to
avoid duplicating the walk file's own row-level documentation.
