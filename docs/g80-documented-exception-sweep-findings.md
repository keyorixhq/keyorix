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
