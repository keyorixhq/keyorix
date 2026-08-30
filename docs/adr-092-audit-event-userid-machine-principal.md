# ADR-092: `AuditEvent.UserID` held a machine principal's raw ID at eight call sites — fixed at the choke point, not the call sites

## Status

**Accepted (2026-08-30).** #1626. Fix landed here; guard is the deliverable.

## What this is

#1530 added `AuditEvent.MachineIdentityID` alongside `UserID` specifically so a
machine-actored audit row could record WHICH machine acted, not just that a
machine did — and centralized the stamp at `emitAudit`, the single choke
point every audit writer funnels through, so the fix cost zero call sites.

#1626 is the same model's `UserID` column, the other direction: eight
`internal/core` call sites built `userID` from a `PrincipalID()`-derived
value (correct for `AuthorizePrincipal`, which needs the machine's real ID;
wrong for `UserID`, a human-attribution column) and handed it to
`writeAuditEventFull`/`writeAuditEventDiff`/`writeAuditEventFailed`. Found
during #1623's `PrincipalID()` sweep (PR #1625) and deliberately filed
separately — `AuditEvent` already has the discriminator #1623's persisted
model columns lacked, so this is a narrower, differently-shaped bug: every
affected row is still resolvable via `ActorType`/`MachineIdentityID`, just
carries a corrupt `UserID`.

## Task 1 — mechanism: pass-through, not bypass

Verified directly, not assumed: `writeAuditEvent` → `writeAuditEventFull` →
`writeAuditEventDiff` (and the parallel `writeAuditEventFailed`) all
construct `&models.AuditEvent{UserID: userID, ..., ActorType:
actorTypeFromContext(ctx)}` and call `c.emitAudit(ctx, event)` — every one of
them, no exceptions. All eight go through this correctly; none bypass it.
`TestDirectLogAuditEventCallersAreSafe` (#1530's existing guard) already
confirms `emitAudit` is the sole legitimate caller of `storage.LogAuditEvent`
repo-wide, with one unrelated allowlisted exception.

This is not "eight independent mistakes" in the sense of needing eight
independent fixes — it's the same mistake repeated eight times at the
boundary where a `PrincipalID()`-derived authorization value gets reused as
an attribution value, all funneling through one writer. That makes the fix
belong at the writer.

Confirmed safe to fix at `emitAudit` specifically (not just `writeAuditEvent*`)
by checking all six `emitAudit` call sites repo-wide: the two
`writeImpersonationEvent`/`writeImpersonationDeniedEvent` events
(`impersonation.go`) never set `ActorType` at all (defaults to `""`), and
`SetRetentionPolicy`/`AuditLicenseState` (`data_retention.go`, `service.go`)
hardcode `ActorTypeSystem`/`"system"`. None of the four ever produce
`ActorType == ActorTypeMachine`, so the fix's guard condition only ever fires
for the real bug.

## Task 2 — detectable, not silent, for all eight

`writeAuditEventDiff`/`writeAuditEventFailed` set `ActorType:
actorTypeFromContext(ctx)` — context-derived, independent of whatever
`userID` the call site passed. `emitAudit`'s `MachineIdentityID` stamp fires
on the identical `ActorType == ActorTypeMachine` condition, from the
identical context. All eight are reached through ordinary HTTP/gRPC routes
(real permission-gated requests, not an untagged background path), so
`ActorType`/`MachineIdentityID` were always correctly populated even before
this fix.

**All eight land in the self-contradicting, detectable bucket**:
`ActorType="machine_identity"` + `MachineIdentityID=<real machine ID>` +
`UserID=<the same real machine ID, misplaced>`. A consumer that checks
`ActorType` first — which any correct consumer must, `UserID` alone having
always been nil-vs-set ambiguous — never mistakes one of these for a genuine
human action. This is a materially different, better answer than #1623's:
these rows are identifiable as machine-actored and the acting machine is
still recoverable from `MachineIdentityID`. It is `UserID` specifically that
was corrupt, not the row's overall attributability. Do not overstate this —
identifying the row as bad is not the same claim as having a valid `UserID`.

## Task 3 — the fix and the guard

Fix: `emitAudit` (`internal/core/service.go`) now sets `event.UserID = nil`
unconditionally whenever `event.ActorType == ActorTypeMachine`, right
alongside the existing `MachineIdentityID` stamp. One correction, one place,
covering all eight current call sites and any future one — not a second
machine-actor field, not eight separate patches. This is the same "close the
path, don't patch the habit" move #1530 made for `MachineIdentityID` itself.

Guard: `internal/core/audit_userid_machine_principal_test.go`.
- `TestEmitAudit_MachineActorNeverGetsUserID` pins the choke-point invariant
  directly against `emitAudit`. Verified red by temporarily removing the
  `event.UserID = nil` line and confirming the mocked `storage.LogAuditEvent`
  call no longer matched (a raw machine ID surviving in `UserID`), then
  restored.
- `TestEmitAudit_HumanActorKeepsUserID` is the positive control: a
  human-actored event's `UserID` is untouched, `MachineIdentityID` stays
  nil — the fix is conditioned on `ActorType == machine`, not a blanket
  UserID-clearing rule.
- `TestAddSecretDependency_AuditEventUserIDNotMachinePrincipal` reproduces
  the bug end-to-end against one of the real eight call sites (not just
  `emitAudit` in isolation), with `ctx` tagged via `WithActorType`/
  `WithMachineActor` exactly as the real HTTP auth middleware
  (`buildRequestContext`) tags a machine-authenticated request — a bare
  `context.Background()` would not reproduce the real bug, since
  `AddSecretDependency`'s own `actorKind` parameter only drives
  `AuthorizeSecretPrincipal`, not the audit writer's context-derived
  `ActorType`/`MachineIdentityID`. Verified red the same way.

This is this campaign's fifth instance of "guard the invariant, not the
conclusion" (after #1494's DTO-shape guard, the `/system` proxy-layer sweep,
#1573's machine-global-scope-invariant guard, and #1623's per-model
discriminator pattern). It is the standing answer to "a completed fix with a
per-caller hole in it": fix and guard the choke point every caller already
funnels through, not the callers.

## Task 4 — relationship to #1623 / PR #1624

Same mechanism as #1623: `PrincipalID()` — correct for authorization, wrong
when reused as a human-attribution value — feeding a column with no
(#1623) or, here, an existing-but-bypassable (#1626) discriminator.

The `PrincipalID()` sweep in PR #1625 did not miss these eight — it found
them and deliberately filed them here rather than folding them into #1623,
specifically because `AuditEvent` already carries `ActorType`/
`MachineIdentityID` (landed by #1530), making this a narrower bug (a wrong
value at an established choke point) than #1623's (no discriminator field
existed at all, needing new columns and per-call-site threading). Confirmed
by re-reading PR #1625's own description, not assumed. Nothing to flag about
sweep coverage.

Fix order, as scoped: this before any #1623-adjacent follow-up, since
`AuditEvent` already has its target fields (`ActorType`/`MachineIdentityID`,
#1530) and needed no schema change — unlike #1623's models, which needed a
migration decision before any fix could land.

## The data question

Existing rows already conflate the two ID spaces on `AuditEvent.UserID` for
every event these eight call sites wrote while the caller was a machine
identity, and this cannot be disambiguated retroactively — the discriminating
information was never recorded on `UserID` itself. No production installs
exist yet; no backfill is possible or implied. Unlike #1623's persisted model
rows, though, these rows ARE flaggable as suspect without any backfill: any
row with `ActorType == "machine_identity"` and a non-nil `UserID` predates
this fix and is known-wrong in that one column, even though which `User.ID`
it accidentally collided with cannot be un-recorded.

## Verification

- `go build ./...`, `go vet ./...`, `gofmt -l .` clean.
- Full suite: `internal/core`, `internal/storage`, `server/http`,
  `server/grpc` green.
- Guard registry: `TestDirectLogAuditEventCallersAreSafe` (#1530's existing
  bypass guard) predicted unaffected (this fix doesn't add or remove any
  `storage.LogAuditEvent` caller) — confirmed green, unchanged allowlist
  (still 1 entry).
