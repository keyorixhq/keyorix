# ADR-092: `AuditEvent.UserID` held a machine principal's raw ID at eight call sites — fixed at the choke point, not the call sites

## Status

**Closed (2026-08-30).** #1626, fixed in #1628, independently re-verified
complete in a follow-up pass the same day (see "Verification pass" below) —
#1628's title ("emitAudit clears UserID") undersold its own scope: it also
correctly leaves `MachineIdentityID` populated and `ActorType` machine-typed,
and it reaches all eight call sites structurally (through the choke point),
not eight individual patches. Not an instance of #1573 (a cleared field with
nothing recorded) — the actor ends up correctly attributed, just via
`MachineIdentityID` instead of `UserID`.

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
rows, though, these rows ARE flaggable as suspect without any backfill, and
better than merely flaggable: **the true actor is recoverable, not just the
row's badness.** Directly verified (not assumed) against
`server/middleware/auth.go`'s `buildRequestContext`: `WithActorType(ctx,
ActorTypeMachine)` and `WithMachineActor(ctx, *userCtx.MachineIdentityID)`
are set together, unconditionally, for every machine-authenticated request —
so any pre-#1628 row from a real machine caller has all three of
`ActorType="machine_identity"`, `MachineIdentityID=<the real machine>`, AND
`UserID=<the same ID, misplaced>` simultaneously. Any row with
`ActorType == "machine_identity"` and a non-nil `UserID` predates this fix,
is known-wrong in that one column, and the correct actor is sitting right
there in `MachineIdentityID` on the same row — "we can identify these rows
AND recover the actor" is the accurate claim, stronger than "we can identify
these rows but not recover the actor."

**Detection query** (installs that ran between #1626's bug window and #1628's
fix):

```sql
SELECT * FROM audit_events
WHERE actor_type = 'machine_identity' AND user_id IS NOT NULL;
```

Every matching row's real actor is `machine_identity_id` on that same row;
`user_id` on a matching row should be treated as garbage and ignored, never
displayed as-is. This predicate is structurally unreachable for any row
written after #1628 landed (`emitAudit` clears `UserID` unconditionally the
instant `ActorType` is machine), so the query is self-limiting to the
historical window without needing a cutoff timestamp.

## Verification pass (2026-08-30) — is #1628 actually complete?

A follow-up pass re-verified this ADR's claims from the merged diff, not the
PR title or the closed issue, per standing practice. Three yes/no answers:

1. **Does the machine principal end up in `MachineIdentityID`, or only out of
   `UserID`? Both — populated into `MachineIdentityID` AND cleared from
   `UserID`.** `git show 9f3adc42 -- internal/core/service.go` shows the
   pre-existing #1530 `MachineIdentityID`-stamp logic untouched, now nested
   alongside the new unconditional `event.UserID = nil`. Not a narrowing —
   the original mechanism plus the new correction, in the same block.
2. **Is `ActorType` set to machine on those events? Yes**, and independently
   of the bug: `writeAuditEventDiff`/`writeAuditEventFailed`
   (`internal/core/audit.go`) set `ActorType: actorTypeFromContext(ctx)` from
   context, never from the call site's own (buggy) `userID` value.
3. **Did the fix reach all eight call sites, or only the ones routed through
   `emitAudit`? All eight — because all eight were already routed through
   `emitAudit`.** Directly grepped each of the eight functions'
   current bodies (`connect.go`, `rotation_executor.go`,
   `secret_ownership.go`, `users.go`, `secret_dependencies.go`): every one
   calls `writeAuditEvent`/`writeAuditEventFull`/`writeAuditEventDiff`/
   `writeAuditEventFailed`, none constructs `models.AuditEvent{}` directly.

**Task 2 — eight sites were wrong, not "the audit writer is optional."**
Confirmed: none of the eight construct `AuditEvent` directly. The original
diagnosis (a value-correctness bug at a converged choke point, not a bypass)
holds. No structural closure needed for the eight themselves.

**But the "audit writer is optional" question has a different answer at repo
scope, found during this pass — not among the eight, a separate discovery.**
`rg -n '\.LogAuditEvent\(' --type=go -g '!*_test.go'` across the whole repo
(not just `internal/core`, which is all #1530's original guard scanned)
found two direct callers the guard had never seen:
`server/main.go:auditConnectorProjectBindingCreate` and
`server/http/handlers/audit_ingest_proxy.go:IngestAuditEventProxy`. Both are
safe on inspection (first hardcodes `ActorType: system`, never sets
`UserID`; second is the `storage.type: remote` hub-side proxy, persisting an
event a follower's own `emitAudit` already corrected before serializing it
over the wire — a genuinely different trust boundary, `#G79`, already
tracked and deferred, not something #1626/#1628 was scoped to close). But
the OLD guard's own doc comment claimed "there is exactly one direct
caller" — true for `internal/core`, false for the repository. Widened to
walk the whole repo (see Guard, below) rather than leave a completeness
claim that was accurate only by accident of where it looked.

**One-sentence rule for #1573/#1623 to cite**: a machine principal's own ID
belongs in `MachineIdentityID` (or a model's `*MachineIdentityID` companion
field, #1573's shape) whenever it is being recorded as WHO acted, and must
never occupy a `UserID`/`CreatedBy`-shaped human-attribution column, even
though the identical `PrincipalID()` value is exactly what
`AuthorizePrincipal` correctly needs for the SAME request's authorization
decision — the two are different questions (who is allowed vs. who acted)
that happen to share a source value, and conflating them is the single
mistake #1573, #1623, and #1626 all trace back to.

**Guard — widened, verified red-first, twice, in this pass.**
`internal/core/g80_1530_machine_actor_attribution_guard_test.go`
(`TestDirectLogAuditEventCallersAreSafe`, #1530's original guard) now walks
the entire repository via `filepath.WalkDir` from repo root, not just
`internal/core`'s own directory — the allowlist grew from 1 entry to 3
(`anomaly.go`, `server/main.go`, `audit_ingest_proxy.go`), each with its own
reasoning. Verified red twice, by actually breaking things, not by
inspection:
- Reverted `emitAudit`'s `event.UserID = nil` line locally; confirmed
  `TestEmitAudit_MachineActorNeverGetsUserID` and
  `TestAddSecretDependency_AuditEventUserIDNotMachinePrincipal` both failed
  (a mocked `storage.LogAuditEvent` call no longer matched); restored;
  confirmed green again.
- Removed the new `audit_ingest_proxy.go` allowlist entry; confirmed
  `TestDirectLogAuditEventCallersAreSafe` failed, naming that exact
  `path:func`; restored; confirmed green again.

Positive control: `TestEmitAudit_HumanActorKeepsUserID` — a human-actored
event's `UserID` survives untouched and `MachineIdentityID` stays nil; the
fix is conditioned on `ActorType == machine`, not a blanket clear.

## Verification

- `go build ./...`, `go vet ./...`, `gofmt -l .` clean.
- Full suite: `internal/core`, `internal/storage`, `server/http`,
  `server/grpc` green.
- Guard registry: `TestDirectLogAuditEventCallersAreSafe` — predicted 3
  entries after widening to repo scope (1 pre-existing + 2 newly discovered,
  both safe); confirmed actual = 3, green.
