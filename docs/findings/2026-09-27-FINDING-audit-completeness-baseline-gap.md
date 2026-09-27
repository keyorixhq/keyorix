# FINDING: 62 of 192 catalogued mutating operations succeed with no audit trail

**Date:** 2026-09-27
**Component:** widespread — `internal/core/*.go` handler/service methods across
projects, users (gRPC), environments, folders, secret templates, sessions,
PATs, alert-escalation policies, admin jobs, compliance reporting,
notifications, and several auth flows. Full list: see
`server/faultops/audit_completeness_fuzz_test.go`'s
`knownUnauditedOperations` map.
**Status:** Confirmed, reproducible via `FuzzAuditCompleteness`
(`server/faultops/audit_completeness_fuzz_test.go`, FUZZ-MECH M6). **Not
fixed** — filed **NEEDS ANDREI** (see Impact/Scope below for why).
**Severity:** Medium (compliance/forensics gap, not an authorization
bypass or data-disclosure primitive) — but broad: 62 of 192 (32%) of the
currently-catalogued mutating operations.

## Reproduction

`FuzzAuditCompleteness` runs every operation in `server/faultops`'s shared
op catalog (`opcatalog_test.go`, FAULTOPS-SPEED-owned, 192 entries as of
this writing) against a fresh world with no fault armed, and checks: does a
successful call write at least one new `AuditEvent` row? 62 operations do
not.

Spot-verified by reading source directly (not inferred from the fuzzer
output alone, per "verify before you report"): `core.DeleteProject`
(`internal/core/catalog.go`) calls `writeAuditEventFull` on exactly one
path — a dynamic-secret-cascade **failure** (`"dynamic_secret.project_cascade_failed"`)
— and nowhere else. A successful project deletion, the actual destructive
action, writes zero audit rows.

## Impact

Bounded to a **detection/forensics gap**, not an authorization bypass:
every operation's own RBAC/authority checks are unaffected — this finding
is purely about whether the ALLOWED, successful action leaves a record.
Concretely: an admin (or a caller in a role authorized to delete a
project, alert-escalation policy, session, PAT, secret template,
environment, etc.) can currently take that action with no entry in
`audit/logs`, `audit/search`, or `audit/rbac-logs` — closing an incident-
response/compliance trail an ISO 27001 / SOC 2-style audit would expect
for a destructive administrative action. `GRPC keyorix.v1.UserService.CreateUser`/
`UpdateUser` and `ProjectService`'s CRUD trio are the highest-severity
entries (user/project lifecycle via the gRPC surface); the `admin/jobs/*`
and `compliance/*` triggers are lower-stakes (on-demand re-runs of
scheduled, already-logged jobs) but still currently silent.

## Why NEEDS ANDREI, not a fix PR

62 call sites spanning roughly a dozen subsystems is a scope and
prioritization decision (which operations get a bespoke audit event now
vs. later, whether a generic "any successful mutating call gets a
baseline audit event" middleware-level backstop is the better structural
fix vs. per-handler `writeAuditEvent` calls, and whether any of the
lower-stakes entries — e.g. `notifications/{id}/read`, a self-service,
non-security-relevant action — are intentionally excluded from the audit
surface rather than an oversight) — not a "small, obvious" single-PR fix
this track is scoped to make unilaterally.

## What ships in this PR instead

`server/faultops/audit_completeness_fuzz_test.go`:
`FuzzAuditCompleteness`, asserting (a) a successful call always writes at
least one audit event UNLESS the operation is in the reviewed
`knownUnauditedOperations` baseline (dated, this finding, not silently
grown), (b) every new audit row's `Success` field agrees with what
actually happened, (c) the audit hash chain always still verifies.
`TestKnownUnauditedOperationsAreRealCatalogKeys` guards the baseline map
itself against drift (a stale/typo'd key silently doing nothing).
`TestAuditCompletenessCoverage` reports the current 62/192 split.

Red-proofed: temporarily removing one baseline entry
(`"REST POST /api/v1/users/"`) made the harness catch it immediately with
the expected violation message; restored and re-verified all 192 seeds
green.

## Next steps (for whoever picks this up)

1. Decide the structural fix shape (per-handler vs. a backstop mechanism).
2. Prioritize by severity — the gRPC user/project CRUD trio and the
   session/PAT/environment/secret-template DELETE routes are the
   highest-value closures.
3. As each is fixed, remove its entry from `knownUnauditedOperations` (the
   harness then asserts on it unconditionally) rather than leaving the
   baseline to rot.

## Ledger

Add a row to `claude/2026-09-15-fuzzing-catches-ledger.md` (coordinator, per
FUZZ-MECH report) — `verification: manual` (no automated test can prove the
GAP is safe to leave open; the automated proof here is that the gap
currently exists and is bounded, tracked via this doc + the harness).
