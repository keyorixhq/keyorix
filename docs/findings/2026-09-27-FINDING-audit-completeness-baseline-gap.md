# FINDING: 62 of 192 catalogued mutating operations succeed with no audit trail

**Date:** 2026-09-27
**Component:** widespread — `internal/core/*.go` handler/service methods across
projects, users (gRPC), environments, folders, secret templates, sessions,
PATs, alert-escalation policies, admin jobs, compliance reporting,
notifications, and several auth flows. Full list: see
`server/faultops/audit_completeness_fuzz_test.go`'s
`knownUnauditedOperations` map.
**Status:** Closed as of F5 (2026-09-28), pending merge of PRs F2–F5 (all
opened, none merged as of this writing — the baseline map only reaches its
final shrunk state once all four land on `main`; see Closure table below).
Originally filed **NEEDS ANDREI** on 2026-09-27; picked up and worked as
Session F, items F2 through F5 (F1 was a prerequisite permission, unrelated
to this finding directly).
**Severity:** Was Medium (compliance/forensics gap, not an authorization
bypass or data-disclosure primitive) — broad: 62 of 192 (32%) of the
then-catalogued mutating operations. Reduced to 7 confirmed-intentional
exclusions (documented below) once F2–F5 merge.

## Closure

Each row is one PR against `server/faultops/audit_completeness_fuzz_test.go`'s
`knownUnauditedOperations` map — real gaps closed with a red/green-proofed
audit write, or reclassified as confirmed-intentional with a one-line reason
inline in the map. F2/F3/F4 figures are as reported by their own PR bodies at
push time (not independently re-verified from this branch — each is an
unmerged sibling branch this session cannot see); F5's figures are verified
directly against this branch's own build/test/fuzz runs.

| Item | PR    | Ops closed | Ops reclassified intentional |
|------|-------|------------|-------------------------------|
| F2   | #2246 | 6          | 0                              |
| F3   | #2247 | 14         | 0                              |
| F4   | #2249 | 16         | 0                              |
| F5   | (this PR) | 13     | 7                               |

61 baseline entries (as measured on this branch's own unmerged-`main` base)
→ 13 fixed directly by F5, 7 reclassified intentional by F5, the remaining
41 belong to F2/F3/F4's own branches. F5 leaves those 41 untouched in its own
copy of the map specifically to avoid duplicate/conflicting fixes across
independently-branched PRs — see each sibling's own PR for its removals.
**`TestAuditCompletenessCoverage` will report 0 unexplained gap entries only
once all of F2–F5 are merged to `main`** — not on any single branch alone,
since each branch is missing the other three's code. This is a merge-order
fact, not a discrepancy to chase further.

### F5's 13 fixed operations (red/green-proofed; see PR body for the full
red-proof transcript, 3 representative cases shown — an inline write, a
bulk-summary write, and the subtlest one, a no-op branch inside
`SetProjectMemberRole` that mirrors F4's own early-return-bypass class of bug):

- `REST DELETE /api/v1/secrets/{id}/schedule`
- `REST DELETE /api/v1/secrets/{id}/versions/{versionId}/comments/{commentId}`
- `REST POST /api/v1/access-requests/bulk-approve` (+ sibling `bulk-reject`, not in the original map but fixed alongside it)
- `REST POST /api/v1/auth/change-password`
- `REST POST /api/v1/projects/{id}/secrets/bulk-rotate`
- `REST POST /api/v1/projects/{id}/secrets/extend-expiring`
- `REST POST /api/v1/projects/{id}/secrets/reassign-owner`
- `REST POST /api/v1/projects/{id}/secrets/resume-all`
- `REST POST /api/v1/projects/{id}/secrets/suspend-all`
- `REST POST /api/v1/rejection-reason-templates`
- `REST POST /api/v1/secrets/{id}/versions/{versionId}/comments`
- `REST PUT /api/v1/projects/{id}/members/{userId}`
- `REST PUT /api/v1/secrets/{id}/schedule`

### F5's 7 confirmed-intentional exclusions (reasons inline in the map;
summarized here):

- `REST POST /api/v1/audit/migrate-chain-encoding` — dry run persists
  nothing by design (pre-existing test enforces this); only a real run is
  audited, and that path already was.
- `REST POST /api/v1/notifications/{id}/read`, `REST POST /api/v1/notifications/read-all`
  — personal UI state, no security-relevant effect.
- `REST POST /api/v1/projects/{id}/secrets/render` — already audits every
  resolved secret reference as a `secret.read` event; a template with zero
  references has nothing to audit.
- `REST POST /api/v1/secrets/{id}/rotation/simulate` — pure read-only
  diagnostic, never mutates state, no actor parameter.
- `REST POST /auth/refresh` — the security-relevant branch (reused/stolen
  token) is already audited via `EventSessionReuseDetected`; ordinary
  refresh is high-volume self-service, consistent with login success also
  not being audited.
- `REST POST /auth/password-reset` — a real reset for an existing account is
  already audited via delivery; unknown/blocked/SSO-external accounts are
  deliberately silent by anti-enumeration design, with abuse tracked by a
  separate rate limiter, not the audit log.

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

## Next steps — DONE (see Closure table above)

Worked as Session F, items F2–F5 (2026-09-28): per-handler `writeAuditEvent`/
standalone `Log*` method calls, not a middleware-level backstop — the
structural-fix-shape decision this doc originally deferred. The gRPC
user/project CRUD trio and the DELETE routes named above as highest-value
were F2's scope. Remaining follow-up, if any, is standard drift going
forward: when a new mutating operation is added to the op catalog with no
audit write, `FuzzAuditCompleteness` fails on it immediately (it is not
grandfathered into `knownUnauditedOperations` — that map only shrinks).

## Ledger

Add a row to `claude/2026-09-15-fuzzing-catches-ledger.md` (coordinator, per
FUZZ-MECH report) — `verification: manual` (no automated test can prove the
GAP is safe to leave open; the automated proof here is that the gap
currently exists and is bounded, tracked via this doc + the harness).
