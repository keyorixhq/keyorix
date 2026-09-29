# FINDING: fuzz oracle's `presenceOnlyFields` enumeration missed the `*Meta`
sibling of every `*Enc` column, producing a false ORACLE (a) VIOLATION on MFA
enrollment

**Date:** 2026-09-29
**Component:** `server/faultops/snapshot_test.go` (`presenceOnlyFields`) —
test infrastructure only, no production code changed.
**Status:** Fixed, same PR as this finding doc.
**Severity:** None (not a security or correctness defect) — a false positive
in the fuzz oracle's own field-exclusion list, same class as the
already-documented `TokenPrefix` and `GetRoleByName` gaps in the same file.

## Summary

Session X's own 5-minute fuzz burst (see `reports/SESSION-X.md`, X1) surfaced:

```
op=REST POST /api/v1/auth/mfa/enroll fault=LogAuditEvent#1/error: ORACLE (a)
VIOLATION — reported SUCCESS but final state does not match the fault-free
reference run's state (partial/incorrect commit). Differing tables:
[AuditEvent MFASecret]
```

Reproduced red on current `origin/main` with `REPLAY_HEX=c179` (seed
`[]byte("\xc1y")`).

`internal/core/mfa.go`'s `BeginMFAEnrollment` writes `MFASecret` via
`storage.UpsertMFASecret` (its only mutating storage call), THEN emits the
`mfa.enrolled` audit event via `writeAuditEventFull` → `emitAudit` →
`storage.LogAuditEvent`. `LogAuditEvent` is already, repo-wide, best-effort:
`emitAudit`'s own doc comment says a write failure there is "surfaced loudly
instead of swallowing" (a `log.Printf("SECURITY: ...")` line, not a returned
error) — the same architectural guarantee `bestEffortTables["LogAuditEvent"]
= {"AuditEvent"}` in this fuzz harness already encodes and that the harness's
own `onlyOutcomeLogTables` branch generalizes ("every traced instance of
'reported SUCCESS, only AuditEvent differs' has turned out to be benign audit
content degradation... never a real business-state inconsistency").

So the *AuditEvent* half of the diff is expected and already handled. The
*MFASecret* half should not exist at all: the fault only targets
`LogAuditEvent`, which runs strictly after `UpsertMFASecret` has already
committed, so the `MFASecret` row's real content cannot depend on whether the
later audit write succeeds.

## Root cause: `SecretMeta` was never added to `presenceOnlyFields`

`MFASecret.SecretMeta` (`internal/storage/models/models.go:525`) is populated
by `c.encryptAuthSecret` → `encryption.Service.EncryptSecretWithAAD`
(`internal/encryption/service.go:328`), which JSON-marshals an
`EncryptionMetadata` struct (`internal/encryption/encryption.go:65`) into the
column. That struct embeds a random per-encryption `Nonce` **and** a
wall-clock `EncryptedAt` timestamp — both genuinely different on every run,
including between the fault-free reference world and the fault world, which
are two entirely independent bootstraps (`newFaultWorld` is called twice,
once per world — `fuzz_storage_fault_operations_test.go:342` and `:361`).

`presenceOnlyFields`' own doc comment says it was "derived by grepping
`internal/storage/models/models.go` for every field whose name ends in
Hash/Enc, or that holds WebAuthn credential material" — `SecretMeta` ends in
neither, so the grep never caught it, even though it is exactly as
nondeterministic as its own `SecretEnc` sibling (already listed) for the same
underlying reason. Confirmed by toggling `SecretMeta` into
`presenceOnlyFields` and re-running the identical `REPLAY_HEX=c179` input: the
diff reduces to `[AuditEvent]` alone, which the pre-existing
`acceptableByDesign`/`bestEffortTables` machinery already classifies
`ACCEPTABLE-BY-DESIGN`, with no other change anywhere.

This is the third instance of this exact enumeration-completeness failure
mode in this file (see `presenceOnlyFields`' `TokenPrefix` entry and
`opScopedBestEffortTables`' `GetRoleByName` entry for the first two) and the
fourth+fifth in this codebase overall per CLAUDE.md's running list — "An
enumeration is only as complete as the idioms it knows about."

## Why this is a harness bug, not a code bug

- `BeginMFAEnrollment` is not present in `docs/atomicity-exempt.tsv` and is
  not flagged by `TestAtomicityGuard_UnclassifiedMultiWriteFunction` (it
  makes exactly one `c.storage.<Write>` call, `UpsertMFASecret`; `GetUser` is
  a read) or by `TestAtomicityGuard_AuditBeforeWrite` (the audit call is
  textually and causally AFTER the storage write, the safe order this
  codebase already establishes elsewhere — e.g. the `AUDIT:D` entries for
  `bootstrapSystemLocked`/`completeInvitationAccept`, "audit only after the
  transaction has committed"). There is no atomicity gap to close here: the
  secret write and its audit event are already correctly independent,
  ordered the safe way, with the audit failure already loud
  (`log.Printf("SECURITY: ...")`) rather than silent.
- Per Session Z's Z1 instructions ("Decide... (a) enroll's secret write and
  its audit event must be atomic... or (b) audit is best-effort here and the
  MFASecret difference is something else... if you choose anything other
  than (a), justify it... and add the carve-out with a reason, not
  silently"): **(b)**, justified above — the MFASecret difference is not a
  real state divergence at all, it is this oracle gap. No code carve-out
  (e.g. an `atomicity-exempt.tsv` row) is needed because no guard currently
  flags `BeginMFAEnrollment` in the first place; the only thing to fix is the
  oracle's own field list.

## Widened the fix to the two sibling `*Meta` columns

`internal/storage/models/models.go` has two other `*Meta []byte` columns with
the identical shape — the same `EncryptionMetadata` JSON, produced by the
same `c.encryptAuthSecret` helper: `AdminDSNMeta`
(`internal/core/dynamic_secrets.go:417`) and `CredentialMeta`
(`internal/core/dynamic_secrets.go:740`). Both added to `presenceOnlyFields`
alongside `SecretMeta` in this fix rather than left for the next fuzz burst
to find one at a time (grepped `models.go` for `Meta \[\]byte` to confirm
these are the only three).

## Reproduction / regression

- `REPLAY_HEX=c179 go test ./server/faultops/... -run
  TestReplayStorageFaultInput -v`: red before this fix (`Differing tables:
  [MFASecret AuditEvent]`), green after (`ACCEPTABLE-BY-DESIGN: ... state
  diverges only in [AuditEvent]`).
- Corpus seed committed:
  `server/faultops/testdata/fuzz/FuzzStorageFaultOperations/mfa-enroll-secretmeta-oracle-gap-c179`
  (same bytes as the original discovery, for continuity with
  `reports/SESSION-X.md`'s own citation of this exact seed).
- Full `go test ./server/faultops/...`: pass, all pre-existing corpus entries
  (including the `SecretEnc`/`TokenPrefix`/`GetRoleByName` regression seeds)
  still pass unchanged — widening `presenceOnlyFields` did not mask anything
  else in the existing corpus.
- 5-minute indicative Mac fuzz burst (`-fuzz FuzzStorageFaultOperations
  -fuzztime 300s`): the MFA-enroll signature did not reappear. One new,
  unrelated signature surfaced — recorded, not fixed, out of this item's
  `internal/core` MFA/account/break-glass scope (`catalog.go` is on this
  session's MUST-NOT list):

  ```
  op=REST POST /api/v1/projects fault=WithTransaction#4/error: ORACLE (a)
  VIOLATION — reported SUCCESS but final state does not match the fault-free
  reference run's state (partial/incorrect commit). Differing tables:
  [Environment]
  ```

  The generated crasher corpus file was deleted from the local clone (not
  committed), same as Session X's own MFA finding was handled — flagging for
  the coordinator to route/add to the fuzzing-catches ledger.

## Tests

`go test ./server/faultops/...`: pass. `gofmt -l`, `go vet ./server/faultops/...`,
`golangci-lint run ./server/faultops/...`: clean (see PR body for tails).
`gosec` not run meaningfully against this package — `server/faultops`
contains only `_test.go` files, which gosec skips by design, and this fix
touches no production code.
