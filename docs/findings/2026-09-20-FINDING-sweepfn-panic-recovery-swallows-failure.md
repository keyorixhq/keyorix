# FINDING: RotateDEKWithSweep reports SUCCESS after a mid-sweep panic, promoting the new DEK while rows stay under the wiped-and-discarded old one

**Date:** 2026-09-20
**Component:** `internal/encryption/service_rotation.go` (`Service.RotateDEKWithSweep`'s
`sweepFn` closure) and `internal/encryption/keymanager_rotation.go`
(`KeyManager.RotateDEKWithSweep`)
**Status:** **Fixed.** `sweepFn` now has a named `error` return, set inside
its deferred `recover()` — see "Fix implemented" below. Closure proven by
`TestRotateDEKWithSweep_PanicMidSweepDoesNotPromoteOrWipe`
(`internal/encryption/sweepfn_panic_recovery_test.go`), red-proofed both
directions (fails without the fix, passes with it).
**Severity: High impact / Low likelihood** — see "Severity: what can actually
panic here" below for the concrete basis of "low," not an unsupported claim.

Found while proving/disproving a specific question posed for the
`test/durability-fuzz-postgres-world` task ("if a panic mid-transaction
leaves a Postgres connection in an aborted state, is that real"). The
confirmed defect is **not** the hypothesized Postgres-connection-pool
issue — it reproduces identically on SQLite — see "What this is NOT" below.

- **Impact:** once triggered, **every row the sweep hasn't already
  re-encrypted becomes permanently, unconditionally undecryptable** — the
  active `dek.key` file is promoted to the NEW DEK for real, the OLD DEK's
  only in-memory copy is wiped, and the OLD DEK's on-disk backup files are
  deleted, all while the DB rows remain encrypted under that now-destroyed
  OLD DEK (the sweep's own transaction was rolled back). No cryptographic or
  operational recovery path survives this — same severity class as
  `2026-09-19-FINDING-kek-rotation-rename-dek-cleanup-dataloss.md`, and
  arguably a simpler trigger: that finding required a specific ambiguous
  rename-then-error filesystem race; this one requires only that a Go panic
  (not a returned error — those are already handled correctly) occurs
  anywhere between `tx.Begin()` and `tx.Commit()` inside the sweep.
- **Likelihood: Low** — see "Severity" section below. The most obvious
  candidate trigger (a Go crypto-library panic) is already explicitly
  guarded against elsewhere in this same package; the residual risk is a
  generic, non-specific ORM/driver-internal-panic class that applies
  equally to every other GORM call site in this codebase, not something
  elevated by this code path specifically.

## Summary

`Service.RotateDEKWithSweep` (`service_rotation.go:36`) built a `sweepFn`
closure with this shape (pre-fix):

```go
sweepFn := func(oldSvc, newSvc *EncryptionService, newKeyVersion string) error {
    tx := db.Begin()
    if tx.Error != nil {
        return fmt.Errorf("failed to begin transaction: %w", tx.Error)
    }
    defer func() {
        if recover() != nil {
            tx.Rollback()
        }
    }()

    result, err := SweepAllTables(tx, oldSvc, newSvc, newKeyVersion, false)
    if err != nil {
        tx.Rollback()
        return fmt.Errorf("sweep failed: %w", err)
    }
    ...
    if err := tx.Commit().Error; err != nil {
        return fmt.Errorf("failed to commit sweep transaction: %w", err)
    }
    ...
    sweepResult = result
    return nil
}
```

`sweepFn`'s return type was a plain, **unnamed** `error`. Go's panic/recover
semantics: when a deferred function recovers a panic, the function that
panic unwound into (`sweepFn`, via its own `defer`) returns normally, with
its return values equal to whatever they were set to at the point of the
panic — for an unnamed return that was never explicitly assigned, that is
the **zero value**. So if `SweepAllTables` (or anything else between
`tx.Begin()` and `tx.Commit()`) panicked, the deferred `recover()` rolled
the transaction back correctly, but `sweepFn` itself then returned `nil` —
not an error — to its caller.

Its caller, `KeyManager.RotateDEKWithSweep` (`keymanager_rotation.go:103`):

```go
if err := sweepFn(oldEncSvc, newEncSvc, newKeyVersion); err != nil {
    wipeBytes(newDEK)
    _ = os.Remove(filepath.Join(km.baseDir, pendingDEKPath))
    return fmt.Errorf("re-encryption sweep failed — old DEK remains active: %w", err)
}
// ... proceeds normally ...
```

saw `err == nil` and took the SUCCESS branch — exactly the one the comment
above it says only runs when the sweep actually committed. It:

1. Renamed `dek.key.pending` → `dek.key` for real (line 116) — the new DEK
   became active.
2. `wipeBytes(km.currentDEK)` (line 132) — the OLD DEK's only in-memory copy
   was destroyed.
3. `km.currentDEK = newDEK` (line 133).
4. `km.deleteBackupFiles()` (line 136) — deleted every `dek.key.backup.*`
   file, which is where an old DEK's wrapped material would otherwise still
   exist on disk.
5. Logged `"✅ DEK rotated and full re-encryption sweep complete."` —
   literally claiming success.

Meanwhile the DB transaction that was supposed to re-encrypt every row was
rolled back by the recover — the rows were exactly as they were before the
rotation started: encrypted under the OLD DEK. That DEK no longer existed
anywhere.

## What already works (so this isn't a broader "the sweep is unsound" claim)

A normal `error` returned from `SweepAllTables` (e.g. a decrypt failure, a
missing project mapping, a normal DB error from a `.Error` field) was
already handled correctly: `sweepFn`'s own `if err != nil { tx.Rollback();
return fmt.Errorf(...) }` (the `"sweep failed: %w"` branch) propagates a
real error, and `KeyManager.RotateDEKWithSweep`'s `if err != nil` branch
correctly aborts, cleans up the pending file, and leaves the old DEK active.
This is exactly what `FuzzDEKSweepCrashConsistency`'s existing crash
checkpoints prove, and that proof is not invalidated by this finding — none
of those checkpoints panic; they only interrupt between already-durable
steps. This finding is specifically about the **panic** path, which no
existing test (fuzzer or otherwise) exercised — see "Reachability" for why.

## Reachability: why no existing test caught this

`FuzzDEKSweepCrashConsistency`'s four crash checkpoints
(`sweep:after-write-dek-pending`, `sweep:after-sweep-commit`,
`sweep:after-rename-dek`, `sweep:after-syncdir`, `keymanager_rotation.go`)
are placed strictly **before** `sweepFn` is called or strictly **after** it
has already returned — never while `sweepFn`'s own transaction is open.
Grepped every `rotationCheckpointHook`/`rotationCheckpoint(` call site in
`internal/encryption`'s production code (`keymanager_rotation.go`,
`keymanager_kek_rotation.go`, `keymanager_rewrap.go`) — confirmed none fire
from inside `SweepAllTables` or between `tx.Begin()`/`tx.Commit()`. So no
amount of running that fuzzer longer would ever have found this: it
structurally cannot inject a panic at the one point that matters.

Also checked every OTHER existing test exercising `RotateDEKWithSweep`'s
failure paths (`TestRotateDEKWithSweep_SweepErrorKeepsOldDEK`,
`TestKeyManager_RotateDEKWithSweep_SweepFnError(Cleanup)`,
`TestRotateDEKWithSweep_RollbackOnError`, and siblings) — every one
simulates failure via a **genuinely returned error** (either a fake
`sweepFn` that does `return sweepErr` directly, or `db.Migrator().DropTable(...)`
making a real GORM query fail), never a panic. All of these go through the
`if err != nil { tx.Rollback(); return ... }` branch, which was never
broken by this bug and is unaffected by the fix — none of these tests were
"passing for the wrong reason."

## Does PR #1918's redo-marker recovery still hold under this bug?

**Yes — #1918's mechanism (`RecoverInterruptedRotation`, the write-ahead
redo marker in `system_metadata`) is entirely unaffected by this bug. This
is a genuinely new, third failure mode, not a case of an earlier fix resting
on a wrong assumption.** Traced deliberately because the two mechanisms
look adjacent (same function, same transaction, same "does the sweep really
commit" question) — they turn out to be answering different questions about
different failure classes:

- **#1918's fix is about a real OS-level process crash** (power loss,
  SIGKILL, OOM) landing in the window **after** `sweepFn` has already
  returned successfully but **before** `KeyManager.RotateDEKWithSweep` has
  renamed `dek.key.pending` → `dek.key`. Its own commit message scopes it
  exactly this way, and its own red-proof (disabling the recovery
  promotion, watching `FuzzDEKSweepCrashConsistency` fail again at
  `sweep:after-sweep-commit`) exercises a checkpoint that fires from
  `keymanager_rotation.go` **after** `sweepFn` has already returned — a
  completely different code path from `sweepFn`'s own internal
  `defer`/`recover`.
- **This finding is about a Go-level panic recovered *within a single,
  otherwise-healthy process*, before `sweepFn`'s transaction ever commits.**
  The process never crashes; `RotateDEKWithSweep` runs to completion (from
  its own caller's point of view) in one continuous execution. Because of
  that, `RecoverInterruptedRotation` — a **startup-only** function, called
  by a **fresh process** at boot, checking **durable DB state** — is never
  invoked at all in this bug's manifestation. It has no opportunity to be
  fooled by it, correctly or incorrectly.
- Traced the actual DB-state consequence directly: in this finding's
  reproduction, the panic fires from inside `sweepSecretVersions`'s
  per-row loop, which runs **before** the redo-marker's own
  `tx.Clauses(clause.OnConflict{...}).Create(&models.SystemMetadata{...})`
  line even executes. The whole transaction — rows AND marker, whichever
  of either had been attempted — rolls back together. A fresh process
  reading `system_metadata` afterward would find **no marker at all**,
  which is exactly the state `RecoverInterruptedRotation` already handles
  correctly (marker absent ⇒ discard any stray pending file, old DEK stays
  active). The redo-marker invariant the #1918 fix documents — "marker
  durable ⇒ new DEK durably present" — is never violated by this bug,
  because a panic before commit can't produce a durable marker without also
  producing the durable DEK file state it implies.
- The one theoretically adjacent sub-case — a panic occurring **after**
  `tx.Commit()` has already returned successfully (e.g. in the `log.Printf`
  call or the final `sweepResult = result` assignment) — was also checked:
  in that sub-case the transaction (rows + marker) is ALREADY durably
  committed regardless of what happens next, so `sweepFn` returning `nil`
  via the swallowed panic is, by coincidence, the CORRECT return value
  there. This sub-case was not a source of a wrong verdict either way,
  fixed or not — it's only the pre-commit window that matters, and that's
  exactly what this finding and its regression test target.

Conclusion: this is a **third, independent rotation bug**, not a
reinterpretation of #1918. #1918's own claims and its own red-proof remain
accurate and unaffected.

## Adversarial reproduction

Minimized and verified via a standalone scratch test (deleted after
verification, not committed — same red-proof discipline as
`2026-09-19-FINDING-kek-rotation-rename-dek-cleanup-dataloss.md`'s own
reproduction script), then re-verified permanently by the committed
regression test this fix ships with
(`sweepfn_panic_recovery_test.go`, `TestRotateDEKWithSweep_PanicMidSweepDoesNotPromoteOrWipe`).
Method: register a GORM `Before-Update` callback (same technique
`fault_injected_operations_fuzz_test.go`'s `armSQLFault` already uses for
error injection — zero other production code changes) that `panic()`s
instead of `AddError`s, on the first UPDATE `SweepAllTables` issues against
`secret_versions` — i.e. while `sweepFn`'s transaction is open. Calls the
REAL `Service.RotateDEKWithSweep`, not a reimplementation.

Pre-fix, on both SQLite and PostgreSQL (same result both times):

```
✅ DEK rotated and full re-encryption sweep complete. New version: v1789924210
FINDING: RotateDEKWithSweep returned err=nil after a mid-transaction panic
(result=<nil>) -- sweepFn's recover() swallows the panic AND the failure,
per its unnamed error return.
```

Confirmed the seeded row's `secret_versions.encrypted_value` was unchanged
(the sweep transaction really was rolled back — not a partial-commit
issue), and confirmed the connection/DB handle itself remained perfectly
usable afterward on both backends (a follow-up `Count()` query succeeded
cleanly) — so **the specific "pooled Postgres connection left aborted"
hypothesis this investigation started from is NOT what's happening**; the
defect is a pure Go control-flow bug in `sweepFn`'s unnamed-return +
`recover()` interaction, present identically regardless of backend.

## What this is NOT

- **Not** a Postgres-specific connection-pool corruption. `db.Model(...).Count(...)`
  immediately after the swallowed panic succeeded cleanly on both backends —
  no "current transaction is aborted" error, no stuck connection. Go's
  `database/sql` pool and GORM's `Rollback()` both behaved correctly; the
  transaction really was cleanly rolled back. The bug was entirely in what
  `RotateDEKWithSweep`'s CALLER did with the (incorrectly nil) return value.
- **Not** something `FuzzDEKSweepCrashConsistency`'s existing red-proofs
  cover or contradict — that fuzzer's own checkpoints and this finding's
  panic-injection point are disjoint by construction (see "Reachability").
- **Not** a reinterpretation of PR #1918 — see the dedicated section above.

## Severity: what can actually panic here (not the injected fault)

The injected fault (a GORM callback that calls `panic()` directly) proves
the *code path* is unsound; it says nothing on its own about how a REAL
panic would arise in production. Went through `SweepAllTables` and its
per-table sweepers (`sweepSecretVersions` and siblings in `sweep.go`/
`sweep_auth.go`) and the encryption primitives they call, looking for
concrete panic sources — not to inflate or deflate the finding, but to
state plainly what's actually there:

- **Go crypto AEAD nonce-length panic — checked, already mitigated.** The
  single most well-documented Go stdlib panic in this exact area:
  `cipher.AEAD.Open`/`.Seal` panic (not error) on a wrong-length nonce.
  `EncryptionService.Decrypt` and `DecryptWithAAD` (`encryption.go:162`,
  `:265`) — the functions `sweepSecretVersions` calls to decrypt each row
  under the old DEK — both already have an explicit, commented guard:
  `if len(nonce) != es.gcm.NonceSize() { return nil, fmt.Errorf(...) }`
  BEFORE calling `gcm.Open`, with a comment citing this exact hazard
  ("gcm.Open PANICS on a wrong-length nonce ... guard it as an error").
  `Seal` is never at risk here — its nonce is always freshly generated at
  the correct size immediately before use. **This is the most plausible
  concrete trigger, and it is already closed** — not by this fix, by
  pre-existing code this investigation happened to re-verify.
- **JSON marshal/unmarshal — not a panic source here.** `DeserializeEncryptedData`
  (`json.Unmarshal`) and the metadata `json.Marshal` call in
  `sweepSecretVersions` both return errors for malformed/incompatible data
  under normal Go semantics; none of the types involved (fixed structs, no
  channels/functions/cyclic references) can trigger the exotic
  `json.Marshal` panic cases (unsupported type, cyclic pointer structure).
- **Nil pointer / index / type-assertion panics — none found in the sweep's
  own code.** Read `sweepSecretVersions` end to end: the `nodeProjectMap`
  lookup already returns an error (not a panic) on a miss; no unguarded
  pointer dereferences, slice indexing, or type assertions in the
  re-encrypt loop or the per-table sweepers.
- **Residual, unclosed risk: a GORM/database-driver internal panic.**
  Go SQL drivers and reflect-based ORMs have historically had rare panic
  reports on adversarial or corrupted low-level conditions (unexpected
  column shape, a scan-target type mismatch). This is a real, non-zero
  category, but it is **not specific to or elevated by this code** — it
  applies equally to every other `*gorm.DB` call site in this entire
  codebase, of which there are hundreds. No driver-source audit was
  performed here (out of scope for this fix); this is named as the
  genuinely open residual category, not swept under "unlikely."
- **NOT part of this bug's surface: true OOM / stack overflow.** Go's
  runtime `fatal error` conditions (genuine out-of-memory, stack overflow)
  bypass `recover()` entirely and crash the process outright — they cannot
  be caught by `sweepFn`'s defer, so they are not a trigger for THIS
  specific silent-success bug (they would instead surface as an actual
  process crash, which IS covered by #1918's mechanism).

**Conclusion:** the most likely concrete trigger for a real panic in this
location was already closed by pre-existing code, independent of this fix.
The residual risk is a generic, low-specificity category shared by the
entire codebase's GORM usage, not something this code path makes more
likely than any other write path in the system. This supports **Low
likelihood** — not "impossible" (the `recover()` exists because SOME panic
is anticipated as possible, and if it's worth catching, it's worth catching
correctly), but not an elevated or code-specific risk either.

## Fix implemented

`sweepFn` (`service_rotation.go`) now has a **named** return, set inside the
recover:

```go
sweepFn := func(oldSvc, newSvc *EncryptionService, newKeyVersion string) (err error) {
    tx := db.Begin()
    if tx.Error != nil {
        return fmt.Errorf("failed to begin transaction: %w", tx.Error)
    }
    defer func() {
        if r := recover(); r != nil {
            tx.Rollback()
            err = fmt.Errorf("re-encryption sweep panicked: %v", r)
        }
    }()
    ...
}
```

No other change was needed: `KeyManager.RotateDEKWithSweep`'s existing
`if err := sweepFn(...); err != nil { wipeBytes(newDEK); os.Remove(pending);
return ... }` branch was already correct — it simply never got a chance to
run before, because `sweepFn` always reported `nil` on a panic. The
`result, err := SweepAllTables(...)` line inside `sweepFn`'s body correctly
reuses the named `err` (same-block short-variable-declaration rule: `result`
is new, `err` is not, so it's reused, not shadowed) — its own existing
`if err != nil { tx.Rollback(); return fmt.Errorf(...) }` branch is
unaffected by this change and continues to work exactly as before.

### Same code shape elsewhere (not independently fixed here, flagged only)

Two more `defer func(){ if recover() != nil { tx.Rollback() } }()` sites in
the same file, `service_rotation.go`, both wrapping functions with unnamed
`error` returns — NOT fixed in this PR (out of scope; flagged for a
follow-up):

- `PreviewRotationSweep` (~line 171): lower impact — this function already
  has an UNCONDITIONAL `defer tx.Rollback()` ahead of the recover-based one
  (it's a read-only dry run that never commits regardless), so a swallowed
  panic here means the preview silently returns `(nil, nil)` instead of an
  error — a caller-visible correctness gap (an empty/wrong preview reported
  as success), not a data-loss one, since nothing is ever written either
  way.
- `UpgradeAuthAAD` (~line 212): same shape as the main finding (commits on
  success, no unconditional rollback), but the operation itself re-encrypts
  under the SAME DEK (no key material is destroyed or promoted) and is
  documented as idempotent/safe-to-re-run — so a false "success" here means
  the AAD upgrade silently didn't happen and would need a subsequent run to
  actually apply, not a permanent loss.

### Red-proof

Verified both directions with `TestRotateDEKWithSweep_PanicMidSweepDoesNotPromoteOrWipe`
(`sweepfn_panic_recovery_test.go`):

- **Without the fix** (unnamed return restored via a temporary local
  revert): test fails — `RotateDEKWithSweep` returns `(nil, nil)`, prints
  its success banner, exactly reproducing this finding.
- **With the fix**: test passes — `RotateDEKWithSweep` returns a non-nil
  error containing `"panicked"`, the active DEK is unchanged, no
  `dek.key.pending` remains, and the row's ciphertext is byte-for-byte
  unchanged.

Also reran the full existing sweep-related suite
(`TestRotateDEKWithSweep_*`, `TestUpgradeAuthAAD_*`,
`FuzzDEKSweepCrashConsistency`'s seed corpus) — all green, no regressions;
none of those tests exercise the panic path this fix touches (see
"Reachability" above), so none of their pass/fail status changed.
