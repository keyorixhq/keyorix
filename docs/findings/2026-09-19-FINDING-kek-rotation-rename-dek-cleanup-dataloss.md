# FINDING: KEK-rotation's rename-dek error cleanup can destroy the only DEK recovery path

**Date:** 2026-09-19
**Component:** `internal/encryption/keymanager_kek_rotation.go` (`commitNewKEKFiles`)
**Status:** Unfixed (finding only, per task scope — do not fix here)
**Severity: High** (a real, if narrow, permanent-DEK-loss path in a security-boundary
component — crypto/key material)

## Summary

`commitNewKEKFiles` persists a KEK-passphrase rotation via two coupled
write-pending → rename steps: `kek.salt.pending`/`dek.key.pending` are written
first, then `dek.key.pending` is renamed to `dek.key`, then
`kek.salt.pending` is renamed to `kek.salt`. This ordering is deliberate — the
code's own comment says a crash between the two renames leaves a documented,
recoverable "hazard window" (active `dek.key` new, active `kek.salt` old),
which an operator completes manually by renaming the leftover
`kek.salt.pending` into place.

The bug is in the error-handling branch for the **first** rename
(`keymanager_kek_rotation.go:159-163`):

```go
if err := durableRename(pendingDEKFull, activeDEKFull, "kek:rename-dek"); err != nil {
    _ = os.Remove(filepath.Join(km.baseDir, pendingSaltPath))
    _ = os.Remove(pendingDEKFull)
    return fmt.Errorf("rotate KEK: promote pending DEK to active: %w", err)
}
```

(`durableRename` here is this task's thin, nil-in-production fault-injection
wrapper around the real `os.Rename` — see `fault_hooks.go`; the underlying
`os.Rename` call and this surrounding error-handling are unchanged from the
pre-existing code.)

This cleanup **unconditionally deletes `kek.salt.pending`** — the file that a
completed-dek-but-incomplete-salt hazard window needs for recovery — on ANY
error from the rename call, without checking whether the rename actually
happened. That is correct when the rename genuinely did not happen (nothing
changed, so removing the leftover `.pending` files is tidy and safe). It is
**not** correct when the rename call reports an error despite having actually
renamed the file — a real, if rare, possibility: `rename(2)` returning an
error after the metadata change has already landed can happen on some
filesystems/storage backends under fault conditions (network filesystems
reporting a client-side timeout after the server-side rename already
committed; a transient I/O error surfaced after the underlying operation
completed). This is exactly the "rename error after the write is durable"
ambiguous fault class this task's fault-injection design was built to probe
(see `fault_injected_operations_fuzz_test.go`'s doc comment).

## Adversarial reproduction

Minimized and verified directly (not part of the committed fuzz corpus — see
"Why this isn't in the shipped fuzz target" below):

1. Seed a fresh `KeyManager` with `oldPass` (creates `dek.key` + `kek.salt`,
   generates DEK `dek0`).
2. Call `RotateKEKPassphrase(oldPass, newPass)` with the `kek:rename-dek` seam
   faulted to *actually perform* the real `os.Rename(dek.key.pending →
   dek.key)` and then still report an error (this task's
   `faultRealEffectThenError` fault kind, modeling the scenario above).
3. Observed: `RotateKEKPassphrase` returns a non-nil error, as expected
   (`rotate KEK: promote pending DEK to active: <injected>`).
4. Observed: `kek.salt.pending` is already gone — deleted synchronously by
   `commitNewKEKFiles`' own cleanup, *before* `RotateKEKPassphrase` even
   returns (not something a later startup step does).
5. Ran the real production startup step, `KeyManager.CleanPendingDEK()` — no
   effect either way (it only ever touches `dek.key.pending`, which was
   already renamed away for real in step 2).
6. Attempted recovery via the existing crash-consistency trilogy's own
   `recoverDEK` helper (`keymanager_crash_consistency_fuzz_test.go`), which
   tries: old passphrase against the active files, new passphrase against the
   active files, then applying the leftover `kek.salt.pending` if present.
   **Result: no recovery path succeeds.** `dek.key` on disk is wrapped under a
   KEK derived from `newPass` + a salt that no longer exists anywhere (it was
   never promoted to `kek.salt`, and its only other copy —
   `kek.salt.pending` — was just deleted). The DEK — and therefore every
   secret encrypted under it — becomes **permanently unrecoverable**.

Log excerpt from the verification run:

```
RotateKEKPassphrase reported (as expected, the ambiguous fault): rotate KEK: promote pending DEK to active: <injected>
confirmed: kek.salt.pending is GONE (deleted by commitNewKEKFiles' rename-dek error-cleanup path itself, synchronously, before RotateKEKPassphrase even returned — the bug)
CONFIRMED DATA LOSS: recoverDEK found no way to recover the DEK (original dek0=ce85328491dab4e275348c1e5a7f4add80c9b91b92fb4601d59136d4761039e0). Neither old-passphrase, new-passphrase, nor apply-pending-salt (file gone) works.
```

The reproduction script itself was a scratch file, deleted after verification
(not committed), per this task's red-proof discipline.

## Why this is a real, security-relevant bug and not a fuzz-harness artifact

- The fault type modeled (a rename call reporting failure after the change
  actually landed) is one of the exact three example fault/seam combinations
  the task's own directive named as needing sound "old-or-new, never a mix"
  handling — it is a documented, anticipated real-world failure shape, not an
  invented one.
- The code's OWN doc comment already acknowledges a closely related hazard
  window is expected and recoverable ("a crash between the two renames...
  The pending salt file allows the operator to complete the rename
  manually") — this finding shows the recovery mechanism the comment
  describes is itself deleted by the adjacent error path under a fault that
  lands one line earlier than the comment's assumed crash point.
- Contrast with the analogous cleanup in `RewrapDEK`
  (`keymanager_rewrap.go`), which only ever removes its OWN pending file
  (there is no second coupled file for that operation) — so the same fault
  shape applied to `rewrap:rename-dek` does **not** reproduce this bug class;
  this is specific to KEK-passphrase rotation's two-coupled-file design.

## Why this isn't in the shipped fuzz target's active corpus

`FuzzFaultInjectedOperations` (this task's new harness) is explicitly excluded
from selecting this exact (operation=KEK-rotate, seam=`kek:rename-dek`,
kind=ambiguous) combination — see `decodeFault`'s comment in
`fault_injected_operations_fuzz_test.go` — so the target stays usable (green
seed corpus, and undirected `-fuzz` won't immediately rediscover and get
stuck re-reporting the same known, filed bug on every run). This is a
deliberate scoping decision for a KNOWN, ALREADY-FILED finding, not a gap in
the harness's own coverage: every other seam/kind combination for KEK rotation
IS exercised, and this exact combination was found, minimized, and confirmed
via the reproduction above before being excluded.

## Suggested direction (not implemented — filing only)

The cleanup at `keymanager_kek_rotation.go:159-163` needs to distinguish "the
rename definitely did not happen" from "the rename may have happened despite
the reported error" before deciding whether `kek.salt.pending` is safe to
delete. One option: after a rename error, `os.Stat` the target path
(`activeDEKFull`) — if it now has the NEW content (e.g., compare against the
wrapped bytes just written), the rename actually succeeded and the function
should proceed down the SAME path `kek:after-rename-dek` already takes on
success (leaving `kek.salt.pending` in place and returning the informative
"DEK rename already succeeded — manually rename... to complete" error that
the `rename-salt` failure branch already uses), rather than deleting the
recovery artifact. This is a design/implementation decision for whoever picks
up the fix, not made here.
