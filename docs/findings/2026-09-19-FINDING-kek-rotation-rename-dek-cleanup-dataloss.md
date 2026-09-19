# FINDING: KEK-rotation's rename-dek error cleanup can destroy the only DEK recovery path

**Date:** 2026-09-19 (reachability detail added 2026-09-19, same-day review)
**Component:** `internal/encryption/keymanager_kek_rotation.go` (`commitNewKEKFiles`)
**Status:** Unfixed (finding only, per task scope — do not fix here)
**Severity: High.** Impact when triggered: **every secret in the vault becomes
permanently undecryptable** — the DEK is wrapped under a KEK derived from a salt
that no longer exists anywhere on disk, and there is no cryptographic or
operational path back to it (see "Impact" below). Likelihood is deployment-
dependent and narrower than "any local disk error" — see "Reachability" below
for the precise trigger conditions, including why a directory-fsync (`SyncDir`)
error does **not** reach this path.

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
renamed the file.

## Reachability: exact trigger conditions

**Does a directory-fsync (`SyncDir`) error after a successful rename reach
this cleanup? No.** Trace of `commitNewKEKFiles` (`keymanager_kek_rotation.go:159-168`):

```go
if err := durableRename(pendingDEKFull, activeDEKFull, "kek:rename-dek"); err != nil {
    _ = os.Remove(filepath.Join(km.baseDir, pendingSaltPath))   // <- the buggy cleanup
    _ = os.Remove(pendingDEKFull)
    return fmt.Errorf("rotate KEK: promote pending DEK to active: %w", err)
}
// best-effort: this SyncDir's error is deliberately discarded ...
_ = securefiles.SyncDir(filepath.Dir(activeDEKFull))
```

The `SyncDir` call is a **separate statement that runs only after the `if
err != nil` block has already been skipped** (i.e., only on the success path
of the rename itself), and its own return value is discarded (`_ =`) —
it is never wired into the `if err != nil` condition and cannot cause that
branch to be taken. A directory-fsync failure at this point is silently
swallowed and `commitNewKEKFiles` proceeds normally to `kek:after-rename-dek`.
**So a local-disk EIO on the directory fsync does NOT trigger this bug** — it
triggers a different, separate, much lower-severity gap (an un-surfaced
`SyncDir` error — already noted in the code's own inline comment as
deliberate best-effort behavior, mirroring the SIEM-spool finding's shape but
not filed separately here since it has no data-loss consequence: the rename
itself, which is what actually matters for recoverability, already succeeded
by the time `SyncDir` runs).

The **actual** trigger is narrower and specific: `os.Rename` (inside
`durableRename`) itself must return a non-nil error despite having actually
applied the rename. `rename(2)` is documented as atomic on a single local
POSIX filesystem — under ordinary local disk I/O errors (EIO, ENOSPC) the
kernel is expected to either fully apply the metadata change or fully fail
without applying it, not both. The realistic, well-documented source of this
exact ambiguity is a filesystem whose operations are executed by a remote
server over a protocol with **at-least-once, non-transactional RPC
semantics**:

- **NFS** (v3 most clearly, and v4 under certain client/server recovery
  paths): a client issues a RENAME RPC; the server executes it and would
  reply success, but the reply is lost (network partition, server briefly
  unresponsive under load, a server reboot between executing the request and
  sending the response). The client's RPC layer times out and surfaces an
  error (`ETIMEDOUT`, `ESTALE`, or a similar I/O error depending on the
  client's mount options and recovery behavior) to the calling process —
  even though the rename already committed server-side. This is the classic
  "at-least-once RPC vs. non-idempotent operation" ambiguity NFS is
  documented to have; RENAME is not safely retryable/idempotent from the
  client's point of view (a retried RENAME of an already-renamed source
  fails with `ENOENT`, which client implementations do not uniformly
  distinguish from "never happened").
- The same class of ambiguity applies to any other client-server network
  filesystem with similar RPC semantics reachable as a POSIX mount — FUSE-
  backed network filesystems and various Kubernetes CSI drivers that proxy to
  network storage (e.g., NFS-backed `PersistentVolume`s, which are common and
  unremarkable in real K8s deployments) share the same characteristic.
- Checked: **Keyorix has no validation, restriction, or documentation
  anywhere in this repository (`docs/`, the encryption package, the CLI, the
  Helm chart) constraining what filesystem backs the key/data directory.**
  Grepped for "NFS"/"nfs" across `docs/`, `internal/encryption/`,
  `internal/cli/encryption/`, and chart/helm directories — no hits. An
  operator deploying Keyorix in Kubernetes with the key directory on an
  NFS-backed volume (a normal, unremarked-upon choice, not a misconfiguration
  the product warns against) is a realistic, currently-supported-by-omission
  deployment shape that can hit this exact ambiguity.
- A raw **local disk EIO exactly at rename-metadata-commit time** is a much
  less certain trigger for this specific ambiguity (most local journaling
  filesystems either fully apply or fully fail a rename transaction) — it is
  not ruled out on every possible local storage stack (e.g., a distributed
  block device presented as "local" disk, or unusual overlay/container
  storage driver edge cases), but it is not the well-documented case the way
  NFS is, and should not be cited as the primary trigger.

This is exactly the "rename error after the write is durable" ambiguous
fault class this task's fault-injection design was built to probe (see
`fault_injected_operations_fuzz_test.go`'s doc comment) — modeled precisely,
not the `SyncDir` path.

## Impact

Once triggered: `dek.key` on disk holds the DEK wrapped under a KEK derived
from `newPass` + the NEW salt. That salt was never promoted to `kek.salt`
(the second rename never got the chance to run), and its only other copy —
`kek.salt.pending` — was just deleted by the buggy cleanup. There is **no
remaining copy of the new salt anywhere**, so the new KEK cannot be
re-derived by any means (operator-known passphrase or otherwise), so the DEK
cannot be unwrapped, so **every secret in the vault encrypted under that DEK
is permanently undecryptable** — a full, unrecoverable data-loss event, not a
partial or single-secret one.

## Adversarial reproduction

Minimized and verified directly via a standalone scratch reproduction
(deleted after verification, not committed — see "How the shipped fuzz
target handles this" below for how the shipped harness itself now exercises
and tolerates this exact case):

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

## How the shipped fuzz target handles this: tolerated, not excluded

`FuzzFaultInjectedOperations` (this task's new harness) does **not** exclude
this exact (operation=KEK-rotate, seam=`kek:rename-dek`, kind=ambiguous)
combination from its decoder or seed corpus — it stays live, and both the
seed corpus and undirected `-fuzz` keep exercising it. `runKEKRotateFaultCase`
tolerates the failure ONLY when it exactly matches this finding's verified
signature (`isToleratedKnownOpenDataLoss` in
`fault_injected_operations_fuzz_test.go`):

1. seam is exactly `kek:rename-dek` (the only seam this bug class applies to
   — `RewrapDEK`'s analogous cleanup only ever removes its own pending file,
   so the same ambiguous fault at `rewrap:rename-dek` does not reproduce it,
   and is NOT tolerated there);
2. the fault kind is exactly `faultRealEffectThenError` (the deterministic
   `faultCleanError` case at the same seam is NOT tolerated — it is expected,
   and asserted, to recover cleanly via the old passphrase, per
   `expectedKEKVia`);
3. `kek.salt.pending` is confirmed **absent** on disk — the direct,
   checkable fingerprint of the buggy cleanup having actually run (it is the
   exact file that cleanup deletes). If it's still present, the failure has
   some OTHER cause and is treated as fatal, not tolerated.

Any recoverDEK failure that doesn't match all three conditions still fails
the test loudly — a regression that made this bug WORSE (e.g., started
corrupting `dek.key` itself, not just deleting `kek.salt.pending`), or a
wholly different bug at a different seam, is not masked by this tolerance.
Verified directly: temporarily forcing `isToleratedKnownOpenDataLoss` to
always return `false` makes the known case fail with the original `DATA
LOSS: no recovery yields the DEK after kek-rotate fault "kek:rename-dek"`
message again (red-proof; not committed), and the deterministic
`faultCleanError` case at the same seam (seed \#22) was independently
confirmed to pass via the normal `old-passphrase` recovery path without ever
reaching the tolerance branch (positive control — the tolerance is narrowly
scoped, not a blanket allowance for this seam).

## Suggested fix (drafted, not implemented — filing only)

The cleanup at `keymanager_kek_rotation.go:159-163` needs to distinguish "the
rename definitely did not happen" from "the rename may have happened despite
the reported error" **before** deciding whether `kek.salt.pending` is safe to
delete — it must never delete pending material whose committed counterpart
cannot be proven absent. Draft approach:

1. On a `durableRename`/`os.Rename` error for the DEK rename, do **not**
   immediately clean up. First verify the ACTUAL on-disk state:
   - Read `activeDEKFull` (the target of the rename). If it does not exist,
     or its content does not match `newWrappedDEK` (the bytes this call just
     tried to promote), the rename genuinely did not happen — safe to fall
     through to the existing cleanup (`os.Remove` both `.pending` files) and
     return the original error unchanged.
   - If `activeDEKFull` DOES exist and its content matches `newWrappedDEK`
     byte-for-byte, the rename actually succeeded despite the reported
     error. In this case:
     - Do **not** delete `kek.salt.pending` — it is the only recovery path
       for the hazard window that now genuinely exists.
     - Do **not** delete `pendingDEKFull` either (it's already gone if the
       rename succeeded; harmless either way, but should not be assumed).
     - Return the same informative error the `rename-salt` failure branch
       already uses for this exact hazard window: `"rotate KEK: promote
       pending DEK to active: DEK rename already succeeded — manually
       rename %s to %s to complete: %w"` — i.e., treat this exactly like a
       `kek:after-rename-dek` completion followed by a `rename-salt`
       failure, since that's what actually happened on disk, regardless of
       what the rename call itself reported.
2. This requires reading the salt/DEK's on-disk content for comparison — a
   plain `os.ReadFile`/`securefiles.SafeReadFile`, not a size/mtime heuristic
   (a size-only check could not distinguish "genuinely new content" from "old
   content that happens to be the same length").
3. Apply the identical pattern to `RewrapDEK`'s `rewrap:rename-dek` cleanup
   for consistency and defense-in-depth, even though it is not currently
   exploitable there (no second coupled file to lose) — the same "verify
   before cleanup" discipline avoids the same bug class re-appearing if
   `RewrapDEK`'s structure ever gains a second coupled file.

This is a design/implementation decision for whoever picks up the fix, not
made here.
