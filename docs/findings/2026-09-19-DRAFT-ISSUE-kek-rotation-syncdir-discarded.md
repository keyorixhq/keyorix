# DRAFT — NOT FILED

**Status: already fixed**, in the same branch/PR as this draft
(`fix/kek-rename-dek-verify-before-cleanup`, commit checking both `SyncDir`
errors below). Left drafted rather than deleted in case there's value in
filing it anyway for changelog/release-note linkage (`git log`/PR history
otherwise carries the record) — your call once you review the PR.

This is a drafted GitHub issue for review before filing. It is not a
`docs/findings/*-FINDING-*.md` (no severity/adversarial-verification claim is
made here) — it's the enumeration the KEK-rotation rename-dek finding
surfaced while tracing `SyncDir` call sites, kept separate per that finding's
own reachability analysis (the discarded `SyncDir` calls do NOT feed the
rename-dek cleanup bug — see
`2026-09-19-FINDING-kek-rotation-rename-dek-cleanup-dataloss.md`'s
"Reachability" section).

---

**Title:** encryption: rotation discards SyncDir errors after renaming key material

**Labels:** `enhancement`, `go`, priority: low

**Body:**

While investigating the KEK-rotation rename-dek finding
(`docs/findings/2026-09-19-FINDING-kek-rotation-rename-dek-cleanup-dataloss.md`)
I traced every `securefiles.SyncDir` call site in `internal/encryption`. Most
check and surface the error; two do not. This issue is specifically about
those two.

## Discarded (`_ = ...SyncDir(...)`) — the actual scope of this issue

**1. `keymanager_kek_rotation.go:168`**, `commitNewKEKFiles`, immediately
after the DEK rename (`pendingDEKPath` → `dek.key`):

```go
_ = securefiles.SyncDir(filepath.Dir(activeDEKFull))
```

What a non-durable rename leaves behind after power loss here: `dek.key` has
already been renamed at the syscall level (the in-memory/VFS state reflects
the new, KEK-rotated content), but the containing directory's own entry
update for that rename may not yet be flushed to stable storage. A power
loss before the OS would otherwise have flushed it can, on journaling
filesystems that checkpoint asynchronously, leave the directory in a state
consistent with a point in time *before* the rename — i.e., on remount,
`dek.key` could revert to reflecting the OLD (pre-rotation) wrapped DEK, or
in principle leave the directory entry in whatever intermediate state the
journal last checkpointed. Concretely: `RotateKEKPassphrase` can have already
returned `nil` (success) to its caller — the operator believes the rotation
is complete — while the rename's own durability is still unconfirmed.

**2. `keymanager_kek_rotation.go:178`**, `commitNewKEKFiles`, immediately
after the SALT rename (`pendingSaltPath` → `kek.salt`), the LAST step of the
function:

```go
_ = securefiles.SyncDir(filepath.Dir(activeSaltFull)) // best-effort — see the rename-dek SyncDir comment above
```

What a non-durable rename leaves behind after power loss here: the same
class of ambiguity, but for the salt rename specifically. If it reverts on
crash+remount, the result is: `dek.key` = NEW (already renamed+attempted-sync
at line 168), `kek.salt` = OLD (reverted). This happens to be the SAME hazard
window state the existing crash-consistency fuzzer
(`FuzzKEKRotationCrashConsistency`) and its `recoverDEK` model already handle
via the leftover `kek.salt.pending` file — **provided that file itself
reverted back into existence** rather than having been fully, durably
removed by the rename. This case is lower-risk than #1 (a working documented
recovery path already exists for it), but it's still an un-surfaced error the
function silently swallows.

## For contrast — already-correct call sites (not in scope, listed so this
issue doesn't get re-litigated against the wrong lines)

- `keymanager_rewrap.go` (`rewrap:syncdir` seam, via `durableSyncDir`): error
  checked and returned.
- `keymanager_rotation.go:80` (`RotateDEKWithSweep`, before the sweep
  commits): error checked and returned.
- `keymanager_rotation.go:125` (`RotateDEKWithSweep`, after the DEK rename):
  error checked and returned.
- `keymanager_rotation.go:185` (`PromotePendingDEK`, crash recovery): error
  checked and returned.

So this is specifically a KEK-passphrase-rotation gap (`commitNewKEKFiles`),
not a repo-wide pattern — the other three rotation-family functions already
surface this exact class of error.

## Suggested direction (not a commitment — for discussion) — IMPLEMENTED

Both discarded calls could simply have their errors surfaced the same way
the four already-correct call sites do — return an error that tells the
operator the rename likely succeeded but its durability is unconfirmed
(mirroring the `kek:rename-salt` failure branch's existing message style,
"...already succeeded — manually verify/complete..."), rather than silently
returning `nil` (full success) while a lower-probability but real durability
gap remains open. Filed as `enhancement`/low priority since realized impact
requires the AND of "rename succeeds" + "process survives to return success"
+ "power loss before the next unrelated fsync happens to flush this
directory anyway" — narrower and lower-probability than the rename-dek
finding, but the same fsync-discipline class of issue.

**Implemented as drafted**, in `keymanager_kek_rotation.go`'s
`commitNewKEKFiles`: both `SyncDir` calls now check and surface their error
(`kek:syncdir-dek` after the DEK rename, `kek:syncdir-salt` after the salt
rename), each with a fault-injection seam test added to
`FuzzFaultInjectedOperations`'s KEK-rotate operation catalog. Red-proofed by
temporarily reverting both checks to discarded (`_ = ...`) — the fuzzer's new
seam tests immediately failed (`HARNESS/oracle-c: ... fault did not fire`);
restored — green again.

## Related

- `docs/findings/2026-09-19-FINDING-kek-rotation-rename-dek-cleanup-dataloss.md`
  (the finding that prompted this trace; explicitly NOT the same bug — that
  one is about the rename-dek error-cleanup path deleting recovery material,
  which is reachable even without any `SyncDir` failure at all).
- `docs/findings/2026-09-19-FINDING-siem-spool-no-fsync.md` (same general
  class of issue — a discarded/absent fsync — in an unrelated, lower-severity
  component).
