# Key-custody availability: coalescer Stop + KeyManager fsync-under-lock

Date: 2026-11-15 · Branch: `fuzz/s3-key-custody` · Task S3 (design phase)
Status (2026-11-21, #4376): §2 implemented for `RotateKEKPassphraseWithPrepare` (`rotateMu` + an immutable `keyState` published with `atomic.Pointer`); `RotateDEKWithSweep` is unchanged and still holds `KeyManager.mu` across its sweep (follow-up).
Source: fuzz-corpus issue 114 (two availability/integrity risks in key custody).

This document covers two findings:

1. **`lastUsedCoalescer` has no lifecycle stop** — its flush timer/goroutine is not
   latched shut on shutdown, so a late stamp can re-arm a timer that fires against a
   closing store. **Fixed in this PR** (minimal `Stop`, proven red/green).
2. **`KeyManager` holds its write lock across the KEK fsync** — a stalled disk blocks
   every reader (secret reads included) for the rotation's duration. **Design-only**:
   already characterised and proven by an existing repo test; the safe narrowing is far
   larger than a small PR, so it is specified here, not implemented.

---

## 1. Coalescer lifecycle stop (implemented)

### 1.1 Problem

`internal/core/last_used_coalescer.go` keeps per-request `last_used_at` /
`last_seen_at` bookkeeping off the request path: a request records a use in memory
(`record`), a `time.AfterFunc` timer flushes once per `lastUsedFlushInterval` (30 s),
and background flushes run on the timer goroutine (`onTimer`) or a `kick()` goroutine
when the pending map hits its cap. The only shutdown hook was `FlushLastUsed(ctx)` →
`flush(ctx)`.

`flush` drains once but does **not** stop the coalescer. Two concrete holes:

- **Re-arm after flush.** A `record()` that lands after `FlushLastUsed` (an in-flight
  request finishing after the HTTP drain) re-arms the 30 s timer via `armTimerLocked`.
  That timer later fires `onTimer` → `flushInBackground` → `a.write` → the store — which
  the process may already be tearing down (`encSvc.Shutdown`, `swGuard.Close`, DB handle
  close on exit). A write against a closing store is a use-after-teardown race.
- **Re-arm on failed final flush.** If the final `flush` fails (storage already going
  away), `finishFlush` puts the keys back and calls `armTimerLocked` — re-arming the
  same timer for the same hazard.

This is not hypothetical: every coalescer test hand-rolls `stopLastUsedTimerNow` in
cleanup (`last_used_coalescer_overload_test.go:29`, used from `newLastUsedWorld`)
precisely "so it cannot fire (and re-arm) against a database the test has closed." The
test band-aid is the production hole, written down.

**Severity: DEFECT, low.** In the shipping `server/main.go` the window is narrow (servers
drain before the shutdown defers, and storage is not force-closed under the coalescer),
so it is latent there; it is a real correctness gap for embedded/CLI/test lifecycles and
removes a class of shutdown race outright.

### 1.2 Evidence by test

Executed red/green of the exact state machine (see §1.5 on why the proof runs against an
isolated copy):

- `TestStopVsFlushOnLateStamp` (one harness, both sides): `drain = flush` →
  a post-close stamp re-arms the timer and a write lands after close (the defect
  reproduces); `drain = Stop` → the post-close stamp is dropped, no write after close.
- Mutation/red proof: deleting the `a.stopped = true` latch makes the `Stop` side (and
  `TestStopNoReArmNoLeak`) fail; restoring it returns green. The latch is load-bearing.
- `TestStopFinalFlushNotLost`, `TestStopIdempotent`,
  `TestStopBoundedWhenFlushWedged`, `TestStopNoReArmNoLeak` cover the rest of the
  contract. All green under `-race`.

The committed package tests (`internal/core/last_used_coalescer_stop_test.go`) mirror
these against the real `KeyorixCore`/`lastUsedCoalescer` and storage write hook.

### 1.3 Goroutine / timer / lock map (coalescer)

| Actor | Synchronisation | Touches store? |
|---|---|---|
| `record` (request goroutine) | `a.mu`; may `armTimerLocked` or `kick` | no |
| timer `AfterFunc` → `onTimer` | `a.mu`, `a.flushing` CAS, `a.flushSem` | yes (via flush) |
| `kick` goroutine (cap overflow) | `a.flushing` CAS, `a.flushSem` | yes |
| `FlushLastUsed` / `Stop` (shutdown goroutine) | `a.flushSem` (ctx-bounded), `a.mu` | yes |

`a.flushSem` (capacity 1) serialises every flush; `acquireFlush` honours `ctx`, so a
shutdown flush is bounded even if a background flush is wedged in a slow write.

### 1.4 Proposal (implemented, minimal)

Add a `stopped bool` field (under `a.mu`) and a `Stop(ctx)` method:

```
Stop(ctx):
  lock mu; first = !stopped; stopped = true; stop+nil the timer; unlock
  if !first: return          // idempotent — first Stop did/does the final flush
  flush(ctx)                 // final drain, ctx-bounded, waits on flushSem
```

Every arm/flush entry point honours `stopped` (all under `a.mu`):
`record` early-returns; `armTimerLocked` returns (covers `finishFlush`/`rearm`/`record`);
`onTimer` returns after clearing its timer; `kick` re-checks `stopped` under `a.mu`
(because `record` releases `a.mu` before calling it).

Wire it in: `KeyorixCore.StopLastUsed(ctx)` → `a.Stop(ctx)`; `server/shutdown.go`'s
`flushLastUsedOnShutdown` calls `StopLastUsed` instead of `FlushLastUsed`.
`FlushLastUsed` stays for the flush-only callers (monotonic-replica test, etc.).

Contract: idempotent · waits for the in-flight flush goroutine (via `flushSem`) · final
flush bounded by `ctx` · safe to call after the store closed · after it, no coalescer
goroutine/timer touches the store.

### 1.5 Rejected alternatives (issue 1)

- **Leave `FlushLastUsed`, keep hand-rolling `stopLastUsedTimerNow` in tests.** The
  helper only stops the *current* timer; it neither latches nor prevents re-arm, and it
  is test-only. Rejected: it is the symptom, not the fix.
- **`context.Context` threaded through the whole coalescer.** Larger surface, changes
  every `record`/`flush` signature, and the lifecycle question ("is this coalescer
  retired?") is a latch, not a cancellation. Rejected as over-build.
- **Stop the timer without a final flush.** Loses the pending stamps a graceful stop is
  supposed to persist. Rejected: `Stop` must flush first.
- **Make `record` after `Stop` panic/error.** A late stamp from an in-flight request is
  normal at shutdown; dropping it silently (matching the crash bound) is correct, erroring
  is not. Rejected.

---

## 2. KeyManager fsync-under-lock (design-only)

### 2.1 Problem

All three rotation operations hold `km.mu.Lock()` (the write lock) across the on-disk
commit, which includes `durableWriteSync` / `durableRename` / `durableSyncDir` (each an
fsync), and in the DEK-sweep case the entire re-encryption sweep:

- `RotateKEKPassphraseWithPrepare` (`keymanager_kek_rotation.go:53`) → `commitNewKEKFiles`
  (writes pending salt+DEK, renames both, two directory fsyncs).
- `RewrapDEKWithPrepare` (`keymanager_rewrap.go:39`).
- `RotateDEKWithSweep` (`keymanager_rotation.go:37`) — lock held across `sweepFn` (the
  full DB re-encryption) plus the rename and dir fsync.

Readers take `km.mu.RLock()`: `GetDEK`, `GetKeyVersion`, `GetEvidenceSignKey`,
`GetAuditCheckpointKey`, `GetBackupManifestKey` (`keymanager_io.go:16–75`).
`EncryptSecret` calls `GetKeyVersion` on *every* encrypt, and secret decryption calls
`GetDEK`. So while a rotation's fsync is stalled, every secret read/write that needs the
key manager blocks for the full stall — a slow/stuck disk becomes a full key-manager
outage.

### 2.2 Evidence by test (already in the repo)

`internal/encryption/keymanager_slow_disk_sync_test.go`:

- `TestSlowDiskSync_HoldsReadLockAcrossSync` injects a slow directory fsync
  (`armSlowSyncOnce("kek:syncdir-dek", 300ms)`), runs a KEK rotation on a goroutine, and
  measures `GetKeyVersion` (RLock) blocked ≈ the injected delay, **3× replay**, against a
  **zero-contention green baseline** that proves the probe itself is fast. It classifies
  this as a **HARDENING** observation, benign in production (rotation is rare and
  admin-initiated), and includes a no-FD-leak and no-goroutine-leak gate.
- `TestSlowDiskSync_KEKRotationAtomicAndRecovers` is the gate that a slow-but-succeeding
  fsync still commits atomically and reopens.

This finding is therefore **already proven and characterised**; this PR does not add a
duplicate test. Re-running it is the recommended confirmation step (blocked here only by
the offline module cache, §4).

### 2.3 Why design-only

The task authorises implementing the narrowing *only if a small, test-proven change
leaves crash-safety and rotation ordering unchanged*. It cannot be small here:

- The lock protects not just the fsync but the **staleness check** (`dekSnapshot`
  re-read under the lock, #195), the **key-set manifest staging/commit**
  (`stageKeySet`/`commitKeySet`, INV-ENCRYPTION-keyset-manifest-bracketed-writes), the
  in-memory key swap, and the three-way `classifyDEKRename` recovery. These must stay
  mutually exclusive with each other and with the in-memory `currentDEK`/`dekSnapshot`
  update.
- Crash-consistency is covered by `FuzzDEKSweepCrashConsistency`,
  `FuzzDEKRewrapCrashConsistency` and the `rotationCheckpointHook` seams at every
  write/rename/syncdir boundary. Any lock narrowing must re-prove all of them.
- `RotateDEKWithSweep` holds the lock across the whole DB sweep by design (readers must
  not observe a half-rotated world); narrowing that is a separate, deeper change.

Narrowing is a multi-PR effort with a real regression surface against the most
safety-critical code in the tree. Per the task, it is specified here, not implemented.

### 2.4 Intended invariant

> **Readers never wait on a writer's fsync.** `GetDEK`/`GetKeyVersion`/`GetEvidenceSignKey`/
> `GetAuditCheckpointKey`/`GetBackupManifestKey` return the *currently committed* key
> material without blocking on any in-progress rotation's disk I/O. A rotation replaces
> the KEK/DEK files atomically (write-temp → fsync → rename → fsync-dir) with the durable
> I/O performed **outside** the lock that readers take, and the in-memory key swap happens
> under a short lock held only for the pointer swap, never across an fsync.

### 2.5 Proposed design (for a future multi-PR change)

**Lock split.** Replace the single `km.mu sync.RWMutex` with two locks and an immutable
snapshot:

1. `rotateMu sync.Mutex` — the *serialisation* lock. Held for the whole rotation
   (staleness re-read, prepare, file writes+fsyncs, manifest staging, rename, dir fsync,
   recovery classification). Readers never take it. This is the cross-process DEK flock's
   in-process analogue and subsumes today's "only one rotation at a time."
2. `state atomic.Pointer[keyState]` — an immutable struct holding `{currentDEK,
   keyVersion, dekSnapshot, evidenceSignKey+ID, auditCheckpointKey+ID,
   backupManifestKey+ID}`. Readers do one `state.Load()` and copy out of the pointed-to
   struct; they never block on I/O. The rotation builds the *entire* next `keyState` in
   locals, and only after the on-disk rename+dir-fsync have committed does it
   `state.Store(next)` — a single pointer publish, O(1), no fsync under any reader-visible
   lock.

**Resulting lock order (declared):** `rotateMu` (coarse, rotation-only) → file/flock I/O →
`state.Store` (atomic, no lock). Readers: `state.Load` only. No reader ever waits on
I/O; concurrent rotations serialise on `rotateMu` and the cross-process DEK flock exactly
as today.

**States and the atomic publish point.** The on-disk protocol is unchanged
(pending-write → fsync → stage manifest → rename DEK → fsync dir → rename salt → fsync dir
→ commit manifest). The in-memory `state.Store(next)` replaces today's field-by-field
assignment under `mu.Lock`, and it happens at the same logical point (after the rename is
durable). Wipe of the superseded key material moves to *after* the store, once no reader
can still be mid-copy — handled by not wiping the old `keyState` (let GC reclaim it) or by
a short grace, since the old DEK bytes are still valid ciphertext keys until then.

**Failure cases to preserve.**
- Stale `dekSnapshot` (another process rotated): abort before any write — unchanged, now
  under `rotateMu` + flock instead of `mu.Lock`.
- `classifyDEKRename` three-way (`NotApplied`/`Applied`/`Unknown`): unchanged; it runs
  under `rotateMu`, publishes `state` only on `Applied`/success.
- Failed final fsync-dir: unchanged (surfaced, not discarded).
- Wipe-on-error paths (`Initialize`, `RotateKEKPassphrase`): the locals are wiped on every
  early-return exactly as today; `state` is published only on full success.

### 2.6 Rejected alternatives (issue 2)

- **Drop the lock around just `durableSyncDir`.** Unsound: the rename and the dir fsync
  must be atomic w.r.t. readers, and `dekSnapshot`/manifest state would be mutable mid-fsync.
- **Copy-under-RLock then fsync-unlocked in the same method.** Still publishes the new
  in-memory key before the rename is durable, so a reader could see a key whose on-disk
  backing is not yet committed — reopens a crash-consistency gap the current ordering
  closes.
- **A reader-side timeout / `TryRLock`.** Turns a stall into an error on the read path
  (secret reads failing) rather than removing the coupling; worse availability shape.
- **Shrink `RotateDEKWithSweep`'s lock to exclude the sweep.** Readers would observe a
  half-rotated DEK during the sweep; separate, larger change, out of scope here.

### 2.7 Test plan (for the future change)

1. Re-run `TestSlowDiskSync_HoldsReadLockAcrossSync` and assert it goes **green**
   (reader no longer blocked ≥ delay/2) — the inverse of today's assertion; this is the
   acceptance test for the narrowing.
2. Keep `TestSlowDiskSync_KEKRotationAtomicAndRecovers` green (atomic + recovers).
3. Re-prove `FuzzDEKSweepCrashConsistency` and `FuzzDEKRewrapCrashConsistency` at every
   `rotationCheckpointHook` seam.
4. New: concurrent `GetDEK`/`GetKeyVersion` readers racing a rotation under `-race`, with
   an assertion that every read returns either the fully-old or fully-new `keyState`,
   never a mix (e.g. new DEK with old `keyVersion`).
5. New: concurrent rotation × rotation still serialises (two rotations, one wins the
   staleness check, the other aborts) — unchanged behaviour under the new `rotateMu`.
6. Pending-rotation + backup interplay (§4): a rotation interrupted mid-commit, recovered
   by `PromotePendingDEK`/`RecoverInterruptedRotation`, still reaches a consistent
   `state` publish.

---

## 3. Classification (honest)

- Issue 1: **DEFECT (availability / use-after-teardown, low)** — fixed, minimal, red/green.
- Issue 2: **HARDENING** — real but benign in the shipping server (rotation rare,
  admin-initiated; storage not force-closed under the lock). Design-only by task rule.

## 4. What these changes do NOT cover

- **Issue 1 oracle limits.** The write hook is in-memory: "closed" is a flag, not a torn
  DB handle, so it proves the *coalescer* no longer re-arms, not the kernel/driver
  behaviour of a write to a genuinely closed `*sql.DB`. The server shutdown *ordering*
  (that `StopLastUsed` runs before any real store teardown) is verified by reading
  `server/main.go`/`server/shutdown.go`, not executed.
- **Issue 2 is not implemented.** No lock is narrowed; the blocking remains exactly as
  `TestSlowDiskSync_HoldsReadLockAcrossSync` describes. The §2.5 design is unproven code.
- **Power loss on reordering filesystems.** Neither change addresses filesystems that
  reorder writes/renames without barriers; the existing `durableSyncDir` hazards
  (documented in `keymanager_kek_rotation.go` and the `docs/findings/2026-09-19-*`
  notes) are unchanged.
- **NFS.** The `classifyDEKRename` NFS lost-reply ambiguity is untouched; the lock split
  does not change rename semantics on NFS.
- **Pending-rotation ↔ backup interplay.** The neighbouring "backup during pending key
  rotation" analysis is out of scope; §2.7 item 6 lists it as a required test for the
  future narrowing, not something proven here.
- **Execution in this sandbox.** The offline module cache lacks `github.com/digitorus/pkcs7`
  (GOPROXY=off, no network), so `internal/core` and `internal/encryption` could not be
  compiled/tested here; the issue-1 red/green was executed against a verbatim isolated copy
  of the coalescer state machine instead (see the report). The committed package tests are
  gofmt-clean and mirror that logic; they run once the module is cached.
