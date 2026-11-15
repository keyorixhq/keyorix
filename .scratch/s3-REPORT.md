# S3 — Key custody availability: design + proof by test

Branch: `fuzz/s3-key-custody`  ·  Date: 2026-11-15  ·  Status: IN PROGRESS

**Report location note.** The prescribed path `/mnt/data/wave4/out/s3-REPORT.md` is
outside this session's sandbox (writes there are blocked), so the report lives
committed on the branch at `.scratch/s3-REPORT.md` (force-added past `.gitignore`),
as the runtime rules allow.

**Environment note.** The package-temperature sensor
(`/sys/class/hwmon/hwmon2/temp1_input`) is not readable from this sandbox
(blocked path), so thermal pacing relies on `nice -n 10`, `GOMAXPROCS=2`,
`-p 2` and `-parallel 2` as instructed. `GOCACHE`/`GOMODCACHE` already default to
the prescribed `/mnt/data/wave4/{gocache,gomod}` paths.

**Most reasonable reading of the task (stated up front).** Two availability risks
in key custody. (1) `lastUsedCoalescer` has no `Stop`: its flush timer/goroutine is
not stopped on shutdown, so a late stamp re-arms a timer that can fire against a
closing store, and the existing shutdown `FlushLastUsed` is not a true lifecycle
stop. This is the one piece the task authorises a **production change** for (the
minimal `Stop`). (2) `KeyManager` holds its write lock across the KEK fsync, so a
stalled disk blocks every reader (secret reads included). The task says: implement
the lock narrowing only if a small, test-proven change keeps crash-safety and
rotation ordering; otherwise deliver a **design document**. Finding: (2) is already
characterised and proven by an existing repo test and the safe fix is far larger
than a small PR, so (2) is **design-only**.

---

## What is committed / what ran

- [x] Design doc `docs/design/2026-11-15-key-custody-availability.md`
- [x] (1) `lastUsedCoalescer.Stop` + `StopLastUsed` + `server/shutdown.go` wiring
- [x] (1) red/green test `internal/core/last_used_coalescer_stop_test.go`
- [x] (1) changelog fragment `changelog.d/s3-key-custody-last-used-stop.md`
- [x] (1) INVARIANTS `internal/core/INVARIANTS.d/INV-CORE-last-used-stop-latches-shut.md`
- [x] (2) design-only; references existing `TestSlowDiskSync_HoldsReadLockAcrossSync`
- [~] `go test` on touched packages — **could not execute in this sandbox**: the
  offline module cache lacks `github.com/digitorus/pkcs7` (GOPROXY=off, no network),
  which transitively blocks compiling `internal/core` and `internal/encryption`
  (even `internal/core/storage`). See "Execution evidence" below for the isolated
  red/green that was run instead.
- Fuzz wall time used: **0s** — both defects are deterministic; no new fuzzer is
  required and issue (2) reuses an existing deterministic test.

## Execution evidence (what actually ran)

Because the full package cannot compile offline, the issue-1 state machine
(`record`/`armTimerLocked`/`onTimer`/`kick`/`flush`/`finishFlush`/`Stop`) was copied
**verbatim** into a dependency-free module (`.scratch/iso/`, gitignored, not
committed) and the Stop tests were run there with `-race`:

```
GREEN (fix in place):   ok  iso  1.387s   (all 6 Stop tests, -race)
RED   (latch removed):  --- FAIL: TestStopVsFlushOnLateStamp
                        --- FAIL: TestStopNoReArmNoLeak
GREEN (latch restored): ok  iso  1.387s
```

`TestStopVsFlushOnLateStamp` is the two-sided proof in one harness: with `drain=flush`
a post-close stamp re-arms the timer and a write lands after the store is "closed" (the
defect reproduces); with `drain=Stop` nothing writes after close. Removing the
`a.stopped = true` latch flips exactly the Stop oracles red — the latch is load-bearing.
The committed package tests mirror this logic against the real `KeyorixCore` and storage
hook; they are gofmt-clean and run once `pkcs7` is cached.

Validations that DID run in-sandbox:
- `gofmt -l` on all touched files: clean.
- `scripts/changelog-assemble.sh --check`: `ok: 86 changelog fragment(s) valid`.

---

## Evidence map (code, read directly)

### Issue (1) — lastUsedCoalescer lifecycle gap
- `internal/core/last_used_coalescer.go`
  - timer: `time.AfterFunc(delay, a.onTimer)` armed in `armTimerLocked` (L276–282).
  - background flush goroutines: `kick()` (L307–315, `go func(){…}`) and `onTimer`
    (L286–303).
  - shutdown hook: `FlushLastUsed(ctx)` (L545) → `flush(ctx)`; it stops the timer
    *for that flush* but **does not** prevent a later `record()` from re-arming it,
    and `finishFlush` re-arms on a failed final flush (L453–455). There is **no**
    idempotent `Stop`.
- `server/main.go:335` `defer flushLastUsedOnShutdown(coreService)` →
  `server/shutdown.go:15` `FlushLastUsed` — the only shutdown wiring.
- **Direct corroboration in-repo:** test helper `stopLastUsedTimerNow`
  (`internal/core/last_used_coalescer_overload_test.go:29`) and the cleanup in
  `newLastUsedWorld` (`last_used_coalescer_test.go:122`) exist *only* because
  "a never-flushed 30 s timer … can fire (and re-arm) against a database the test
  has closed." Tests hand-roll the missing Stop.

### Issue (2) — KeyManager lock across fsync (blocking)
- All three rotations hold `km.mu.Lock()` across `durableWriteSync`/`durableRename`/
  `durableSyncDir` (fsyncs):
  `RotateKEKPassphraseWithPrepare` (`keymanager_kek_rotation.go:53` lock →
  `commitNewKEKFiles`), `RewrapDEKWithPrepare` (`keymanager_rewrap.go:39`),
  `RotateDEKWithSweep` (`keymanager_rotation.go:37`, lock held across the **entire
  re-encryption sweep**).
- Readers take `km.mu.RLock()`: `GetDEK`/`GetKeyVersion`/`GetEvidenceSignKey`/
  `GetAuditCheckpointKey`/`GetBackupManifestKey` (`keymanager_io.go:16–75`).
  `EncryptSecret` calls `GetKeyVersion` on every encrypt → stalls under a slow fsync.
- **Already proven in-repo:** `TestSlowDiskSync_HoldsReadLockAcrossSync`
  (`keymanager_slow_disk_sync_test.go`) injects a slow directory fsync, holds
  `mu.Lock`, and measures `GetKeyVersion` (RLock) blocked ≈ the injected delay,
  3× replay, with a zero-contention green baseline. It classifies this as a
  **HARDENING** observation (benign in production: rotation is rare, admin-initiated).

---

## Oracles and what they do NOT verify

Issue (1) — `last_used_coalescer_stop_test.go` (and the isolated run):
- `StopVsFlushOnLateStamp`: proves `Stop` latches the coalescer shut so a late stamp
  cannot re-arm a timer that writes after close, and that plain `flush` does not.
  Does NOT verify real `*sql.DB` close behaviour — "closed" is an in-memory flag, not
  a torn handle; does NOT verify server shutdown ordering (read, not executed).
- `StopFinalFlushNotLost`: `Stop` flushes pending before latching. Does NOT bound the
  flush beyond `ctx`.
- `StopIdempotent`: second `Stop` is a no-op, post-`Stop` `record` is dropped. Does
  NOT assert anything about concurrent `Stop` callers beyond no-panic/no-double-write.
- `StopBoundedWhenFlushWedged`: `Stop(ctx)` returns on `ctx`, not blocked on a wedged
  background flush. Does NOT prove the wedged write is cancelled (the background
  goroutine stays until the fake unblocks — same as production, where the OS write
  eventually returns or the process exits).
- `StopNoReArmNoLeak`: no timer re-arm, no leaked goroutine after `Stop`. The
  goroutine count is a settled `runtime.NumGoroutine()` with `+1` slack, not goleak.

Issue (2) — existing `TestSlowDiskSync_HoldsReadLockAcrossSync` (NOT re-run here):
- Proves readers (`GetKeyVersion` RLock) block ≈ the injected fsync delay during a
  rotation, 3× replay, with a green zero-contention baseline. Does NOT prove the
  blocking happens under a *live* production stall (it injects the delay), does NOT
  cover `RewrapDEK`/`RotateDEKWithSweep` reader-blocking directly (same lock, by
  inspection), and classifies the finding as HARDENING, not a defect.

---

## Classification (honest)

- Issue (1): **DEFECT (availability/correctness, low severity)** — a late stamp can
  re-arm a timer that touches a closing store; no idempotent lifecycle stop.
  Production change authorised and minimal.
- Issue (2): **HARDENING** — real but benign in the shipping server (rotation rare,
  admin-initiated; storage is not force-closed under the lock in `server/main.go`).
  Narrowing is a large, crash-safety-sensitive change → design-only.

## Talk material

Fuzz-corpus issue 114 named two key-custody availability risks; I confirmed both in
code and found that the repo already told the story — issue (2)'s fsync-under-lock
blocking is proven by an existing `TestSlowDiskSync_HoldsReadLockAcrossSync` (3× replay,
green baseline, self-classified HARDENING), and issue (1)'s missing coalescer stop is
visible as the hand-rolled `stopLastUsedTimerNow` every coalescer test calls in cleanup
"so it cannot fire against a database the test has closed." For (1) I added the minimal
`Stop` the task authorised — idempotent, final-flush-then-latch, context-bounded,
wired into shutdown via `StopLastUsed` — and proved it red/green (removing the
`stopped` latch flips exactly the Stop oracles red), but honestly: that proof ran
against a verbatim isolated copy of the state machine because the sandbox's offline
module cache can't compile `internal/core` (missing `digitorus/pkcs7`, GOPROXY=off), so
the committed package tests are reviewed and gofmt-clean but unexecuted here. For (2) I
deliberately did **not** touch the lock: the write lock also guards the staleness check,
manifest staging, the three-way rename classification and the in-memory key swap, so a
safe narrowing (an `atomic.Pointer[keyState]` publish after the rename, readers never
taking the rotation lock) is a multi-PR change against the most crash-sensitive code in
the tree — I wrote the lock order, states, failure cases and test plan instead of
shipping unproven code. Net: one small proven fix, one honest design, and a clear list
of what neither covers — power-loss reordering, NFS, the pending-rotation/backup
interplay, and real DB-handle close semantics.
