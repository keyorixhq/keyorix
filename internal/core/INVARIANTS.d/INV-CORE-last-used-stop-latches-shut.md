- **INV-CORE-last-used-stop-latches-shut** The `lastUsedCoalescer` has a lifecycle
  `Stop(ctx)` that is the shutdown counterpart to `flush`: it latches `a.stopped`
  under `a.mu`, stops the periodic timer, cancels the in-flight background flush's
  context (`bgCancel`, registered under `a.mu` with a `stopped` re-check), and
  performs one final flush bounded by `ctx`. After `Stop`, `record` is a no-op,
  `armTimerLocked`/`onTimer`/`kick`/`flushInBackground` refuse to arm a timer or
  start a background flush, a non-final flush that gets `flushSem` after the latch
  returns without writing, and `finishFlush` cannot re-arm on a failed final flush —
  so no new timer or flush starts, and when `Stop` returns before `ctx` ends no flush
  is running. The one exception: if `ctx` ends while the cancelled background flush
  is inside a store call that ignores cancellation, that one call can finish after
  `Stop` returns (bounded by `lastUsedFlushTimeout`); it writes no further key. The
  server wires it through `KeyorixCore.StopLastUsed`
  (`server/shutdown.go` → `flushLastUsedOnShutdown`) instead of the bare
  `FlushLastUsed`. `flush` alone is *not* a stop: a stamp recorded after it re-arms
  the 30 s timer, which then fires against a store the caller believed drained, and a
  failed final flush re-arms the timer from `finishFlush`. Why: S3 key-custody
  availability review (fuzz-corpus issue 114, item 1) — before `Stop`, the only
  shutdown hook was `flush`, and every coalescer test had to hand-roll
  `stopLastUsedTimerNow` in cleanup "so it cannot fire (and re-arm) against a database
  the test has closed", which is exactly the production hole. `Stop` is idempotent and
  bounded (it gives up on `ctx` rather than block on the flush semaphore a wedged
  background flush holds). Guard:
  `TestLastUsedCoalescer_StopVsFlushOnLateStamp` (red/green in one harness: `flush`
  re-arms and writes after close, `Stop` latches shut),
  `TestLastUsedCoalescer_StopFinalFlushNotLost`, `TestLastUsedCoalescer_StopIdempotent`,
  `TestLastUsedCoalescer_StopBoundedWhenFlushWedged`,
  `TestLastUsedCoalescer_StopNoReArmNoLeak`,
  `TestLastUsedCoalescer_StopLateBackgroundFlushDoesNotWrite` (a background flush
  past the latch check that gets the semaphore after Stop writes nothing),
  `TestLastUsedCoalescer_StopCancelsInFlightBackgroundFlush` (Stop cancels a
  ctx-honouring in-flight flush, its final flush writes the stamp, and no flush runs
  when Stop returns). **Not covered**: real DB close semantics
  (the oracle uses an in-memory write hook, so "closed" is a flag, not a torn handle);
  that the server's shutdown *ordering* reaches `StopLastUsed` before any real store
  teardown (verified by reading `server/main.go` + `server/shutdown.go`, not executed);
  and the KeyManager fsync-under-lock blocking (issue 114 item 2), a separate concern:
  narrowed for KEK rotation and DEK re-wrap by #4376 and guarded by `internal/encryption`'s
  `TestSlowDiskSync_ReadersNotBlockedAcrossKEKSync` and
  `TestSlowDiskSync_ReadersNotBlockedAcrossRewrapSync` (`RotateDEKWithSweep` still holds
  `KeyManager.mu` across its sweep by design).
