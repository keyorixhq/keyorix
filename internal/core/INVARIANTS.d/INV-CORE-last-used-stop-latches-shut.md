- **INV-CORE-last-used-stop-latches-shut** The `lastUsedCoalescer` has a lifecycle
  `Stop(ctx)` that is the shutdown counterpart to `flush`: it latches `a.stopped`
  under `a.mu`, stops the periodic timer, and performs one final `flush` bounded by
  `ctx`. After `Stop` returns, `record` is a no-op, `armTimerLocked`/`onTimer`/`kick`
  refuse to arm a timer or start a background flush, and `finishFlush` cannot re-arm
  on a failed final flush — so no timer or flush goroutine of the coalescer touches
  the store again. The server wires it through `KeyorixCore.StopLastUsed`
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
  `TestLastUsedCoalescer_StopNoReArmNoLeak`. **Not covered**: real DB close semantics
  (the oracle uses an in-memory write hook, so "closed" is a flag, not a torn handle);
  that the server's shutdown *ordering* reaches `StopLastUsed` before any real store
  teardown (verified by reading `server/main.go` + `server/shutdown.go`, not executed);
  and the KeyManager fsync-under-lock blocking (issue 114 item 2), which is a separate
  concern tracked by `internal/encryption`'s `TestSlowDiskSync_HoldsReadLockAcrossSync`.
