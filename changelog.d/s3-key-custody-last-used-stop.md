### Fixed
- **Last-used coalescer now has a lifecycle `Stop` wired into graceful shutdown.**
  On shutdown the server now calls `StopLastUsed` instead of the bare
  `FlushLastUsed`: it performs the final flush of `last_used_at` / `last_seen_at`
  stamps and then latches the coalescer shut, so a stamp recorded after the flush
  can no longer re-arm the 30 s timer (and a failed final flush can no longer
  re-arm it either) to fire a write against a store the process has already torn
  down. Idempotent and bounded by its context. No behaviour change for a healthy
  server; closes an availability/use-after-teardown hole in the key-custody path.

### Testing
- **Coalescer `Stop` red/green.** `TestLastUsedCoalescer_StopVsFlushOnLateStamp`
  proves, in one harness, that a plain flush re-arms the timer and writes after the
  store is closed while `Stop` latches shut; plus final-flush-not-lost, idempotency,
  context-bounded stop under a wedged background flush, and no timer/goroutine
  re-arm after stop.
