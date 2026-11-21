- **INV-FUZZCLOUD-bounded-time-heartbeat** A wall-clock "did not return" oracle in a fuzz
  target must not call a frozen fuzz PROCESS a hung call. `internal/fuzzutil` runs one
  stall monitor per process (ticks every 50 ms, records gaps over 500 ms); a deadline miss
  with a freeze share of at least limit/3 gets ONE more full limit after recovery, and only
  a call still unreturned then fails (`fuzzutil.Wait`, `WaitBounded`, and `fuzzutil.Guard`,
  the oracle behind ~96 targets). A deadline miss while the process was running fails
  exactly as before. Why: FuzzPgxCopyResponse cba59eeb6c4b (vCD, execs/sec stuck at 0 for
  12+ s before it) never reproduced in 55 replays, idle or CPU-starved; and
  `fault_injected_operations_fuzz_test.go` already recorded that its 30 s guard "conflates
  the operation is stuck with the machine is busy". Guard: `TestWait*`, `TestGuard_*` and
  `TestFrozenSince_*` (`internal/fuzzutil/stall_test.go`) pin both classifications, the
  Guard path included, with an injected freeze; red-proven by disabling the classification.
  Converted: Guard, `fuzz/thirdparty/internal/hostile.WaitBounded` (pgx x2, mysql, redis),
  spf13pflag, goi18n, gopsutil, gotpm, burnttoml, mongodb, azure, aws, and the encryption
  hang guards (kek-rotation, dek-sweep, dek-rewrap, fault-injected-operations). Does NOT
  cover: a real hang that also freezes the process (reported one limit later); oracles
  whose verdict comes from an INNER read/ctx deadline (`server/wirefuzz` stalled flags,
  `keymanager_subprocess_crash_test.go`'s ctx kill, `interleave_sync_points` degrade,
  `secret_ops_canary_pg` rendezvous wait); other Go modules (`cli`, `migrate`, dashdiag).
