- **INV-FUZZCLOUD-bounded-time-heartbeat** A wall-clock "did not return" oracle in a fuzz
  target must not call a frozen fuzz PROCESS a hung call. `internal/fuzzutil` runs one
  stall monitor per process (ticks every 50 ms, records gaps over 500 ms); a deadline miss
  with a freeze share of at least limit/3 gets ONE more full limit after recovery, and only
  a call still unreturned then fails (`fuzzutil.Wait`, `WaitBounded`, and `fuzzutil.Guard`,
  the oracle behind ~96 targets). A deadline miss while the process was running fails
  exactly as before. The grace never forgives a freeze the INPUT caused: when the window
  shows at least 64 MiB of heap allocation, or GC CPU of at least a quarter of the freeze
  (`runtime/metrics`, sampled by the monitor every tick), the miss fails at once. It also
  forgives only frozen time: a call that returns in the grace but ran longer than the limit
  fails. Every excused miss is logged (stderr and `FUZZ_STALL_LOG`) and counted
  (`StallsRecovered`). Bounded-work oracles that time a synchronous call use
  `fuzzutil.OverDeadline`: over when wall time exceeds 2x the deadline (hard ceiling), when
  running time exceeds the deadline, or when the freeze was self-inflicted. Why:
  FuzzPgxCopyResponse cba59eeb6c4b (vCD, execs/sec stuck at 0 for 12+ s before it) never
  reproduced in 55 replays, idle or CPU-starved; and
  `fault_injected_operations_fuzz_test.go` already recorded that its 30 s guard "conflates
  the operation is stuck with the machine is busy". Guard: `TestWait*`, `TestGuard_*` and
  `TestFrozenSince_*` (`internal/fuzzutil/stall_test.go`) pin both classifications, the
  Guard path included, with an injected freeze; red-proven by disabling the classification.
  `TestGuard_SelfInflictedFreezeStillFails`, `TestWait_SelfInflictedFreezeFails` and the
  `*SlowBut*` tests (`internal/fuzzutil/stall_selfcaused_test.go`: real heap growth,
  injected freeze; red at the pre-fix head) and `TestOverDeadline_*` /
  `TestSelfCausedFreeze_RealCounters` pin the self-inflicted and running-time rules.
  Converted: Guard, `fuzz/thirdparty/internal/hostile.WaitBounded` (pgx x2, mysql, redis),
  spf13pflag, goi18n, gopsutil, gotpm, burnttoml, mongodb, azure, aws, and the encryption
  hang guards (kek-rotation, dek-sweep, dek-rewrap, fault-injected-operations); OverDeadline:
  yaml (`FuzzYAMLDecodeBoundedWork`) and webauthn (`FuzzWebAuthnParsePublicKey`). Does NOT
  cover: a hang of a call that does not allocate while a genuine host freeze covers a third
  of its window (Wait/Guard report it one limit later; OverDeadline once running time passes
  the deadline, and at 2x wall time at the latest); self-inflicted work that neither
  allocates 64 MiB nor spends GC CPU (a pure CPU loop does not stop the tick monitor, so it
  is classified as running and fails at the first deadline anyway); oracles
  whose verdict comes from an INNER read/ctx deadline (`server/wirefuzz` stalled flags,
  `keymanager_subprocess_crash_test.go`'s ctx kill, `interleave_sync_points` degrade,
  `secret_ops_canary_pg` rendezvous wait); other Go modules (`cli`, `migrate`, dashdiag).
