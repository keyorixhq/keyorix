- **INV-FUZZCLOUD-bounded-time-heartbeat** The bounded-time oracle of the hostile-server
  harnesses (`fuzz/thirdparty/{pgx,mysql,redis}`) reports a driver hang only when the
  process itself was running: it goes through `hostile.WaitBounded`, whose heartbeat
  separates a hung driver call (healthy heartbeat, fails at the first deadline) from a
  frozen process (heartbeat gap >= limit/3; the call gets one more full limit after
  recovery, and only a call that is STILL unreturned fails). Why: FuzzPgxCopyResponse
  cba59eeb6c4b (vCD, execs/sec stuck at 0 for 12+ s before it) never reproduced in 55
  replays, idle or CPU-starved; a bare wall-clock oracle cannot tell the two apart.
  Guard: `TestWaitBounded_*` (`fuzz/thirdparty/internal/hostile/bounded_test.go`) pin
  all four classifications with an injected heartbeat. Does NOT cover: a real hang that
  also freezes the process (it is still reported, one limit later), the other
  wall-clock oracles in `fuzz/thirdparty` that do not use `WaitBounded` yet, or
  harnesses outside `fuzz/thirdparty`.
