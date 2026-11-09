### Internal
- **Faster closure guard self-test.** `scripts/check-closures.sh --self-test` now runs its independent calibration cases through the same bounded pool as the package run (`CHECK_CLOSURES_JOBS`, sequential under a shared Postgres DSN) and prints every verdict in the original order. It also prints per-phase `timing:` lines to stderr.
