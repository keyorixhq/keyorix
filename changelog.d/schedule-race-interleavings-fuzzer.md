### Testing
- **New `FuzzScheduleInterleavings` concurrency/interleaving fuzzer (`internal/core`).**
  Fuzzes the *order* of concurrent operations on the paths whose correctness
  depends on interleaving — PAT revoke vs validate, secret delete/update vs read,
  role grant/revoke vs authorize, and concurrent audit-chain appends — by running
  2–4 operations goroutine-per-op against one seeded `KeyorixCore`, with a
  per-op `runtime.Gosched()` schedule and a happens-before mode decoded from the
  input. Four oracles, each documenting what it does NOT verify: serial
  equivalence (linearizability of result class + final state over every
  HB-constrained permutation), post-return visibility (a revoked token / deleted
  secret / revoked role is never observed live after the mutation returned),
  audit-chain integrity plus one event per successful synchronously-audited
  operation, and no deadlock / panic / data race under `-race`. Oracles 1–3 are
  pure-function-checked with committed red/green self-tests; a companion
  `TestScheduleInterleavings_Postgres` replays the two-writer schedules against a
  real Postgres pool (`KEYORIX_TEST_PG_DSN`) where goroutine-per-op gets genuine
  DB-level write concurrency. Target registered in `scripts/fuzzing/targets.d/`.
