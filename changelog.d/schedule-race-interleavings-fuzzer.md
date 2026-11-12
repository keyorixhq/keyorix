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
- **Oracle 2 soundness fix (schedule-race fuzzer).** The post-return-visibility
  oracle's role branch flagged `authorize=true` whenever group 1 revoked the role
  and group 2 did not re-grant it — but missed the case where group 1 *itself*
  contains a `grantRole` concurrent with the revoke. Such a grant can legally
  commit last, leaving the role held, so `authorize=true` is serializable (oracle 1
  accepts it). The branch now also skips when group 1 contains a grant, mirroring
  the existing group-2 skip. Regression seed
  `testdata/fuzz/FuzzScheduleInterleavings/b78054a10a72fe74` plus a self-test case
  lock it in; red/green-proved (reverting the guard re-fails both). No production
  code changed — this was a false positive in the fuzz oracle, not a Keyorix
  defect.
