### Added

- Long-lived **soak test for bounded resource growth** (`TestSoakBoundedGrowth`,
  `server/http/soak_bounded_growth_test.go`). Drives a deterministic, seeded,
  replayable stream of mixed operations (secret create/read/update/rotate/delete,
  login/logout token churn, audit reads, project/environment churn) against the real
  in-process stack (NewRouter + auth middleware + handlers + core + crypto + storage),
  file-backed SQLite always and PostgreSQL when `KEYORIX_TEST_PG_DSN` is set, and
  asserts bounded growth of goroutines, open file descriptors, heap-in-use after GC,
  database+WAL size per logical record, audit-chain completeness, and probe latency
  drift — the leak class per-input fuzzers cannot see. Duration is env-driven
  (`KEYORIX_SOAK_OPS` / `KEYORIX_SOAK_DURATION` / `KEYORIX_SOAK_SEED`), short by default.
- **Soak operation-sequence fuzzer** (`FuzzSoakOperationSequence`,
  `server/http/soak_bounded_growth_fuzz_test.go`): maps corpus bytes onto operation
  orderings and re-verifies audit-chain integrity and goroutine boundedness after every
  sequence, so coverage-guided fuzzing can explore operation orders for a crash,
  audit-chain break, or goroutine runaway.
