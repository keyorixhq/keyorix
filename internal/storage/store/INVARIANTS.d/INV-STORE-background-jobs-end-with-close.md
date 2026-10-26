- **INV-STORE-background-jobs-end-with-close** Every goroutine a `LocalStorage` starts in the
  background (`StartAuditListIndexBuild`, `StartRolePermissionsGenerationIntegrityCheck`) is
  created through `newBackgroundJob` and is gone when `Close` returns: `Close` cancels it and
  waits for `done`, and the goroutine deregisters itself (`backgroundJob.exit`) before closing
  `done`. `LiveBackgroundJobs` lists every job still running with the stack that started it.
  Every test that builds a Postgres storage closes it (`createStorageClosedAtCleanup` in
  `internal/storage` and `internal/storage/store`), and both packages' `TestMain` fail the run
  when `LiveBackgroundJobs` is not empty after the last test. Why: FIX-3631-RACE-1 (merge-group
  run 40288380028). Tests that never closed a factory-built Postgres storage left the integrity
  check running for the rest of the test binary; after their database was dropped it logged an
  error through the global logger every interval, into the log buffer a later test had swapped
  in (`TestCreateLocalStorage_ExistingPath_LogsOpeningExisting`), and `-race` failed the run at
  random. The TestMain check does not depend on `-race` timing. Residual, stated: it only sees
  jobs on Postgres (`KEYORIX_TEST_PG_DSN` set), only in these two packages, and only goroutines
  started through `newBackgroundJob` (not the audit flusher). Other packages that build Postgres
  storage through the factory are not checked. Guard:
  `TestCreateStorage_Postgres_CloseStopsBackgroundJobs` (pg-gated), the `TestMain` of
  `internal/storage` (`background_job_leak_main_test.go`) and of `internal/storage/store`
  (`account_store_test.go`).
