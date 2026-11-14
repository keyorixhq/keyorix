- **INV-STORE-legal-hold-release-conditional** The only write to an existing `legal_holds`
  row is `ReleaseLegalHold`: one UPDATE of `released`, `released_by`, `released_at` and
  `release_reason`, conditional on `id = ? AND released = false`, reporting whether a row
  matched. No storage method writes a whole `LegalHold` struct back, so no caller holding a
  stale copy can set `released` back to false (re-activating a lifted hold) or overwrite the
  attribution of an earlier lift; a second lift matches no row and core refuses it with
  `ErrLegalHoldAlreadyReleased` and no audit row (#4210). Guard:
  `TestReleaseLegalHold_StaleUnreleasedWriteCannotReactivate`,
  `TestFullRowWriters_NarrowWriteSurvivesStaleTransition_ReleaseLegalHold` (SQLite and
  Postgres), the core `TestCTAReview_LegalHoldLift_SecondLifterRefused_CrossReplicaPostgres` /
  `TestLegalHoldLift_SecondLifterRefused_CrossReplicaSQLite`, and
  `TestFullRowWriteGuard_NoStaleFullRowWriteOnSecurityStateModels` (a new `Save` of a
  `LegalHold` fails it, `LegalHold` is security-state through `Released`). **Not covered**:
  raw SQL written outside `internal/storage/store` (the guard does not scan it) and the
  placement path (`CreateLegalHold`, guarded by the partial unique index, #305).
