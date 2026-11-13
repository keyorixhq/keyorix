- **INV-CORE-dynamic-admin-dsn-every-write-checked** Every path that writes a dynamic-secret
  config's `admin_dsn` from caller input (`CreateDynamicSecretConfig`,
  `UpdateDynamicSecretConfigAdminDSN`) checks, before anything is stored: dynamic-secret admin
  authority of the actor at the config's scope (`requireDynamicSecretAdminAuthority`), the
  SSRF host guard (`enforceDynamicSecretSSRFGuard`) and the refused local-file options
  (`dsn.CheckLocalFileOptions`); it stores the DSN only encrypted, bound to the config's
  (id, project, environment), through the column-scoped `SetDynamicSecretConfigAdminDSN`; and
  no audit row, log line or error it produces carries the DSN. The replace commits in one
  transaction with its audit row. Why: an update path that skipped one check would re-open what create closes
  (#162 authority, the SSRF guard, #3952 file options). Guard: `internal/core`
  `TestDynamicSecrets_UpdateAdminDSN_RefusesWhatCreateRefuses`, `_NonAdminRefused`,
  `_AuditFailureChangesNothing`, `_DSNNeverLeaves` (SQLite, PostgreSQL pg-gated);
  `TestDynamicSecrets_CreateConfig_RefusesLocalFileOptions` for create.
  **Not covered**: a third writer of `admin_dsn` added later is not detected by a static guard.
