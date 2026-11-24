- **INV-CORE-dynamic-admin-dsn-every-write-checked** Every path that writes a dynamic-secret
  config's `admin_dsn` from caller input (`CreateDynamicSecretConfig`,
  `UpdateDynamicSecretConfigAdminDSN`) checks, before anything is stored: dynamic-secret admin
  authority of the actor at the config's scope (`requireDynamicSecretAdminAuthority`), the
  SSRF host guard (`enforceDynamicSecretSSRFGuard`), the refused local-file options
  (`dsn.CheckLocalFileOptions`) and the transport policy (`checkAdminDSNTransportOnSave`: a
  postgres/mysql DSN whose parsed driver config does not verify the server certificate is
  refused unless the operator allowed insecure transport, #4374; no soft period on save); it stores the DSN only encrypted, bound to the config's
  (id, project, environment), through the column-scoped `SetDynamicSecretConfigAdminDSN`; and
  no audit row, log line or error it produces carries the DSN. The replace commits in one
  transaction with its audit row, and while the config has an active or revoke_failed lease it
  must name the same revoke target as the stored DSN (`requireSameTargetWhileLeasesLive`,
  `dsn.RevokeTarget`: host and port with the driver's default port; for kubernetes api_server,
  namespace and revocable; a target that cannot be read on either side is refused): those leases
  are revoked through it, and a revoke on another server would mark them revoked while the role
  lives on. The read-only listing of configs with a refused option
  (`ListProjectConfigsWithRefusedAdminDSN`) has the same authority gate and returns config and
  option names only. Why: an update path that skipped one check would re-open what create closes
  (#162 authority, the SSRF guard, #3952 file options). Guard: `internal/core`
  `TestDynamicSecrets_UpdateAdminDSN_RefusesWhatCreateRefuses`, `_NonAdminRefused`,
  `_AuditFailureChangesNothing`, `_DSNNeverLeaves`, `_LiveLeasesPinTheHost`,
  `_LiveLeasesPinKubernetesTarget`, `internal/core/dsn` `TestRevokeTarget_*`,
  `TestDynamicSecrets_ListProjectRefusedAdminDSN_Gate` (SQLite, PostgreSQL pg-gated);
  `TestDynamicSecrets_CreateConfig_RefusesLocalFileOptions` for create;
  `TestDynamicSecrets_CreateConfig_RefusesSQLTransportThatDoesNotVerify`,
  `TestDynamicSecrets_UpdateAdminDSN_RefusesSQLTransportThatDoesNotVerify` for the transport
  policy. The transport check asks the engine (`ports.DynamicAdminDSNTransportInspector`); an
  engine that does not implement it is not checked (`TestNew_SQLEnginesCarryTheTransportPolicy`
  in internal/dynamic pins that the real postgres/mysql engines do).
  **Not covered**: a lease issued between the target check and the write; a third writer of
  `admin_dsn` added later is not detected by a static guard.
