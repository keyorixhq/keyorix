- **INV-STORAGE-postgres-tls-trust-is-named** A PostgreSQL connection whose sslmode verifies
  the server (`verify-full`, `verify-ca`; from `storage.database.ssl_mode`, or from the `dsn` /
  `PGSSLMODE`) is only opened when the Keyorix config names the CA it verifies against:
  `storage.database.ssl_root_cert` (passed to pgx as `sslrootcert`) or `sslrootcert` inside the
  `dsn` — a PEM file that exists, is a regular file of at most 1 MiB, holds a certificate and no
  private key, and is not group/world-writable — or the explicit value `system`. Never the
  driver's implicit `PGSSLROOTCERT`, `~/.postgresql/root.crt` or OS store. `ssl_root_cert` with
  `dsn`, or with `ssl_mode: disable`, is refused rather than ignored. Enforced in
  `config.ValidateDatabaseTLS`, run by `Config.Validate` (server boot) AND by
  `config.ResolvePostgresDSN`, which returns an error instead of a DSN — so every connection
  (`createPostgresStorage`, `OpenGormDB`, `serverguard`, admin restore/verify-audit) is checked
  even where `Validate` never ran. Why: PG-VERIFYFULL-1 (triage #3). Guard:
  `server/database_tls_startup_test.go:TestInitializeCoreService_PostgresVerifyFullWithoutCA_RefusesToStart`;
  `internal/config/database_tls_test.go` (`TestValidate_VerifyingSSLModeWithoutRootCert_RefusesToStart`,
  `_VerifyFull_ImplicitDriverCAIsNotEnough`, `_UnusableRootCert_RefusesToStart`,
  `_DSN_VerifyingModeNeedsSSLRootCert`, `TestResolvePostgresDSN_RefusesWhatValidateRefuses`);
  `factory_postgres_tls_test.go:TestCreateStorage_Postgres_VerifyFull_TrustedVsUntrustedCA`
  (real pgx + crypto/tls handshake: trusted CA completes, untrusted CA and wrong host name are
  refused, no CA opens no connection); drift between the check's DSN reader and pgx:
  `internal/config/database_tls_pgx_test.go:TestDSNTLSSettings_AgreesWithPgx`, and open-ended in
  the fail-open direction by
  `internal/config/database_tls_pgx_fuzz_test.go:FuzzDSNTLSSettings_NeverMissesPgxVerification`
  (the URL query starts where pgx finds it: after the userinfo and any bracketed IPv6 host, with
  no `#` fragment). The
  `(string, error)` signature of `ResolvePostgresDSN` is the structural guard: a new caller cannot
  get a DSN without the check. `ResolvePostgresDSN` quotes every field value it splices in, so no
  field (a password, user or database name) can append a later `sslmode`/`sslrootcert`/`host`
  that overrides the validated one: `TestResolvePostgresDSN_FieldValuesCannotInjectKeywords`
  (parsed by pgx). A FIFO named as the CA is refused without blocking boot:
  `TestLoadDatabaseCAPool_FIFORefusedWithoutBlocking`. A connection service is refused, not
  resolved: `service=`/`servicefile=` in the dsn (either form) or `PGSERVICE` in the environment
  make pgx merge a service file's sslmode/sslrootcert/host in behind the check, so
  `ValidateDatabaseTLS` refuses them (`TestValidateDatabaseTLS_ConnectionServiceIsRefused`;
  `TestConnectionService_PgxVerifiesWhatTheConfigNeverNamed` shows the bypass; the fuzz target
  above carries a verify-full service file). `PGSERVICEFILE` alone is inert (pgx reads it only when
  a service is selected) and is not refused. **Not covered**: the CA file is re-read by pgx at
  connect time, so a CA replaced between the check and the connection is what pgx uses (only the
  owner/root can replace it, since a group/world-writable file is refused).
