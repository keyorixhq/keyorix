- **INV-STORAGE-postgres-tls-trust-is-named** A PostgreSQL connection whose sslmode verifies
  the server (`verify-full`, `verify-ca`; from `storage.database.ssl_mode`, or from the `dsn` /
  `PGSSLMODE`) is only opened when the Keyorix config names the CA it verifies against:
  `storage.database.ssl_root_cert` (passed to pgx as `sslrootcert`) or `sslrootcert` inside the
  `dsn` — a PEM file that exists, is a regular file of at most 1 MiB, holds a certificate and no
  private key, and is not group/world-writable — or the explicit value `system`. Never the
  driver's implicit `PGSSLROOTCERT`, `~/.postgresql/root.crt` or OS store. `ssl_root_cert` with
  `dsn`, or with `ssl_mode: disable`, is refused rather than ignored. Enforced in
  `config.ValidateDatabaseTLS`, run by `Config.Validate` (server boot) AND by
  `config.BuildPostgresDSN`, which returns an error instead of a DSN — so every connection
  (`createPostgresStorage`, `OpenGormDB`, `serverguard`, admin restore/verify-audit) is checked
  even where `Validate` never ran. Why: PG-VERIFYFULL-1 (triage #3). Guard:
  `server/database_tls_startup_test.go:TestInitializeCoreService_PostgresVerifyFullWithoutCA_RefusesToStart`;
  `internal/config/database_tls_test.go` (`TestValidate_VerifyingSSLModeWithoutRootCert_RefusesToStart`,
  `_VerifyFull_ImplicitDriverCAIsNotEnough`, `_UnusableRootCert_RefusesToStart`,
  `_DSN_VerifyingModeNeedsSSLRootCert`, `TestBuildPostgresDSN_RefusesWhatValidateRefuses`);
  `factory_postgres_tls_test.go:TestCreateStorage_Postgres_VerifyFull_TrustedVsUntrustedCA`
  (real pgx + crypto/tls handshake: trusted CA completes, untrusted CA and wrong host name are
  refused, no CA opens no connection); drift between the check's DSN reader and pgx:
  `internal/config/database_tls_pgx_test.go:TestDSNTLSSettings_AgreesWithPgx`, and open-ended in
  the fail-open direction by
  `internal/config/database_tls_pgx_fuzz_test.go:FuzzDSNTLSSettings_NeverMissesPgxVerification`
  (the URL query starts where pgx finds it: after the userinfo and any bracketed IPv6 host, with
  no `#` fragment). The
  `(string, error)` signature of `BuildPostgresDSN` is the structural guard: a new caller cannot
  get a DSN without the check. `BuildPostgresDSN` quotes every field value it splices in, so no
  field (a password, user or database name) can append a later `sslmode`/`sslrootcert`/`host`
  that overrides the validated one: `TestBuildPostgresDSN_FieldValuesCannotInjectKeywords`
  (parsed by pgx). A FIFO named as the CA is refused without blocking boot:
  `TestLoadDatabaseCAPool_FIFORefusedWithoutBlocking`. PG-TLS-2: the sslmode is one pgx accepts
  (`validSSLModes`), `ssl_mode` next to a `dsn` must equal the dsn's own `sslmode`, and a dsn with
  no `sslmode` that names a connection service (`service=`, `PGSERVICE`) is refused rather than
  read from a service file Keyorix does not parse; every reader (validation, the insecure-settings
  registry, the posture line) shares one resolution, `resolveDatabaseTLS`:
  `internal/config/database_sslmode_test.go`, and against pgx's real plaintext fallback
  `TestDSNTLSSettings_AgreesWithPgx` (plaintext comparison) and
  `FuzzEffectiveSSLMode_NeverMissesPgxPlaintext`. **Not covered**: service-file settings other
  than sslmode (a service's `sslrootcert` can only add verification to a dsn that states its own
  sslmode, never remove it), and the file is re-read by pgx at connect
  time, so a CA replaced between the check and the connection is what pgx uses (only the
  owner/root can replace it, since a group/world-writable file is refused).
