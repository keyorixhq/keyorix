- **INV-FUZZCLOUD-db-no-tls-downgrade** Under the TLS-required mode Keyorix passes to a
  database driver, a hostile server that declines TLS must make the connection FAIL, never
  silently fall back to plaintext: for PostgreSQL (pgx) `sslmode=require` must reject a
  server answering `'N'` to the SSLRequest; for MySQL (go-sql-driver) a `tls=true` / TLS
  config must reject a server whose greeting clears the `CLIENT_SSL` capability flag. Why:
  Keyorix's dynamic-secret and rotation callers (`internal/dynamic/{postgres,mysql}.go`,
  `internal/rotation/*`) connect to operator-configured targets; a silent downgrade sends
  the admin credential in plaintext to an attacker. For PostgreSQL the storage layer also
  enforces this Keyorix-side (`config.ResolvePostgresConnConfig` + `finalTLSMismatch`,
  `internal/config/postgres_dsn.go`). Guard: `TestPgxTLSRequireRejectsPlaintext` (+ `_RedProof`)
  and `TestMySQLTLSRequiredRejectsNoSSLFlag` (+ `_RedProof`) — each asserts the required mode
  fails and its red proof shows the SAME server completes a plaintext connection when the
  mode is downgraded (not vacuous). Does NOT assert certificate / hostname verification
  (the MySQL test uses InsecureSkipVerify), nor the operator-DSN parsing that decides
  whether TLS is required — only the driver's refusal to downgrade once it is.
