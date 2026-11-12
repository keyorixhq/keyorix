### Security
- **Updated `jackc/pgx/v5` to v5.13.0 (from v5.11.0).** The update fixes a panic in
  `Rows.Values()` when a PostgreSQL server sends a DataRow with fewer values than its
  RowDescription declares (GHSA-w9rp-vfrh-q8vv, low: a malicious or compromised database server,
  or an on-path attacker without TLS, could crash a client that calls `Values()`). It also takes
  in the v5.12.0 fixes for `require_auth` / `channel_binding=require` being bypassable
  (GHSA-95fj-3fxw-g62g) and for SQL injection in simple-protocol batches (GHSA-j38q-h3ph-jjpq;
  Keyorix uses the extended protocol).
- **The server's own PostgreSQL client certificate is still never offered to a project
  `admin_dsn` target.** pgx v5.12.0 and later install the `sslcert`/`sslkey` (and default
  `~/.postgresql/postgresql.crt`, `PGSSLCERT`) certificate through a private loader that
  emptying the TLS config no longer stops, so the admin-DSN parse now also sets
  `sslcertmode=disable`. `TestPostgresEngineNeverPresentsTheServersDefaultClientCert` covers it.
- pgx v5.12.0 added `Tx()` to `pgx.BatchResults`; the audit-chain pipeline results reader
  implements it by returning nil, as it never begins a transaction through `pgx.Batch.BeginTx`.
