### Security
- **Updated `jackc/pgx/v5` to v5.13.0.** Earlier versions panic in `Rows.Values()` when a
  PostgreSQL server sends a DataRow with fewer values than its RowDescription declares
  (GHSA-w9rp-vfrh-q8vv, low severity: a malicious or compromised database server, or an on-path
  attacker without TLS, could crash a client that calls `Values()`). v5.13.0 also adds
  `BatchResults.Tx()`; the audit-chain pipeline results reader implements it by returning nil, as
  it never begins a transaction through `pgx.Batch.BeginTx`.
