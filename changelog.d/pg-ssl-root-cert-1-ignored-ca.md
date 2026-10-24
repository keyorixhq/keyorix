### Security
- **A PostgreSQL CA that the connection would never check is refused.** With `ssl_mode: allow`
  or `prefer`, the driver loaded `storage.database.ssl_root_cert` (or a dsn's `sslrootcert`) but
  skipped certificate verification and could still fall back to plaintext, so a config naming a
  CA looked authenticated and was not. The server now **refuses to start** on a CA file with
  `ssl_mode` `disable`/`allow`/`prefer`, in the fields and in a `dsn` (a dsn with no `sslmode` is
  `prefer`), and on `sslrootcert=system` with `disable`. `system` with allow/prefer (the driver
  runs verify-full) and a CA with `require` (the chain is verified) are unchanged. The Helm chart
  fails the render on the same `externalDatabase.sslRootCert` shapes. New walk-through:
  docs/operator/postgres-tls.md (private CA, verify-full, wrong-CA check). **Upgrade note:** a
  config with a CA and `ssl_mode: prefer`/`allow` must switch to `ssl_mode: verify-full` (or drop
  the CA) before upgrading.
