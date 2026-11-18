### Security
- **Postgres dynamic-secret backends bound the message length a target server may claim.**
  The `admin_dsn` host is project-admin input, and pgx sizes its read buffer from the length a
  server announces in a message header before any body byte arrives (its own ceiling is ~1 GiB).
  A rogue or compromised target could therefore make the Keyorix server allocate ~775 MB with a
  5-byte header, ~1.5 GB peak RSS over repeated connections, and OOM-kill a 512 MiB container
  within three `issue`, `renew` or `revoke` calls. `internal/dynamic` now caps a single protocol
  message body at 16 MiB (`internal/pgxlimits`); an over-long claim fails the connection with
  pgx's `ExceededMaxBodyLenErr` instead of allocating. Guarded by
  `TestPostgresEngineBoundsServerClaimedMessageLength` (asserts the allocation, not only the
  error) and `TestEveryPgxConnectInDynamicUsesTheBoundedConfig`. The MySQL backends were measured
  and are not affected the same way (peak RSS stays flat); they are unchanged.

### Testing
- **pgx and MySQL hostile-server fuzz budgets model server-claimed lengths.** The RESGUARD alloc
  budgets for the length-prefixed protocol parsers were a per-input-byte slope, so every input
  whose header claims a large body failed, which is why `fuzz-changed` went red on unrelated PRs
  that touch those targets. The pgx harness now builds its connection config with the same bound
  production uses, the four length-prefixed pgx targets and the three MySQL targets use an
  absolute ceiling derived from that bound (MySQL: the protocol's 16 MiB per-packet maximum), and
  the pgx process is warmed once so the first metered input no longer pays one-time
  initialisation (`FuzzPgxSSLNegotiation` failed on its 1-byte seed).
