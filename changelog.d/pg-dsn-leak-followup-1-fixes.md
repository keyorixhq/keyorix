### Testing
- **Postgres test helpers and tests no longer print the test DSN's password on failure.** `pgdsn.PGReplaceDBName`'s panic on an unparseable URL DSN is a fixed message with no parse-error detail (a `*url.Error` quotes the whole URL, and its inner error can quote a password prefix when the password holds an unescaped `/` or `#`), and the assertions that compared passwords/DSNs derived from `KEYORIX_TEST_PG_DSN` (or printed the DSN in a failure message) now use fixed messages. Guarded by `TestPGReplaceDBName_PanicMessageHasNoPassword`.

### Documentation
- **`docs/CONFIGURATION.md` states exactly when `PGSSLMODE` applies.** It replaces the `prefer` default only for a `dsn` with no `sslmode` and no `ssl_mode`; it is ignored when the dsn names a mode and when no `dsn` is set.
