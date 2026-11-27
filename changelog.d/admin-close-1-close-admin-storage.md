### Fixed
- **Storage is closed by the code that opens it.** `admin migrate`, `admin restore` (migration steps), the audit-event helper of state-changing admin commands, `rotate-kek` / `migrate-provider` (audit key transition) and the server on graceful shutdown now close their storage, which on Postgres stops the background integrity check and releases the connections.

### Testing
- `server/admin` fails the package when a storage background job is still running after the last test, like `internal/storage`; tests that dropped their storage close it at cleanup.
- The key-lifecycle resource-guard red proof no longer depends on the benign runs growing the disk (closing storage can shrink it), so its meter ceiling has a floor.
