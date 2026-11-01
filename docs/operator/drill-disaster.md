# Disaster drills

`scripts/drills/disaster.sh` rehearses three failures on throwaway instances with real
binaries (shared helpers and environment: [upgrade drill](drill-upgrade.md)). The rule it
checks: the server either recovers or fails closed with a clear message, and nothing it
acknowledged is lost.

```sh
scripts/drills/disaster.sh                                   # SQLite: kill9 + diskfull
DRILL_BACKEND=postgres DRILL_PG_DSN_FILE=a.txt DRILL_PG_DSN_FILE2=b.txt \
  scripts/drills/disaster.sh                                 # PostgreSQL: kill9 + pgdown
DRILL_SCENARIOS=kill9 scripts/drills/disaster.sh             # pick scenarios
```
(Each PostgreSQL scenario needs its own EMPTY database; the URL files hold
`postgres://user:password@host:port/db`.)

## Which backend each drill covers

Every drill under `scripts/drills/` runs on SQLite (the default) and on PostgreSQL
(`DRILL_BACKEND=postgres`) unless the table says otherwise. A leg a backend does not cover
prints `SKIP <backend>: <reason>` and the drill carries on; a failed check exits non-zero.
The same table, with run times and what each drill proves, is in `scripts/drills/README.md`.

| Drill | Backends covered |
| --- | --- |
| `accept-loss.sh` | sqlite, postgres (step 6, the host witness file, is SQLite only: `SKIP postgres`) |
| `upgrade.sh` | sqlite, postgres |
| `backup-restore.sh` | sqlite, postgres (needs `DRILL_PG_DSN_FILE2`; the tamper leg also `DRILL_PG_DSN_FILE3`, else `SKIP postgres`) |
| `key-rotation.sh` | sqlite, postgres (needs `DRILL_PG_DSN_FILE2`) |
| `disaster.sh` `kill9` | sqlite, postgres |
| `disaster.sh` `pgdown` | postgres only (`SKIP sqlite`; needs `DRILL_PG_DSN_FILE2` or `DRILL_PG_DSN_FILE`) |
| `disaster.sh` `diskfull` | sqlite only (`SKIP postgres`) |
| `rotation-under-load.sh` | sqlite, postgres |
| `kill9-soak.sh` | sqlite, postgres |
| `selftest.sh` | none (no server; helper functions and a static scan of these scripts) |

## kill9: SIGKILL under write load

Four writers create secrets in a loop; the server is killed with `kill -9`; three rounds.
After every kill: the restart needs no `--force` (no stale lock to clear), every write the
server acknowledged is present, a write that was in flight is either whole or absent, the
seeded data still decrypts, MFA login and machine tokens work, and `admin verify-audit` is
VALID. What to expect in production: just start the server again. An acknowledged write is
committed; the client that saw a connection error should retry (a retried create can then
report a name clash if the first attempt did land).

SQLite note: after a stop, committed data may still sit in `keyorix.db-wal`, and the main
file can look tiny. Never copy `keyorix.db` alone as a backup or for `verify-audit --db`:
copy the `-wal` and `-shm` files with it, or use `admin backup`.

## pgdown: PostgreSQL goes away and comes back

The drill cannot restart a shared database, so it puts a TCP forwarder
(`scripts/drills/tools/tcpproxy.go`) between the server and PostgreSQL and takes it down
(open connections reset, new ones refused) and up again, which is what a PostgreSQL restart
looks like from the server. During the outage: reads and writes are refused and never
reported as successes, nothing hangs, the server does not panic. The server holds a
process-wide advisory lock on its database connection; when that connection is lost the
server shuts itself down gracefully (fail closed, so an admin command cannot run beside a
server that no longer holds the lock). A request that arrives before it has gone gets a
retryable `503` rather than a `401`. After the database is back: restart the server (the
drill does) and it serves and accepts writes again, nothing acknowledged is lost, the audit
chain verifies. Alert on a stopped server and on a rise in `503`, not on `401`. The
permission lookup behind an authenticated request answers the same way where a middleware
gate performs it (and over gRPC, `Unavailable`): a retryable `503`, not a `403` that no
client retries. Routes that check the permission inside the REST handler (for example
secret create) still answer `403` until a follow-up change.

## diskfull: the data directory fills up

A full filesystem cannot be made without a privileged mount, so the server runs under
`ulimit -f` just above the SQLite file size: growing a file past it fails like `ENOSPC` on
the write. Expect: writes are refused with an error (log: `Storage operation failed: disk
I/O error`), the server stays up and keeps serving what it can, and a secret read whose
audit row cannot be written is refused (`SECURITY: audit write failed for secret read ...
failing closed, value NOT returned`): the drill checks that every value handed out has its
audit row. Free space (or raise the limit) and restart: all accepted writes are there, new
writes work, `verify-audit` is VALID. Check disk space and `df` alerts before it gets here:
once audit writes fail, reads fail too.

## Not covered (pending a run on the e2e VM)

A real `docker restart postgres`, a really full filesystem or volume, PostgreSQL's own disk
full, and the Compose / Helm / Kubernetes variants of these failures.
