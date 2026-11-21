## SQLite accepts `audit_durability: standard` (read audits only)

**Nothing changes unless you set it.** SQLite installs stay on `strict`, the
SQLite default, and open no extra connection.

Before: `storage.database.audit_durability: standard` (or the deprecated
`insecure_audit_skip_durable_sync: true`) on a SQLite backend refused to start
with `standard is only supported with PostgreSQL`.

Now (ADR-112 Amendment 7) a SQLite server set to `standard` starts and opens
one extra connection to the same database file with `synchronous=NORMAL`. The
audit flusher commits a batch on it only when every row is a successful
secret-value read audit (`secret.read`, `connect.secret_read`). Secret writes,
revocations, rotations, the audit rows of every mutation, denied reads and
mixed batches stay on the `synchronous=FULL` pool. The start-up log says so:

```
INFO: audit durability: standard (committed before every disclosure; secret mutations and their audit rows are synced to disk, successful read audits are not: ...)
storage: audit_durability standard: successful secret-read audits commit on a dedicated synchronous=NORMAL connection; every other transaction stays synchronous=FULL (ADR-112 Amendment 7)
```

What it costs: a server process crash still loses nothing. An OS crash or
power loss can lose the read-audit rows (and their access-log rows) committed
since the last disk sync, as a tail; never a gap or fork in the audit chain and
never a committed mutation. SQLite has no background WAL writer, so no timer
bounds that window; the next write or checkpoint ends it. On an in-memory
database the setting has no effect.

To stay as you are, do nothing, or write `audit_durability: strict`. The level
is recorded by the start-to-start settings diff like any other change.
