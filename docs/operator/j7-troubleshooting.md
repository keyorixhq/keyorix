# Troubleshooting common startup failures

What each of these looks like, and what to do about it. The messages are quoted from the
server; paths and addresses differ on your install.

First step for any start-up failure: `keyorix-server admin diagnose --config ./keyorix.yaml`
runs the checks server start-up depends on (config parse, encryption key access, database
open, migration state) and reports which one fails, without starting a listener. It needs
the master passphrase like the server does. It creates no keys: pointed at a directory with
no key files it stops with `[FAIL] KEK/passphrase access: key file <abs path>/kek.salt does not
exist; key file <abs path>/dek.key does not exist. diagnose is read-only and does not create
keys; ...`, naming each missing file by absolute path, and leaves the salt, the DEK and
`dek.lock` uncreated (`keyorix-server admin encryption init` creates the keys of a new
install). When the schema is behind the binary it ends with
`The database schema is behind this binary; run keyorix-server admin migrate before starting.`
Exit status 0 means every check that can stop the boot passed, WARN lines included.

**The server refuses to start, or an `admin` command stops with `Error:`?** Every
fail-closed refusal (configuration, TLS, key files, schema epoch, locks, backup/restore)
is listed with its message, cause and fix in [startup-refusals.md](startup-refusals.md).
The sections below cover three of them in more detail plus failures that are not refusals.

## Wrong or typo'd config value

```yaml
storage:
  type: sqllite  # typo
```

```
Configuration is invalid: invalid storage.type "sqllite": must be one of "local", "sqlite", "postgres", "postgresql", or "remote"
```

Fix the value to one of the ones listed and restart. Nothing else to do.

## Postgres unreachable

```yaml
storage:
  type: postgres
  database:
    dsn: "host=localhost user=keyorix dbname=keyorix port=59999 sslmode=disable"
```

```
failed to connect to postgres: failed to connect to `user=keyorix database=keyorix`:
	[::1]:59999 (localhost): dial error: dial tcp [::1]:59999: connect: connection refused
	127.0.0.1:59999 (localhost): dial error: dial tcp 127.0.0.1:59999: connect: connection refused
```

The server exits with status 75 and ends with `keyorix-server: exit 75 (dependency unavailable)`
(the shipped systemd unit retries it every 30 s; see
[startup-refusals.md](startup-refusals.md#exit-statuses)). An `admin` command (for example `admin validate`) reports the
same cause after the prefix `cannot connect to the database to check for a running server:
connect to postgres for server-presence check:`.

The exact host/port that failed is in the message — check Postgres is actually running
and reachable at that address, and that `storage.database.dsn` (or `host`/`port`) matches
your real deployment.

## Port already in use

```
HTTP server error: HTTP server failed to start: failed to bind HTTP listener: listen tcp 127.0.0.1:18080: bind: address already in use
```

Something else (possibly an earlier `keyorix-server` you thought you'd stopped) is
already listening on that port. Check for it before assuming your config is wrong:

```bash
lsof -i :8080 -sTCP:LISTEN
```

The server that failed to bind exits with status 1 (checked on the current tree; an earlier
version of this page described it as staying alive). If you see
`another process already holds the DEK lock` on a retry, an earlier server is still
running against the same data directory: find and stop it (the `lsof` command above), and
see [startup-refusals.md](startup-refusals.md#another-process-holds-the-key-lock).

## An admin command while the server is (still) running

```
Error: a Keyorix server (or another admin command) appears to be using this database (another process holds this database (a live server, or another admin command) via <path>/keyorix.db.server.lock) — admin commands must not run concurrently with either; stop it first, or pass --force if you are certain this is safe.
Run admin commands with the server stopped: stop the server (for example 'systemctl stop keyorix'), run this command again, then start the server.
```

Inside the Docker Compose container the second line is replaced by the Compose recipe
(`docker compose stop backend`, `docker compose run --rm backend ./keyorix-server admin <command>`,
`docker compose start backend`). The exit status is 1.

This is exactly right — every `admin` subcommand (`init`, `migrate`, `backup`,
`encryption rotate`, ...) needs the database to itself. Stop the server, or confirm you
really mean to run alongside it and pass `--force`.

`keyorix.db.server.lock` is never a stale lock file: the lock on it is an `flock` that
ends when its holder process exits. **Do not delete it.** Deleting it does not release
the lock; the running server keeps it on the deleted file. Within 5 seconds the server
notices, re-creates the file and takes the lock again, logging
`serverguard: WARNING: <path>/keyorix.db.server.lock was deleted or replaced while this server held it`.
If an admin command created the new file and took it first, the server stops instead
(`serverguard presence lock: ... an admin command now holds the new file exclusively, so the lock is lost`,
then `ERROR: the server-presence lock was lost ...`, exit status 1) rather than serve beside
it; your supervisor restarts it, and it refuses to start until the admin command
finishes. An admin command that starts and finishes inside those 5 seconds still ran
beside the server. A run with `--force` without the lock is recorded as such in its
audit event.

The same holds the other way round. If the file is deleted or replaced while an admin
command runs, the command notices within 5 seconds and takes the new file, so no
server can start. Then it stops with exit status 1
(`serverguard admin exclusive lock: ... was deleted or replaced while this admin command held it ...`,
then `ERROR: this admin command's exclusive database lock was lost ...`). Check that no
server or admin command started meanwhile, then re-run the command.

On a filesystem without `flock` support or without inode numbers (some network and FUSE
mounts), the server and every admin command refuse to start with an error saying so: put
the SQLite database on a local filesystem, or use PostgreSQL.

## Expired TLS certificate

The server checks its own certificate when it starts. It still starts and serves with an
expired one (so a renewal can happen with the listener up), but it logs, at start:

```
WARNING: /etc/keyorix/tls/server.crt: TLS certificate expired on 2020-01-02T00:00:00Z (system clock reads 2026-11-14T13:22:23Z): clients that check expiry will refuse this server; renew the certificate, or set the clock if it is wrong
```

A certificate that is close to expiry logs `TLS certificate expires on <date> (within <n> days): renew it`.
The check runs at start only: a server that has been up since before the certificate expired
logs nothing more. `deploy/observability/prometheus-alerts.yaml` has alerts for a listener
certificate that expires within 14 and 3 days.

Clients refuse the connection. The message depends on whether they trust the issuing CA:

```
$ curl https://your-server/health
curl: (60) SSL certificate problem: certificate has expired

$ keyorix login --server https://your-server --username alice --ca-file ca.pem
Error: cannot trust the TLS certificate of the Keyorix server at https://your-server (tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-11-14T14:22:41+01:00 is after 2020-01-02T00:00:00Z). Next step: ...
```

`x509: certificate signed by unknown authority` means the client does not trust the CA
(for a private CA, pass `--ca-file`), not that the certificate expired. Check the certificate's
own dates directly rather than assuming a network problem:

```bash
openssl x509 -in /path/to/server.crt -noout -dates
```
