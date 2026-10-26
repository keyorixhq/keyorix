# PostgreSQL with the single binary

Use this when you run `keyorix-server` as a plain binary (no Docker) and want
PostgreSQL instead of SQLite. It replaces steps 4 to 7 of
[INSTALL-WITH-AI.md](../../INSTALL-WITH-AI.md) (the rest of that page is unchanged).
The reference for every key is [CONFIGURATION.md](../CONFIGURATION.md#storage);
the TLS rules are in [CONFIGURATION.md, PostgreSQL TLS](../CONFIGURATION.md#postgresql-tls).

## What you provide

- An **empty database** and a role that owns it (Keyorix creates the schema with
  `admin migrate`).
- A server that speaks **TLS**. The secure-baseline check
  (`admin validate --posture`) reports a connection with `sslmode=disable` as
  `storage.database.insecure_disable_database_tls`, and `prefer`/`allow` as
  `insecure_allow_plaintext_database_fallback`. Use `require` or, better,
  `verify-full` with the CA that signed the database's certificate.
- The database password in a **file** (mode 0600), not in the config, not in the DSN.

## Config keys

`storage.type` is the backend selector; the connection lives under `storage.database`.
Use **one** of two forms:

```yaml
storage:
  type: postgres
  database:
    # Form A: a DSN. Put the CA in the DSN; keep the password out of it.
    dsn: "host=db.internal port=5432 user=keyorix dbname=keyorix sslmode=verify-full sslrootcert=/etc/keyorix/pg-ca.pem"

    # Form B: fields (instead of dsn)
    # host: db.internal
    # port: "5432"
    # name: keyorix
    # user: keyorix
    # ssl_mode: verify-full
    # ssl_root_cert: /etc/keyorix/pg-ca.pem   # relative paths are relative to this file
```

- `ssl_root_cert` is for the field form. Next to a `dsn` it is refused: write
  `sslrootcert=` in the DSN instead. `ssl_mode` next to a `dsn` must equal the DSN's
  own `sslmode`.
- `verify-full` and `verify-ca` need the CA (a PEM path, or `system` for the OS store);
  without one the server and every `admin` command refuse to start.
- The generated config has no `path:` line for Postgres; do not add one.

## The password: `KEYORIX_DB_PASSWORD_FILE`

The password comes from the first of these that is set (setting two is an error, not a
silent choice): `KEYORIX_DB_PASSWORD`, `KEYORIX_DB_PASSWORD_FILE`, or
`storage.database.password`. Prefer the file form:

```bash
umask 077
printf '%s\n' 'THE-DATABASE-PASSWORD' > secrets/db_password   # one trailing newline is fine
```

Only the password has a `_FILE` form. There is no `KEYORIX_DB_DSN_FILE`: the DSN
holds no secret when the password is kept out of it, so it stays in `keyorix.yaml`.
A DSN that already carries a password together with `KEYORIX_DB_PASSWORD_FILE` is
refused. Export the variable for **every** `keyorix-server` command that opens the
database (`admin init`, `admin migrate`, `admin validate`, `admin backup`,
`admin restore`, ...) and for the service itself, next to
`KEYORIX_MASTER_PASSWORD_FILE`.

## Steps

Run from the install directory, after `admin generate-secrets` (step 3).

**`--storage-type` is newer than v0.96.3.** On v0.96.3 or older, `admin init` fails with
`unknown flag: --storage-type`, so the first command below does not work there. Instead run
plain `admin init --config ./keyorix.yaml` (it writes the config, the TLS files and an empty
SQLite database), then `rm -f keyorix.db keyorix.db-shm keyorix.db-wal keyorix.db.*.lock`, set
`storage.type: postgres` in `keyorix.yaml`, delete the `path:` line, add the `dsn:` line from
"Config keys", create `secrets/db_password`, and continue at step 2. On a build that has the
flag, use step 1 as written. Check which you have with `./bin/keyorix-server admin init --help`.

```bash
# 1. Write the config and TLS files WITHOUT a SQLite file (builds newer than v0.96.3).
./bin/keyorix-server admin init --storage-type postgres --config ./keyorix.yaml
```

This prints `Config written with storage.type: postgres and no SQLite file` and stops.
Now edit `keyorix.yaml` (the `dsn:` line above) and create `secrets/db_password`.

```bash
export KEYORIX_DB_PASSWORD_FILE=secrets/db_password
export KEYORIX_MASTER_PASSWORD_FILE=secrets/master_password

# 2. Run init again to finish (it now connects to the database).
./bin/keyorix-server admin init --config ./keyorix.yaml
./bin/keyorix-server admin encryption init --config ./keyorix.yaml
./bin/keyorix-server admin migrate --config ./keyorix.yaml
./bin/keyorix-server admin validate --posture --config ./keyorix.yaml   # expect: No deviations found.
```

Then continue with step 6 (recovery key) and step 8 (start the server) of
INSTALL-WITH-AI.md, keeping both variables set. `--storage-type` only applies to a
config that `init` writes; with an existing config of another type it refuses.

If you ran `admin init` **without** `--storage-type postgres` first, it created an
empty SQLite file. Delete it (`rm keyorix.db*`), set `storage.type: postgres`, and
continue as above. Nothing else in the directory depends on it.

## Errors you can meet

| Message (shortened) | Cause |
|---|---|
| `the sslmode in storage.database.dsn is verify-full but no CA certificate is configured` | add `sslrootcert=<pem>` (or `system`) to the DSN |
| `tls error: server refused TLS connection` | the database has TLS off; enable it, or (test databases on loopback only) accept the posture deviation with `sslmode=disable` |
| `storage.database.dsn already contains a password and KEYORIX_DB_PASSWORD_FILE is also set` | keep the password in one place |
| `postgres authentication failed for user ...` | wrong role or password; the message names the password sources |
| `1 deviation(s) ... insecure_disable_database_tls` | the connection is not encrypted; fix the database, not the check |

## Making the database speak TLS

Any PostgreSQL with `ssl = on` works. Keep these in mind:

- The server key must be owned by the user PostgreSQL runs as, mode 0600 (or 0640 with
  root ownership and group access on some distributions). A stock `postgres` container
  with a bind-mounted key owned by another user does not start.
- `verify-full` checks the host name: the certificate must list the name you put in
  `host=` (a DNS name or IP address in its subject alternative names).
- Give Keyorix the CA that signed the **server** certificate, as a PEM file with no
  private key, not writable by group or others.

A throwaway example for a test host (Docker; a CA and a server certificate valid for
`localhost` and `127.0.0.1`, files in `./pgtls`; the stock image runs as `postgres`, so the
wrapper copies the key into place with the right owner and mode):

```bash
mkdir pgtls && cd pgtls
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 -subj "/CN=test CA"
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost"
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > san.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.crt -days 2 -extfile san.ext
chmod 644 server.crt server.key ca.pem && cd ..

docker run -d --name pg -p 127.0.0.1:5432:5432 \
  -e POSTGRES_USER=keyorix -e POSTGRES_PASSWORD="$(cat secrets/db_password)" -e POSTGRES_DB=keyorix \
  -v "$PWD/pgtls:/certs:ro" --entrypoint sh postgres:15-alpine -c \
  'cp /certs/server.crt /certs/server.key /var/lib/postgresql/ \
   && chown postgres:postgres /var/lib/postgresql/server.* && chmod 600 /var/lib/postgresql/server.key \
   && exec docker-entrypoint.sh postgres -c ssl=on \
      -c ssl_cert_file=/var/lib/postgresql/server.crt -c ssl_key_file=/var/lib/postgresql/server.key'
```

Then use `sslmode=verify-full sslrootcert=$PWD/pgtls/ca.pem` in the DSN with `host=localhost`.

## What was verified, and what was not

Run on 2026-10-23 with a `keyorix-server` built from `main`, PostgreSQL through the
sandbox's `kpg` (a loopback test database without TLS):

- `admin init --storage-type postgres` created the config and TLS files and **no**
  `keyorix.db`; the second `admin init`, `admin encryption init` and `admin migrate`
  all ran with only `KEYORIX_DB_PASSWORD_FILE` supplying the password; the server
  started and `/health` answered `healthy`.
- `sslmode=verify-full` with no CA was refused, `sslmode=require` against a server
  without TLS failed with `server refused TLS connection`, and `sslmode=disable` was
  reported by `admin validate --posture` as `insecure_disable_database_tls`.

Verified 2026-10-23 on v0.96.3 (the release binaries, on the e2e VM, PostgreSQL 15 in the
container above with `ssl = on`):

- `admin init --storage-type postgres` fails there with `unknown flag: --storage-type`; the
  fallback in "Steps" (plain `admin init`, delete the SQLite files, edit the config) worked.
- DSN form with `sslmode=verify-full` and `sslrootcert=<ca.pem>`, password from
  `KEYORIX_DB_PASSWORD_FILE`: `admin init`, `admin encryption init` and `admin migrate` ran and no
  `keyorix.db` was recreated; `admin validate --posture` printed `No deviations found.`; the
  server started and `/health` answered `healthy`.
- `admin backup` ran beside the running server (78 tables, 2 key files); `admin restore` of that
  archive into a second database ended with `verify-audit on the restored database: VALID`.

Not run on a release: `admin init --storage-type postgres` (no release has the flag yet) and the
field form (Form B) with `ssl_root_cert`.
