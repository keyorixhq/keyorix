# PostgreSQL TLS: verify-full with your own CA

How to make the Keyorix server authenticate its PostgreSQL server: the
connection is encrypted **and** the database's certificate is checked against
a CA you name, including the host name. The key reference (every `ssl_mode`
value, the `dsn` form, `system`) is "PostgreSQL TLS" in
[CONFIGURATION.md](../CONFIGURATION.md#postgresql-tls); this page is the
walk-through.

The two keys:

```yaml
storage:
  type: postgres
  database:
    host: db.internal
    ssl_mode: verify-full              # encrypt, check the chain AND the host name
    ssl_root_cert: /etc/keyorix/pg-ca.pem   # the CA that signed the database's certificate
```

`ssl_root_cert` is a path to a PEM file (relative paths are relative to the
config file's directory), or `system` for the OS CA store. There is no
environment variable for it; it is set in the config file, like the rest of
`storage.database`.

## Example: a private CA, start to finish

### 1. Make a CA (once; keep `pg-ca.key` offline)

```sh
openssl ecparam -name prime256v1 -genkey -noout -out pg-ca.key
openssl req -x509 -new -sha256 -days 3650 -key pg-ca.key \
  -subj "/CN=keyorix-db-ca" -out pg-ca.pem
```

### 2. Issue the database server's certificate

The subject alternative name must contain the exact name the Keyorix server
uses in `storage.database.host`: `verify-full` checks it.

```sh
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -sha256 -key server.key -subj "/CN=db.internal" -out server.csr
printf 'subjectAltName=DNS:db.internal\nextendedKeyUsage=serverAuth\n' > server.ext
openssl x509 -req -sha256 -days 825 -in server.csr -CA pg-ca.pem -CAkey pg-ca.key \
  -CAcreateserial -extfile server.ext -out server.crt
openssl verify -CAfile pg-ca.pem server.crt     # server.crt: OK
```

### 3. Turn TLS on in PostgreSQL

Copy `server.crt` and `server.key` to the database host. The key must be owned
by the `postgres` user (or root) and not readable by others (`chmod 600`).
In `postgresql.conf`:

```
ssl = on
ssl_cert_file = '/etc/postgresql/tls/server.crt'
ssl_key_file  = '/etc/postgresql/tls/server.key'
```

Optionally, so that no client can connect in plaintext, use `hostssl` instead
of `host` for the Keyorix user in `pg_hba.conf`. Reload PostgreSQL
(`SELECT pg_reload_conf();`).

### 4. Point Keyorix at the CA

Put `pg-ca.pem` (the CA certificate only, never `pg-ca.key`) next to the
config, readable by the server's user and **not writable by group or others**
(`chmod 644`), and set:

```yaml
    host: db.internal
    ssl_mode: verify-full
    ssl_root_cert: pg-ca.pem
```

`keyorix-server admin validate --posture` prints one line saying what is
verified:

```
database TLS: storage.database.ssl_mode=verify-full -- encrypted; certificate chain and host name verified against CA file /etc/keyorix/pg-ca.pem (1 certificate(s))
```

### 5. Check that a wrong CA fails

Point `ssl_root_cert` at any other CA (for example a second one made with
step 1) and start the server. It cannot connect:

```
tls: failed to verify certificate: x509: certificate signed by unknown authority
```

A `host` that is not in the certificate's SAN fails the same way, with
`x509: certificate is valid for db.internal, not <host>`. Neither falls back to
an unverified or plaintext connection. Put the right CA back.

## What the server refuses at start-up

| Config | Why it is refused |
|---|---|
| `ssl_mode: verify-full` or `verify-ca` with no `ssl_root_cert` | the driver would verify against whatever it finds on the host (`PGSSLROOTCERT`, `~/.postgresql/root.crt`, the OS store) |
| `ssl_root_cert` that is missing, not a regular file, empty, over 1 MiB, holds a private key, or is group/world-writable | never a fallback to other roots |
| `ssl_root_cert` with `ssl_mode: disable` | no TLS at all |
| a CA file with `ssl_mode: allow` or `prefer` (or a `dsn` with `sslrootcert` and `sslmode` allow/prefer/none) | the driver loads the CA but never checks the certificate against it, and may fall back to plaintext |
| `ssl_root_cert` together with `dsn` | the dsn is used as-is; put `sslrootcert=` in the dsn |

`ssl_mode: require` with a CA file is accepted: the driver then checks the
chain (as `verify-ca` does) but not the host name. Use `verify-full`.

The exact messages and fixes are in
[startup-refusals.md](startup-refusals.md) ("Database TLS").

## Docker Compose and Helm

- **Docker Compose** (`docker-compose.yml`): already verify-full.
  `scripts/selfhost/init-secrets.sh` generates `secrets/postgres_tls.crt`/`.key`;
  the `postgres` service runs with `ssl=on` and that pair, and the backend
  mounts the certificate as a secret and names it in `ssl_root_cert`
  (`ssl_mode: verify-full`, host `postgres`). See
  [SELF_HOSTING.md](../SELF_HOSTING.md) for rotation.
- **Helm, external database**: put the CA in a Secret and let the chart mount
  it read-only (mode 0440) at `/app/db-ca/ca.crt` and render it as
  `ssl_root_cert`:

  ```sh
  kubectl create secret generic pg-ca --from-file=ca.crt=./pg-ca.pem
  helm upgrade --install keyorix deploy/helm/keyorix \
    --set postgresql.enabled=false \
    --set externalDatabase.host=db.internal \
    --set externalDatabase.sslMode=verify-full \
    --set externalDatabase.caSecret.name=pg-ca
    # ...plus your usual auth.* and database password settings
  ```

  The rendered config then has `ssl_mode: verify-full` and
  `ssl_root_cert: "/app/db-ca/ca.crt"`.

  `externalDatabase.sslRootCert` takes `system` or a path you mount yourself
  instead. `helm template` fails on the shapes the server would refuse
  (verify-full with no CA, a CA with `sslMode` disable/allow/prefer). The
  server reads the CA when it opens its pool: after rotating the Secret,
  `kubectl rollout restart` the server.
