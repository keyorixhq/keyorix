## PostgreSQL and MySQL dynamic-secret `admin_dsn`s must verify the server certificate

Until this release the operator's transport policy,
`dynamic_secrets.insecure_allow_plaintext_dynamic_secret_transport`, applied only to MongoDB
and Redis targets. From this release (#4374) it applies to PostgreSQL and MySQL targets too:
with the setting off (the default) an `admin_dsn` is accepted only if its connection verifies
the server certificate.

| Backend | Accepted | Refused |
|---|---|---|
| `postgres` | `sslmode=verify-full`, `sslmode=verify-ca` | `sslmode=disable`, `allow`, `prefer`, `require`, and no `sslmode` at all (the driver's default is `prefer`). A `PGSSLMODE` environment value of the Keyorix server counts as if it were in the DSN. |
| `mysql` | `tls=true` | `tls=false`, no `tls` at all (the driver's default is plaintext), `tls=skip-verify`, `tls=preferred`, `allowFallbackToPlaintext=true` |

The check reads the connection settings the database driver builds from the DSN, not the DSN
text, so every spelling of these settings is covered.

**Who is affected:** project admins whose PostgreSQL or MySQL dynamic-secret configs use one of
the refused settings, which includes every PostgreSQL `admin_dsn` without `sslmode` and every
MySQL `admin_dsn` without `tls=true`.

What changes:

- **Creating a config or replacing its `admin_dsn` with a refused setting fails at once**, with
  an error that names the setting (for example `admin_dsn option "sslmode=prefer" is not
  allowed for postgres backends`), never the DSN.
- **A config stored before the upgrade keeps issuing for this release.** Every issue from it
  writes a `dynamic_lease.insecure_transport` audit event naming the config and the setting,
  and the server logs `WARNING: postgres admin_dsn has sslmode=prefer: ... accepted only during
  the upgrade grace period and will be refused in the next release`. In the next release issue
  from such a config is refused (`dsn.StoredSQLTransportGrace` is set to false).
- **Revoke and the expiry sweep keep working during this release** exactly as issue does. From
  the next release, with the setting off, revoke replaces the refused setting by a verified TLS
  connection instead of refusing; a target whose certificate the Keyorix server does not trust
  then fails the handshake and the lease stays `revoke_failed` with an error that names the
  setting.
- **With `dynamic_secrets.insecure_allow_plaintext_dynamic_secret_transport: true`** every
  setting is accepted, as before; each save writes a `dynamic_secret.config_insecure_transport`
  audit event, each issue a `dynamic_lease.insecure_transport` audit event, and each connection
  logs a WARNING that names the backend and the setting.

What to do, during this release:

1. Give the database server a certificate that the Keyorix server's system trust store
   accepts (an `admin_dsn` cannot name a CA file: `sslrootcert` is refused). For PostgreSQL
   a root certificate in the Keyorix server's `PGSSLROOTCERT` or `~/.postgresql/root.crt` also
   works.
2. Replace each affected `admin_dsn` with `sslmode=verify-full` (PostgreSQL) or `tls=true`
   (MySQL): `keyorix dynamic-secret set-admin-dsn <config-id>` (the DSN is read from
   `KEYORIX_DYNAMIC_ADMIN_DSN` or stdin, never the command line). Find the affected configs in
   the audit log (`dynamic_lease.insecure_transport`) or in the server log (the WARNING above).
3. Only if a target truly cannot use verified TLS (a legacy database on a trusted network),
   the operator can set `dynamic_secrets.insecure_allow_plaintext_dynamic_secret_transport:
   true` instead. It applies to every dynamic-secret backend, MongoDB and Redis included.
