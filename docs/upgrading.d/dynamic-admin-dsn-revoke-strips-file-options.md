## Dynamic-secret configs whose `admin_dsn` names a server file

A dynamic-secret config stored before #3952 can carry an `admin_dsn` option that
makes the driver read a file on the Keyorix server: PostgreSQL `sslrootcert`,
`sslcert`, `sslkey`, `passfile`, `service`, `servicefile`; MySQL `allowAllFiles`;
MongoDB `tlsCAFile` and the other `tls*File` / `ssl*File` options, or an
`authMechanism` of `MONGODB-AWS`, `MONGODB-OIDC` or `GSSAPI`.

- **Issue and renew from such a config fail** with an error naming the option.
- **Revoke and the expiry sweep still drop its leases (#3980)**: the option is
  removed and the named file is never read. A CA file is replaced by the system
  trust store, so a target signed by a private CA fails the TLS handshake and
  the lease stays `revoke_failed` with the option named in the error. PostgreSQL
  `service`/`servicefile` and the MongoDB mechanisms above cannot be removed, so
  their leases stay `revoke_failed`.

After the upgrade, look for `WARNING: dynamic secrets:` in the server log at
startup: it counts these configs and their live leases and lists each config. A
stored `admin_dsn` cannot be edited: create a replacement config whose DSN names
no server file, and drop by hand the database user of every lease that stays
`revoke_failed`, especially on MongoDB and MySQL, whose users never expire on
their own. The full table is in
[CONFIGURATION.md](../CONFIGURATION.md#revoking-leases-of-a-config-whose-admin_dsn-names-a-server-file).
