## MongoDB dynamic-secret configs whose `admin_dsn` has `tlsInsecure=true`

A MongoDB dynamic-secret config can carry `tlsInsecure=true` (or its alias
`sslInsecure=true`, in any option-name case) in its `admin_dsn`, for example
`mongodb://admin:password@mongo.internal:27017/?tls=true&tlsInsecure=true`. The driver
then connects over TLS without checking the server certificate or host name. From this
release (#4374):

- **Issue from such a config fails** with an error naming `tlsInsecure`, unless
  `dynamic_secrets.insecure_allow_plaintext_dynamic_secret_transport` is enabled. With
  that setting on, the connection is made and the server logs
  `WARNING: mongodb admin_dsn host "<host>" has tlsInsecure=true`.
- **Saving such a DSN is not refused yet**: the check runs when a credential is issued
  or revoked, not when the config is created or updated.
- **Revoke and the expiry sweep still drop the users**: with that setting off,
  `tlsInsecure` is removed and the certificate is verified. A target whose certificate
  is not trusted by the Keyorix server fails the handshake, and the lease stays
  `revoke_failed` with an error that names `tlsInsecure`. MongoDB users have no native
  expiry, so such a user stays able to log in until it is dropped.
- **A `mongodb+srv://` `admin_dsn` that turns TLS off** with `TLS=false` or `SSL=false`
  (any case other than lower case) is now refused like `tls=false`, unless the same
  setting is enabled.

What to do, before or after upgrading:

- Before upgrading, you can revoke the leases issued from such configs while the old
  release still connects to the target.
- Give the MongoDB server a certificate the Keyorix server's system trust store accepts
  (an `admin_dsn` cannot name a CA file: `tlsCAFile` is refused on issue and removed on
  revoke), then replace the stored `admin_dsn`
  without `tlsInsecure` using `keyorix dynamic-secret set-admin-dsn <config-id>` (the
  DSN is read from `KEYORIX_DYNAMIC_ADMIN_DSN` or stdin, never the command line).
- Drop by hand (`db.dropUser("<username>")` in the `admin` database) the MongoDB user of
  every lease that stays `revoke_failed`.
