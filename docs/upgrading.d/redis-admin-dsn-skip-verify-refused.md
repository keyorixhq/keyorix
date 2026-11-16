## Redis dynamic-secret configs whose `admin_dsn` has `skip_verify=true`

A Redis dynamic-secret config can carry `skip_verify=true` (or `skip_verify=1`) in its
`admin_dsn`, for example `rediss://:password@redis.internal:6380/0?skip_verify=true`.
go-redis then connects over TLS without checking the server certificate. From this
release (#4377):

- **Issue from such a config fails** with an error naming `skip_verify`, unless
  `dynamic_secrets.insecure_allow_plaintext_dynamic_secret_transport` is enabled. With
  that setting on, the connection is made and the server logs
  `WARNING: redis admin_dsn "<host:port>" has skip_verify=true`.
- **Saving such a DSN is not refused yet**: the check runs when a credential is issued,
  not when the config is created or updated.
- **Revoke and the expiry sweep still drop the leases**: with that setting off,
  `skip_verify` is removed and the certificate is verified. A target whose certificate is not trusted by the Keyorix
  server fails the handshake, and the lease stays `revoke_failed` with an error that
  names `skip_verify`.

What to do: give the Redis server a certificate the Keyorix server trusts, then replace
the stored `admin_dsn` without `skip_verify` using
`keyorix dynamic-secret set-admin-dsn <config-id>` (the DSN is read from
`KEYORIX_DYNAMIC_ADMIN_DSN` or stdin, never the command line). Delete by hand the ACL
user of every lease that stays `revoke_failed`: Redis ACL users never expire on their own.
