## MySQL admin DSNs with `compress=true`

The MySQL clients Keyorix builds for operator-supplied endpoints (dynamic MySQL credentials and
MySQL password rotation) now dial through a guard that bounds what a server can make the driver
allocate (#4567). The guard follows the plaintext packet framing and does not support the
compressed protocol, so from this release:

- **A MySQL `admin_dsn` or rotation DSN with `compress=true` fails to connect.** Issue, revoke
  and rotation against such a target fail with `invalid connection`; the server log carries the
  driver's `[mysql]` line `netutil: MySQL packet rejected: compressed protocol is not supported
  on a guarded connection`.
- **Saving such a DSN is not refused**: the failure appears at the first connection.

What to do: remove `compress=true` from the DSN (for a dynamic-secret config, replace the stored
`admin_dsn` with `keyorix dynamic-secret set-admin-dsn <config-id>`, which reads the DSN from
`KEYORIX_DYNAMIC_ADMIN_DSN` or stdin). Connections that use TLS (`tls=true` and the other `tls=`
modes) are not affected by this change.
