### Security
- **Redis dynamic secrets refuse `skip_verify=true` in the `admin_dsn`.** go-redis turns
  certificate verification off for `rediss://...?skip_verify=true` (or `=1`), which still
  passed the TLS requirement, so a project admin who sets the `admin_dsn` could undo the
  operator's transport policy without a log line. Issue now fails with a
  forbidden-option error naming `skip_verify` (the DSN is not quoted), unless
  `dynamic_secrets.insecure_allow_plaintext_dynamic_secret_transport` is enabled; then the
  connection is made and a WARNING is logged, like a plaintext one. The check runs on the
  parsed options, so every spelling go-redis accepts is covered. Revoke drops `skip_verify`
  and keeps verification on, so leases issued from such a config can still be revoked; a
  failed revoke names the dropped option. Upgrade note:
  `docs/upgrading.d/redis-admin-dsn-skip-verify-refused.md` (#4372).

### Testing
- **`FuzzDSNHostsCoverDriverHosts` oracle trims the port-stripped host.** The oracle compared
  `net.SplitHostPort`'s host untrimmed against the parser's trimmed candidates, so the input
  `host=0\ :` failed on main as well. Test-only.
