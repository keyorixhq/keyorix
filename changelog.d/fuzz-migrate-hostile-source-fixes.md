### Security
- **`keyorix-migrate` Vault import now fails closed on a non-success read.** The hand-rolled
  Vault client (`migrate/internal/vaultsource`) accepted only `status >= 400` as a failure, so a
  3xx redirect — which the client already refuses to *follow* — had its un-followed body parsed
  as the secret/list/mount response. It now treats any status other than 200 (and the
  deliberately-handled 404) as an error and never reads the body, so a proxy/LB redirect or a
  compromised Vault can no longer have a redirect body imported as a secret value. AppRole login
  likewise succeeds only on 200: a 3xx or other 2xx login response no longer has its
  `client_token` adopted as the session token. Guarded by
  `INV-VAULTSOURCE-non-2xx-read-is-an-error` and new regression tests.

### Fixed
- **`keyorix-migrate` no longer derives malformed secret names.** `sanitizeSecretName` now drops
  control characters and is a fixed point, so a Vault KV key or cloud secret name containing
  control bytes can no longer reach the create-secret API embedded in a name. A source name that
  normalises to empty (only separators/control characters) is reported as a skip instead of being
  sent as an empty name. Compatibility: a source key that contains control characters, or starts
  or ends with Unicode whitespace, now derives a different Keyorix name than before, so a re-run
  after upgrading looks up the new name rather than one created by an earlier import.
- **`keyorix-migrate` Vault import stops re-resolving the KV mount version on every read.** The
  per-client mount-version cache was keyed by the mount path Vault reports but looked up with
  mount-relative paths, so it never hit and every list/read issued a redundant
  `sys/internal/ui/mounts` round-trip. A `Client` targets one mount, so the version is now
  resolved at most once per import. Guarded by `INV-VAULTSOURCE-mount-version-resolved-once`.
- **`keyorix-migrate` Vault import bounds its KV walk depth.** `Walk` now stops with a clear error
  past a fixed recursion-depth cap, so a Vault that returns a folder key at every level can no
  longer drive unbounded-depth recursion. Guarded by `INV-VAULTSOURCE-walk-depth-bounded`.
