### Security
- **Azure Key Vault and Google Cloud KMS clear the unwrapped KEK when its integrity check fails.** `azurekms` dropped the unwrap result without zeroing it when a version-pinned envelope's MAC did not match, and `gcpkms` did the same with the decrypt plaintext on a `PlaintextCrc32C` mismatch, so recovered key material stayed in memory after the error. Both now `clear` the buffer before returning. `awskms` has no discard path after the unwrap.

### Testing
- **A report-only guard flags an `addr`/`address` value that is parsed as a URL and then formatted into a log or error.** `TestNoConfiguredAddrURLFormattedIntoLogsOrErrors` (`internal/urlleakguard`) exempts values the same function uses as a host:port dial address, and is report-only until its first green nightly on main.
