### Added
- **KDF-invocation counter seam (`internal/kdfmeter`) for password-hash cost.**
  Production credential paths in `internal/core` and `server/admin` now hash and
  verify passwords through `kdfmeter.GenerateFromPassword`/`CompareHashAndPassword`
  (thin wrappers over `golang.org/x/crypto/bcrypt`). With no observer installed —
  the production default — the only added work per call is one atomic load and a
  nil check; behaviour is byte-for-byte unchanged. A test-only observer (installed
  by the resguard `KDFMeter`) counts invocations deterministically; a repo guard
  (`TestKDFMeterSetObserver_NoProductionCallers`) fails the build if any production
  file enables the meter.

### Testing
- **resguard `KDFMeter` resource seam.** The fuzz resource helper
  (`internal/fuzzutil/resguard`) gains a `KDFMeter`, exposed as
  `Cost.KDFGenerates`/`KDFCompares`, counterpart to `DBMeter` for password-hash
  cost — the signal an account-enumeration timing oracle needs that a DB-query
  counter cannot see.
- **`FuzzKDFEnumerationOracle` (`internal/core`).** Account-enumeration-by-difference
  oracle on the local bcrypt login path: for every account-existence class
  (known-active, known-wrong, locked, deactivated, suspended, reset-required,
  absent) it asserts `VerifyPasswordCredentials` spends exactly one KDF compare and
  zero generates, and that DB round-trips match the absent baseline for the balanced
  classes. Makes the login timing-equaliser machine-checked where a wall-clock test
  is flaky.
