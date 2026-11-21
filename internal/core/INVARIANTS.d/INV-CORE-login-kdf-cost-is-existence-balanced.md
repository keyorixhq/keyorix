- **INV-CORE-login-kdf-cost-is-existence-balanced** `VerifyPasswordCredentials`
  spends EXACTLY ONE password-hash KDF comparison (`bcrypt.CompareHashAndPassword`,
  now via `internal/kdfmeter`) and ZERO hash generations for EVERY input, regardless
  of whether the username exists, is locked, is deactivated (`IsActive=false`), is
  suspended (`AccountState`), is in a restricted state, or is wrong-password. The
  not-found and locked paths spend a dummy comparison against `dummyBcryptHash`
  (`auth.go`) so a missing/locked account never returns faster than a wrong password
  — the bcrypt invocation is the dominant cost, and balancing it is what closes the
  account-enumeration timing side-channel. Why: F-KDF-SEAM (KDF1) — before the
  `internal/kdfmeter` seam existed, nothing MACHINE-CHECKED this balance; a
  wall-clock test is flaky and the resguard `DBMeter` counts DB round-trips, a
  different signal (a path can be DB-balanced yet KDF-unbalanced, which is exactly
  the enumeration bug). Guard: `FuzzKDFEnumerationOracle`
  (`kdf_enumeration_oracle_fuzz_test.go`) asserts the 1-compare/0-generate balance
  across all existence classes over a real world (SQLite always, PostgreSQL when
  `KEYORIX_TEST_PG_DSN` is set), with its assertion logic red/green-proven by
  `TestKDFEnumerationOracle_ParityCheckRedGreen`. Known ACCEPTED asymmetry (NOT a
  KDF asymmetry, surfaced and bounded by the same oracle): a wrong password against
  an EXISTING account writes lockout-accounting state (`recordFailedLogin`) while a
  nonexistent account writes nothing, so the DB round-trip count differs between
  `known_wrong` and `absent_wrong` — a potential DB-timing oracle on a cost far
  below bcrypt; see the KDF1 report's hardening proposal (equalise with a dummy
  lockout-accounting write on the not-found path, or make `recordFailedLogin`
  asynchronous like the expired-OTP audit).
