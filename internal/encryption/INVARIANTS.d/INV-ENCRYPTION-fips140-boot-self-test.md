- **INV-ENCRYPTION-fips140-boot-self-test** When `fips140.Enforced()` is true
  (`GODEBUG=fips140=only`), the server runs `encryption.BootFIPSSelfTest` right after logging is
  set up and before any key is loaded, and refuses to start if it fails. It exercises every
  path in `fipsSelfTestPaths` once with a throwaway random key: DEK wrap/unwrap (with a tamper
  check), secret AEAD (AAD, plain, chunked, fingerprint, wrong-AAD refusal), PBKDF2 KEK
  derivation, and the evidence-signing, audit-checkpoint and backup-manifest HKDF keys with an
  HMAC-SHA256 under each. A FIPS-module panic counts as a failure; the refusal is a
  `*FIPSSelfTestError` naming the path. Outside fips140=only it runs nothing. The result goes
  into `FIPSSelfTestPostureLine` (server log and `admin validate --posture`), which never says
  "passed" unless the self-test ran and passed. A new runtime AEAD or KEK-derived-key path
  must be added to `fipsSelfTestPaths`. Why: FIPS-TAILS-1 item 3. Guard:
  `internal/encryption/fips_selftest_test.go` (`TestRunFIPSSelfTest_PassesUnderFIPS140Only`
  runs a child under fips140=only; `TestRunFIPSSelfTestPaths_FailingPathIsNamed`;
  `TestBootFIPSSelfTest_FailingPathRefusesBoot`;
  `TestBootFIPSSelfTest_EnforcedStubbedFailureNamesThePath` drives the refusal in default
  mode through the `fipsSelfTestEnforced` seam), `server/admin/posture_fips_selftest_test.go`,
  `server/fips_selftest_wiring_test.go` (source check: the call and its `log.Fatalf` sit in
  `main()` before `runStartupValidation`). The refusal is documented in
  `docs/operator/startup-refusals.md` (Match `fips140 self-test failed on`, checked by
  `internal/refusaldocs`).
  **Not covered**: the backup path checks the manifest key derivation and the HMAC-SHA256
  primitive, not `backupfmt.SignManifest` itself (importing backupfmt would pull
  internal/storage into this package). Nothing detects a new path that is missing from the list.
