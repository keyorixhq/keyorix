### Testing
- **Vault→Keyorix migration round-trip & convergence fuzz oracles (task MGV1).** Added two
  fuzz targets exercising the full Vault importer (`vaultsource.Walk` →
  `buildVaultPlanEntries`/`sanitizeSecretName` → `plan.BuildPlan`/`Apply` → target).
  `FuzzVaultImportRoundTrip` (migrate/cmd) generates KV v1/v2 export shapes — nested paths,
  versions, custom_metadata, soft-deleted/destroyed versions, binary/multiline/unicode/bidi/
  NUL/long/duplicate-key fields, odd mounts, empty secrets — serves them over a faithful
  httptest Vault, and asserts a non-mirroring conservation oracle: nothing silently dropped or
  duplicated, no invented or resurrected (soft-deleted) value, every target name namespace-safe
  (no `/`,`\\`,NUL,control), versions/custom_metadata recorded, deleted/empty leaves reported
  not dropped, and the secret-value canary never in an error/log/skip-reason (Walk metered by
  the shared `hostile.Harness`). `FuzzVaultImportConvergence` fails each write seam
  before/after an atomic commit and requires a clean re-run to converge with no lost names, no
  duplicates and a fixed point — guarding the `plan.planOne` idempotency design. Registered in
  `scripts/fuzzing/targets.d/`; new invariant `INV-VAULTSOURCE-walk-conserves-and-reports`.
