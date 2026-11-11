- **INV-STORAGE-upgrade-secrets-still-decrypt** Upgrading a database a released binary wrote (v0.91.0
  through v0.96.3, SQLite) keeps every secret version decryptable to the value that was written, and
  the latest version of a live secret reads back through `core.GetSecretValue`. Why: no migration
  re-encrypts anything, so a step that rebuilds or rewrites `secret_nodes` / `secret_versions` must
  not disturb the ciphertext or the ids its AAD binds. Guard: `internal/storage`
  `FuzzUpgradeFromOldSchema`, `FuzzUpgradeInterrupted`, red-proved by
  `TestUpgradeOracles_RedProof/invariant1_*`. **Not covered**: PostgreSQL (the FuzzUpgradePG* targets cover it with their own oracles, see upgrade_pg_fuzz_test.go); sources
  before v0.91.0; per-release key-file formats (every snapshot was written under one test key).
