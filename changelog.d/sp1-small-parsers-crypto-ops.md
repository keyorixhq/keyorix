### Testing
- **Fuzz: SQLite DDL parse/print round-trip + engine differential
  (`FuzzSqliteDDLRoundTrip`).** The GORM SQLite migrator parses persisted
  `CREATE TABLE` text out of `sqlite_master`, mutates it and compiles it back to
  run against the live DB; a parse/compile disagreement would corrupt a
  migration. The new target asserts two real oracles over `parseDDL`/`ddl.compile`
  (scoped to the migrator's reachable domain — DDL the real modernc SQLite engine
  accepts): (1) `compile()`'s output must re-parse, preserve the parsed column
  metadata, and be an idempotent fixed point; (2) the recompiled DDL must be
  accepted by the real engine with the same column names in order. Wired to the
  resguard resource layer (alloc/malloc bounded-work budget over the regex-heavy,
  `buf += string(c)` O(n²)-shaped parser). Committed red/green proof
  (`TestResguardSqliteDDLRoundTripRedGreen`).
- **Fuzz: key-Secret render/unpack round-trip (`FuzzKeySecretRoundTrip`).** The
  `admin encryption key-secret` command renders a DEK/salt/wrapped-key set to a
  Kubernetes Secret manifest and `… unpack` base64-decodes it back onto disk —
  these files are the key material that decrypts the database, so a round-trip
  that drops or mangles a byte is silent key loss. The new target asserts that
  for any validly-named key set with arbitrary byte contents,
  `renderKeySecret → UnpackKeySecret` succeeds and reproduces the exact file-name
  set with byte-identical contents (exercising the YAML name-quoting and the
  base64 encode/decode across every byte pattern). Wired to resguard
  (disk_bytes/disk_files + alloc bounded-work). Committed red/green proof
  (`TestResguardKeySecretRoundTripRedGreen`).
