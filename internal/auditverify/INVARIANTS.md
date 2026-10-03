# internal/auditverify invariants

Read this before changing anything in `internal/auditverify`. It offline-verifies the
ADR-029 audit tamper-evidence hash chain directly against a database artifact, independently
of the server that wrote it. See `doc.go` and `docs/design-b4-offline-audit-verify.md` for the
full design and trust model.

Format: `INV-AUDITVERIFY-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

- **INV-AUDITVERIFY-01** This package must never import `internal/core`, `internal/storage`
  (or any subpackage), or `gorm.io/*` — every fact it checks must be independently re-derived,
  never reused from the code that wrote the chain. Why: `doc.go` / design doc §4 — a verifier
  that reuses the writer's own code proves nothing about a bug or backdoor in that code.
  Guard: `TestDependencyGuard_NoCoreOrStorageImports` (dependency_guard_test.go) — parses every
  non-test `.go` file's imports via `go/parser`.
- **INV-AUDITVERIFY-02** `checkpointCanonical` (the exact byte string an audit checkpoint's
  HMAC covers) must byte-for-byte match `internal/core.checkpointCanonical`. Why: checkpoint.go
  — the offline verifier and the online writer must agree on what was signed, or the verifier
  validates/rejects against a format the writer never produced. Guard:
  `TestCheckpointCanonical_ExactByteFormat` (verify_internal_test.go) plus the
  `TestDifferential_*` suite (differential_test.go) which builds real fixtures via `internal/core`
  and parses them with this package.
- **INV-AUDITVERIFY-03** `auditRetentionAnchorCanonical` must byte-for-byte match
  `internal/core.auditRetentionAnchorCanonical`, domain-separated from `checkpointCanonical` by
  its `"retanchor-v1"` prefix. Why: retention.go. Guard:
  `TestRetentionAnchorCanonical_ExactByteFormat`.
- **INV-AUDITVERIFY-04** The high-water-mark and retention-anchor separator byte is `\x1f`
  (ASCII unit separator), never `\x00` — a Postgres text/varchar column rejects an embedded NUL
  outright, and this value is persisted as a plain string via `SetSystemMetadata`. Why:
  checkpoint.go:50-53, retention.go:23-25. Guard: the `TestDifferential_*` suite exercises
  real core-written values through this package's parser; no test asserts the separator byte
  directly — UNGUARDED (#issue: add a direct unit test pinning the `\x1f` byte and a negative
  case with `\x00`).
- **INV-AUDITVERIFY-05** A verdict escalation only ever moves a `Result` toward the MORE
  severe finding, regardless of check order — never downgrades. Why: `verdictRank` doc comment,
  verify.go. Guard: `TestResult_Escalate_NeverDowngrades`.
- **INV-AUDITVERIFY-06** A byte-level tamper to an audit row's description, an audit row's hash
  fields, a checkpoint's signature, or a checkpoint's head hash must be detected by the offline
  verifier, not silently accepted. Guard: `TestExhaustiveByteTamper_AuditRowDescription`,
  `_AuditRowHashFields`, `_CheckpointSignature`, `_CheckpointHeadHash` (tamper_exhaustive_test.go).
- **INV-AUDITVERIFY-07** A truncated tail (rows removed from the end of the chain) must be
  caught whenever a checkpoint beyond the truncation point exists. Guard:
  `TestDifferential_TruncatedTail_CheckpointEnforced`.
- **INV-AUDITVERIFY-08** A forged checkpoint signature must be detected, never accepted as
  authentic. Guard: `TestDifferential_ForgedCheckpoint`.
- **INV-AUDITVERIFY-09** `ExternalAnchorStatus` (a caller-supplied `--anchor` bundle held
  outside this host's blast radius) must never be conflated with `AnchorStatus` (the in-DB
  checkpoint's own RFC 3161 receipt) — a host admin who controls the DB can forge the latter.
  Why: verify.go `ExternalAnchorStatus` doc comment. Guard: `anchor_status_independence_test.go`
  — `TestAnchorStatus_InDBAnchorDoesNotMaskExternalMismatch` (a re-seeded chain with a re-signed
  in-DB checkpoint and anchor token passes every in-DB check, yet an earlier external bundle
  drives the verdict to BROKEN, and `Anchor` is identical with or without the bundle) and
  `TestAnchorStatus_ExternalAuthenticationDoesNotMarkInDBAnchor` (an authenticated bundle never
  makes the in-DB anchor present or verified). Not covered: an in-DB anchor that verifies
  against TSA roots, which needs a real RFC 3161 token the fixtures cannot mint (#2516).
- **INV-AUDITVERIFY-10** `WriteWitnessIfHigher` must never lower the witness file's recorded
  high-water mark — only monotonically advance it. Why: witness.go — the rollback protection in
  `docs/design-b3-backup-v2.md` §6.3 compares an archive's recorded high-water mark against this
  host-local witness; a witness that could regress would let a restored-from-backup DB pass a
  check it shouldn't. Guard: `TestWriteWitnessIfHigher_NeverLowersTheMark`.
- **INV-AUDITVERIFY-11** The witness file is a sibling of the database file (never a backup
  archive tar member, never listed in `internal/keyfiles.Registry`) so it survives being
  overwritten by `admin restore`. Why: witness.go — comparing an old archive against its own
  (also-old) embedded witness would prove nothing. Guard: `TestWitnessPath_SiblingOfDBFile`
  proves the path relationship; the "never a tar member / never in keyfiles.Registry" half has
  no direct cross-package test found — UNGUARDED (#issue: add a test in internal/backupfmt or
  internal/keyfiles asserting the witness filename is excluded from both).
- **INV-AUDITVERIFY-12** The backup-manifest signing key must be domain-separated from (never
  equal to) the audit-checkpoint signing key, even when both are derived from the same KEK.
  Guard: `TestDeriveBackupManifestKey_DomainSeparatedFromAuditCheckpointKey`.
- **INV-AUDITVERIFY-13** `DeriveBackupManifestKey` is deterministic for the same KEK and
  differs for different KEKs. Guard: `TestDeriveBackupManifestKey_DeterministicForTheSameKEK`,
  `TestDeriveBackupManifestKey_DiffersForDifferentKEKs`.
- **INV-AUDITVERIFY-14** A retention gap (the earliest surviving row carries a non-genesis
  `prev_hash`, i.e. rows before it were removed) must be reported as a distinct status whether
  or not the retention-anchor key is available to authenticate it as sanctioned. Guard:
  `TestDifferential_RetentionGap_KeyAvailable`, `TestDifferential_RetentionGap_KeyUnavailable`.
- **INV-AUDITVERIFY-15** Audit-row decoding must never panic or hang on arbitrary/malformed
  byte input. Guard: `FuzzAuditChainRowDecode` (rowdecode_fuzz_test.go).
