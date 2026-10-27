- **INV-AUDITVERIFY-seals-authenticated-never-valid** The offline verifier reads the
  `audit_seals` record (accepted audit losses) with its own parser and MAC check, which match
  `internal/core/audit_seal.go` byte for byte. It steps over a sealed gap only when every record
  authenticates under the supplied checkpoint key, and only at the exact rows and hashes the
  record names. Without a key the record is never trusted, so a sealed chain reads BROKEN. Every
  record needs an in-chain `system.audit_loss_accepted` event naming its digest, and every such
  event a record. Checkpoint and high-water signatures are checked under the v2 canonical form
  bound to the seal count and newest digest, and a sealed mark must name the current binding. An
  intact seal is SEALED (exit 4), never VALID. A pre-seal `--anchor` may not certify more than the
  next seal recorded as certified before its loss. `WriteWitnessIfHigher` orders marks by seal
  count first. Why: AUDIT-ACCEPT-LOSS-1, constraint 8 of docs/design/recovery-options.md §2.
  Guard: `TestSealDifferential_*` (seal_differential_test.go), fixtures written by the real
  `internal/core` path; `TestCheckRollbackProtection_SealedMarks` (server/admin).
