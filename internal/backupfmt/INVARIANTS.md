# internal/backupfmt invariants

Read this before changing anything in `internal/backupfmt`. It is the v2 *logical* backup
format: `WriteBackup`/`writeBackupModels` produce a signed, per-entry-digest-pinned
gzip+tar archive (`MANIFEST.json` first), `ExtractArchive` reads an operator-supplied,
not-yet-signature-verified archive into a staging directory, and `LoadArchive` loads the
staged NDJSON rows into an already-migrated database inside one transaction. See
`docs/design-b3-backup-v2.md` and the sibling `server/admin` restore command for the full
extract → verify-signature → schema-epoch-gate → load → verify-audit sequence.

Format: `INV-BACKUPFMT-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-BACKUPFMT-<slug>.md`, one per file.
