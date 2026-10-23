- **INV-ENCRYPTION-keyset-manifest-bracketed-writes** Every write that replaces an active key
  file (salt, wrapped DEK, provider blob, Shamir share) is bracketed in the key-set manifest
  (`internal/keyfiles/manifest.go`, `keyset.manifest.json` next to the DEK): `StageManifest`
  records the hashes the files will have BEFORE the first active file is renamed (a stage
  failure aborts with nothing changed), `CommitManifest` records them AFTER the last fsync (a
  commit failure is a WARN: the staged intent already makes the state classifiable). So every
  on-disk state a crash leaves has each file at its recorded or its staged hash, and boot
  (`keyfiles.InspectKeySet` / `ReconcileKeySet`, run under the key lock before
  `RecoverInterruptedRotation` and `Initialize`) can tell an interrupted operation from a set
  mixed from two backups without a passphrase: a file matching neither hash is refused; a
  staged operation is abandoned (harmless leftover staging), completed (commit recorded),
  finishable (each old file's `.pending` holds the staged content: renamed into place, audit
  event) or incoherent (refused). First boot commits the whole set from disk; a writer on a
  pre-manifest install adopts the current set first; boot adopts a complete set with no or an
  unparseable manifest (WARN + `encryption.keyset_manifest_adopted`). Why: #2900 — presence
  and mtimes cannot tell these states apart. Guard:
  `internal/keyfiles/manifest_writers_structural_test.go:TestEveryKeyMaterialWriterUpdatesTheManifest`
  (every function in internal/encryption, internal/encryptionops, server/admin using a
  recognised write form calls a manifest update or is exempted with a reason),
  `keyset_manifest_writers_test.go` (per writer: manifest matches disk),
  `keyset_manifest_crash_test.go:TestRotateKEKCrashPoints_BootClassifiesAndRecovers`,
  `internal/keyfiles/manifest_rotation_test.go`, `manifest_consistency_test.go`,
  `manifest_adopt_test.go`. **Not covered**: a write through a form the structural guard does
  not list ((*os.File).Write on a handle opened elsewhere, a helper in another package); the
  KEK providers' first-run writes in internal/crypto (recorded by the first-boot commit, not by
  the guard); the hashes are unkeyed, so this detects accidents and N-1 binaries, not an
  attacker who can write the key directory.
<!-- section: Crash consistency (write-pending → rename → fsync) -->
