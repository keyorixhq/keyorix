- **INV-ENCRYPTION-kek-lock-split** Readers (`GetDEK`, `GetKeyVersion`, `GetEvidenceSignKey`,
  `GetAuditCheckpointKey`, `GetBackupManifestKey`) are never blocked by any rotation's on-disk
  I/O. All rotation operations (`RotateKEKPassphraseWithPrepare`, `RewrapDEKWithPrepare`,
  `RotateDEKWithSweep`, `PromotePendingDEK`, `Wipe`, `Initialize`) hold `KeyManager.rotateMu`
  for their entire duration; readers hold no lock and use `state.Load()` only. The in-memory
  key material is published as an immutable `keyState` snapshot via `state.Store()` after all
  durable on-disk I/O has committed; readers see either the fully-old or the fully-new
  snapshot, never a partial write. `rotateMu` is not taken inside any reader, and no reader
  holds a lock when `rotateMu` is acquired — there is no lock inversion and no deadlock
  possible. Why: `docs/design/2026-11-15-key-custody-availability.md §2`, issue #4376 step 1
  — a KEK passphrase rotation holding its write lock across an fsync stalled every secret-read
  on the encrypt path for the rotation's full disk latency. Guard:
  `TestSlowDiskSync_HoldsReadLockAcrossSync` (acceptance: `GetKeyVersion` is NOT blocked
  ≥ delay/2 while rotation holds `rotateMu` through a 300 ms slow fsync — was red under the
  old `mu.Lock()` design, is green after the split);
  `TestKEKLockSplit_ConcurrentReadersUnderRotation_NoRace` (§2.7 item 4: 50 concurrent
  readers under `-race` while rotation is in-flight — no data race, every `state.Load()`
  snapshot is fully consistent);
  `TestKEKLockSplit_ConcurrentRotations_Serialized` (§2.7 item 5: two concurrent
  `RotateKEKPassphrase` calls with the same old passphrase serialise under `rotateMu` and
  exactly one succeeds). **Not covered**: the duration of `rotateMu` hold itself (steps 2 and
  3 of the split — narrowing Rewrap's flock wait and Sweep's DB sweep — are future work
  requiring separate go-aheads); concurrent cross-process staleness (covered by
  `FuzzDEKRewrapCrashConsistency`/`FuzzKEKRotationCrashConsistency`); the wipe trade-off for
  signing keys on KEK rotation (released to GC rather than immediately zeroed, per design doc
  §2.5, as the server continues running and concurrent readers may hold the old pointer).
<!-- section: Concurrency -->
