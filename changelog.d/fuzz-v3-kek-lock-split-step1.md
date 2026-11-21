### Internal
- **KeyManager lock split step 1 (issue #4376).** `KeyManager.mu sync.RWMutex` replaced
  with `rotateMu sync.Mutex` + `state atomic.Pointer[keyState]`. Readers (`GetDEK`,
  `GetKeyVersion`, `GetEvidenceSignKey`, `GetAuditCheckpointKey`, `GetBackupManifestKey`)
  now use a lock-free `state.Load()` and are never blocked by any rotation's fsync. All
  three rotation operations (`RotateKEKPassphrase`, `RewrapDEK`, `RotateDEKWithSweep`)
  still hold the rotation lock for their entire duration; the DEK sweep's scope and
  ordering are unchanged. Guards: `TestSlowDiskSync_HoldsReadLockAcrossSync` (flipped
  from red to green), `TestKEKLockSplit_ConcurrentReadersUnderRotation_NoRace` (§2.7 item
  4), `TestKEKLockSplit_ConcurrentRotations_Serialized` (§2.7 item 5).
  `INV-ENCRYPTION-kek-lock-split` added.
