- **INV-ENCRYPTION-service-readers-skip-kek-rotation-io** `Service.RotateKEKPassphraseWithPrepare`
  and `Service.RewrapDEKWithProviderPrepare` do not hold `Service.mu` across the key manager's
  rotation: neither changes a Service field (the DEK, so `s.encryptionService`, is unchanged), and
  the key manager serialises them against `Initialize`, `Wipe` and every other rotation itself
  (`rotateMu` + the DEK flock, `keymanager_state.go`). So `EncryptSecret*`, `DecryptSecret*` and
  the KEK-derived key getters keep serving the old keys while the key files are written and
  fsynced, and the new ones once they are durable; a value written during the rotation opens after
  it and after a reopen under the new KEK. A `Shutdown` that arrives mid-rotation waits for it
  (`KeyManager.Wipe` takes `rotateMu`). Why: #4625. Guard:
  `service_rotation_lock_scope_test.go` (`TestServiceKEKRotation_EncryptDecryptNotBlockedAcrossSync`,
  `TestServiceRewrap_EncryptDecryptNotBlockedAcrossSync`,
  `TestServiceShutdownDuringKEKRotation_NoDeadlock`). **Not covered**: `Service.RotateDEKWithSweep`,
  which changes the DEK and so holds `Service.mu` for writing across the whole sweep and the
  Service swap instead (INV-ENCRYPTION-dek-sweep-holds-service-write-lock, #4654); readers and
  writers wait for it. Before #4654 reads did not wait but failed closed (AEAD error, never wrong
  plaintext) on swept rows between the sweep commit and the swap, and a write that waited out the
  sweep on `KeyManager.mu` sealed under the superseded DEK. Neither is reachable in a shipped
  deployment: a live server holds `dek.lock` for its lifetime, so no server runs during a sweep
  (#4624).
<!-- section: First-boot / cross-process coordination -->
