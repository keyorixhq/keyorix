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
  whose key manager still holds `KeyManager.mu` across the sweep (#4624).
<!-- section: First-boot / cross-process coordination -->
