- **INV-ENCRYPTION-dek-sweep-holds-service-write-lock** `Service.RotateDEKWithSweep` holds
  `Service.mu` for writing from before the key manager's sweep until the Service has swapped
  `s.encryptionService` to the new DEK (`service_rotation.go`), released by `defer` so a panic or
  crash seam in the sweep releases it. Every `EncryptSecret*` reads the pair
  (`s.encryptionService`, key version) under `Service.mu.RLock`, so no write can seal under the
  old DEK while labelling the value with the new key version, and the sweep's transaction (which
  cannot see a row committed after it) never has to catch such a row. Readers wait for the swap
  instead of failing closed on swept rows. Lock order: `Service.mu` → `KeyManager.mu` → DEK
  flock; the key manager never calls back into the Service (`keymanager_state.go`). Why: #4654
  (a write that waited out the sweep on `KeyManager.mu` resumed on the superseded DEK; the value
  never opened again). Guard: `service_rotation_write_gate_test.go`
  (`TestRotateDEKWithSweep_WriteDuringSweepOpensAfterRotation`, one row per `Encrypt*` entry point;
  red at the pre-fix commit). Not reachable in shipped deployments, where a live server holds
  `dek.lock` and no server runs during a sweep; it protects in-process users (tests, fuzzers,
  embedders).
<!-- section: First-boot / cross-process coordination -->
