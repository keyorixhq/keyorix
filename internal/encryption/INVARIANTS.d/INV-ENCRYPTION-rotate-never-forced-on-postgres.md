- **INV-ENCRYPTION-rotate-never-forced-on-postgres** no DEK rotation (`admin encryption
  rotate` not `--dry-run`, and `admin encryption auth-encryption rotate`, both
  `RotateDEKWithSweep`) runs on PostgreSQL without the exclusive server-presence lock:
  `--force` cannot drop it, in either `key_dir_lock` mode. `dek.lock` is per host, and the
  DEK epoch fences a running replica's NEW encryptions only, so a value a replica on another
  host encrypted before the fence and INSERTs after the sweep's table lock would commit under
  the old DEK after the sweep; the presence lock is what keeps every replica stopped. Why:
  DEK-ROTATE-SAFETY-1 item 2 (STORAGE-2, DEK-ROTATION-CROSS-HOST), finding
  `docs/findings/2026-10-27-FINDING-dek-rotation-cross-host.md`. Guard:
  `server/admin/rotate_force_cross_replica_postgres_test.go:TestAdminEncryptionRotate_Postgres_ForceNextToLiveReplica_NoStaleDEKRow`
  (pg-gated, a subtest per command; on main it shows the old-DEK row) and
  `server/admin/rotate_force_guard_family_test.go:TestEveryDEKRotatingAdminCommandRefusesForce`
  (every `server/admin` function that reaches `RotateDEKWithSweep`, by name through
  `internal/encryption` and `internal/encryptionops`, calls `refuseForcedDEKRotation` first).
  **Not covered**: a server whose presence lock
  was lost and that is still draining requests.
<!-- section: First-boot / cross-process coordination -->
