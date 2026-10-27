- **INV-ENCRYPTION-rotate-never-forced-on-postgres** `admin encryption rotate` (not
  `--dry-run`) never runs on PostgreSQL without the exclusive server-presence lock:
  `--force` cannot drop it, in either `key_dir_lock` mode. `dek.lock` is per host, and the
  DEK epoch fences a running replica's NEW encryptions only, so a value a replica on another
  host encrypted before the fence and INSERTs after the sweep's table lock would commit under
  the old DEK after the sweep; the presence lock is what keeps every replica stopped. Why:
  DEK-ROTATE-SAFETY-1 item 2 (STORAGE-2, DEK-ROTATION-CROSS-HOST), finding
  `docs/findings/2026-10-27-FINDING-dek-rotation-cross-host.md`. Guard:
  `server/admin/rotate_force_cross_replica_postgres_test.go:TestAdminEncryptionRotate_Postgres_ForceNextToLiveReplica_NoStaleDEKRow`
  (pg-gated; on main it shows the old-DEK row). **Not covered**: a server whose presence lock
  was lost and that is still draining requests.
<!-- section: First-boot / cross-process coordination -->
