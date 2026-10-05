- **INV-STORE-read-path-cache-generation-covers-writers** A read-path cache's generation must
  change whenever ANY column of the cached value changes. Ordering alone (see
  INV-STORE-read-path-cache-stamp-before-data) is not enough: a timestamp is a stamp only for
  writers that advance it, `UpdateColumn`/`UpdateColumns` bypass GORM's auto-timestamp callback
  entirely, and two writes landing in one stored microsecond tie. Three Go-side mechanisms were
  tried and each had a hole — updated_at (misses `UpdateColumn`), a `BeforeUpdate` hook calling
  `SetColumn` (silently a no-op under a full-struct `Save()`), and a per-write-site bump
  (opt-in correctness). The resolutions now in force, one per cache:
  **secret_nodes** uses `cache_epoch`, a per-row counter maintained by a DATABASE TRIGGER
  (`store.EnsureSecretNodeCacheEpoch`) so the database covers `Save`/`Updates`/`UpdateColumn`/
  raw SQL identically, with the column read-only to GORM (`gorm:"<-:false"`) so no Go write can
  set it; **secret_versions** uses a content-derived aggregate
  `(count, max(version_number), sum(read_count))` with no clock in it; **secret_access_schedules**
  uses the row's own updated_at plus the whole access policy, so a tie implies an identical
  policy. A cache whose stamp cannot be trusted must be DISABLED, not trusted — an absent
  trigger freezes `cache_epoch`, which a trigger-less Postgres restore or a bare-AutoMigrate
  schema really does produce, so `SecretNodeCacheEpochTriggerPresent` turns the node cache off
  instead. Why: #2764 (a stale cached `read_count` written back by `RotateSecret` reset a
  burn-after-N-reads budget; a node-timestamp stamp made `storeNextSecretVersion`'s retry loop
  re-read its own stale answer; a 25-column content stamp made a cache HIT measurably SLOWER
  than a miss) and #2767 (a `time.Now()`-plus-random generation value turned
  `FuzzStorageFaultOperations`' oracle (a) red on seven seeds). Guard:
  `secret_metadata_cache_fieldledger_test.go:TestCacheEpochTrigger_FiresForEveryPersistedColumn`
  (reflection over `models.SecretNode`: every persisted column's own UPDATE must bump the
  epoch), `TestCacheEpochTrigger_IsRedWithoutTheTrigger`,
  `TestCacheEpochTrigger_FiresOncePerRowOnAMultiRowUpdate`,
  `TestCacheEpoch_HardDeletedIDIsNeverReissued`,
  `TestSecretNodeCacheEpoch_FieldStaysReadOnlyToGORM`,
  `TestSecretNodeCacheEpoch_AbsentTriggerDisablesTheNodeCache`,
  `TestScheduleGeneration_CoversEveryPersistedScheduleField`,
  `internal/storage/factory_secret_node_cache_epoch_test.go` (the migration creates both on a
  fresh install AND on an upgrade of a database holding data, on both backends), and
  `role_permission_generation_guard_test.go:TestRolePermissionWriters_BumpTheGenerationInTheSameTransaction`
  for the explicit-counter case.
<!-- section: Read-path caches -->
