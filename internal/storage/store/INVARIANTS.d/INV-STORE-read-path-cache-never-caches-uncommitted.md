- **INV-STORE-read-path-cache-never-caches-uncommitted** A transaction-scoped
  `LocalStorage` never reads and never writes a read-path cache. It shares the parent's cache
  pointer but reads through the transaction handle, so every generation and every row it sees
  is UNCOMMITTED; caching from there publishes an answer into a cache that outlives the
  transaction, and after a rollback the next COMMITTED write that reproduces the same
  generation value makes that answer validate and be served. Enforced by
  `LocalStorage.cacheEnabled`, set in exactly one place (`NewLocalStorage`) and never copied,
  so every derived store — `WithTransaction`'s clone and the package's ad-hoc
  `&LocalStorage{db: tx}` literals — is cache-free by construction and fails closed rather
  than open. Why: coordinator review of #2764/#2767 — for `RoleSetHasPermission` a rolled-back
  grant kept authorizing (and the monotonic-integer generation made the collision exact, not
  merely possible); for `GetLatestSecretVersion` a version row that never committed was
  served, with a row id SQLite can reissue after a rollback. Guard:
  `read_path_cache_race_test.go:TestReadPathCacheRace_RolledBackTransactionDoesNotPoisonTheCache`,
  `secret_metadata_cache_rollback_test.go:TestSecretMetadataCache_TransactionScopedStoreNeverTouchesTheSharedCache`,
  `role_permission_cache_rollback_test.go:TestRoleSetHasPermission_TransactionScopedStoreNeverTouchesTheSharedCache`,
  and structurally `read_path_cache_guard_test.go:TestReadPathCacheGuard_RealRepo`, which
  confines every `genCache` access — reads included — to the one file where `cacheEnabled` is
  checked.
<!-- section: Read-path caches -->
