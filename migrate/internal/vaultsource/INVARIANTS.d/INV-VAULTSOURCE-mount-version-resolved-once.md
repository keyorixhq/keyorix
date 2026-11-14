- **INV-VAULTSOURCE-mount-version-resolved-once** A `vaultsource.Client` targets exactly one KV
  mount (`c.mount`), so `resolveKVMountVersion` resolves the mount's KV version (1 or 2) at most
  once per Client and caches it in `c.mountVersion` (0 = not yet resolved); every subsequent
  list/read reuses it. A whole `Walk` therefore issues at most one `GET sys/internal/ui/mounts`
  round-trip regardless of how many folders/leaves it visits. Why: the previous per-path cache
  was keyed by the mount path Vault reports (`"secret/"`) but looked up with mount-relative KV
  paths (`"db"`), so it never hit and every list()/read() issued a redundant mounts round-trip,
  doubling+ the request load the import places on a customer's Vault (campaign FINDING F2). Guard:
  `TestWalk_ResolvesMountVersionOnce` (vault_mountcache_test.go) counts mounts requests over a
  multi-leaf walk and asserts exactly one; `FuzzVaultSourceHostileWalk` additionally fails if the
  mounts endpoint is hit more than once in any single Walk.
