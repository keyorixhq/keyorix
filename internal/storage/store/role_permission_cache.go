// role_permission_cache.go — the read-path "principal permissions" cache
// (PERF-3, docs/specs/read-path-caching.md PR-2): caches
// RoleSetHasPermission's own result ("does this exact role-ID set grant
// permission P"), not role MEMBERSHIP. Role membership (which role IDs a
// principal currently holds — GetMachineRoleIDsAt, scopedRoleIDs,
// GetUserGroupRoleIDsAt) is deliberately left uncached: a role grant/revoke
// is exactly the #G18 "stop authorizing on the very next request" case, and
// keeping membership resolution live means a bug in this cache can at most
// make a permission check for a role a principal legitimately and
// CURRENTLY holds briefly stale by one generation-check round trip — it
// cannot let a revoked role keep authorizing, because the role list itself
// is never cached here.
//
// Unlike secret_metadata_cache.go's per-row generation (one column per
// secret), role_permissions edits are rare, install-wide, admin-only
// actions (grant/revoke a permission on a role) — a single GLOBAL
// generation signal is simplest and safest: no per-role invalidation key
// can under-invalidate when there's only one key. Stored as a
// system_metadata row (rolePermissionsGenerationKey) rather than a new
// table/column — reuses the existing generic key/value store, no migration
// needed. Value is an opaque, monotonically-fresh string (nanosecond
// timestamp), not a parsed integer counter — avoids an atomic-increment-on-
// a-string-column dialect difference between SQLite and Postgres; the only
// property that matters is "did this change since I last looked," never
// "by how much."
//
// Same per-LocalStorage-instance-not-package-global design as
// secret_metadata_cache.go, for the identical reason (see that file's
// header) — this cache is a field on *LocalStorage, shared with a
// transaction-scoped copy, never a package-level var.
package store

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const rolePermissionsGenerationKey = "role_permissions_generation"

type rolePermCacheEntry struct {
	generation string
	allowed    bool
}

type rolePermissionCache struct {
	mu      sync.Mutex
	entries map[string]rolePermCacheEntry
}

func newRolePermissionCache() *rolePermissionCache {
	return &rolePermissionCache{entries: make(map[string]rolePermCacheEntry)}
}

// rolePermKey builds the cache key for a (roleIDs, permission) pair,
// sorting a COPY of roleIDs so this never mutates the caller's slice (which
// may be shared/reused elsewhere up the call chain).
func rolePermKey(roleIDs []uint, permission string) string {
	ids := make([]uint, len(roleIDs))
	copy(ids, roleIDs)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	var b strings.Builder
	for _, id := range ids {
		b.WriteString(strconv.FormatUint(uint64(id), 10))
		b.WriteByte(',')
	}
	b.WriteByte('|')
	b.WriteString(permission)
	return b.String()
}

func (c *rolePermissionCache) get(key string) (rolePermCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	return e, ok
}

func (c *rolePermissionCache) set(key string, e rolePermCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = e
}

// liveRolePermissionsGeneration reads the current global generation value.
// A never-bumped install reads as ("", nil) — "" is a perfectly valid
// generation value (every cache entry recorded before the first-ever bump
// shares it), not a sentinel error.
func liveRolePermissionsGeneration(ctx context.Context, ls *LocalStorage) (string, error) {
	val, _, err := ls.GetSystemMetadata(ctx, rolePermissionsGenerationKey)
	if err != nil {
		return "", err
	}
	return val, nil
}

// bumpRolePermissionsGenerationTx writes a fresh generation value using tx,
// so the bump commits atomically with whatever role_permissions write it's
// paired with (AssignPermissionToRole, RemovePermissionFromRole, DeleteRole's
// cascade) — a reader can never observe the new role_permissions row with
// the old generation, or vice versa.
func bumpRolePermissionsGenerationTx(ctx context.Context, tx *LocalStorage) error {
	return tx.SetSystemMetadata(ctx, rolePermissionsGenerationKey, strconv.FormatInt(time.Now().UnixNano(), 10))
}
