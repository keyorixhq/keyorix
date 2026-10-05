// role_permission_cache_bench_test.go — microbenchmark for the "principal
// permissions" cache (PERF-3, docs/specs/read-path-caching.md PR-2): cache
// hit (warm, repeat RoleSetHasPermission with an unchanged role_permissions
// table) vs cache miss (evicted before every call). Not a substitute for
// the pve01 before/after harness numbers — a quick local sanity check.
package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func BenchmarkRoleSetHasPermission_CacheHit(b *testing.B) {
	ls := newRolePermCacheTestStorage(b)
	ctx := context.Background()
	role, err := ls.CreateRole(ctx, mustFoldedName(b, "bench-role"), "")
	if err != nil {
		b.Fatal(err)
	}
	perm, err := ls.CreatePermission(ctx, &models.Permission{Name: "bench.permission"})
	if err != nil {
		b.Fatal(err)
	}
	if err := ls.AssignPermissionToRole(ctx, role.ID, perm.ID); err != nil {
		b.Fatal(err)
	}
	if _, err := ls.RoleSetHasPermission(ctx, []uint{role.ID}, "bench.permission"); err != nil { // warm
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ls.RoleSetHasPermission(ctx, []uint{role.ID}, "bench.permission"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRoleSetHasPermission_CacheMiss(b *testing.B) {
	ls := newRolePermCacheTestStorage(b)
	ctx := context.Background()
	role, err := ls.CreateRole(ctx, mustFoldedName(b, "bench-role"), "")
	if err != nil {
		b.Fatal(err)
	}
	perm, err := ls.CreatePermission(ctx, &models.Permission{Name: "bench.permission"})
	if err != nil {
		b.Fatal(err)
	}
	if err := ls.AssignPermissionToRole(ctx, role.ID, perm.ID); err != nil {
		b.Fatal(err)
	}
	key := rolePermKey([]uint{role.ID}, "bench.permission")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// GUARD-6: the cache is a genCache now (read_path_cache.go), so evicting
		// goes through invalidateCachedRead instead of reaching into the map
		// under its own mutex. Same effect — force a miss every iteration.
		invalidateCachedRead(ls.rolePermCache.entries, key)
		if _, err := ls.RoleSetHasPermission(ctx, []uint{role.ID}, "bench.permission"); err != nil {
			b.Fatal(err)
		}
	}
}
