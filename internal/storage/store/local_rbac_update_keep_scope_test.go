package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestUpdateRole_EmptyAssignableScopeKeepsStoredScope pins the storage half of
// #3909: UpdateRole with AssignableScope "" leaves the column out of its UPDATE,
// so a scope another connection (lsB) wrote after the caller read the role is
// kept. A non-empty scope is still written. The core-level two-replica race is
// internal/core TestCTAReview_UpdateRoleKeepScope_vs_NarrowScope_CrossReplicaPostgres;
// this test fixes the write itself, on SQLite and (with a DSN) Postgres.
func TestUpdateRole_EmptyAssignableScopeKeepsStoredScope(t *testing.T) {
	for _, backend := range roleRaceBackends() {
		t.Run(backend, func(t *testing.T) {
			w := newRoleRaceWorld(t, backend)
			ctx := context.Background()
			seeded := w.seedRole(t, "keep-scope")
			require.NoError(t, w.lsA.SetRoleAssignableScope(ctx, seeded.ID, models.RoleAssignableAny))

			stale, err := w.lsA.GetRole(ctx, seeded.ID) // read "any"
			require.NoError(t, err)
			require.NoError(t, w.lsB.SetRoleAssignableScope(ctx, seeded.ID, models.RoleAssignableProject))

			stale.AssignableScope = ""
			stale.Description = "description only"
			got, err := w.lsA.UpdateRole(ctx, stale)
			require.NoError(t, err)
			require.Equal(t, models.RoleAssignableProject, got.AssignableScope, "an empty scope wrote over the stored one")
			require.Equal(t, "description only", got.Description)

			// Control: an explicit scope is written.
			stale.AssignableScope = models.RoleAssignableGlobal
			got, err = w.lsA.UpdateRole(ctx, stale)
			require.NoError(t, err)
			require.Equal(t, models.RoleAssignableGlobal, got.AssignableScope)
		})
	}
}
