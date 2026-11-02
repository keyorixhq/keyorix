// cta_review_update_role_keep_scope_postgres_test.go — #3909: a description-only
// UpdateRole (AssignableScope "" = keep the stored scope) must never undo a
// narrowing another replica committed after this update read the role.
//
// Before the fix, the keep-scope path copied the scope it had read (plain GetRole,
// no row lock) into the UPDATE, so A's write put back the wider scope B had just
// removed, and A's audit row said nothing about a scope change. The fix omits
// assignable_scope from the UPDATE entirely when the caller keeps it.
//
// The interleaving is forced, not raced: a one-shot GORM callback on replica A's
// own *gorm.DB runs replica B's complete, committing UpdateRole (on B's own
// independent connection pool) immediately before A's UPDATE of the roles row,
// after A has already read the stored scope. A holds no lock B needs at that
// point, so running B synchronously is safe, and the test is red on the unfixed
// code on every run. Under READ COMMITTED A's UPDATE then sees B's committed row.
//
// SQLite is not affected and is not tested here: its transactions are
// BEGIN IMMEDIATE (one writer at a time), so B cannot commit between A's read
// and A's write inside A's transaction.
package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestCTAReview_UpdateRoleKeepScope_vs_NarrowScope_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)

	role, _, err := f.setup.CreateRoleWithScope(f.ctx, f.adminID, "cta-keep-scope", "before", nil, models.RoleAssignableAny)
	require.NoError(t, err)

	var narrowErr error
	fired := f.beforeA("update", "roles", func() {
		// Replica B narrows any -> project and commits, after A read "any".
		narrow := *role
		narrow.AssignableScope = models.RoleAssignableProject
		_, _, narrowErr = f.coreB.UpdateRole(f.ctx, f.adminID, &narrow, nil)
	})

	// Replica A edits only the description and keeps the stored scope.
	keep := *role
	keep.AssignableScope = ""
	keep.Description = "A edits the description"
	_, _, updErr := f.coreA.UpdateRole(f.ctx, f.adminID, &keep, nil)

	require.True(t, fired(), "replica A never reached its roles UPDATE — the interleaving under test never happened")
	require.NoError(t, narrowErr, "replica B's narrowing")
	require.NoError(t, updErr, "replica A's description edit")

	var stored models.Role
	require.NoError(t, f.setupDB.First(&stored, role.ID).Error)
	assert.Equal(t, models.RoleAssignableProject, stored.AssignableScope,
		"a description-only edit undid a narrowing committed by another replica")
	assert.Equal(t, "A edits the description", stored.Description, "A's description edit was lost")

	// The audit trail records each change once, by the update that made it: B's
	// row names the narrowing; A's row names no scope change, because A made none.
	var descs []string
	require.NoError(t, f.setupDB.Model(&models.AuditEvent{}).
		Where("event_type = ? AND description LIKE ?", EventRoleUpdated, "%cta-keep-scope%").
		Order("id").Pluck("description", &descs).Error)
	require.Len(t, descs, 2, "one role.updated row per update: %v", descs)
	assert.Contains(t, descs[0], "(assignable_scope any -> project)", "B's row must record the narrowing")
	assert.NotContains(t, descs[1], "assignable_scope", "A's row must not claim a scope change")
}
