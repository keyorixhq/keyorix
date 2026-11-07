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
// own *gorm.DB starts replica B's complete UpdateRole (on B's own independent
// connection pool) immediately before A's UPDATE of the roles row, after A has
// already read the stored scope. Before #3919 B committed inside that window and
// A's UPDATE then saw B's row under READ COMMITTED; since #3919 A holds the role
// row lock (LockRoleForUpdate), so B waits for A and applies after it
// (beforeARoleUpdate detects either). The invariant holds both ways: the
// narrowing survives and each audit row names only its own change.
//
// SQLite is not affected and is not tested here: its transactions are
// BEGIN IMMEDIATE (one writer at a time), so B cannot commit between A's read
// and A's write inside A's transaction.
package core

import (
	"strings"
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
	fired, waitB := f.beforeARoleUpdate(func() {
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
	waitB()

	require.True(t, fired(), "replica A never reached its roles UPDATE — the interleaving under test never happened")
	require.NoError(t, narrowErr, "replica B's narrowing")
	require.NoError(t, updErr, "replica A's description edit")

	var stored models.Role
	require.NoError(t, f.setupDB.First(&stored, role.ID).Error)
	assert.Equal(t, models.RoleAssignableProject, stored.AssignableScope,
		"a description-only edit undid a narrowing committed by another replica")

	// The audit trail records each change once, by the update that made it: B's
	// row names the narrowing; A's row names no scope change, because A made none.
	// Which commits first depends on the lock, so the rows are matched by content.
	var descs []string
	require.NoError(t, f.setupDB.Model(&models.AuditEvent{}).
		Where("event_type = ? AND description LIKE ?", EventRoleUpdated, "%cta-keep-scope%").
		Order("id").Pluck("description", &descs).Error)
	require.Len(t, descs, 2, "one role.updated row per update: %v", descs)
	var narrowRows, noScopeRows int
	for _, d := range descs {
		switch {
		case strings.Contains(d, "(assignable_scope any -> project)"):
			narrowRows++
		case !strings.Contains(d, "assignable_scope"):
			noScopeRows++
		}
	}
	assert.Equal(t, 1, narrowRows, "B's row must record the narrowing: %v", descs)
	assert.Equal(t, 1, noScopeRows, "A's row must not claim a scope change: %v", descs)
	// Both requests carry a description, so it is last writer wins: before #3919 B
	// committed inside A's window and A's edit was last; with the row lock B waits
	// and its own request's description ("before") is last. Either way the stored
	// description is the last committer's, never a mix.
	wantDesc := "A edits the description"
	if strings.Contains(descs[len(descs)-1], "(assignable_scope any -> project)") {
		wantDesc = role.Description
	}
	assert.Equal(t, wantDesc, stored.Description, "the description is not the last committed update's: rows %v", descs)
}
