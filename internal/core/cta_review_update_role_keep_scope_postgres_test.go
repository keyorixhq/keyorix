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
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestCTAReview_UpdateRoleKeepScope_vs_NarrowScope_CrossReplicaPostgres(t *testing.T) {
	// delayAAudit holds replica A's audit INSERT back until B's audit row exists, which
	// forces the order the unforced run only hits occasionally: B commits its roles
	// UPDATE after A, finishes and audits before A's post-commit audit row lands.
	for _, delayAAudit := range []bool{false, true} {
		t.Run(fmt.Sprintf("delay-A-audit=%v", delayAAudit), func(t *testing.T) {
			t.Parallel()
			testUpdateRoleKeepScopeVsNarrowScope(t, delayAAudit)
		})
	}
}

func testUpdateRoleKeepScopeVsNarrowScope(t *testing.T, delayAAudit bool) {
	f := newCTAReview(t)
	coreA := f.coreA
	if delayAAudit {
		// A's audit row is the one that names no scope change; B's names the narrowing.
		coreA = NewKeyorixCore(hooked(localstore.NewLocalStorage(f.dbA), &storeHooks{
			WrapTx: true,
			LogAuditEvent: func(next storage.Storage, ctx context.Context, e *models.AuditEvent) error {
				if strings.Contains(e.Description, "cta-keep-scope") && !strings.Contains(e.Description, "assignable_scope") {
					time.Sleep(500 * time.Millisecond)
				}
				return next.LogAuditEvent(ctx, e)
			},
		}))
		coreA.SetAuthEncryptor(f.enc)
	}

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
	_, _, updErr := coreA.UpdateRole(f.ctx, f.adminID, &keep, nil)
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
	// Both requests carry a description, so it is last writer wins, and which
	// request writes the roles row last depends on the row lock. The order of the
	// audit rows says nothing about it: an update's audit row is inserted after its
	// own transaction commits (best-effort, or owed), so B can commit second, finish
	// and audit before A's row lands (delay-A-audit=true forces exactly that). Roles
	// have no timestamp to tell the writers apart, so the invariant is: the stored
	// description is one of the two requests' descriptions, never a mix or anything else.
	assert.Contains(t, []string{keep.Description, role.Description}, stored.Description,
		"the stored description is neither request's: rows %v", descs)
}
