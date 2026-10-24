package core

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failOnceAssignRoleForRoleStorage makes AssignRole fail once for a specific
// roleID, mirroring the failOnceStorage idiom from #2295.
func failOnceAssignRoleForRoleStorage(inner storage.Storage, failRoleID uint, armed *bool) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx: true,
		AssignRole: func(next storage.Storage, ctx context.Context, userID, roleID uint, scope storage.Scope) error {
			if *armed && roleID == failRoleID {
				*armed = false
				return errors.New("injected fault: AssignRole")
			}
			return next.AssignRole(ctx, userID, roleID, scope)
		},
	})
}

// WithTransaction keeps the fault on the transaction-scoped handle: a grant is
// written through tx since AUDIT-TX-2 (it commits with its audit row).
// TestSetUserRoles_AdditionFailureLeavesExactlyTheRemovalsAndSaysSo started as the
// red-proof for Session O's O3 SetUserRoles finding: a failure partway through a
// role-set replacement returned with NO compensation and NO way for the caller to
// tell which changes had landed. O3's answer was a compensating revert (re-grant the
// removed roles); #3488 found that revert fails closed on the same audit outage that
// failed the grant, losing the role while saying "nothing was changed". Since #3488
// the replacement is a split mixed request (role_set_replace.go): the removals are
// one transaction, the additions another, and a failure of the additions leaves
// EXACTLY the removals applied and says so (PartialMutationError) -- never an
// arbitrary in-between state, never a silent one. The removal-side counterpart (a
// failed removal leaves the original set) is
// TestSetUserRoles_AuditOutage_NeverLosesARole/narrowing-fails-midway.
func TestSetUserRoles_AdditionFailureLeavesExactlyTheRemovalsAndSaysSo(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "roles-proj", Description: "d"})
	require.NoError(t, err)
	u, err := st.CreateUser(ctx, foldedTestUser(t, "target", "target@example.com"))
	require.NoError(t, err)

	viewer, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	developer, err := st.GetRoleByName(ctx, "project_developer")
	require.NoError(t, err)
	admin, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)

	scope := storage.Scope{ProjectID: proj.ID}
	require.NoError(t, st.AssignRole(ctx, u.ID, viewer.ID, scope))
	require.NoError(t, st.AssignRole(ctx, u.ID, developer.ID, scope))

	// New set: keep viewer, drop developer, add admin (which will fail).
	armed := true
	c.storage = failOnceAssignRoleForRoleStorage(st, admin.ID, &armed)

	const actor = uint(1) // bootstrapped global admin
	err = c.SetUserRoles(ctx, actor, u.ID, []uint{viewer.ID, admin.ID}, scope, false)
	require.Error(t, err)
	require.False(t, armed, "the injected fault must actually have fired")
	pe, ok := AsPartialMutationError(err)
	require.True(t, ok, "the call must say the removals applied and the additions did not: %v", err)
	assert.Contains(t, pe.Applied, fmt.Sprint(developer.ID))
	assert.Contains(t, pe.NotApplied, fmt.Sprint(admin.ID))

	got, gerr := st.GetUserRoleIDsExact(ctx, u.ID, scope)
	require.NoError(t, gerr)
	assert.ElementsMatch(t, []uint{viewer.ID}, got,
		"a failed addition must leave EXACTLY the removals applied -- developer removed, admin not present, viewer kept")

	// A retry of the same request completes it.
	require.NoError(t, c.SetUserRoles(ctx, actor, u.ID, []uint{viewer.ID, admin.ID}, scope, false))
	got, gerr = st.GetUserRoleIDsExact(ctx, u.ID, scope)
	require.NoError(t, gerr)
	assert.ElementsMatch(t, []uint{viewer.ID, admin.ID}, got)
}
