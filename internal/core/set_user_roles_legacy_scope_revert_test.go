package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSetUserRoles_RevertRestoresLegacyGlobalProjectRole is #3554 review
// follow-up 3: SetUserRoles' compensating revert re-grants what it removed
// through AssignUserRole, which runs the role-scope check since #3546. A legacy
// project role held at the global scope (written before #3546) is a grant the
// check refuses as NEW, so without the restore marker a failed SetUserRoles
// removed it and could not put it back: the failure silently dropped a grant.
func TestSetUserRoles_RevertRestoresLegacyGlobalProjectRole(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	u, err := st.CreateUser(ctx, foldedTestUser(t, "legacy", "legacy@example.com"))
	require.NoError(t, err)
	developer, err := st.GetRoleByName(ctx, "project_developer")
	require.NoError(t, err)
	auditor, err := st.GetRoleByName(ctx, "system_auditor")
	require.NoError(t, err)

	global := storage.Scope{}
	// The legacy row, written the way pre-#3546 servers wrote it (raw storage).
	require.NoError(t, st.AssignRole(ctx, u.ID, developer.ID, global))

	// New set: drop the legacy developer grant, add system_auditor (which fails).
	armed := true
	c.storage = failOnceAssignRoleForRoleStorage(st, auditor.ID, &armed)

	const actor = uint(1) // bootstrapped global admin
	err = c.SetUserRoles(ctx, actor, u.ID, []uint{auditor.ID}, global, false)
	require.Error(t, err)
	require.False(t, armed, "the injected fault must actually have fired")

	got, gerr := st.GetUserRoleIDsExact(ctx, u.ID, global)
	require.NoError(t, gerr)
	assert.ElementsMatch(t, []uint{developer.ID}, got,
		"the revert must restore the legacy global project_developer grant it removed, not drop it")
}

// TestRoleScopeRestoreMarker_CoversOnlyItsOwnGrant: the marker skips the check
// for the exact (role, scope) it names and for nothing else, so it cannot be
// used to slip a different refused grant through.
func TestRoleScopeRestoreMarker_CoversOnlyItsOwnGrant(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	developer, err := st.GetRoleByName(ctx, "project_developer")
	require.NoError(t, err)
	viewer, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)

	marked := withRoleScopeRestore(ctx, developer.ID, storage.Scope{})
	require.NoError(t, c.requireScopeValidForRole(marked, developer.ID, storage.Scope{}),
		"the marked (role, scope) is the restore")
	for name, tc := range map[string]struct {
		roleID uint
		scope  storage.Scope
	}{
		"another role at the same scope": {viewer.ID, storage.Scope{}},
		"the same role at another scope": {developer.ID, storage.Scope{EnvironmentID: 9}},
	} {
		err := c.requireScopeValidForRole(marked, tc.roleID, tc.scope)
		assert.True(t, errors.Is(err, ErrRoleScopeInvalid), "%s: must still be refused, got %v", name, err)
	}
}
