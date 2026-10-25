package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSetUserRoles_LegacyGlobalProjectRole_NeverDroppedSilently is #3554 review
// follow-up 3, restated for the #3488 split (role_set_replace.go). A legacy
// project role held at the global scope (written before #3546) is a grant the
// role-scope check refuses as NEW. Before #3488 a failed SetUserRoles re-granted
// what it had removed through AssignUserRole, whose scope check refused the legacy
// row, so the failure silently dropped it. Since #3488 nothing re-grants: the
// removal is the caller's own request and stands, and a failed addition after it
// is a PartialMutationError naming the removed role, never a silent drop. A
// replacement whose addition the scope check refuses is refused before the
// removal, so the legacy row stays.
func TestSetUserRoles_LegacyGlobalProjectRole_NeverDroppedSilently(t *testing.T) {
	t.Parallel()

	t.Run("addition fails after the removal: the removal is reported", func(t *testing.T) {
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
		pe, ok := AsPartialMutationError(err)
		require.True(t, ok, "a failed addition after the legacy grant's removal must say the removal landed, got %v", err)
		assert.Contains(t, pe.Applied, "removal", "Applied names the removal")
		assert.Contains(t, pe.NotApplied, "addition", "NotApplied names the addition")

		got, gerr := st.GetUserRoleIDsExact(ctx, u.ID, global)
		require.NoError(t, gerr)
		assert.Empty(t, got, "exactly the requested removal applied, the failed addition not")
	})

	t.Run("addition refused by the scope check: nothing is removed", func(t *testing.T) {
		t.Parallel()
		c, st := newBootstrappedCore(t)
		ctx := context.Background()

		u, err := st.CreateUser(ctx, foldedTestUser(t, "legacy2", "legacy2@example.com"))
		require.NoError(t, err)
		developer, err := st.GetRoleByName(ctx, "project_developer")
		require.NoError(t, err)
		viewer, err := st.GetRoleByName(ctx, "project_viewer")
		require.NoError(t, err)

		global := storage.Scope{}
		require.NoError(t, st.AssignRole(ctx, u.ID, developer.ID, global))

		const actor = uint(1)
		err = c.SetUserRoles(ctx, actor, u.ID, []uint{viewer.ID}, global, false)
		require.True(t, errors.Is(err, ErrRoleScopeInvalid), "project_viewer at the global scope must be refused, got %v", err)

		got, gerr := st.GetUserRoleIDsExact(ctx, u.ID, global)
		require.NoError(t, gerr)
		assert.ElementsMatch(t, []uint{developer.ID}, got,
			"the scope refusal comes before the removal: the legacy grant stays")
	})
}
