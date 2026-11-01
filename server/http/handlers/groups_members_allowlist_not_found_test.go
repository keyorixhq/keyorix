package handlers

// groups_members_allowlist_not_found_test.go — REVFIX-3903-1.
//
// With a membership domain allowlist set and a group that holds a role grant at the
// join's scope, AddUserToGroup reads the user through domainAllowedForUser, whose
// positive not-found is ErrMembershipTargetNotFound (not storage.ErrUserNotFound).
// AddGroupMember must still answer that absent user 404, and a GetUser fault on the
// same path must not become that 404.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestFoldHandlers_Item3_AddGroupMemberAllowlistMissingUser(t *testing.T) {
	fw := newFoldWorld(t)
	ctx := t.Context()
	h, err := NewGroupHandler(fw.cs)
	require.NoError(t, err)

	g, err := fw.local.CreateGroup(ctx, &models.Group{Name: "fold3-allow", NameFolded: "fold3-allow"})
	require.NoError(t, err)
	rn, err := identity.NewFoldedName("fold3-allow-role")
	require.NoError(t, err)
	role, err := fw.local.CreateRole(ctx, rn, "")
	require.NoError(t, err)
	// A global grant: every membership scope reaches it, so the domain gate runs.
	require.NoError(t, fw.db.Create(&models.GroupRole{GroupID: g.ID, RoleID: role.ID}).Error)
	fw.cs.SetMembershipDomainAllowlist([]string{"example.com"})

	add := func(userID uint) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.AddGroupMember(w, suReq(http.MethodPost, `{"user_id":`+suID(userID)+`}`, map[string]string{"id": suID(g.ID)}))
		return w
	}

	w := add(9_999_999)
	assert.Equal(t, http.StatusNotFound, w.Code, "an absent user under the allowlist gate is 404: %s", w.Body.String())

	fw.armFault("GetUser", 1, errFoldDriver)
	w = add(fw.admin.ID)
	require.True(t, fw.faulty.Fired(), "the allowlist gate reads the user")
	requireNot404Fault(t, w, false, "GetUser fault under the allowlist gate")
	fw.faulty.Arm(nil)
}
