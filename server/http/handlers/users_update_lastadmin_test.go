// users_update_lastadmin_test.go — ADR-108 PR 6 (docs/cli-split-inventory.md §7): before
// this fix, UserHandler.UpdateUser's error switch had no case for
// guardLastAdminDeactivation's "refusing to deactivate the last install administrator"
// error, so a caller deactivating the install's sole admin via PUT /api/v1/users/{id} got
// a generic 500 "Failed to update user" instead of the readable 409 its sibling
// DeleteUser already returned for the identical guard. Found while porting `keyorix-next
// user update` (a thin, REST-only CLI with no fallback of its own to mask this).
//
// Reaching this WITHOUT self-action (which core.UpdateUser refuses earlier, via
// ErrCannotActOnSelf, before ever reaching the last-admin guard) requires an actor who
// passes requireAdminRankCeilingForTarget's bypass check without being counted as an
// admin by guardLastAdminDeactivation's resolveGlobalAdminHolders -- these use two
// different definitions of "admin" (any role with BypassesPermissionChecks=true, vs. the
// fixed installAdminRoleNames list). A role named outside that fixed list but flagged
// BypassesPermissionChecks is exactly that gap, and is a real, already-used test pattern
// in this package (see internal/core/certificate_expiry_test.go's "project_admin").
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpdateUser_RefusesLastAdminDeactivation_RealServer attempts to deactivate the
// seeded install admin via a non-self actor holding a bypass-flagged, non-canonical role,
// and asserts the HTTP layer surfaces a readable 409 (not a bare 500) and that the
// deactivation does not persist.
func TestUpdateUser_RefusesLastAdminDeactivation_RealServer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	admin, err := cs.GetUserByUsername(ctx, "testuser_s12")
	require.NoError(t, err)
	require.True(t, admin.IsActive)

	// A second actor who bypasses the admin-rank ceiling (so the request reaches the
	// last-admin guard at all) but is NOT counted among installAdminRoleNames's
	// holders -- see this file's doc comment.
	require.NoError(t, db.Create(&models.Role{Name: "custom_bypass_role", BypassesPermissionChecks: true}).Error)
	var bypassRole models.Role
	require.NoError(t, db.Where("name = ?", "custom_bypass_role").First(&bypassRole).Error)
	actorID := uint(9001)
	require.NoError(t, db.Create(&models.User{
		ID: actorID, Username: "bypassactor", UsernameFolded: "bypassactor",
		Email: "bypassactor@example.com", EmailFolded: "bypassactor@example.com",
		DisplayName: "Bypass Actor", IsActive: true,
	}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: actorID, RoleID: bypassRole.ID}).Error)

	body, err := json.Marshal(map[string]interface{}{"active": false})
	require.NoError(t, err)
	req := withChiParams(httptest.NewRequest("PUT", "/", bytes.NewReader(body)), map[string]string{"id": machineUintToStr(admin.ID)})
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), actorCtx(actorID, "bypassactor")))
	w := httptest.NewRecorder()
	h.UpdateUser(w, req)

	assert.Equal(t, 409, w.Code, "deactivating the install's last admin must be a readable refusal, not a bare 500: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "last install administrator", "the real refusal reason must reach the client")

	reloaded, err := cs.Storage().GetUser(ctx, admin.ID)
	require.NoError(t, err)
	assert.True(t, reloaded.IsActive, "the last admin must still be active -- the deactivation must not have persisted")
}
