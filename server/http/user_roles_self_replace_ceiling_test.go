package http

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestUpdateUserRolesHTTP_SelfReplacementLosingRolesAssign_ChangesNothing is #3684 over
// PUT /api/v1/users/{id}/roles: the global admin (user 2) replaces their OWN global
// roles with a role they could grant only through the admin role the replacement
// removes. A second global admin exists, so the last-admin guard lets user 2 drop it.
// Before the fix the removal committed, the grant was refused afterwards and the
// answer was 503 MutationPartiallyApplied with retry_safe true, leaving user 2 with no
// role; the retry was refused. Now the request is refused before anything commits.
func TestUpdateUserRolesHTTP_SelfReplacementLosingRolesAssign_ChangesNothing(t *testing.T) {
	w := newRoleScopeHTTPWorld(t)
	now := time.Now()
	require.NoError(t, w.db.AutoMigrate(&models.PendingAuditEvent{}))
	require.NoError(t, w.db.Create(&models.User{ID: 4, Username: "admin2", Email: "admin2@test.com", IsActive: true, AccountState: "active", CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, w.db.Create(&models.UserRole{UserID: 4, RoleID: 1}).Error) // second global admin
	require.NoError(t, w.db.Create(&models.Role{ID: 12, Name: "viewer", NameFolded: "viewer"}).Error)

	before := w.userGrants(t, 2)
	status, body := w.put(t, "/api/v1/users/2/roles", `{"role_ids":[12],"project_id":0}`)
	require.NotEqual(t, http.StatusServiceUnavailable, status, body)
	require.NotContains(t, body, "MutationPartiallyApplied", "nothing may be applied")
	require.NotEqual(t, http.StatusOK, status, body)
	require.Equal(t, before, w.userGrants(t, 2), "the refused self-replacement changed the actor's roles")
}
