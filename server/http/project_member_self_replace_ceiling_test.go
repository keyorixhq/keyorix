package http

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #3684 over the REST role-set replacements, the cases the core tests do not drive
// through a real router: PUT /api/v1/projects/{id}/members/{self} by a project-scoped
// roles.assign holder, and the same replacements made by ANOTHER admin, which must
// still apply. gRPC has no role-set replacement RPC (only AssignRole/RemoveRole, one
// grant each), so these routes are the whole transport surface of replaceUserRoleSet.

const selfReplaceSecondToken = "self-replace-3684-tok-4"

// newSelfReplaceProjectWorld: user 2 is no global admin; users 2 and 4 each hold
// proj_assigner (20, roles.assign) at project 2, so the last-project-admin guard lets
// either drop it; proj_viewer (22) carries no permission. User 4 has its own session.
func newSelfReplaceProjectWorld(t *testing.T) *roleScopeHTTPWorld {
	t.Helper()
	w := newRoleScopeHTTPWorld(t)
	now := time.Now()
	require.NoError(t, w.db.AutoMigrate(&models.PendingAuditEvent{}))
	require.NoError(t, w.db.Where("user_id = ?", 2).Delete(&models.UserRole{}).Error) // no global admin
	require.NoError(t, w.db.Create(&models.User{ID: 4, Username: "assigner2", Email: "assigner2@test.com", IsActive: true, AccountState: "active", CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, w.db.Create(&models.Permission{ID: 100, Name: "roles.assign", Resource: "roles", Action: "assign"}).Error)
	require.NoError(t, w.db.Create(&models.Role{ID: 20, Name: "proj_assigner", NameFolded: "proj_assigner"}).Error)
	require.NoError(t, w.db.Create(&models.Role{ID: 22, Name: "proj_viewer", NameFolded: "proj_viewer"}).Error)
	require.NoError(t, w.db.Create(&models.RolePermission{RoleID: 20, PermissionID: 100}).Error)
	require.NoError(t, w.db.Create(&models.UserRole{UserID: 2, RoleID: 20, ProjectID: 2}).Error)
	require.NoError(t, w.db.Create(&models.UserRole{UserID: 4, RoleID: 20, ProjectID: 2}).Error)
	seedSession(t, w.db, 4, selfReplaceSecondToken)
	return w
}

// putAs is put with another session's token.
func (w *roleScopeHTTPWorld) putAs(t *testing.T, token, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, w.server.URL+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if rerr != nil {
			break
		}
	}
	return resp.StatusCode, sb.String()
}

// TestUpdateProjectMemberHTTP_SelfReplacementLosingRolesAssign_ChangesNothing: user 2
// sets their OWN project-2 role to proj_viewer, which they could grant only through
// the proj_assigner role the replacement removes. Before the fix the removal
// committed, the grant was refused afterwards, and the answer was 503
// MutationPartiallyApplied with retry_safe true, leaving user 2 with no role at the
// project and a retry that could never succeed. Now: exactly 403, nothing changed.
func TestUpdateProjectMemberHTTP_SelfReplacementLosingRolesAssign_ChangesNothing(t *testing.T) {
	w := newSelfReplaceProjectWorld(t)

	before := w.userGrants(t, 2)
	status, body := w.put(t, "/api/v1/projects/2/members/2", `{"role":"proj_viewer"}`)
	require.Equal(t, http.StatusForbidden, status, body)
	require.Contains(t, body, "cannot grant this role", "the 403 is the core ceiling refusal, not the route middleware")
	require.NotContains(t, body, "MutationPartiallyApplied", "nothing may be applied")
	require.NotContains(t, body, "retry_safe")
	require.Equal(t, before, w.userGrants(t, 2), "the refused self-replacement changed the actor's roles")
}

// TestRoleSetReplaceHTTP_OtherAdminReplacement_StillApplies: the up-front refusal is
// for an actor's OWN set only. The same replacements made for another user apply:
// the actor keeps roles.assign, so the grant is within their ceiling.
func TestRoleSetReplaceHTTP_OtherAdminReplacement_StillApplies(t *testing.T) {
	t.Run("PUT members", func(t *testing.T) {
		w := newSelfReplaceProjectWorld(t)
		status, body := w.putAs(t, selfReplaceSecondToken, "/api/v1/projects/2/members/2", `{"role":"proj_viewer"}`)
		require.Equal(t, http.StatusOK, status, body)
		got := w.userGrants(t, 2)
		require.Len(t, got, 1)
		require.Equal(t, uint(22), got[0].RoleID)
		require.Equal(t, uint(2), got[0].ProjectID)
	})
	t.Run("PUT users roles", func(t *testing.T) {
		// The route needs global authority: the global admin (user 2) replaces a
		// second global admin's global set with viewer, the same shape
		// TestUpdateUserRolesHTTP_SelfReplacementLosingRolesAssign_ChangesNothing refuses
		// for the actor's own set.
		w := newRoleScopeHTTPWorld(t)
		now := time.Now()
		require.NoError(t, w.db.AutoMigrate(&models.PendingAuditEvent{}))
		require.NoError(t, w.db.Create(&models.User{ID: 4, Username: "admin2", Email: "admin2@test.com", IsActive: true, AccountState: "active", CreatedAt: now, UpdatedAt: now}).Error)
		require.NoError(t, w.db.Create(&models.UserRole{UserID: 4, RoleID: 1}).Error)
		require.NoError(t, w.db.Create(&models.Role{ID: 12, Name: "viewer", NameFolded: "viewer"}).Error)

		status, body := w.put(t, "/api/v1/users/4/roles", `{"role_ids":[12],"project_id":0}`)
		require.Equal(t, http.StatusOK, status, body)
		got := w.userGrants(t, 4)
		require.Len(t, got, 1)
		require.Equal(t, uint(12), got[0].RoleID)
		require.Equal(t, uint(0), got[0].ProjectID)
	})
}
