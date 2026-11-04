package http

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestPATOwnerLostGrantCeilingAfterCreation_RefusedAtUseTime pins PAT-SCOPE-TAILS-1
// item 4: a PAT carries no authority of its own. It is a filter over its owner's LIVE
// roles, so a PAT scoped to roles.assign, created while its owner held roles.assign at
// project 2, stops granting roles the moment the owner loses that role, even though
// the token row (and its scopes) is unchanged. The same token first succeeds (the
// test is not vacuous), the owner is demoted through the real API by another admin
// (so every cache eviction the product runs runs here too), then the same request
// with the same token is refused and changes nothing.
func TestPATOwnerLostGrantCeilingAfterCreation_RefusedAtUseTime(t *testing.T) {
	w := newRoleScopeHTTPWorld(t)
	db := w.db
	require.NoError(t, db.AutoMigrate(&models.PendingAuditEvent{}, &models.PersonalAccessToken{}))
	now := time.Now()

	// User 2 (the PAT owner): roles.assign at project 2 only, no global admin.
	require.NoError(t, db.Where("user_id = ?", 2).Delete(&models.UserRole{}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 100, Name: "roles.assign", Resource: "roles", Action: "assign"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 20, Name: "proj_assigner", NameFolded: "proj_assigner"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 20, PermissionID: 100}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 22, Name: "proj_member", NameFolded: "proj_member"}).Error) // bundles nothing
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 20, ProjectID: 2}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 10, ProjectID: 2}).Error) // target: an existing member

	// User 4: the global admin who demotes user 2.
	const adminToken = "pat-owner-lost-ceiling-admin-tok"
	require.NoError(t, db.Create(&models.User{ID: 4, Username: "admin2", Email: "admin2@test.com", IsActive: true, AccountState: "active", CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 4, RoleID: 1}).Error)
	// ... who also administers project 2, so the last-project-admin guard lets user 2 go.
	require.NoError(t, db.Create(&models.UserRole{UserID: 4, RoleID: 20, ProjectID: 2}).Error)
	seedSession(t, db, 4, adminToken)

	// User 2's PAT, scoped to roles.assign (what CreateOwnPAT stores).
	const pat = "kx_pat_ownerlostceilingusetime0001"
	sum := sha256.Sum256([]byte(pat))
	require.NoError(t, db.Create(&models.PersonalAccessToken{
		UserID: 2, Name: "assigner", TokenHash: hex.EncodeToString(sum[:]), TokenPrefix: pat[:13], Scopes: `["roles.assign"]`,
	}).Error)

	do := func(method, path, token, body string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(method, w.server.URL+path, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := w.server.Client().Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, string(b)
	}
	memberRoles := func() []uint {
		var ids []uint
		require.NoError(t, db.Model(&models.UserRole{}).Where("user_id = ? AND project_id = ?", 3, 2).Order("role_id").Pluck("role_id", &ids).Error)
		return ids
	}

	// While the owner holds roles.assign at project 2, the PAT can grant.
	status, body := do(http.MethodPut, "/api/v1/projects/2/members/3", pat, `{"role":"proj_member"}`)
	require.Equal(t, http.StatusOK, status, body)
	require.Equal(t, []uint{22}, memberRoles())

	// Another admin removes the owner's project role through the API.
	status, body = do(http.MethodPut, "/api/v1/users/2/roles", adminToken, `{"role_ids":[],"project_id":2}`)
	require.Equal(t, http.StatusOK, status, body)

	// The token row is unchanged, but the owner no longer holds the ceiling: refused.
	status, body = do(http.MethodPut, "/api/v1/projects/2/members/3", pat, `{"role":"project_developer"}`)
	require.Equal(t, http.StatusForbidden, status, body)
	require.Equal(t, []uint{22}, memberRoles(), "the refused grant changed the member's roles")
}
