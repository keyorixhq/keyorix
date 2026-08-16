// secret_version_diff_acl_gate_test.go — regression coverage for the
// DiffSecretVersions ACL-membership disclosure gap (Wave 6 medium-severity
// batch 2, findings-handlers/handlers-secret-version-comments.json#3).
//
// GET /api/v1/secrets/{id}/versions/{from}/diff/{to} is gated at the router
// level on secrets.read (see router.go), but core.DiffSecretVersions'
// response also carries ACLUserIDs — the secret's full ACL membership — which
// is otherwise exposed only via the more tightly-gated secrets.manage-only
// GET /{id}/acl endpoint. A caller holding nothing but read permission on a
// secret could therefore recover its ACL membership through the diff
// endpoint, bypassing the manage-only gate on the dedicated ACL endpoint.
//
// The fix (secret_version_diff.go) performs an in-handler
// AuthorizeSecretPrincipal(..., permSecretsManage) check and strips
// ACLUserIDs/Degraded from the response for any caller who does not hold
// secrets.manage on the specific secret — mirroring the same in-handler
// tiered-visibility pattern ListSecrets already uses (secrets_list.go).
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// grantedACLUserID is the user ID seeded into the secret's ACL for these
// tests — distinct from any principal ID used as a caller, so its presence
// (or absence) in the response unambiguously signals whether ACL membership
// leaked.
const grantedACLUserID = 555

// withUserCtxDiffACL builds a request carrying a plain (non-machine) user
// context for the given userID.
func withUserCtxDiffACL(r *http.Request, userID uint) *http.Request {
	userCtx := &customMiddleware.UserContext{UserID: userID, Username: fmt.Sprintf("u%d", userID), Email: fmt.Sprintf("u%d@test.com", userID)}
	return r.WithContext(context.WithValue(r.Context(), customMiddleware.GetUserContextKey(), userCtx))
}

// newDiffACLGateFixture seeds a secret (project 1 / env 1, ID 100, versions 1
// and 2, matching seedVersionDiffFixtureS36's shape) with one ACL grant for
// grantedACLUserID, plus two distinct non-admin callers scoped to that
// project/environment:
//   - readOnlyUserID holds only secrets.read.
//   - manageUserID holds only secrets.manage.
//
// Neither holds an admin-bypass role name, so AuthorizeSecretPrincipal's
// result for each depends solely on the permission actually granted.
func newDiffACLGateFixture(t *testing.T) (h *SecretHandler, db *gorm.DB, secretID, readOnlyUserID, manageUserID uint) {
	t.Helper()
	cs, db := freshCoreS36WithAdmin(t)
	secretID = seedVersionDiffFixtureS36(t, db)

	require.NoError(t, db.Create(&models.SecretACL{
		SecretID:    secretID,
		UserID:      grantedACLUserID,
		Permissions: `["secrets.read"]`,
		GrantedBy:   1,
	}).Error)

	readPerm := &models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
	require.NoError(t, db.Where("name = ?", "secrets.read").FirstOrCreate(readPerm).Error)
	managePerm := &models.Permission{Name: "secrets.manage", Resource: "secrets", Action: "manage"}
	require.NoError(t, db.Where("name = ?", "secrets.manage").FirstOrCreate(managePerm).Error)

	readerRole := &models.Role{Name: "diff-acl-gate-reader", Description: "read-only"}
	require.NoError(t, db.Create(readerRole).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: readerRole.ID, PermissionID: readPerm.ID}).Error)

	managerRole := &models.Role{Name: "diff-acl-gate-manager", Description: "manage-only"}
	require.NoError(t, db.Create(managerRole).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: managerRole.ID, PermissionID: managePerm.ID}).Error)

	readOnlyUser := &models.User{Username: "diff-acl-reader", Email: "diff-acl-reader@example.com", AccountState: "active"}
	require.NoError(t, db.Create(readOnlyUser).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: readOnlyUser.ID, RoleID: readerRole.ID, ProjectID: 1, EnvironmentID: 0}).Error)

	manageUser := &models.User{Username: "diff-acl-manager", Email: "diff-acl-manager@example.com", AccountState: "active"}
	require.NoError(t, db.Create(manageUser).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: manageUser.ID, RoleID: managerRole.ID, ProjectID: 1, EnvironmentID: 0}).Error)

	handler, err := NewSecretHandler(cs)
	require.NoError(t, err)
	return handler, db, secretID, readOnlyUser.ID, manageUser.ID
}

// diffACLGateResponse mirrors the fields of the diff endpoint's JSON envelope
// this test cares about.
type diffACLGateResponse struct {
	Success bool `json:"success"`
	Data    struct {
		SecretID   uint   `json:"secret_id"`
		ACLUserIDs []uint `json:"acl_user_ids"`
		Degraded   bool   `json:"degraded"`
		Changes    []struct {
			Field string `json:"field"`
		} `json:"changes"`
	} `json:"data"`
}

// TestDiffSecretVersions_ACLHiddenForReadOnlyCaller is the negative-case
// regression test for the ACL-disclosure gap: a caller holding only
// secrets.read on the secret must NOT see ACLUserIDs in the diff response,
// even though the secret does have an ACL grant. The diff's own content
// (changes) must still come back correctly — this is a field-level gate, not
// a request-level denial.
func TestDiffSecretVersions_ACLHiddenForReadOnlyCaller(t *testing.T) {
	h, _, secretID, readOnlyUserID, _ := newDiffACLGateFixture(t)

	r := withUserCtxDiffACL(withChiParam3_S36(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/versions/1/diff/2", secretID), nil),
		"id", fmt.Sprintf("%d", secretID), "from", "1", "to", "2",
	), readOnlyUserID)
	w := httptest.NewRecorder()
	h.DiffSecretVersions(w, r)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp diffACLGateResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.Equal(t, secretID, resp.Data.SecretID)
	assert.Empty(t, resp.Data.ACLUserIDs, "a read-only caller must not see the secret's ACL membership via the diff endpoint")
	assert.False(t, resp.Data.Degraded, "Degraded is meaningless once ACLUserIDs is hidden and must not be surfaced as true")
	assert.NotContains(t, w.Body.String(), fmt.Sprintf("%d", grantedACLUserID), "the granted user's ID must not leak anywhere in the response body")
}

// TestDiffSecretVersions_ACLVisibleForManageCaller is the positive-case
// counterpart: a caller who holds secrets.manage on the secret (the same
// permission the dedicated GET /{id}/acl endpoint requires) must still see
// the ACL snapshot in the diff response, exactly as before this fix.
func TestDiffSecretVersions_ACLVisibleForManageCaller(t *testing.T) {
	h, _, secretID, _, manageUserID := newDiffACLGateFixture(t)

	r := withUserCtxDiffACL(withChiParam3_S36(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/versions/1/diff/2", secretID), nil),
		"id", fmt.Sprintf("%d", secretID), "from", "1", "to", "2",
	), manageUserID)
	w := httptest.NewRecorder()
	h.DiffSecretVersions(w, r)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp diffACLGateResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.Equal(t, secretID, resp.Data.SecretID)
	assert.Contains(t, resp.Data.ACLUserIDs, uint(grantedACLUserID), "a manage-permission caller must still see the ACL snapshot")
}
