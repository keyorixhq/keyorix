// secrets_list_overcap_test.go — CORE-ERRMAP-TAILS-5: GET /api/v1/secrets answers a
// typed 422 ShareListOverCap when the caller's share list is over the cap.
package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestListSecrets_ShareListOverCapIs422 makes the shared-with-me fetch come back at
// the storage row cap (10000 shares received by the caller) on each list path that
// calls it: no scope filter (plain and shared-only) and a scope the caller's role
// covers. (A project filter without a covering role lists owned secrets only and never
// fetches shares.) Each used to answer 500 InternalError.
func TestListSecrets_ShareListOverCapIs422(t *testing.T) {
	h, db := freshListFixtureS38(t)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "sharer", Email: "sharer@example.com", AccountState: "active"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "scoped-reader"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)

	const atCap = 10000 // core.maxShareViewBatchSize, and the storage list cap
	rows := make([]models.ShareRecord, atCap)
	for i := range rows {
		rows[i] = models.ShareRecord{SecretID: 1, OwnerID: 2, RecipientID: 1, Permission: "read"}
	}
	require.NoError(t, db.CreateInBatches(rows, 500).Error)

	cases := []struct {
		name, query string
		grantRole   bool
	}{
		{"no-scope", "/api/v1/secrets", false},
		{"no-scope-shared-only", "/api/v1/secrets?show_shared_only=true", false},
		{"scope-with-role", "/api/v1/secrets?project_id=1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.grantRole {
				require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
			}
			w := httptest.NewRecorder()
			h.ListSecrets(w, withUserCtxS38(httptest.NewRequest(http.MethodGet, tc.query, nil), 1))
			require.Equal(t, http.StatusUnprocessableEntity, w.Code, w.Body.String())
			require.Contains(t, w.Body.String(), "ShareListOverCap")
		})
	}
}
