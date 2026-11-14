package handlers

// rbac_errmap_test.go — ERRMAP-CATALOG-NOV-1 item 2. The role and permission routes of
// rbac.go answered each core refusal from a per-handler switch that ended in a blanket 500.
// They answer through answerCoreError; this table pins case -> status for every refusal the
// routes can see, written first against the old switches so every status that was already
// right stays right.

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func rbacCall(fn http.HandlerFunc, method, body string, params map[string]string, machine bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = withChiParams(req, params)
	if machine {
		req = withMachineCtx(req)
	} else {
		req = withUserCtx(req)
	}
	rec := httptest.NewRecorder()
	fn(rec, req)
	return rec
}

// rbacFoldedRole is mustCreateRole with name_folded set, as core's CreateRole sets it.
func rbacFoldedRole(t *testing.T, db *gorm.DB, name string) *models.Role {
	t.Helper()
	role := &models.Role{Name: name, NameFolded: name, Description: name + " role", AssignableScope: models.RoleAssignableAny}
	require.NoError(t, db.Create(role).Error)
	return role
}

func TestRBACRoutes_RefusalsAnswerTheirStatus(t *testing.T) {
	h, _, db := setupRBACTestWithDB(t)
	// The live-name uniqueness is an index the storage factory creates, not an AutoMigrate tag.
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_roles_name_folded ON roles (name_folded)").Error)

	custom := rbacFoldedRole(t, db, "custom-role")
	builtin := rbacFoldedRole(t, db, "admin")
	perm := mustCreatePermission(t, db, "audit.read", "audit", "read")
	held := mustCreatePermission(t, db, "secrets.read", "secrets", "read")
	require.NoError(t, db.Create(&models.RolePermission{RoleID: custom.ID, PermissionID: held.ID}).Error)
	target := &models.User{Username: "target", Email: "target@example.com"}
	require.NoError(t, db.Create(target).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: target.ID, RoleID: custom.ID}).Error)
	id := func(n uint) string { return fmt.Sprint(n) }

	cases := []struct {
		name    string
		fn      http.HandlerFunc
		method  string
		body    string
		params  map[string]string
		machine bool
		status  int
	}{
		{"CreateRole reserved name", h.CreateRole, http.MethodPost, `{"name":"admin","description":"d","permissions":["audit.read"]}`, nil, false, http.StatusConflict},
		{"CreateRole duplicate name", h.CreateRole, http.MethodPost, `{"name":"custom-role","description":"d","permissions":["audit.read"]}`, nil, false, http.StatusConflict},
		{"CreateRole machine without the permission", h.CreateRole, http.MethodPost, `{"name":"made-by-machine","description":"d","permissions":["audit.read"]}`, nil, true, http.StatusForbidden},

		{"UpdateRole absent", h.UpdateRole, http.MethodPut, `{"description":"d"}`, map[string]string{"id": "999999"}, false, http.StatusNotFound},
		{"UpdateRole built-in", h.UpdateRole, http.MethodPut, `{"description":"d"}`, map[string]string{"id": id(builtin.ID)}, false, http.StatusForbidden},

		{"DeleteRole absent", h.DeleteRole, http.MethodDelete, "", map[string]string{"id": "999999"}, false, http.StatusNotFound},
		{"DeleteRole built-in", h.DeleteRole, http.MethodDelete, "", map[string]string{"id": id(builtin.ID)}, false, http.StatusForbidden},

		{"AssignPermissionToRole duplicate", h.AssignPermissionToRole, http.MethodPost, fmt.Sprintf(`{"permission_id":%d}`, held.ID), map[string]string{"id": id(custom.ID)}, false, http.StatusConflict},
		{"AssignPermissionToRole absent role", h.AssignPermissionToRole, http.MethodPost, fmt.Sprintf(`{"permission_id":%d}`, perm.ID), map[string]string{"id": "999999"}, false, http.StatusNotFound},
		{"AssignPermissionToRole absent permission", h.AssignPermissionToRole, http.MethodPost, `{"permission_id":999999}`, map[string]string{"id": id(custom.ID)}, false, http.StatusNotFound},
		{"AssignPermissionToRole machine without it", h.AssignPermissionToRole, http.MethodPost, fmt.Sprintf(`{"permission_id":%d}`, perm.ID), map[string]string{"id": id(custom.ID)}, true, http.StatusForbidden},

		{"RemovePermissionFromRole not assigned", h.RemovePermissionFromRole, http.MethodDelete, "", map[string]string{"id": id(custom.ID), "permissionId": id(perm.ID)}, false, http.StatusNotFound},
		{"RemovePermissionFromRole absent role", h.RemovePermissionFromRole, http.MethodDelete, "", map[string]string{"id": "999999", "permissionId": id(perm.ID)}, false, http.StatusNotFound},

		{"AssignRole already assigned", h.AssignRole, http.MethodPost, fmt.Sprintf(`{"user_id":%d,"role_id":%d}`, target.ID, custom.ID), nil, false, http.StatusConflict},
		{"AssignRole absent role", h.AssignRole, http.MethodPost, fmt.Sprintf(`{"user_id":%d,"role_id":999999}`, target.ID), nil, false, http.StatusNotFound},
		{"AssignRole past expiry", h.AssignRole, http.MethodPost, fmt.Sprintf(`{"user_id":%d,"role_id":%d,"expires_at":"2001-01-01T00:00:00Z"}`, target.ID, custom.ID), nil, false, http.StatusBadRequest},

		{"RemoveRole not assigned", h.RemoveRole, http.MethodDelete, fmt.Sprintf(`{"user_id":%d,"role_id":%d}`, target.ID, builtin.ID), nil, false, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := rbacCall(tc.fn, tc.method, tc.body, tc.params, tc.machine)
			require.Equal(t, tc.status, rec.Code, rec.Body.String())
		})
	}
}
