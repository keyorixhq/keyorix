// access_write_client_origin_test.go — #2545 extended to the access-model (not just secret-
// value) migration: a role/machine identity/role-grant/OIDC binding apply-access creates was
// indistinguishable in the audit trail from one a human created by hand, because these four
// handlers never read core.ClientOriginHeader into the audit context the way CreateSecret/
// UpdateSecret already do (secrets_crud_client_origin_test.go). These tests drive the real
// handlers and read the persisted audit row, asserting the origin is recorded.
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const accessOriginValue = "keyorix-migrate/1.2.3 source=policy:team-a-ro path:secret/data/team-a/*"

// accessOriginFixture seeds a project/environment and makes withUserCtx's actor (UserID 1) a
// global admin (BypassesPermissionChecks) so every handler's own authorization passes, the same
// pattern rbac_role_audit_test.go uses.
func accessOriginFixture(t *testing.T) (*CatalogHandler, *RBACHandler, *gorm.DB, uint, uint) {
	t.Helper()
	cs, db := freshCoreS12WithAdmin(t)
	proj := &models.Project{Name: "proj-access-origin"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "env-access-origin", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	require.NoError(t, db.Create(&models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	return NewCatalogHandler(cs), NewRBACHandler(cs), db, proj.ID, env.ID
}

func lastAuditEvent(t *testing.T, db *gorm.DB, eventType string) models.AuditEvent {
	t.Helper()
	var ev models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", eventType).Order("id desc").First(&ev).Error)
	return ev
}

func TestCreateRole_ClientOriginRecordedInAudit(t *testing.T) {
	_, rbacHandler, db, _, _ := accessOriginFixture(t)
	body, err := json.Marshal(map[string]any{"name": "vault-migrated-read", "description": "d", "permissions": []string{"secrets.read"}})
	require.NoError(t, err)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/roles", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(core.ClientOriginHeader, accessOriginValue)
	w := httptest.NewRecorder()
	rbacHandler.CreateRole(w, req)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	ev := lastAuditEvent(t, db, core.EventRoleCreated)
	assert.Contains(t, ev.Description, "[client-asserted origin: "+accessOriginValue+"]")
	assert.Equal(t, core.ActorTypeUser, ev.ActorType, "the origin header must never change ActorType")
}

func TestCreateMachineIdentity_ClientOriginRecordedInAudit(t *testing.T) {
	catalogHandler, _, db, projectID, _ := accessOriginFixture(t)
	body, err := json.Marshal(map[string]any{"name": "vault-approle-ci", "identity_type": "service", "description": "d"})
	require.NoError(t, err)
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/machine-identities", projectID), bytes.NewReader(body))), "id", fmt.Sprint(projectID))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(core.ClientOriginHeader, accessOriginValue)
	w := httptest.NewRecorder()
	catalogHandler.CreateMachineIdentity(w, req)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	ev := lastAuditEvent(t, db, "machine_identity.created")
	assert.Contains(t, ev.Description, "[client-asserted origin: "+accessOriginValue+"]")
}

func TestGrantMachineRole_ClientOriginRecordedInAudit(t *testing.T) {
	catalogHandler, rbacHandler, db, projectID, envID := accessOriginFixture(t)

	roleBody, err := json.Marshal(map[string]any{"name": "vault-migrated-read", "description": "d", "permissions": []string{"secrets.read"}})
	require.NoError(t, err)
	roleReq := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/roles", bytes.NewReader(roleBody)))
	roleReq.Header.Set("Content-Type", "application/json")
	roleW := httptest.NewRecorder()
	rbacHandler.CreateRole(roleW, roleReq)
	require.Equal(t, http.StatusCreated, roleW.Code, roleW.Body.String())
	var roleEnv struct {
		Data struct{ Role struct{ ID uint } } `json:"data"`
	}
	require.NoError(t, json.Unmarshal(roleW.Body.Bytes(), &roleEnv))
	roleID := roleEnv.Data.Role.ID
	require.NotZero(t, roleID)

	machBody, err := json.Marshal(map[string]any{"name": "vault-approle-ci", "identity_type": "service", "description": "d"})
	require.NoError(t, err)
	machReq := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/machine-identities", projectID), bytes.NewReader(machBody))), "id", fmt.Sprint(projectID))
	machReq.Header.Set("Content-Type", "application/json")
	machW := httptest.NewRecorder()
	catalogHandler.CreateMachineIdentity(machW, machReq)
	require.Equal(t, http.StatusCreated, machW.Code, machW.Body.String())
	var machEnv struct {
		Data struct {
			MachineIdentity struct{ ID uint } `json:"machine_identity"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(machW.Body.Bytes(), &machEnv))
	machineID := machEnv.Data.MachineIdentity.ID
	require.NotZero(t, machineID)

	grantBody, err := json.Marshal(map[string]any{"role_id": roleID, "environment_id": envID})
	require.NoError(t, err)
	grantReq := withChiParams(withUserCtx(httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/roles", projectID, machineID), bytes.NewReader(grantBody))),
		map[string]string{"id": fmt.Sprint(projectID), "machineId": fmt.Sprint(machineID)})
	grantReq.Header.Set("Content-Type", "application/json")
	grantReq.Header.Set(core.ClientOriginHeader, accessOriginValue)
	grantW := httptest.NewRecorder()
	catalogHandler.GrantMachineRole(grantW, grantReq)
	require.Equal(t, http.StatusOK, grantW.Code, grantW.Body.String())

	ev := lastAuditEvent(t, db, "machine_identity.role_granted")
	assert.Contains(t, ev.Description, "[client-asserted origin: "+accessOriginValue+"]")
}

func TestCreateOIDCBinding_ClientOriginRecordedInAudit(t *testing.T) {
	catalogHandler, _, db, projectID, _ := accessOriginFixture(t)

	machBody, err := json.Marshal(map[string]any{"name": "vault-k8s-ci", "identity_type": "k8s", "description": "d"})
	require.NoError(t, err)
	machReq := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/machine-identities", projectID), bytes.NewReader(machBody))), "id", fmt.Sprint(projectID))
	machReq.Header.Set("Content-Type", "application/json")
	machW := httptest.NewRecorder()
	catalogHandler.CreateMachineIdentity(machW, machReq)
	require.Equal(t, http.StatusCreated, machW.Code, machW.Body.String())
	var machEnv struct {
		Data struct {
			MachineIdentity struct{ ID uint } `json:"machine_identity"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(machW.Body.Bytes(), &machEnv))
	machineID := machEnv.Data.MachineIdentity.ID
	require.NotZero(t, machineID)

	bindBody, err := json.Marshal(map[string]any{"issuer": "https://k8s.example.com", "subject": "system:serviceaccount:prod:deployer"})
	require.NoError(t, err)
	bindReq := withChiParams(withUserCtx(httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d/oidc-bindings", projectID, machineID), bytes.NewReader(bindBody))),
		map[string]string{"id": fmt.Sprint(projectID), "machineId": fmt.Sprint(machineID)})
	bindReq.Header.Set("Content-Type", "application/json")
	bindReq.Header.Set(core.ClientOriginHeader, accessOriginValue)
	bindW := httptest.NewRecorder()
	catalogHandler.CreateOIDCBinding(bindW, bindReq)
	require.Equal(t, http.StatusCreated, bindW.Code, bindW.Body.String())

	ev := lastAuditEvent(t, db, "machine_identity.oidc_bound")
	assert.Contains(t, ev.Description, "[client-asserted origin: "+accessOriginValue+"]")
}

// TestCreateRole_NoOriginHeader_NoNote is the converse: an ordinary create carries no origin
// note, so the marker actually distinguishes the two (mirrors
// TestCreateSecret_NoOriginHeader_NoNote).
func TestCreateRole_NoOriginHeader_NoNote(t *testing.T) {
	_, rbacHandler, db, _, _ := accessOriginFixture(t)
	body, err := json.Marshal(map[string]any{"name": "manual-role", "description": "d", "permissions": []string{"secrets.read"}})
	require.NoError(t, err)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/roles", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	rbacHandler.CreateRole(w, req)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	ev := lastAuditEvent(t, db, core.EventRoleCreated)
	assert.NotContains(t, ev.Description, "client-asserted origin")
}
