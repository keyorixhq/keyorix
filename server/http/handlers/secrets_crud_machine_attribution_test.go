// secrets_crud_machine_attribution_test.go — #1625 (#1573 machine-actor
// attribution family, Part 2 continuation finding, 2026-09-04): every other
// model CreateSecretRequest's sibling PR touched (invitations, machine
// identities, break-glass, access-review campaigns, secret dependencies,
// setup tokens) got its own *MachineIdentityID companion field AND had its
// real production entry points updated to populate it. SecretNode.
// OwnerMachineIdentityID got the model column and the request-struct field --
// the full shape of a completed fix -- but neither real production entry
// point (this HTTP handler, nor the gRPC CreateSecret RPC) was ever updated
// to set it. The original PR's own regression test called core.CreateSecret
// directly, bypassing both real handlers entirely, so it gave no assurance
// the shipped endpoints worked -- this test drives the real HTTP handler
// instead, the exact gap the finding called out.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// seedMachineWriteRole creates a Role with secrets.write and grants it to
// machineID at projectID scope via MachineIdentityRole -- the write-side
// counterpart to secrets_list_machine_authz_test.go's seedMachineReadRole.
func seedMachineWriteRole(t *testing.T, db *gorm.DB, roleName string, machineID, projectID uint) uint {
	t.Helper()

	role := &models.Role{Name: roleName}
	require.NoError(t, db.Create(role).Error)

	perm := &models.Permission{}
	if err := db.Where("name = ?", permSecretsWrite).First(perm).Error; err != nil {
		perm = &models.Permission{Name: permSecretsWrite, Resource: "secrets", Action: "write"}
		require.NoError(t, db.Create(perm).Error)
	}
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)

	require.NoError(t, db.Create(&models.MachineIdentityRole{
		MachineIdentityID: machineID,
		RoleID:            role.ID,
		ProjectID:         projectID,
		EnvironmentID:     0,
	}).Error)
	return role.ID
}

// TestCreateSecret_MachineActor_AttributedToOwnerMachineIdentityID drives the
// real HTTP CreateSecret handler as an authorized machine principal and
// confirms the persisted secret's OwnerMachineIdentityID is populated, not
// left at 0 alongside a zero OwnerID (the pre-fix, unattributable shape).
func TestCreateSecret_MachineActor_AttributedToOwnerMachineIdentityID(t *testing.T) {
	h, db := freshMachineAuthzFixture(t)

	proj := &models.Project{Name: "proj-machine-create"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "env-machine-create", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)

	const machineID = uint(41)
	require.NoError(t, db.Create(&models.MachineIdentity{
		ID: machineID, ProjectID: proj.ID, Name: "ci-runner-41", State: "active",
	}).Error)
	seedMachineWriteRole(t, db, "machine_writer_create", machineID, proj.ID)

	body, err := json.Marshal(map[string]any{
		"name":           "machine-created-secret",
		"value":          "s3cr3t",
		"project_id":     proj.ID,
		"environment_id": env.ID,
		"type":           "static",
	})
	require.NoError(t, err)

	// withMachineCtxID doesn't set Username (its own callers don't need
	// CreatedBy) -- real production machine auth does (machineUserContext,
	// server/middleware/auth.go, Username: m.Name), and CreateSecret's own
	// validation requires CreatedBy non-empty, so replicate that here rather
	// than change the shared helper's behavior for its other callers.
	mid := uint(machineID)
	req := withMachineCtxID(httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(body)), machineID)
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), &middleware.UserContext{
		UserID: 0, ActorType: core.ActorTypeMachine, MachineIdentityID: &mid, Username: "ci-runner-41",
	}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateSecret(w, req)

	require.Equal(t, http.StatusCreated, w.Code, "authorized machine token should be able to create a secret: %s", w.Body.String())

	var created models.SecretNode
	require.NoError(t, db.Where("name = ?", "machine-created-secret").First(&created).Error)
	assert.Equal(t, uint(0), created.OwnerID, "a machine caller's UserID is 0 by convention (ADR-030) -- must not collide with a real user ID")
	assert.Equal(t, machineID, created.OwnerMachineIdentityID, "#1625: a machine-created secret must record WHICH machine created it, not leave both owner columns at zero")
}

// TestCreateSecret_UserActor_OwnerMachineIdentityIDStaysZero is the
// counterpart: an ordinary user-created secret must NOT get a nonzero
// OwnerMachineIdentityID -- the discriminator fields are mutually exclusive.
func TestCreateSecret_UserActor_OwnerMachineIdentityIDStaysZero(t *testing.T) {
	h, db := freshMachineAuthzFixture(t)

	proj := &models.Project{Name: "proj-user-create"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "env-user-create", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)

	user := &models.User{Username: "creator", Email: "creator@example.com"}
	require.NoError(t, db.Create(user).Error)

	role := &models.Role{Name: "user_writer_create"}
	require.NoError(t, db.Create(role).Error)
	perm := &models.Permission{}
	if err := db.Where("name = ?", permSecretsWrite).First(perm).Error; err != nil {
		perm = &models.Permission{Name: permSecretsWrite, Resource: "secrets", Action: "write"}
		require.NoError(t, db.Create(perm).Error)
	}
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: user.ID, RoleID: role.ID, ProjectID: proj.ID}).Error)

	body, err := json.Marshal(map[string]any{
		"name":           "user-created-secret",
		"value":          "s3cr3t",
		"project_id":     proj.ID,
		"environment_id": env.ID,
		"type":           "static",
	})
	require.NoError(t, err)

	req := withUserCtxID(httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(body)), user.ID, "creator")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateSecret(w, req)

	require.Equal(t, http.StatusCreated, w.Code, "authorized user should be able to create a secret: %s", w.Body.String())

	var created models.SecretNode
	require.NoError(t, db.Where("name = ?", "user-created-secret").First(&created).Error)
	assert.Equal(t, user.ID, created.OwnerID)
	assert.Equal(t, uint(0), created.OwnerMachineIdentityID, "a user-created secret must not have a nonzero OwnerMachineIdentityID")
}
