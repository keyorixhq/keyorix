package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// #G79 detection_idea: the /system proxy tree must be reachable by EITHER a
// node-type machine credential OR the system.write permission (the dual-gate
// chosen after a sole node-credential gate broke the rest of the RemoteStorage
// surface, see node_credential.go's package doc), and refuse a caller holding
// neither.

func okHandler(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

func TestRequireNodeCredential_NodeMachinePasses(t *testing.T) {
	uc := &UserContext{ActorType: core.ActorTypeMachine, MachineIdentityType: core.MachineTypeNode}
	rec := httptest.NewRecorder()
	RequireNodeCredential()(http.HandlerFunc(okHandler)).ServeHTTP(rec, reqWithUser(uc))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireNodeCredential_NonNodeMachineRefused(t *testing.T) {
	for _, identityType := range []string{"ci", "k8s", "service", "automation", "other"} {
		t.Run(identityType, func(t *testing.T) {
			uc := &UserContext{ActorType: core.ActorTypeMachine, MachineIdentityType: identityType}
			rec := httptest.NewRecorder()
			RequireNodeCredential()(http.HandlerFunc(okHandler)).ServeHTTP(rec, reqWithUser(uc))
			assert.Equal(t, http.StatusForbidden, rec.Code)
		})
	}
}

// TestRequireNodeCredential_AdminSessionRefused proves the credential-CLASS check
// cannot be satisfied by any RBAC role, including admin — a real admin session
// must still be denied by the sole node-credential gate.
func TestRequireNodeCredential_AdminSessionRefused(t *testing.T) {
	uc := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, Roles: []string{"admin"}}
	rec := httptest.NewRecorder()
	RequireNodeCredential()(http.HandlerFunc(okHandler)).ServeHTTP(rec, reqWithUser(uc))
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRequireNodeCredential_NoUserContext(t *testing.T) {
	rec := httptest.NewRecorder()
	RequireNodeCredential()(http.HandlerFunc(okHandler)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// newNodeCredentialTestCore seeds a DB with a "sync_operator" role holding ONLY
// system.write (no admin bypass) and a "limited" role holding an unrelated
// permission, so the permission arm of RequireNodeCredentialOrPermission can be
// exercised distinctly from the admin-tier bypass.
func newNodeCredentialTestCore(t *testing.T) (*core.KeyorixCore, uint, uint) {
	t.Helper()
	db := newScopedTestDB(t)

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "sync-operator", AccountState: "active"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "limited-user", AccountState: "active"}).Error)

	systemWrite := &models.Permission{Name: "system.write"}
	require.NoError(t, db.Create(systemWrite).Error)
	secretsRead := &models.Permission{Name: "secrets.read"}
	require.NoError(t, db.Create(secretsRead).Error)

	syncRole := &models.Role{Name: "sync_operator"}
	require.NoError(t, db.Create(syncRole).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: syncRole.ID, PermissionID: systemWrite.ID}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: syncRole.ID}).Error)

	limitedRole := &models.Role{Name: "limited"}
	require.NoError(t, db.Create(limitedRole).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: limitedRole.ID, PermissionID: secretsRead.ID}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: limitedRole.ID}).Error)

	return core.NewKeyorixCore(store.NewLocalStorage(db)), 1, 2
}

// TestRequireNodeCredentialOrPermission_NodeCredentialPasses proves the node-credential
// arm short-circuits before any AuthorizePrincipal DB lookup: a node identity with no
// role/permission grants at all still passes (core service present, as always in
// production, but empty of any grant for this principal).
func TestRequireNodeCredentialOrPermission_NodeCredentialPasses(t *testing.T) {
	cs, _, _ := newNodeCredentialTestCore(t)
	uc := &UserContext{ActorType: core.ActorTypeMachine, MachineIdentityType: core.MachineTypeNode}
	req := makeRequest(t, http.MethodGet, "/api/v1/system/groups", nil, uc, cs)
	rec := httptest.NewRecorder()
	RequireNodeCredentialOrPermission("system.write")(http.HandlerFunc(okHandler)).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code, "a node credential must pass regardless of RBAC grants")
}

func TestRequireNodeCredentialOrPermission_PermissionHolderPasses(t *testing.T) {
	cs, syncOperatorID, _ := newNodeCredentialTestCore(t)
	uc := &UserContext{UserID: syncOperatorID, ActorType: core.ActorTypeUser}
	req := makeRequest(t, http.MethodGet, "/api/v1/system/groups", nil, uc, cs)
	rec := httptest.NewRecorder()
	RequireNodeCredentialOrPermission("system.write")(http.HandlerFunc(okHandler)).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code, "a non-node caller holding system.write must still reach the group via the permission arm")
}

func TestRequireNodeCredentialOrPermission_NeitherRefused(t *testing.T) {
	cs, _, limitedUserID := newNodeCredentialTestCore(t)
	uc := &UserContext{UserID: limitedUserID, ActorType: core.ActorTypeUser}
	req := makeRequest(t, http.MethodGet, "/api/v1/system/groups", nil, uc, cs)
	rec := httptest.NewRecorder()
	RequireNodeCredentialOrPermission("system.write")(http.HandlerFunc(okHandler)).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code, "a caller with neither a node credential nor system.write must be refused")
}

func TestRequireNodeCredentialOrPermission_NoUserContext(t *testing.T) {
	rec := httptest.NewRecorder()
	RequireNodeCredentialOrPermission("system.write")(http.HandlerFunc(okHandler)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRequireNodeCredentialOrPermission_NoCoreService(t *testing.T) {
	uc := &UserContext{UserID: 1, ActorType: core.ActorTypeUser}
	req := makeRequest(t, http.MethodGet, "/api/v1/system/groups", nil, uc, nil)
	rec := httptest.NewRecorder()
	RequireNodeCredentialOrPermission("system.write")(http.HandlerFunc(okHandler)).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}
