package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

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

// newBareNodeCredentialTestCore seeds a DB with a "sync_operator" role holding
// ONLY system.write (no admin bypass), so TestRequirePermission_BareNodeCredentialRefused
// below can prove a legitimate-looking, RBAC-unrelated permission grant on
// SOMEONE ELSE doesn't leak to a node identity holding no grants of its own.
func newBareNodeCredentialTestCore(t *testing.T) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	db := newScopedTestDB(t)

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "sync-operator", AccountState: "active"}).Error)
	systemWrite := &models.Permission{Name: "system.write"}
	require.NoError(t, db.Create(systemWrite).Error)
	syncRole := &models.Role{Name: "sync_operator"}
	require.NoError(t, db.Create(syncRole).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: syncRole.ID, PermissionID: systemWrite.ID}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: syncRole.ID}).Error)

	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

// TestRequirePermission_BareNodeCredentialRefused is the ADR-085 regression
// test: /system used to be gated by RequireNodeCredentialOrPermission, which
// admitted a node-type machine credential regardless of any RBAC grant at all.
// That OR-arm is gone — router.go now gates /system with plain
// RequirePermission(permSystemWrite), so a node credential with no role/
// permission grants of its own must be refused exactly like any other
// ungranted machine identity, not given a free pass for its credential class.
func TestRequirePermission_BareNodeCredentialRefused(t *testing.T) {
	cs, _ := newBareNodeCredentialTestCore(t)
	uc := &UserContext{ActorType: core.ActorTypeMachine, MachineIdentityType: core.MachineTypeNode}
	req := makeRequest(t, http.MethodGet, "/api/v1/system/groups", nil, uc, cs)
	rec := httptest.NewRecorder()
	RequirePermission("system.write")(http.HandlerFunc(okHandler)).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code,
		"CEILING VIOLATED (ADR-085): a bare node credential with no system.write grant must be refused -- "+
			"credential CLASS alone must never substitute for holding the permission")
}

// TestRequirePermission_NodeCredentialWithGrantPasses is the companion control:
// a machine identity that happens to be node-typed AND has been granted
// system.write via a real machine_identity_roles row (same mechanism as any
// other machine identity) must still reach the group -- the fix removes the
// credential-class shortcut, not the ability for a node identity to ever hold
// system.write the normal way.
func TestRequirePermission_NodeCredentialWithGrantPasses(t *testing.T) {
	cs, db := newBareNodeCredentialTestCore(t)
	require.NoError(t, db.AutoMigrate(&models.MachineIdentity{}, &models.MachineIdentityRole{}))

	systemWrite := &models.Permission{}
	require.NoError(t, db.Where("name = ?", "system.write").First(systemWrite).Error)
	machine := &models.MachineIdentity{ProjectID: 1, Name: "test-node", IdentityType: core.MachineTypeNode, State: "active"}
	require.NoError(t, db.Create(machine).Error)
	nodeRole := &models.Role{Name: "node_system_writer"}
	require.NoError(t, db.Create(nodeRole).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: nodeRole.ID, PermissionID: systemWrite.ID}).Error)
	require.NoError(t, db.Create(&models.MachineIdentityRole{MachineIdentityID: machine.ID, RoleID: nodeRole.ID}).Error)

	uc := &UserContext{ActorType: core.ActorTypeMachine, MachineIdentityType: core.MachineTypeNode, MachineIdentityID: &machine.ID}
	req := makeRequest(t, http.MethodGet, "/api/v1/system/groups", nil, uc, cs)
	rec := httptest.NewRecorder()
	RequirePermission("system.write")(http.HandlerFunc(okHandler)).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code,
		"a node-typed machine identity that genuinely holds system.write via machine_identity_roles must "+
			"still reach the group -- the fix removes the credential-class shortcut, not machine RBAC itself")
}
