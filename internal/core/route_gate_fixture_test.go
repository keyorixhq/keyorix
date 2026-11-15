package core

import (
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// routeGateRoleSeq keeps the fixture roles' names unique.
var routeGateRoleSeq atomic.Int64

// grantRouteGatePerms gives userID a role holding perms at projectID (0 = global),
// in a role of its own so the test's other roles and grants are unchanged. Since
// #4161 core checks the route gate's permission itself (route_gate.go); a test
// about a later check (a ceiling, a bundling rule, an audit row) grants the gate
// with this so it still reaches that check. Missing permission rows are created.
func grantRouteGatePerms(t *testing.T, db *gorm.DB, userID, projectID uint, perms ...string) {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.SystemMetadata{}, &models.Project{}, &models.Environment{}))
	seq := routeGateRoleSeq.Add(1)
	name := fmt.Sprintf("route-gate-%d-%d-%d", userID, projectID, seq)
	// An explicit ID far above the tests' own: an auto ID could become a role
	// ID a test's existing grants already point at (role 1, say).
	role := &models.Role{ID: uint(900000 + seq), Name: name, NameFolded: name}
	require.NoError(t, db.Create(role).Error)
	for _, p := range perms {
		var perm models.Permission
		require.NoError(t, db.Where(models.Permission{Name: p}).
			Attrs(models.Permission{Resource: "route-gate", Action: p}).FirstOrCreate(&perm).Error)
		require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	}
	require.NoError(t, db.Create(&models.UserRole{UserID: userID, RoleID: role.ID, ProjectID: projectID}).Error)
}

// grantMachineRouteGatePerms is grantRouteGatePerms for a machine identity, at the
// global scope, as a raw machine_identity_roles row (core grants a machine roles only
// in its project; storage holds any scope). A test about a machine granter's
// project-scope ceiling uses it to pass the install-wide route gate core checks
// since #4161, without the role adding anything at the project.
func grantMachineRouteGatePerms(t *testing.T, db *gorm.DB, machineID uint, perms ...string) {
	t.Helper()
	seq := routeGateRoleSeq.Add(1)
	name := fmt.Sprintf("route-gate-machine-%d-%d", machineID, seq)
	role := &models.Role{ID: uint(900000 + seq), Name: name, NameFolded: name}
	require.NoError(t, db.Create(role).Error)
	for _, p := range perms {
		var perm models.Permission
		require.NoError(t, db.Where(models.Permission{Name: p}).
			Attrs(models.Permission{Resource: "route-gate", Action: p}).FirstOrCreate(&perm).Error)
		require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	}
	require.NoError(t, db.Create(&models.MachineIdentityRole{MachineIdentityID: machineID, RoleID: role.ID}).Error)
}

// mockRouteGate answers the route gate's permission lookups on a MockStorage for
// userID: role 900, no bypass, holding perms at any scope. Optional expectations,
// so a path refused before the gate does not fail on an unused one.
func mockRouteGate(m *MockStorage, userID uint, perms ...string) {
	m.On("GetUserRoleIDsAt", mock.Anything, userID, mock.Anything).Return([]uint{900}, nil).Maybe()
	m.On("GetUserGroupRoleIDsAt", mock.Anything, userID, mock.Anything).Return([]uint{}, nil).Maybe()
	m.On("RoleSetBypassesPermissionChecks", mock.Anything, []uint{900}).Return(false, nil).Maybe()
	for _, p := range perms {
		m.On("RoleSetHasPermission", mock.Anything, []uint{900}, p).Return(true, nil).Maybe()
	}
}

// mockRouteGateLate is mockRouteGate for a test that already mocks userID's role
// reads: registered after the test's own expectations (testify answers with the
// first match), it only fills in what the gate asks that the test did not: the
// global-scope role set (role 900) when the test mocks none, and perms as held by
// whatever role set the test returns.
func mockRouteGateLate(m *MockStorage, userID uint, perms ...string) {
	m.On("GetUserRoleIDsAt", mock.Anything, userID, Scope{}).Return([]uint{900}, nil).Maybe()
	m.On("GetUserGroupRoleIDsAt", mock.Anything, userID, Scope{}).Return([]uint{}, nil).Maybe()
	m.On("RoleSetBypassesPermissionChecks", mock.Anything, mock.Anything).Return(false, nil).Maybe()
	for _, p := range perms {
		m.On("RoleSetHasPermission", mock.Anything, mock.Anything, p).Return(true, nil).Maybe()
	}
}
