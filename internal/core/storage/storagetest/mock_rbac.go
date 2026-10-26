package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) CreatePermission(_ context.Context, permission *models.Permission) (*models.Permission, error) {
	return permission, nil
}

func (m *MockStorage) AssignPermissionToRole(_ context.Context, _, _ uint) error {
	return nil
}

func (m *MockStorage) ListProjectRoleAssignments(ctx context.Context, projectID uint) ([]storage.RoleAssignment, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.RoleAssignment), args.Error(1)
}

func (m *MockStorage) ListProjectMachineRoleAssignments(ctx context.Context, projectID uint) ([]storage.RoleAssignment, error) {
	a := m.Called(ctx, projectID)
	v, _ := a.Get(0).([]storage.RoleAssignment)
	return v, a.Error(1)
}

// ListGlobalAdminAssignmentsForUpdate is unused by the tests that construct a
// MockStorage directly (they don't exercise RemoveUserRole's last-admin guard);
// returns empty so the guard treats "no other admin" as the default in the rare
// case something reaches it.
func (m *MockStorage) ListGlobalAdminAssignmentsForUpdate(_ context.Context, _ []uint) ([]storage.RoleAssignment, error) {
	return nil, nil
}

// ListAdminBypassRoleIDs (#2496) is the structural replacement for
// installAdminRoleIDSet's name lookups. MockStorage-driven tests never seed a
// bypass-flagged role, so the honest answer here is "this install has none" —
// returned directly rather than via m.Called so no existing test needs a stub,
// which is exactly the position those tests were already in when every
// install-admin name resolved as absent via GetRoleByName. Real last-admin
// coverage lives against store.LocalStorage (last_admin_guard_external_test.go,
// concurrency_last_admin_removal_test.go, admin_role_structural_source_test.go).
//
// The empty answer makes the last-admin guards no-op, never fail-open on a
// masked error: an error return here would be indistinguishable from a real
// storage failure and would turn every MockStorage test that touches a role
// removal into a refusal.
func (m *MockStorage) ListAdminBypassRoleIDs(_ context.Context) ([]uint, error) {
	return nil, nil
}

// RemoveGlobalAdminRoleGuarded (#525) is likewise unused by MockStorage-driven
// tests — none of them seeds a bypass-flagged role, so RemoveUserRole's
// adminBypassRoleIDSlice is always empty and this is never reached
// (real-storage RemoveUserRole/last-admin coverage lives in
// last_admin_guard_external_test.go and concurrency_last_admin_removal_test.go,
// both against a real store.LocalStorage). If a future test DOES reach this
// unmocked, m.Called panics loudly rather than silently allowing the removal.
func (m *MockStorage) RemoveGlobalAdminRoleGuarded(ctx context.Context, userID, roleID uint, adminRoleIDs []uint) error {
	args := m.Called(ctx, userID, roleID, adminRoleIDs)
	return args.Error(0)
}

func (m *MockStorage) ListGroupRoleAssignments(ctx context.Context, groupID uint) ([]storage.RoleAssignment, error) {
	args := m.Called(ctx, groupID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.RoleAssignment), args.Error(1)
}

func (m *MockStorage) GetUserRoleScopesByUserIDs(ctx context.Context, ids []uint) (map[uint][]storage.Scope, error) {
	args := m.Called(ctx, ids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint][]storage.Scope), args.Error(1)
}

func (m *MockStorage) GetUserGroupsAt(ctx context.Context, userID uint, scope storage.Scope) ([]*models.Group, error) {
	args := m.Called(ctx, userID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Group), args.Error(1)
}

func (m *MockStorage) CreateRole(ctx context.Context, name identity.FoldedName, description string) (*models.Role, error) {
	args := m.Called(ctx, name, description)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *MockStorage) SetRoleBypassesPermissionChecks(ctx context.Context, roleID uint, value bool) error {
	args := m.Called(ctx, roleID, value)
	return args.Error(0)
}

func (m *MockStorage) SetRoleAssignableScope(ctx context.Context, roleID uint, scope string) error {
	args := m.Called(ctx, roleID, scope)
	return args.Error(0)
}

func (m *MockStorage) GetRole(ctx context.Context, id uint) (*models.Role, error) {
	if !m.mockHasExpectation("GetRole") {
		return nil, errMockLookupNotStubbed
	}
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *MockStorage) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *MockStorage) UpdateRole(ctx context.Context, role *models.Role) (*models.Role, error) {
	a := m.Called(ctx, role)
	v, _ := a.Get(0).(*models.Role)
	return v, a.Error(1)
}

func (m *MockStorage) DeleteRole(ctx context.Context, id uint) (storage.RoleDeleteCascadeCounts, error) {
	a := m.Called(ctx, id)
	v, _ := a.Get(0).(storage.RoleDeleteCascadeCounts)
	return v, a.Error(1)
}

func (m *MockStorage) ListRoles(ctx context.Context) ([]*models.Role, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Role), args.Error(1)
}

func (m *MockStorage) AssignRole(ctx context.Context, userID, roleID uint, scope storage.Scope) error {
	args := m.Called(ctx, userID, roleID, scope)
	return args.Error(0)
}

func (m *MockStorage) AssignRoleWithExpiry(ctx context.Context, userID, roleID uint, scope storage.Scope, expiresAt time.Time) error {
	args := m.Called(ctx, userID, roleID, scope, expiresAt)
	return args.Error(0)
}

func (m *MockStorage) RemoveRole(ctx context.Context, userID, roleID uint, scope storage.Scope) error {
	return m.Called(ctx, userID, roleID, scope).Error(0)
}

func (m *MockStorage) RemoveAllProjectRoleGrants(ctx context.Context, userID, projectID uint) error {
	args := m.Called(ctx, userID, projectID)
	return args.Error(0)
}

func (m *MockStorage) ClearProjectSecretOwnership(ctx context.Context, userID, projectID uint) error {
	args := m.Called(ctx, userID, projectID)
	return args.Error(0)
}

func (m *MockStorage) AssignRoleToGroupWithExpiry(ctx context.Context, groupID, roleID uint, scope storage.Scope, expiresAt time.Time) error {
	args := m.Called(ctx, groupID, roleID, scope, expiresAt)
	return args.Error(0)
}

func (m *MockStorage) DeleteExpiredRoleGrants(ctx context.Context, before time.Time) ([]storage.RoleAssignment, error) {
	args := m.Called(ctx, before)
	if v := args.Get(0); v != nil {
		return v.([]storage.RoleAssignment), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockStorage) GetUserRoles(ctx context.Context, userID uint) ([]*models.Role, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Role), args.Error(1)
}

func (m *MockStorage) GetUserRoleIDsAt(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	args := m.Called(ctx, userID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uint), args.Error(1)
}

func (m *MockStorage) GetUserRoleIDsExact(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	a := m.Called(ctx, userID, scope)
	v, _ := a.Get(0).([]uint)
	return v, a.Error(1)
}

func (m *MockStorage) IsProjectMember(ctx context.Context, userID, projectID uint) (bool, error) {
	args := m.Called(ctx, userID, projectID)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) ProjectMembershipsAmong(ctx context.Context, userID uint, projectIDs []uint) (map[uint]bool, error) {
	args := m.Called(ctx, userID, projectIDs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]bool), args.Error(1)
}

func (m *MockStorage) ListUserRoleGrants(ctx context.Context, userID uint) ([]storage.UserRoleGrant, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.UserRoleGrant), args.Error(1)
}

func (m *MockStorage) ListUserLiveGroupMemberships(ctx context.Context, userID uint) ([]storage.UserGroupMembershipAt, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.UserGroupMembershipAt), args.Error(1)
}

func (m *MockStorage) IsGroupProjectScoped(ctx context.Context, groupID, projectID uint) (bool, error) {
	args := m.Called(ctx, groupID, projectID)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) GetUserGroupRoleIDsAt(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	a := m.Called(ctx, userID, scope)
	v, _ := a.Get(0).([]uint)
	return v, a.Error(1)
}

func (m *MockStorage) GetUserRoleScopes(ctx context.Context, userID uint) ([]storage.Scope, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.Scope), args.Error(1)
}

func (m *MockStorage) RoleSetHasPermission(ctx context.Context, roleIDs []uint, permission string) (bool, error) {
	args := m.Called(ctx, roleIDs, permission)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) RoleSetBypassesPermissionChecks(ctx context.Context, roleIDs []uint) (bool, error) {
	args := m.Called(ctx, roleIDs)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) GetUserPermissions(ctx context.Context, userID uint) ([]*storage.Permission, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*storage.Permission), args.Error(1)
}

func (m *MockStorage) GetUserGroupPermissions(ctx context.Context, userID uint) ([]*storage.Permission, error) {
	a := m.Called(ctx, userID)
	v, _ := a.Get(0).([]*storage.Permission)
	return v, a.Error(1)
}

func (m *MockStorage) ListPermissions(_ context.Context) ([]*models.Permission, error) {
	return nil, nil
}

func (m *MockStorage) GetPermission(_ context.Context, id uint) (*models.Permission, error) {
	return &models.Permission{ID: id}, nil
}

func (m *MockStorage) GetRolePermissions(ctx context.Context, roleID uint) ([]*models.Permission, error) {
	for _, c := range m.ExpectedCalls {
		if c.Method == "GetRolePermissions" {
			args := m.Called(ctx, roleID)
			if args.Get(0) == nil {
				return nil, args.Error(1)
			}
			return args.Get(0).([]*models.Permission), args.Error(1)
		}
	}
	return nil, nil
}

func (m *MockStorage) RemovePermissionFromRole(_ context.Context, _, _ uint) error {
	return nil
}

func (m *MockStorage) GetGroupRoles(ctx context.Context, groupID uint) ([]*models.Role, error) {
	for _, c := range m.ExpectedCalls {
		if c.Method == "GetGroupRoles" {
			args := m.Called(ctx, groupID)
			if args.Get(0) == nil {
				return nil, args.Error(1)
			}
			return args.Get(0).([]*models.Role), args.Error(1)
		}
	}
	return nil, nil
}

func (m *MockStorage) GetGroupRoleGrants(_ context.Context, _ uint) ([]*storage.GroupRoleGrant, error) {
	return nil, nil
}

func (m *MockStorage) AssignRoleToGroup(_ context.Context, _, _ uint, _ storage.Scope) error {
	return nil
}

func (m *MockStorage) RemoveRoleFromGroup(_ context.Context, _, _ uint, _ storage.Scope) error {
	return nil
}

func (m *MockStorage) ListAllUserRoleGrants(ctx context.Context) ([]*models.UserRole, error) {
	for _, c := range m.ExpectedCalls {
		if c.Method == "ListAllUserRoleGrants" {
			args := m.Called(ctx)
			if args.Get(0) == nil {
				return nil, args.Error(1)
			}
			return args.Get(0).([]*models.UserRole), args.Error(1)
		}
	}
	return nil, nil
}

func (m *MockStorage) ListAllGroupRoleGrants(ctx context.Context) ([]*models.GroupRole, error) {
	for _, c := range m.ExpectedCalls {
		if c.Method == "ListAllGroupRoleGrants" {
			args := m.Called(ctx)
			if args.Get(0) == nil {
				return nil, args.Error(1)
			}
			return args.Get(0).([]*models.GroupRole), args.Error(1)
		}
	}
	return nil, nil
}

func (m *MockStorage) ListExpiringUserRoles(ctx context.Context, cutoff time.Time) ([]models.UserRole, error) {
	args := m.Called(ctx, cutoff)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.UserRole), args.Error(1)
}

// ResolveUserPermissionAt / ResolveMachinePermissionAt (PERF-FIX-6) are
// composed from the mock's own role methods (storage.Compose*PermissionAt, in
// the order core.Authorize used to call them), so a test that stubs those
// (On("GetUserRoleIDsAt"), On("RoleSetBypassesPermissionChecks"),
// On("RoleSetHasPermission"), ...) drives the combined read unchanged, errors
// included.
func (m *MockStorage) ResolveUserPermissionAt(ctx context.Context, userID uint, scope storage.Scope, permission string) (*storage.PrincipalPermission, error) {
	return storage.ComposeUserPermissionAt(ctx, m, userID, scope, permission)
}
