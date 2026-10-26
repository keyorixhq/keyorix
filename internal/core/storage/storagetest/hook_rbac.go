package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (hs *HookStore) AssignPermissionToRole(ctx context.Context, roleID uint, permissionID uint) error {
	if hk := hs.h.AssignPermissionToRole; hk != nil {
		return hk(hs.Storage, ctx, roleID, permissionID)
	}
	return hs.Storage.AssignPermissionToRole(ctx, roleID, permissionID)
}

func (hs *HookStore) AssignRole(ctx context.Context, userID uint, roleID uint, scope storage.Scope) error {
	if hk := hs.h.AssignRole; hk != nil {
		return hk(hs.Storage, ctx, userID, roleID, scope)
	}
	return hs.Storage.AssignRole(ctx, userID, roleID, scope)
}

func (hs *HookStore) AssignRoleWithExpiry(ctx context.Context, userID uint, roleID uint, scope storage.Scope, expiresAt time.Time) error {
	if hk := hs.h.AssignRoleWithExpiry; hk != nil {
		return hk(hs.Storage, ctx, userID, roleID, scope, expiresAt)
	}
	return hs.Storage.AssignRoleWithExpiry(ctx, userID, roleID, scope, expiresAt)
}

func (hs *HookStore) ClearProjectSecretOwnership(ctx context.Context, userID uint, projectID uint) error {
	if hk := hs.h.ClearProjectSecretOwnership; hk != nil {
		return hk(hs.Storage, ctx, userID, projectID)
	}
	return hs.Storage.ClearProjectSecretOwnership(ctx, userID, projectID)
}

func (hs *HookStore) GetGroupRoles(ctx context.Context, groupID uint) ([]*models.Role, error) {
	if hk := hs.h.GetGroupRoles; hk != nil {
		return hk(hs.Storage, ctx, groupID)
	}
	return hs.Storage.GetGroupRoles(ctx, groupID)
}

func (hs *HookStore) GetRole(ctx context.Context, id uint) (*models.Role, error) {
	if hk := hs.h.GetRole; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.GetRole(ctx, id)
}

func (hs *HookStore) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	if hk := hs.h.GetRoleByName; hk != nil {
		return hk(hs.Storage, ctx, name)
	}
	return hs.Storage.GetRoleByName(ctx, name)
}

func (hs *HookStore) GetRolePermissions(ctx context.Context, roleID uint) ([]*models.Permission, error) {
	if hk := hs.h.GetRolePermissions; hk != nil {
		return hk(hs.Storage, ctx, roleID)
	}
	return hs.Storage.GetRolePermissions(ctx, roleID)
}

func (hs *HookStore) GetUserGroupRoleIDsAt(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	if hk := hs.h.GetUserGroupRoleIDsAt; hk != nil {
		return hk(hs.Storage, ctx, userID, scope)
	}
	return hs.Storage.GetUserGroupRoleIDsAt(ctx, userID, scope)
}

func (hs *HookStore) GetUserGroupsAt(ctx context.Context, userID uint, scope storage.Scope) ([]*models.Group, error) {
	if hk := hs.h.GetUserGroupsAt; hk != nil {
		return hk(hs.Storage, ctx, userID, scope)
	}
	return hs.Storage.GetUserGroupsAt(ctx, userID, scope)
}

func (hs *HookStore) GetUserPermissions(ctx context.Context, userID uint) ([]*storage.Permission, error) {
	if hk := hs.h.GetUserPermissions; hk != nil {
		return hk(hs.Storage, ctx, userID)
	}
	return hs.Storage.GetUserPermissions(ctx, userID)
}

func (hs *HookStore) GetUserRoleIDsAt(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	if hk := hs.h.GetUserRoleIDsAt; hk != nil {
		return hk(hs.Storage, ctx, userID, scope)
	}
	return hs.Storage.GetUserRoleIDsAt(ctx, userID, scope)
}

func (hs *HookStore) GetUserRoleScopes(ctx context.Context, userID uint) ([]storage.Scope, error) {
	if hk := hs.h.GetUserRoleScopes; hk != nil {
		return hk(hs.Storage, ctx, userID)
	}
	return hs.Storage.GetUserRoleScopes(ctx, userID)
}

func (hs *HookStore) GetUserRoles(ctx context.Context, userID uint) ([]*models.Role, error) {
	if hk := hs.h.GetUserRoles; hk != nil {
		return hk(hs.Storage, ctx, userID)
	}
	return hs.Storage.GetUserRoles(ctx, userID)
}

func (hs *HookStore) ListAdminBypassRoleIDs(ctx context.Context) ([]uint, error) {
	if hk := hs.h.ListAdminBypassRoleIDs; hk != nil {
		return hk(hs.Storage, ctx)
	}
	return hs.Storage.ListAdminBypassRoleIDs(ctx)
}

func (hs *HookStore) ListAllUserRoleGrants(ctx context.Context) ([]*models.UserRole, error) {
	if hk := hs.h.ListAllUserRoleGrants; hk != nil {
		return hk(hs.Storage, ctx)
	}
	return hs.Storage.ListAllUserRoleGrants(ctx)
}

func (hs *HookStore) ListGlobalAdminAssignmentsForUpdate(ctx context.Context, adminRoleIDs []uint) ([]storage.RoleAssignment, error) {
	if hk := hs.h.ListGlobalAdminAssignmentsForUpdate; hk != nil {
		return hk(hs.Storage, ctx, adminRoleIDs)
	}
	return hs.Storage.ListGlobalAdminAssignmentsForUpdate(ctx, adminRoleIDs)
}

func (hs *HookStore) ListProjectRoleAssignments(ctx context.Context, projectID uint) ([]storage.RoleAssignment, error) {
	if hk := hs.h.ListProjectRoleAssignments; hk != nil {
		return hk(hs.Storage, ctx, projectID)
	}
	return hs.Storage.ListProjectRoleAssignments(ctx, projectID)
}

func (hs *HookStore) RemoveAllProjectRoleGrants(ctx context.Context, userID uint, projectID uint) error {
	if hk := hs.h.RemoveAllProjectRoleGrants; hk != nil {
		return hk(hs.Storage, ctx, userID, projectID)
	}
	return hs.Storage.RemoveAllProjectRoleGrants(ctx, userID, projectID)
}

func (hs *HookStore) RemoveRole(ctx context.Context, userID uint, roleID uint, scope storage.Scope) error {
	if hk := hs.h.RemoveRole; hk != nil {
		return hk(hs.Storage, ctx, userID, roleID, scope)
	}
	return hs.Storage.RemoveRole(ctx, userID, roleID, scope)
}

func (hs *HookStore) RemoveRoleFromGroup(ctx context.Context, groupID uint, roleID uint, scope storage.Scope) error {
	if hk := hs.h.RemoveRoleFromGroup; hk != nil {
		return hk(hs.Storage, ctx, groupID, roleID, scope)
	}
	return hs.Storage.RemoveRoleFromGroup(ctx, groupID, roleID, scope)
}

func (hs *HookStore) RoleSetBypassesPermissionChecks(ctx context.Context, roleIDs []uint) (bool, error) {
	if hk := hs.h.RoleSetBypassesPermissionChecks; hk != nil {
		return hk(hs.Storage, ctx, roleIDs)
	}
	return hs.Storage.RoleSetBypassesPermissionChecks(ctx, roleIDs)
}

func (hs *HookStore) RoleSetHasPermission(ctx context.Context, roleIDs []uint, permission string) (bool, error) {
	if hk := hs.h.RoleSetHasPermission; hk != nil {
		return hk(hs.Storage, ctx, roleIDs, permission)
	}
	return hs.Storage.RoleSetHasPermission(ctx, roleIDs, permission)
}
