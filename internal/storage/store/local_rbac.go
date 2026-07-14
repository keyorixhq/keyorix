// local_rbac.go — Role and RBAC operations for LocalStorage.
//
// Covers: CreatePermission, AssignPermissionToRole,
//
//	CreateRole, GetRole, GetRoleByName, UpdateRole, DeleteRole, ListRoles,
//	AssignRole, RemoveRole, GetUserRoles, GetUserPermissions.
//
// All operations use direct GORM queries.
// For the remote (HTTP) equivalent see remote_rbac.go.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// --- Permissions ---

func (ls *LocalStorage) CreatePermission(ctx context.Context, permission *models.Permission) (*models.Permission, error) {
	if err := ls.db.WithContext(ctx).Create(permission).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return permission, nil
}

func (ls *LocalStorage) AssignPermissionToRole(ctx context.Context, roleID, permissionID uint) error {
	rp := models.RolePermission{RoleID: roleID, PermissionID: permissionID}
	if err := ls.db.WithContext(ctx).Create(&rp).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// --- Roles ---

func (ls *LocalStorage) CreateRole(ctx context.Context, role *models.Role) (*models.Role, error) {
	if err := ls.db.WithContext(ctx).Create(role).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return role, nil
}

func (ls *LocalStorage) GetRole(ctx context.Context, id uint) (*models.Role, error) {
	var role models.Role
	if err := ls.db.WithContext(ctx).First(&role, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s", i18n.T("ErrorRoleNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &role, nil
}

func (ls *LocalStorage) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	var role models.Role
	if err := ls.db.WithContext(ctx).Where("name = ?", name).First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s", i18n.T("ErrorRoleNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &role, nil
}

func (ls *LocalStorage) UpdateRole(ctx context.Context, role *models.Role) (*models.Role, error) {
	if err := ls.db.WithContext(ctx).Save(role).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return role, nil
}

func (ls *LocalStorage) DeleteRole(ctx context.Context, id uint) error {
	result := ls.db.WithContext(ctx).Delete(&models.Role{}, id)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorRoleNotFound", nil))
	}
	return nil
}

func (ls *LocalStorage) ListRoles(ctx context.Context) ([]*models.Role, error) {
	var roles []*models.Role
	if err := ls.db.WithContext(ctx).Find(&roles).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return roles, nil
}

// --- RBAC assignment ---

// AssignRole assigns a permanent role to a user at scope; errors if already
// assigned there.
func (ls *LocalStorage) AssignRole(ctx context.Context, userID, roleID uint, scope storage.Scope) error {
	return ls.assignUserRole(ctx, userID, roleID, scope, nil)
}

// AssignRoleWithExpiry assigns a time-bound role to a user at scope: the grant
// stops authorizing once expiresAt passes and is later swept by the JIT scheduler.
func (ls *LocalStorage) AssignRoleWithExpiry(ctx context.Context, userID, roleID uint, scope storage.Scope, expiresAt time.Time) error {
	return ls.assignUserRole(ctx, userID, roleID, scope, &expiresAt)
}

func (ls *LocalStorage) assignUserRole(ctx context.Context, userID, roleID uint, scope storage.Scope, expiresAt *time.Time) error {
	var existing models.UserRole
	err := ls.db.WithContext(ctx).
		Where("user_id = ? AND role_id = ? AND project_id = ? AND environment_id = ?",
			userID, roleID, scope.ProjectID, scope.EnvironmentID).First(&existing).Error
	switch err {
	case nil:
		// A row already exists at this exact (user, role, project, environment) key. A
		// still-live grant (no expiry, or an expiry still in the future) genuinely blocks
		// a duplicate assignment. But an EXPIRED grant is a stale, un-reaped row — e.g. a
		// prior break-glass activation whose time-bound grant naturally lapsed — and must
		// be treated as ABSENT for this check, or a second real-incident activation for
		// the same user/role/scope is permanently refused with "already assigned" even
		// though nothing live is actually being duplicated (#263). Delete the stale row
		// so the composite primary key (user_id, role_id, project_id, environment_id) is
		// free for the fresh Create below, mirroring how live-authorization queries
		// elsewhere (e.g. GetUserRoles) already exclude expired grants.
		if existing.ExpiresAt == nil || existing.ExpiresAt.After(time.Now()) {
			return fmt.Errorf("%s", i18n.T("ErrorRoleAlreadyAssigned", nil))
		}
		if derr := ls.db.WithContext(ctx).
			Where("user_id = ? AND role_id = ? AND project_id = ? AND environment_id = ?",
				userID, roleID, scope.ProjectID, scope.EnvironmentID).
			Delete(&models.UserRole{}).Error; derr != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), derr)
		}
	case gorm.ErrRecordNotFound:
		// no existing row for this key — proceed to create.
	default:
		return fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), err)
	}
	userRole := models.UserRole{
		UserID:        userID,
		RoleID:        roleID,
		ProjectID:     scope.ProjectID,
		EnvironmentID: scope.EnvironmentID,
		ExpiresAt:     expiresAt,
	}
	if err := ls.db.WithContext(ctx).Create(&userRole).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// RemoveRole removes a role from a user at scope.
func (ls *LocalStorage) RemoveRole(ctx context.Context, userID, roleID uint, scope storage.Scope) error {
	result := ls.db.WithContext(ctx).
		Where("user_id = ? AND role_id = ? AND project_id = ? AND environment_id = ?",
			userID, roleID, scope.ProjectID, scope.EnvironmentID).Delete(&models.UserRole{})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRoleNotAssigned", nil), storage.ErrRoleNotAssigned)
	}
	return nil
}

// RemoveAllProjectRoleGrants deletes every user_roles row for (userID, projectID),
// regardless of environment_id — unlike RemoveRole, which only ever deletes an
// exact-scope match. Used by RemoveProjectMember to fully revoke a departing
// member's access to a project: without it, an environment-scoped grant (e.g.
// "prod-only access", project_id = P, environment_id = E) survives project-level
// removal untouched, because it was never an exact match for
// Scope{ProjectID: P} (environment_id defaults to 0) (#232).
func (ls *LocalStorage) RemoveAllProjectRoleGrants(ctx context.Context, userID, projectID uint) error {
	if err := ls.db.WithContext(ctx).
		Where("user_id = ? AND project_id = ?", userID, projectID).
		Delete(&models.UserRole{}).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// GetUserRoles retrieves all roles assigned to userID via the user_roles join table.
func (ls *LocalStorage) GetUserRoles(ctx context.Context, userID uint) ([]*models.Role, error) {
	var roles []*models.Role
	err := ls.db.WithContext(ctx).Table("roles").
		Joins("JOIN user_roles ON roles.id = user_roles.role_id").
		Where("user_roles.user_id = ?", userID).
		Where("user_roles.expires_at IS NULL OR user_roles.expires_at > ?", time.Now()).
		Find(&roles).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return roles, nil
}

// GetUserRoleIDsAt returns the IDs of roles directly assigned to userID that
// apply at the target scope: a stored assignment applies when its project is
// global (0) or equal, and its environment is global (0) or equal.
//
// A scoped (non-zero) project_id/environment_id must ALSO NOT resolve to a
// soft-deleted project/environment row — mirroring the groups.deleted_at join
// GetUserGroupRoleIDsAt already applies for a group's own soft-delete state
// (#161). Without it, a role bound directly to a project/environment ID keeps
// authorizing regardless of that project's/environment's own soft-delete state,
// so deletion doesn't work as an access boundary for directly-bound roles at all.
// The LEFT JOINs (not INNER) are required because project_id/environment_id 0
// means "global" and has no corresponding row to join against — the "= 0 OR ..."
// clause short-circuits before the joined columns are consulted in that case; a
// scoped project_id/environment_id with no matching row at all (the joined column
// is SQL NULL) is treated as not-deleted, same as every other "unknown" scope ID
// this query already tolerates.
func (ls *LocalStorage) GetUserRoleIDsAt(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	var ids []uint
	err := ls.db.WithContext(ctx).Model(&models.UserRole{}).
		Joins("LEFT JOIN projects ON projects.id = user_roles.project_id").
		Joins("LEFT JOIN environments ON environments.id = user_roles.environment_id").
		Where("user_roles.user_id = ?", userID).
		Where("user_roles.project_id = 0 OR (user_roles.project_id = ? AND projects.deleted_at IS NULL)", scope.ProjectID).
		Where("user_roles.environment_id = 0 OR (user_roles.environment_id = ? AND environments.deleted_at IS NULL)", scope.EnvironmentID).
		Where("user_roles.expires_at IS NULL OR user_roles.expires_at > ?", time.Now()).
		Distinct().Pluck("user_roles.role_id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return ids, nil
}

// GetUserRoleScopes returns the distinct (project, environment) scopes at which
// userID holds ANY LIVE role, directly (user_roles) or via a live (non-deleted)
// group (group_roles). See the storage.Storage interface doc for why this exists
// (#165's scope-aware admin-rank-ceiling check).
func (ls *LocalStorage) GetUserRoleScopes(ctx context.Context, userID uint) ([]storage.Scope, error) {
	type scopeRow struct {
		ProjectID     uint
		EnvironmentID uint
	}
	seen := make(map[storage.Scope]struct{})

	var direct []scopeRow
	if err := ls.db.WithContext(ctx).Model(&models.UserRole{}).
		Select("project_id, environment_id").
		Where("user_id = ?", userID).
		Where("expires_at IS NULL OR expires_at > ?", time.Now()).
		Group("project_id, environment_id").
		Scan(&direct).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, r := range direct {
		seen[storage.Scope{ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID}] = struct{}{}
	}

	var viaGroups []scopeRow
	if err := ls.db.WithContext(ctx).Table("group_roles").
		Select("group_roles.project_id AS project_id, group_roles.environment_id AS environment_id").
		Joins("JOIN user_groups ON user_groups.group_id = group_roles.group_id").
		Joins("JOIN groups ON groups.id = group_roles.group_id AND groups.deleted_at IS NULL").
		Where("user_groups.user_id = ?", userID).
		Where("group_roles.expires_at IS NULL OR group_roles.expires_at > ?", time.Now()).
		Group("group_roles.project_id, group_roles.environment_id").
		Scan(&viaGroups).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, r := range viaGroups {
		seen[storage.Scope{ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID}] = struct{}{}
	}

	scopes := make([]storage.Scope, 0, len(seen))
	for s := range seen {
		scopes = append(scopes, s)
	}
	return scopes, nil
}

// ListProjectRoleAssignments returns every role assignment scoped to the project
// (project_id = projectID, any environment) for both users (user_roles) and groups
// (group_roles) — the raw grant rows behind a project access review. Global
// (project 0) assignments are deliberately excluded (install-level, reviewed
// separately). A principal with several roles at the project yields several rows.
func (ls *LocalStorage) ListProjectRoleAssignments(ctx context.Context, projectID uint) ([]storage.RoleAssignment, error) {
	var out []storage.RoleAssignment

	var userRows []models.UserRole
	if err := ls.db.WithContext(ctx).Where("project_id = ?", projectID).Find(&userRows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, r := range userRows {
		out = append(out, storage.RoleAssignment{
			PrincipalType: "user", PrincipalID: r.UserID, RoleID: r.RoleID,
			ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID,
		})
	}

	var groupRows []models.GroupRole
	if err := ls.db.WithContext(ctx).Where("project_id = ?", projectID).Find(&groupRows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, r := range groupRows {
		out = append(out, storage.RoleAssignment{
			PrincipalType: "group", PrincipalID: r.GroupID, RoleID: r.RoleID,
			ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID,
		})
	}
	return out, nil
}

// ListProjectMachineRoleAssignments returns every machine-identity role grant
// scoped to the project (project_id = projectID, any environment) — the machine
// counterpart to ListProjectRoleAssignments's user/group rows.
func (ls *LocalStorage) ListProjectMachineRoleAssignments(ctx context.Context, projectID uint) ([]storage.RoleAssignment, error) {
	var rows []models.MachineIdentityRole
	if err := ls.db.WithContext(ctx).Where("project_id = ?", projectID).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	out := make([]storage.RoleAssignment, 0, len(rows))
	for _, r := range rows {
		out = append(out, storage.RoleAssignment{
			PrincipalType: "machine", PrincipalID: r.MachineIdentityID, RoleID: r.RoleID,
			ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID,
		})
	}
	return out, nil
}

// ListGlobalAdminAssignmentsForUpdate returns every global-scope (project 0,
// environment 0) direct user and group role grant whose role is in adminRoleIDs,
// taking a row-level write lock on backends that support one (Postgres FOR
// UPDATE), mirroring LockUserForUpdate/LockWebAuthnCredentialForUpdate. See the
// Storage interface doc (#340) for why this exists: a concurrent racing removal
// must serialize against this read on Postgres/HA; the caller's own process
// mutex covers SQLite (single instance, no cross-process concern).
func (ls *LocalStorage) ListGlobalAdminAssignmentsForUpdate(ctx context.Context, adminRoleIDs []uint) ([]storage.RoleAssignment, error) {
	if len(adminRoleIDs) == 0 {
		return nil, nil
	}
	locked := ls.db.Dialector.Name() == "postgres"

	var out []storage.RoleAssignment

	userQ := ls.db.WithContext(ctx)
	if locked {
		userQ = userQ.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var userRows []models.UserRole
	if err := userQ.Where("project_id = 0 AND environment_id = 0 AND role_id IN ?", adminRoleIDs).
		Find(&userRows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, r := range userRows {
		out = append(out, storage.RoleAssignment{
			PrincipalType: "user", PrincipalID: r.UserID, RoleID: r.RoleID,
			ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID,
		})
	}

	groupQ := ls.db.WithContext(ctx)
	if locked {
		groupQ = groupQ.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var groupRows []models.GroupRole
	if err := groupQ.Where("project_id = 0 AND environment_id = 0 AND role_id IN ?", adminRoleIDs).
		Find(&groupRows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, r := range groupRows {
		out = append(out, storage.RoleAssignment{
			PrincipalType: "group", PrincipalID: r.GroupID, RoleID: r.RoleID,
			ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID,
		})
	}
	return out, nil
}

// RemoveGlobalAdminRoleGuarded is the atomic, single-storage-call form of
// guardLastGlobalAdmin (#340) + RemoveRole — added for #525 so RemoteStorage can
// proxy it as ONE HTTP round trip instead of the two separate calls
// (ListGlobalAdminAssignmentsForUpdate then RemoveRole) RemoveUserRole previously
// made inside a WithTransaction closure. See the Storage interface doc for the full
// atomicity reasoning. Runs in its own transaction (mirroring WithTransaction's own
// db.Transaction wrapping) so the row lock ListGlobalAdminAssignmentsForUpdate takes
// on Postgres is actually held for the whole check-then-delete, exactly as it was
// when the caller drove both calls under its own WithTransaction.
func (ls *LocalStorage) RemoveGlobalAdminRoleGuarded(ctx context.Context, userID, roleID uint, adminRoleIDs []uint) error {
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txStorage := &LocalStorage{db: tx, auditChainMu: ls.auditChainMu, auditCheckpointMu: ls.auditCheckpointMu}
		assignments, err := txStorage.ListGlobalAdminAssignmentsForUpdate(ctx, adminRoleIDs)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		survives := false
		for _, a := range assignments {
			// Ignore the exact assignment being removed; any OTHER global admin
			// grant (held by another user, or by a group) means governance survives.
			if a.PrincipalType == "user" && a.PrincipalID == userID && a.RoleID == roleID {
				continue
			}
			survives = true
			break
		}
		if !survives {
			return fmt.Errorf("%w: the install would be left with no super_admin/admin/system_admin at the global scope and no one able to manage users, roles, or settings", storage.ErrWouldStrandLastAdmin)
		}
		return txStorage.RemoveRole(ctx, userID, roleID, storage.Scope{})
	})
}

// GetUserRoleIDsExact returns the IDs of roles directly assigned to userID at
// exactly the given scope (no global/inherited matching). Used for full
// replacement of a user's roles at one scope.
func (ls *LocalStorage) GetUserRoleIDsExact(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	var ids []uint
	err := ls.db.WithContext(ctx).Model(&models.UserRole{}).
		Where("user_id = ? AND project_id = ? AND environment_id = ?",
			userID, scope.ProjectID, scope.EnvironmentID).
		Distinct().Pluck("role_id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return ids, nil
}

// IsProjectMember reports whether the user holds a LIVE role grant scoped to the
// project itself (project_id = projectID), directly or via a group. A global/install-
// wide role (project_id = 0) does NOT count — break-glass and similar controls must
// distinguish a project member from any user who merely holds the install baseline.
func (ls *LocalStorage) IsProjectMember(ctx context.Context, userID, projectID uint) (bool, error) {
	if projectID == 0 {
		return false, nil
	}
	now := time.Now()
	var direct int64
	if err := ls.db.WithContext(ctx).Model(&models.UserRole{}).
		Where("user_id = ? AND project_id = ?", userID, projectID).
		Where("expires_at IS NULL OR expires_at > ?", now).
		Count(&direct).Error; err != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if direct > 0 {
		return true, nil
	}
	var viaGroup int64
	if err := ls.db.WithContext(ctx).Table("group_roles").
		Joins("JOIN user_groups ON user_groups.group_id = group_roles.group_id").
		Joins("JOIN groups ON groups.id = group_roles.group_id AND groups.deleted_at IS NULL").
		Where("user_groups.user_id = ? AND group_roles.project_id = ?", userID, projectID).
		Where("group_roles.expires_at IS NULL OR group_roles.expires_at > ?", now).
		Count(&viaGroup).Error; err != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return viaGroup > 0, nil
}

// ListProjectMembers returns the users holding a LIVE role at the project's scope
// (project_id = projectID, environment_id = 0 — project-level membership per ADR-021).
// Soft-deleted users AND expired time-bound grants are excluded — the same expires_at
// filter every authorization query applies, so a lapsed (but not-yet-swept) grant (e.g.
// an expired break-glass project_admin) confers neither access NOR membership/notification
// eligibility. Without it, sensitive approver notifications would keep reaching a user
// whose grant has already lapsed.
func (ls *LocalStorage) ListProjectMembers(ctx context.Context, projectID uint) ([]storage.ProjectMember, error) {
	var members []storage.ProjectMember
	err := ls.db.WithContext(ctx).Table("user_roles ur").
		Select("u.id AS user_id, u.username, u.display_name, u.email, r.id AS role_id, r.name AS role_name").
		Joins("JOIN users u ON u.id = ur.user_id").
		Joins("JOIN roles r ON r.id = ur.role_id").
		Where("ur.project_id = ? AND ur.environment_id = 0", projectID).
		Where("ur.expires_at IS NULL OR ur.expires_at > ?", time.Now()).
		Where("u.deleted_at IS NULL").
		Order("u.username").
		Scan(&members).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return members, nil
}

// GetUserGroupRoleIDsAt returns the IDs of roles userID inherits via group
// membership that apply at the target scope (same scope-matching rule as
// GetUserRoleIDsAt).
// GetUserGroupRoleIDsAt: like GetUserRoleIDsAt but for group-inherited role
// grants. A scoped (non-zero) project_id/environment_id must ALSO resolve to a
// LIVE project/environment row, same as GetUserRoleIDsAt (#161) — a group-bound
// role scoped to a since-soft-deleted project previously kept authorizing every
// group member regardless of the project's own soft-delete state.
func (ls *LocalStorage) GetUserGroupRoleIDsAt(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	var ids []uint
	err := ls.db.WithContext(ctx).Table("group_roles").
		Joins("JOIN user_groups ON user_groups.group_id = group_roles.group_id").
		// A soft-deleted group confers no roles, even though its membership/grant rows
		// are kept for restore — exclude deleted groups from authorization.
		Joins("JOIN groups ON groups.id = group_roles.group_id AND groups.deleted_at IS NULL").
		Joins("LEFT JOIN projects ON projects.id = group_roles.project_id").
		Joins("LEFT JOIN environments ON environments.id = group_roles.environment_id").
		Where("user_groups.user_id = ?", userID).
		Where("group_roles.project_id = 0 OR (group_roles.project_id = ? AND projects.deleted_at IS NULL)", scope.ProjectID).
		Where("group_roles.environment_id = 0 OR (group_roles.environment_id = ? AND environments.deleted_at IS NULL)", scope.EnvironmentID).
		Where("group_roles.expires_at IS NULL OR group_roles.expires_at > ?", time.Now()).
		Distinct().Pluck("group_roles.role_id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return ids, nil
}

// RoleSetHasPermission reports whether any role in roleIDs grants the named
// permission (e.g. "secrets.read") via the role_permissions join.
func (ls *LocalStorage) RoleSetHasPermission(ctx context.Context, roleIDs []uint, permission string) (bool, error) {
	if len(roleIDs) == 0 {
		return false, nil
	}
	var count int64
	err := ls.db.WithContext(ctx).Table("permissions").
		Joins("JOIN role_permissions ON permissions.id = role_permissions.permission_id").
		Where("role_permissions.role_id IN ?", roleIDs).
		Where("permissions.name = ?", permission).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), err)
	}
	return count > 0, nil
}

// ListPermissions returns all permissions.
func (ls *LocalStorage) ListPermissions(ctx context.Context) ([]*models.Permission, error) {
	var permissions []*models.Permission
	if err := ls.db.WithContext(ctx).Find(&permissions).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return permissions, nil
}

// GetPermission returns a single permission by ID.
func (ls *LocalStorage) GetPermission(ctx context.Context, id uint) (*models.Permission, error) {
	var permission models.Permission
	if err := ls.db.WithContext(ctx).First(&permission, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &permission, nil
}

// GetRolePermissions returns all permissions assigned to a role.
func (ls *LocalStorage) GetRolePermissions(ctx context.Context, roleID uint) ([]*models.Permission, error) {
	var permissions []*models.Permission
	err := ls.db.WithContext(ctx).Table("permissions").
		Joins("JOIN role_permissions ON permissions.id = role_permissions.permission_id").
		Where("role_permissions.role_id = ?", roleID).
		Find(&permissions).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return permissions, nil
}

// RemovePermissionFromRole removes a permission from a role.
func (ls *LocalStorage) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uint) error {
	result := ls.db.WithContext(ctx).
		Where("role_id = ? AND permission_id = ?", roleID, permissionID).
		Delete(&models.RolePermission{})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}

// GetGroupRoles returns all roles assigned to a group.
func (ls *LocalStorage) GetGroupRoles(ctx context.Context, groupID uint) ([]*models.Role, error) {
	var roles []*models.Role
	err := ls.db.WithContext(ctx).Table("roles").
		Joins("JOIN group_roles ON roles.id = group_roles.role_id").
		Where("group_roles.group_id = ?", groupID).
		Find(&roles).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return roles, nil
}

// GetGroupRoleGrants is GetGroupRoles plus each grant's time-bound expiry, joined
// from group_roles.expires_at (nil = permanent).
func (ls *LocalStorage) GetGroupRoleGrants(ctx context.Context, groupID uint) ([]*storage.GroupRoleGrant, error) {
	var grants []*storage.GroupRoleGrant
	err := ls.db.WithContext(ctx).Table("roles").
		Select("roles.id, roles.name, roles.description, group_roles.expires_at").
		Joins("JOIN group_roles ON roles.id = group_roles.role_id").
		Where("group_roles.group_id = ?", groupID).
		Scan(&grants).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return grants, nil
}

// ListGroupRoleAssignments returns every role grant held by groupID across all
// scopes, unlike GetGroupRoles/GetGroupRoleGrants which return the role but not
// which scope it was granted at.
func (ls *LocalStorage) ListGroupRoleAssignments(ctx context.Context, groupID uint) ([]storage.RoleAssignment, error) {
	var rows []models.GroupRole
	if err := ls.db.WithContext(ctx).Where("group_id = ?", groupID).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	out := make([]storage.RoleAssignment, 0, len(rows))
	for _, r := range rows {
		out = append(out, storage.RoleAssignment{
			PrincipalType: "group", PrincipalID: r.GroupID, RoleID: r.RoleID,
			ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID,
		})
	}
	return out, nil
}

// AssignRoleToGroup assigns a permanent role to a group at scope; errors if
// already assigned there.
func (ls *LocalStorage) AssignRoleToGroup(ctx context.Context, groupID, roleID uint, scope storage.Scope) error {
	return ls.assignGroupRole(ctx, groupID, roleID, scope, nil)
}

// AssignRoleToGroupWithExpiry assigns a time-bound role to a group at scope.
func (ls *LocalStorage) AssignRoleToGroupWithExpiry(ctx context.Context, groupID, roleID uint, scope storage.Scope, expiresAt time.Time) error {
	return ls.assignGroupRole(ctx, groupID, roleID, scope, &expiresAt)
}

func (ls *LocalStorage) assignGroupRole(ctx context.Context, groupID, roleID uint, scope storage.Scope, expiresAt *time.Time) error {
	var existing models.GroupRole
	err := ls.db.WithContext(ctx).
		Where("group_id = ? AND role_id = ? AND project_id = ? AND environment_id = ?",
			groupID, roleID, scope.ProjectID, scope.EnvironmentID).First(&existing).Error
	switch err {
	case nil:
		// A row already exists at this exact (group, role, project, environment) key. A
		// still-live grant (no expiry, or an expiry still in the future) genuinely blocks
		// a duplicate assignment. But an EXPIRED grant is a stale, un-reaped row — e.g. a
		// prior break-glass activation whose time-bound grant naturally lapsed — and must
		// be treated as ABSENT for this check, or a second real-incident activation for
		// the same group/role/scope is permanently refused with "already assigned" even
		// though nothing live is actually being duplicated (#263/#471). Delete the stale
		// row so the composite primary key (group_id, role_id, project_id, environment_id)
		// is free for the fresh Create below, mirroring assignUserRole's identical fix.
		if existing.ExpiresAt == nil || existing.ExpiresAt.After(time.Now()) {
			return fmt.Errorf("%s", i18n.T("ErrorRoleAlreadyAssigned", nil))
		}
		if derr := ls.db.WithContext(ctx).
			Where("group_id = ? AND role_id = ? AND project_id = ? AND environment_id = ?",
				groupID, roleID, scope.ProjectID, scope.EnvironmentID).
			Delete(&models.GroupRole{}).Error; derr != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), derr)
		}
	case gorm.ErrRecordNotFound:
		// no existing row for this key — proceed to create.
	default:
		return fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), err)
	}
	groupRole := models.GroupRole{
		GroupID:       groupID,
		RoleID:        roleID,
		ProjectID:     scope.ProjectID,
		EnvironmentID: scope.EnvironmentID,
		ExpiresAt:     expiresAt,
	}
	if err := ls.db.WithContext(ctx).Create(&groupRole).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// DeleteExpiredRoleGrants removes user_roles and group_roles whose ExpiresAt is
// non-NULL and at or before the cutoff, returning the removed grants so the caller
// can audit each expiry. Runs in a transaction so the rows it reports are exactly
// the rows it deleted.
func (ls *LocalStorage) DeleteExpiredRoleGrants(ctx context.Context, before time.Time) ([]storage.RoleAssignment, error) {
	var removed []storage.RoleAssignment
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var userRows []models.UserRole
		if err := tx.Where("expires_at IS NOT NULL AND expires_at <= ?", before).Find(&userRows).Error; err != nil {
			return err
		}
		var groupRows []models.GroupRole
		if err := tx.Where("expires_at IS NOT NULL AND expires_at <= ?", before).Find(&groupRows).Error; err != nil {
			return err
		}
		if len(userRows) > 0 {
			if err := tx.Where("expires_at IS NOT NULL AND expires_at <= ?", before).Delete(&models.UserRole{}).Error; err != nil {
				return err
			}
		}
		if len(groupRows) > 0 {
			if err := tx.Where("expires_at IS NOT NULL AND expires_at <= ?", before).Delete(&models.GroupRole{}).Error; err != nil {
				return err
			}
		}
		for _, r := range userRows {
			removed = append(removed, storage.RoleAssignment{
				PrincipalType: "user", PrincipalID: r.UserID, RoleID: r.RoleID,
				ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID,
			})
		}
		for _, r := range groupRows {
			removed = append(removed, storage.RoleAssignment{
				PrincipalType: "group", PrincipalID: r.GroupID, RoleID: r.RoleID,
				ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID,
			})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return removed, nil
}

// RemoveRoleFromGroup removes a role from a group at scope.
func (ls *LocalStorage) RemoveRoleFromGroup(ctx context.Context, groupID, roleID uint, scope storage.Scope) error {
	result := ls.db.WithContext(ctx).
		Where("group_id = ? AND role_id = ? AND project_id = ? AND environment_id = ?",
			groupID, roleID, scope.ProjectID, scope.EnvironmentID).
		Delete(&models.GroupRole{})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorRoleNotAssigned", nil))
	}
	return nil
}

// GetUserPermissions retrieves all distinct permissions for userID via role membership.
func (ls *LocalStorage) GetUserPermissions(ctx context.Context, userID uint) ([]*storage.Permission, error) {
	var permissions []*storage.Permission
	err := ls.db.WithContext(ctx).Table("permissions").
		Select("permissions.id, permissions.name, permissions.description, permissions.resource, permissions.action").
		Joins("JOIN role_permissions ON permissions.id = role_permissions.permission_id").
		Joins("JOIN user_roles ON role_permissions.role_id = user_roles.role_id").
		Where("user_roles.user_id = ?", userID).
		Where("user_roles.expires_at IS NULL OR user_roles.expires_at > ?", time.Now()).
		Group("permissions.id").
		Find(&permissions).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return permissions, nil
}

// GetUserGroupPermissions returns the permissions a user holds via group
// membership, scope-agnostically across all their groups. Mirrors
// GetUserPermissions but resolves through group_roles/user_groups, excluding
// soft-deleted groups and expired grants (matching GetUserGroupRoleIDsAt).
func (ls *LocalStorage) GetUserGroupPermissions(ctx context.Context, userID uint) ([]*storage.Permission, error) {
	var permissions []*storage.Permission
	err := ls.db.WithContext(ctx).Table("permissions").
		Select("permissions.id, permissions.name, permissions.description, permissions.resource, permissions.action").
		Joins("JOIN role_permissions ON permissions.id = role_permissions.permission_id").
		Joins("JOIN group_roles ON role_permissions.role_id = group_roles.role_id").
		Joins("JOIN user_groups ON user_groups.group_id = group_roles.group_id").
		// A soft-deleted group confers no permissions (matches authz resolution).
		Joins("JOIN groups ON groups.id = group_roles.group_id AND groups.deleted_at IS NULL").
		Where("user_groups.user_id = ?", userID).
		Where("group_roles.expires_at IS NULL OR group_roles.expires_at > ?", time.Now()).
		Group("permissions.id").
		Find(&permissions).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return permissions, nil
}
