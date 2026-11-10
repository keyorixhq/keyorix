package store

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// userGrantRowsSQL reads every live, unexpired grant of one user, direct and
// through a live group, in one statement (#4025). It carries what
// GetUserRoleScopes, GetUserRoleIDsAt and GetUserGroupRoleIDsAt filter on, so
// GetUserScopedRoleSets applies their rules in Go to one snapshot:
//   - scopes: every unexpired direct grant, and every unexpired grant of a
//     non-deleted group the user is in (no liveness or membership filter);
//   - roles at a scope: a grant at project 0, or at that project with a live
//     project row; at environment 0, or at that environment with a live row;
//     for a group grant, a global membership or one in that project.
const userGrantRowsSQL = `
SELECT 0 AS via_group, user_roles.project_id AS project_id, user_roles.environment_id AS environment_id,
       0 AS membership_project_id, user_roles.role_id AS role_id,
       CASE WHEN projects.id IS NOT NULL AND projects.deleted_at IS NULL THEN 1 ELSE 0 END AS project_live,
       CASE WHEN environments.id IS NOT NULL AND environments.deleted_at IS NULL THEN 1 ELSE 0 END AS environment_live
  FROM user_roles
  LEFT JOIN projects ON projects.id = user_roles.project_id
  LEFT JOIN environments ON environments.id = user_roles.environment_id
 WHERE user_roles.user_id = ? AND (user_roles.expires_at IS NULL OR user_roles.expires_at > ?)
UNION ALL
SELECT 1, group_roles.project_id, group_roles.environment_id,
       user_groups.project_id, group_roles.role_id,
       CASE WHEN projects.id IS NOT NULL AND projects.deleted_at IS NULL THEN 1 ELSE 0 END,
       CASE WHEN environments.id IS NOT NULL AND environments.deleted_at IS NULL THEN 1 ELSE 0 END
  FROM group_roles
  JOIN user_groups ON user_groups.group_id = group_roles.group_id
  JOIN groups ON groups.id = group_roles.group_id AND groups.deleted_at IS NULL
  LEFT JOIN projects ON projects.id = group_roles.project_id
  LEFT JOIN environments ON environments.id = group_roles.environment_id
 WHERE user_groups.user_id = ? AND (group_roles.expires_at IS NULL OR group_roles.expires_at > ?)`

type userGrantRow struct {
	ViaGroup            int
	ProjectID           uint
	EnvironmentID       uint
	MembershipProjectID uint
	RoleID              uint
	ProjectLive         int
	EnvironmentLive     int
}

// appliesAt reports whether the grant confers its role at scope, by the rules
// of GetUserRoleIDsAt (direct) and GetUserGroupRoleIDsAt (via a group).
func (r userGrantRow) appliesAt(scope storage.Scope) bool {
	if r.ProjectID != 0 && (r.ProjectID != scope.ProjectID || r.ProjectLive == 0) {
		return false
	}
	if r.EnvironmentID != 0 && (r.EnvironmentID != scope.EnvironmentID || r.EnvironmentLive == 0) {
		return false
	}
	return r.ViaGroup == 0 || r.MembershipProjectID == 0 || r.MembershipProjectID == scope.ProjectID
}

// GetUserScopedRoleSets: see the storage.Storage interface doc. Any error is
// returned; the per-statement reads are not a fallback, because they are the
// inconsistent view this replaces.
func (ls *LocalStorage) GetUserScopedRoleSets(ctx context.Context, userID uint) (map[storage.Scope][]uint, error) {
	now := ls.rbacEffectiveNow(time.Now().UTC())
	var rows []userGrantRow
	if err := ls.db.WithContext(ctx).Raw(userGrantRowsSQL, userID, now, userID, now).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	out := map[storage.Scope][]uint{}
	for _, r := range rows {
		out[storage.Scope{ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID}] = nil
	}
	for scope := range out {
		ids := []uint{}
		for _, r := range rows {
			if r.appliesAt(scope) && !slices.Contains(ids, r.RoleID) {
				ids = append(ids, r.RoleID)
			}
		}
		out[scope] = ids
	}
	return out, nil
}
