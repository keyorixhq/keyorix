package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// GroupStore is the Storage slice for groups and group memberships.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type GroupStore interface {
	GetUserGroups(ctx context.Context, userID uint) ([]*models.Group, error)
	// ListAllUserGroupMemberships returns every user_groups row in the
	// deployment, unfiltered by project scope (#G44) — the batch-load
	// counterpart to GetUserGroups: GetPermissionBaseline uses this to load
	// every user's group membership in one query instead of one GetUserGroups
	// call per user, a genuine N+1 whose cost scales with the deployment's own
	// user count. Preserves GetUserGroups' exact per-user multiplicity (a user
	// with both a global and a project-scoped membership row for the same
	// group yields two rows here too, matching GetUserGroups' unfiltered JOIN).
	ListAllUserGroupMemberships(ctx context.Context) ([]UserGroupMembership, error)

	// Group Management
	CreateGroup(ctx context.Context, group *models.Group) (*models.Group, error)
	GetGroup(ctx context.Context, id uint) (*models.Group, error)
	// UpdateGroupFields persists ONLY the non-nil fields among name,
	// nameFolded and description (plus updated_at) onto a LIVE group row:
	// "UPDATE groups SET ... WHERE id = ? AND deleted_at IS NULL".
	// matched=false (no error) means the group is gone; the caller must not
	// report success. name and nameFolded must be passed together — they are
	// one value in two columns (#1642) and a stale nameFolded would leave the
	// uniqueness index checking a name the group no longer has.
	//
	// This REPLACES the former UpdateGroup, a bare GORM Save (#2697). Save's
	// 0-rows fallback is an upsert that writes deleted_at = NULL, and DeleteGroup
	// deliberately KEEPS a deleted group's GroupRole and UserGroup rows so
	// RestoreGroup can work — so a rename landing after a delete or SCIM
	// deprovision brought the group back with every role grant and membership
	// live, with no restore audit event and without going through RestoreGroup.
	// An IdP DELETE closely followed by a PUT is enough: ReplaceSCIMGroup and
	// PatchSCIMGroup rename through this same primitive, outside the
	// withGroupProjectAdminGuardLocks that deleteGroupGuarded holds.
	UpdateGroupFields(ctx context.Context, id uint, name, nameFolded, description *string, updatedAt time.Time) (matched bool, err error)
	DeleteGroup(ctx context.Context, id uint) error
	// RestoreGroup clears a soft-deleted group's deleted_at (with its grants/members).
	RestoreGroup(ctx context.Context, id uint) error
	ListGroups(ctx context.Context) ([]*models.Group, error)
	// ListGroupsPage returns one name-ordered page of groups (offset is a 0-based
	// row offset) and the total count, without loading the rest of the table — used
	// by the SCIM Groups list so an unfiltered request can't drain the whole
	// directory into memory (see ListGroups' full-scan callers for why that's fine
	// there: they intentionally want every group, e.g. SSO group sync).
	ListGroupsPage(ctx context.Context, offset, pageSize int) ([]*models.Group, int64, error)
	// AddUserToGroup adds userID to groupID. projectID scopes the membership: 0
	// means global (the user is a member in every project context), non-zero
	// restricts it to that project only. The authorisation path unions both.
	AddUserToGroup(ctx context.Context, userID, groupID, projectID uint) error
	// RemoveUserFromGroup removes the (userID, groupID, projectID) membership row.
	// projectID must match the value used when the membership was created.
	RemoveUserFromGroup(ctx context.Context, userID, groupID, projectID uint) error
	ListGroupMembers(ctx context.Context, groupID uint) ([]*models.User, error)
	// ListGroupMembersByGroupIDs is the batch form of ListGroupMembers: the members
	// of every group in groupIDs, keyed by group ID, in one query — used by the
	// rotation planner's risk-scoring batch (#409) instead of one ListGroupMembers
	// call per group share, per candidate secret.
	ListGroupMembersByGroupIDs(ctx context.Context, groupIDs []uint) (map[uint][]*models.User, error)
	// ListGroupMembersAt is ListGroupMembers scoped: only members whose UserGroup
	// row is global (project_id=0) OR matches scope.ProjectID (#G01). Unlike
	// ListGroupMembers (which returns every member regardless of their
	// membership's own scope), this is for callers that need to know whether a
	// member's membership actually confers authority AT this scope — e.g. "does
	// this group's GLOBAL role grant give member X global admin authority" must
	// exclude a member whose membership in the group is itself project-scoped.
	ListGroupMembersAt(ctx context.Context, groupID uint, scope Scope) ([]*models.User, error)
}
