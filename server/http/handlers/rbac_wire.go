// rbac_wire.go — snake_case wire types for internal/storage/models.Role and
// models.Permission (both untagged) and internal/core.RoleWithPermissions
// (which anonymously embeds models.Role — encoding/json promotes Role's
// untagged fields to the top level using its own bare Go names regardless of
// RoleWithPermissions's own "permissions" tag, the same anonymous-embedding
// shape found for SecretWithSharingInfo in the SecretNode casing fix). See
// docs/findings/2026-09-25-FINDING-api-raw-model-exposure.md.
package handlers

import (
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type roleWire struct {
	ID                       uint   `json:"id"`
	Name                     string `json:"name"`
	Description              string `json:"description,omitempty"`
	BypassesPermissionChecks bool   `json:"bypasses_permission_checks"`
}

func newRoleWire(r *models.Role) roleWire {
	return roleWire{
		ID:                       r.ID,
		Name:                     r.Name,
		Description:              r.Description,
		BypassesPermissionChecks: r.BypassesPermissionChecks,
	}
}

type permissionWire struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
}

func newPermissionWire(p *models.Permission) permissionWire {
	return permissionWire{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		Resource:    p.Resource,
		Action:      p.Action,
	}
}

func newPermissionWireList(perms []*models.Permission) []permissionWire {
	out := make([]permissionWire, 0, len(perms))
	for _, p := range perms {
		out = append(out, newPermissionWire(p))
	}
	return out
}

// roleWithPermissionsWire mirrors core.RoleWithPermissions's shape exactly
// (flat, not nested — Role's fields promoted alongside "permissions") but
// with every field correctly tagged, via the same anonymous-embedding-of-a-
// correctly-tagged-wire-type approach as secretWithSharingInfoWire.
type roleWithPermissionsWire struct {
	roleWire
	Permissions []permissionWire `json:"permissions"`
}

func newRoleWithPermissionsWire(r *core.RoleWithPermissions) roleWithPermissionsWire {
	return roleWithPermissionsWire{
		roleWire:    newRoleWire(&r.Role),
		Permissions: newPermissionWireList(r.Permissions),
	}
}

func newRoleWithPermissionsWireList(roles []*core.RoleWithPermissions) []roleWithPermissionsWire {
	out := make([]roleWithPermissionsWire, 0, len(roles))
	for _, r := range roles {
		out = append(out, newRoleWithPermissionsWire(r))
	}
	return out
}

// userRoleAssignmentWire mirrors core.UserRoleAssignment, whose own
// UserID/Username/Email fields are correctly tagged but whose Roles field is
// raw, untagged []*models.Role.
type userRoleAssignmentWire struct {
	UserID   uint       `json:"user_id"`
	Username string     `json:"username"`
	Email    string     `json:"email"`
	Roles    []roleWire `json:"roles"`
}

func newUserRoleAssignmentWire(a *core.UserRoleAssignment) userRoleAssignmentWire {
	roles := make([]roleWire, 0, len(a.Roles))
	for _, r := range a.Roles {
		roles = append(roles, newRoleWire(r))
	}
	return userRoleAssignmentWire{
		UserID:   a.UserID,
		Username: a.Username,
		Email:    a.Email,
		Roles:    roles,
	}
}
