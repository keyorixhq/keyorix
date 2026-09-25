// rbac_wire.go — snake_case wire types for internal/storage/models.Role,
// Permission, and internal/core.RoleWithPermissions (all carry zero/mixed json
// tags — RoleWithPermissions embeds the untagged models.Role, so every route
// returning it was mixed-casing). See
// docs/findings/2026-09-25-FINDING-api-raw-model-exposure.md.
//
// GET /api/v1/roles/by-name is deliberately NOT converted — see
// GetRoleByName's own doc comment: its sole consumer is
// RemoteStorage.GetRoleByName, which decodes the raw (untagged) shape
// directly; there is no other caller, so converting it would only break its
// one real consumer for no benefit.
package handlers

import (
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type permissionWire struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
}

func newPermissionWire(p *models.Permission) permissionWire {
	return permissionWire{
		ID: p.ID, Name: p.Name, Description: p.Description, Resource: p.Resource, Action: p.Action,
	}
}

func newPermissionWireList(perms []*models.Permission) []permissionWire {
	out := make([]permissionWire, 0, len(perms))
	for _, p := range perms {
		out = append(out, newPermissionWire(p))
	}
	return out
}

type roleWire struct {
	ID                       uint   `json:"id"`
	Name                     string `json:"name"`
	Description              string `json:"description"`
	BypassesPermissionChecks bool   `json:"bypasses_permission_checks"`
}

func newRoleWire(r *models.Role) roleWire {
	return roleWire{
		ID: r.ID, Name: r.Name, Description: r.Description, BypassesPermissionChecks: r.BypassesPermissionChecks,
	}
}

// roleWithPermissionsWire mirrors core.RoleWithPermissions's shape (flat role
// fields alongside the permission set), matching every existing consumer's
// expectation modulo casing.
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
