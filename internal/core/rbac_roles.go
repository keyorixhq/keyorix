// rbac_roles.go — role DEFINITION CRUD (CreateRole, UpdateRole), distinct from
// assigning a role to a principal (rbac_management.go/rbac.go).
//
// #1660: server/http/handlers/rbac.go's RBACHandler and server/grpc/services/
// role_service.go's RoleGRPCService both used to call storage.Storage.CreateRole/
// UpdateRole directly, bypassing internal/core entirely — the only two transports
// that create/update roles had no shared validation layer, unlike every other
// resource (users, groups, secrets, projects), each of which routes through a
// core-layer function. #1642's identity.FoldedName constructor closed the
// worst of this as a side effect (charset/length validation on the name), but
// that was incidental to a different fix, not a deliberate one for this shape,
// and left the reserved-builtin-name check and audit logging duplicated
// per-transport rather than defined once. This file is that single definition;
// both transports now call CreateRole/UpdateRole here instead of the storage
// layer directly.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Role Name/Description length bounds — the single source of truth both
// transports' own early-reject validation (server/http/handlers/rbac.go's
// CreateRoleRequest/UpdateRoleRequest struct tags, server/grpc/services/
// role_service.go's validateRoleName/validateRoleDescription) must mirror,
// closing the #191/#1660 duplication where gRPC previously defined its own
// copy of these numbers with no shared layer to inherit them from. Roles get
// their own bounds rather than reusing the generic validateNameLength/
// validateDescription (maxResourceNameLen=255, maxSecretDescriptionLen=1024,
// neither with a minimum) — tighter and minimum-enforcing on purpose, since a
// role name is a short, human-typed identifier, not free text.
const (
	RoleNameMinLen        = 3
	RoleNameMaxLen        = 50
	RoleDescriptionMinLen = 1
	RoleDescriptionMaxLen = 200
)

func validateRoleNameLength(name string) error {
	if len(name) < RoleNameMinLen || len(name) > RoleNameMaxLen {
		return fmt.Errorf("role name must be between %d and %d characters", RoleNameMinLen, RoleNameMaxLen)
	}
	return nil
}

// CreateRole creates a new role definition. name is the raw, caller-supplied
// role name — this is the ONLY point that constructs the identity.FoldedName
// storage.CreateRole requires, so no future call site can reach storage with
// an unfolded/unvalidated name (mirrors CreateGroup's identical treatment,
// groups.go). Rejects reserved built-in role names (#294) before ever writing
// anything: roleSetContainsAdmin (authz.go) grants a full admin bypass by name
// match alone, so a caller-created row named e.g. "super_admin" would function
// as a complete admin-bypass switch the moment it's assigned, even with zero
// permissions of its own. actorID is the admin performing the create (0 = no
// authenticated principal).
func (c *KeyorixCore) CreateRole(ctx context.Context, actorID uint, name, description string) (*models.Role, error) {
	if err := validateRoleNameLength(name); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	foldedName, ferr := identity.NewFoldedName(name)
	if ferr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ferr)
	}
	if IsBuiltinRole(foldedName.Folded()) {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "this role name is reserved and cannot be created")
	}
	role, err := c.storage.CreateRole(ctx, foldedName, description)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.LogRoleCreated(ctx, actorID, role.ID, role.Name)
	return role, nil
}

// UpdateRole updates an existing role's description (role names are immutable —
// #1494's closure rests on this: neither transport's UpdateRoleRequest carries
// a field mapping to models.Role.Name, verified by AST inspection in
// server/http/role_rename_unreachable_guard_test.go's
// TestUpdateRoleRequest_CarriesNoNameField, so there is no rename call site
// here to guard). Rejects mutating a built-in role (mirrors CreateRole's
// reserved-name guard — an
// admin/system_admin role's permission set must not be alterable through this
// path). Callers that also need to replace the role's permission set do so via
// AssignPermissionToRole/RemovePermissionFromRole around this call, matching
// the existing per-transport sequencing — this function only persists the
// role row itself and audits that change.
func (c *KeyorixCore) UpdateRole(ctx context.Context, actorID uint, role *models.Role) (*models.Role, error) {
	if IsBuiltinRole(role.Name) {
		c.LogRoleUpdateDenied(ctx, actorID, role.ID, role.Name, "target is a built-in role")
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil), "cannot update built-in role: "+role.Name)
	}
	updated, err := c.storage.UpdateRole(ctx, role)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.LogRoleUpdated(ctx, actorID, updated.ID, updated.Name)
	return updated, nil
}
