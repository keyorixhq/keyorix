// auth_bootstrap.go — First-boot system initialisation (BootstrapSystem).
//
// Seeds admin user, RBAC roles/permissions (see defaultRoles), default project/environments.
// Idempotent: if users already exist, returns current state with AlreadyInitialized=true.
// For session auth see auth.go.
package core

import (
	"context"
	"crypto/subtle"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// BootstrapRequest holds credentials and display name for the initial bootstrap.
// Token is the caller-supplied bootstrap token, matched against the server's
// configured token (see KeyorixCore.SetBootstrapToken) to authorize the first-admin
// claim.
type BootstrapRequest struct {
	Username    string
	Email       string
	Password    string
	DisplayName string
	Token       string
}

// BootstrapResult is returned after a bootstrap call (first-time or idempotent repeat).
type BootstrapResult struct {
	AlreadyInitialized bool
	User               *models.User
	Project            *models.Project
	Environments       []*models.Environment
}

// bootstrapPermissionDef describes a permission to create during bootstrap.
type bootstrapPermissionDef struct {
	Name        string
	Description string
	Resource    string
	Action      string
}

// defaultPermissions is the canonical set of permissions seeded on first boot.
var defaultPermissions = []bootstrapPermissionDef{
	{"secrets.read", "Read secrets", "secrets", "read"},
	{"secrets.write", "Create and update secrets", "secrets", "write"},
	{"secrets.delete", "Delete secrets", "secrets", "delete"},
	{"users.read", "View user information", "users", "read"},
	{"users.write", "Create and update users", "users", "write"},
	{"users.delete", "Delete users", "users", "delete"},
	{"roles.read", "View roles", "roles", "read"},
	{"roles.write", "Create and update roles", "roles", "write"},
	{"roles.assign", "Assign roles to users", "roles", "assign"},
	{"audit.read", "View audit logs", "audit", "read"},
	{"system.read", "View system information", "system", "read"},
	{"system.write", "Manage service accounts and API tokens", "system", "write"},
	{"connect.read", "Read secrets from external stores via Keyorix Connect (ADR-043)", "connect", "read"},
}

// adminPermissions lists the permission names granted to the admin role.
var adminPermissions = []string{
	"secrets.read", "secrets.write", "secrets.delete",
	"users.read", "users.write", "users.delete",
	"roles.read", "roles.write", "roles.assign",
	"audit.read", "system.read", "system.write",
	"connect.read",
}

// editorPermissions lists the permission names granted to the editor role.
// Editor is the canonical "can change secrets, but not manage users/roles" role
// and is meant to be granted at a project/environment scope (RBAC Phase 2).
var editorPermissions = []string{"secrets.read", "secrets.write", "secrets.delete", "users.read"}

// viewerPermissions lists the permission names granted to the viewer role.
var viewerPermissions = []string{"secrets.read", "users.read", "audit.read"}

// bootstrapRoleDef describes a role to seed on first boot and the permissions
// it grants (by permission name, resolved against defaultPermissions).
type bootstrapRoleDef struct {
	Name        string
	Description string
	Permissions []string
}

// defaultRoles is the canonical set of roles seeded on first boot.
//
// admin/editor/viewer are the legacy single-tier roles, retained for backward
// compatibility. The system_* and project_* roles implement the ADR-021 two-tier
// model on the RBAC Phase 2 sentinel schema: a system role is meant to be
// assigned at the global scope (project 0 = install-wide), a project role at a
// project scope (project P). The split is purely by where each is assigned —
// there is no separate scope column; project_id = 0 is the system sentinel.
// system_admin and project_admin bypass the per-permission check at the scope
// they hold (see adminRoleNames in authz.go), so their explicit permission lists
// matter only where the bypass does not apply.
var defaultRoles = []bootstrapRoleDef{
	{"admin", "Administrator with full access (legacy alias of system_admin)", adminPermissions},
	{"editor", "Create, update and delete secrets within a scope", editorPermissions},
	{"viewer", "Read-only access", viewerPermissions},

	// ADR-021 system roles — assign at the global scope (project 0).
	{"system_admin", "Install-wide administrator: manage projects, users, roles and settings", adminPermissions},
	{"system_auditor", "Install-wide read-only access plus audit, for compliance personas",
		[]string{"secrets.read", "users.read", "roles.read", "audit.read", "system.read"}},
	{"system_viewer", "Minimal install baseline; project access comes from project roles",
		[]string{"system.read"}},

	// ADR-021 project roles — assign at a project scope (project P).
	{"project_admin", "Full control within a project, including members and settings",
		[]string{"secrets.read", "secrets.write", "secrets.delete", "users.read", "roles.read", "roles.assign", "audit.read"}},
	{"project_developer", "Read, write and rotate secrets in all environments of a project",
		[]string{"secrets.read", "secrets.write", "secrets.delete", "users.read"}},
	{"project_viewer", "Read-only access to a project's secrets",
		[]string{"secrets.read", "users.read"}},
	{"project_auditor", "Read-only access to a project's secrets plus its audit log",
		[]string{"secrets.read", "users.read", "audit.read"}},
}

// builtinRoleNames are the roles that ship with the product and must not be
// deleted through any API (deleting e.g. super_admin/admin would invalidate live
// assignments and can lock every administrator out). This is the single source of
// truth shared by the HTTP and gRPC role-delete guards; it is a superset of
// defaultRoles (it also pins the historical "super_admin"/"auditor" aliases).
var builtinRoleNames = map[string]bool{
	"super_admin": true,
	"admin":       true,
	"editor":      true,
	"viewer":      true,
	"auditor":     true,
	// ADR-021 two-tier named roles.
	"system_admin":      true,
	"system_auditor":    true,
	"system_viewer":     true,
	"project_admin":     true,
	"project_developer": true,
	"project_viewer":    true,
	"project_auditor":   true,
}

// IsBuiltinRole reports whether a role name is a product built-in that the API
// must refuse to delete. Used by both the HTTP and gRPC DeleteRole paths so the
// guard cannot be bypassed by switching transport.
func IsBuiltinRole(name string) bool {
	return builtinRoleNames[name]
}

// defaultEnvironmentNames is the ordered list of environment names created on first boot.
var defaultEnvironmentNames = []string{"development", "staging", "production"}

// systemInitializedKey is the permanent SystemMetadata marker set once bootstrap
// completes successfully. Unlike the live user count, it survives every user later
// being soft-deleted (see core.DeleteUser / #106): without it, a full deprovision
// would zero ListUsers' count and SystemNeedsBootstrap/BootstrapSystem would treat
// the install as never-initialised again, letting a stale/leaked bootstrap token
// (or a freshly regenerated one — GenerateBootstrapToken logs it on every restart
// while uninitialised) re-seize admin even though the original users still exist,
// soft-deleted and restorable.
const systemInitializedKey = "system_initialized" // #nosec G101 -- metadata key name, not a credential

// BootstrapSystem ensures the server has a fully-configured initial state:
//   - admin user (with the supplied credentials)
//   - canonical RBAC permissions and roles (legacy admin/editor/viewer plus the
//     ADR-021 two-tier system_* and project_* roles)
//   - default project ("default")
//   - three default environments (development, staging, production)
//
// Idempotent: if the install is already initialised, returns the current state
// with AlreadyInitialized=true and performs no writes. bootstrapMu serializes the
// whole check-then-create sequence so two concurrent first calls can't both pass
// the check and double-seed (the storage layer alone doesn't make this atomic).
func (c *KeyorixCore) BootstrapSystem(ctx context.Context, req *BootstrapRequest) (*BootstrapResult, error) {
	c.bootstrapMu.Lock()
	defer c.bootstrapMu.Unlock()

	// The permanent marker is authoritative once set — see systemInitializedKey.
	if _, found, err := c.storage.GetSystemMetadata(ctx, systemInitializedKey); err != nil {
		return nil, fmt.Errorf("failed to check system initialisation state: %w", err)
	} else if found {
		return c.currentBootstrapState(ctx)
	}

	_, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{Page: 1, PageSize: 1})
	if err != nil {
		return nil, fmt.Errorf("failed to check existing users: %w", err)
	}
	if total > 0 {
		// A pre-fix install has users but never wrote the marker; backfill it now so
		// a future full-deprovision can't reopen bootstrap for THIS install either.
		if err := c.storage.SetSystemMetadata(ctx, systemInitializedKey, "1"); err != nil {
			return nil, fmt.Errorf("failed to record system initialisation state: %w", err)
		}
		return c.currentBootstrapState(ctx)
	}

	// Authorize the first-admin claim. Without this gate the bootstrap is an
	// unauthenticated, first-caller-wins admin seizure on any fresh, network-reachable
	// instance. An unset server token disables API bootstrap entirely (fail closed).
	if c.bootstrapToken == "" {
		return nil, fmt.Errorf("system initialisation over the API is disabled: no bootstrap token is configured")
	}
	if subtle.ConstantTimeCompare([]byte(req.Token), []byte(c.bootstrapToken)) != 1 {
		return nil, fmt.Errorf("invalid bootstrap token")
	}
	// The initial admin is the most privileged account; enforce the password policy
	// here too (plain CreateUser does not), so it can't be seeded with a weak password.
	if err := c.passwordPolicy.Validate(req.Password, nil); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	displayName := req.DisplayName
	if displayName == "" {
		displayName = req.Username
	}
	user, err := c.CreateUser(ctx, &CreateUserRequest{
		Username:    req.Username,
		Email:       req.Email,
		Password:    req.Password,
		DisplayName: displayName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create admin user: %w", err)
	}

	permIDs := make(map[string]uint, len(defaultPermissions))
	for _, def := range defaultPermissions {
		p, err := c.storage.CreatePermission(ctx, &models.Permission{
			Name:        def.Name,
			Description: def.Description,
			Resource:    def.Resource,
			Action:      def.Action,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create permission %s: %w", def.Name, err)
		}
		permIDs[def.Name] = p.ID
	}

	roleIDs := make(map[string]uint, len(defaultRoles))
	for _, rdef := range defaultRoles {
		role, err := c.storage.CreateRole(ctx, &models.Role{
			Name:        rdef.Name,
			Description: rdef.Description,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create role %s: %w", rdef.Name, err)
		}
		roleIDs[rdef.Name] = role.ID
		for _, name := range rdef.Permissions {
			if err := c.storage.AssignPermissionToRole(ctx, role.ID, permIDs[name]); err != nil {
				return nil, fmt.Errorf("failed to assign permission %s to role %s: %w", name, rdef.Name, err)
			}
		}
	}

	// The first user is the install super-user: assign the admin role globally.
	if err := c.storage.AssignRole(ctx, user.ID, roleIDs["admin"], Scope{}); err != nil {
		return nil, fmt.Errorf("failed to assign admin role to user: %w", err)
	}

	project, err := c.storage.CreateProject(ctx, &models.Project{
		Name:        "default",
		Description: "Default project",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create default project: %w", err)
	}

	envs := make([]*models.Environment, 0, len(defaultEnvironmentNames))
	for _, name := range defaultEnvironmentNames {
		env, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: name, ProjectID: project.ID})
		if err != nil {
			return nil, fmt.Errorf("failed to create environment %s: %w", name, err)
		}
		envs = append(envs, env)
	}

	if err := c.storage.SetSystemMetadata(ctx, systemInitializedKey, "1"); err != nil {
		return nil, fmt.Errorf("failed to record system initialisation state: %w", err)
	}
	// The bootstrap token is single-use: clear it so a captured/logged token (see
	// GenerateBootstrapToken) can never re-open initialisation later, even before
	// considering the marker above.
	c.bootstrapToken = ""

	return &BootstrapResult{
		AlreadyInitialized: false,
		User:               user,
		Project:            project,
		Environments:       envs,
	}, nil
}

// currentBootstrapState returns an idempotent BootstrapResult for an already-initialised system.
// Best-effort: partial results are acceptable since the caller only uses this for display output.
func (c *KeyorixCore) currentBootstrapState(ctx context.Context) (*BootstrapResult, error) {
	users, _, err := c.storage.ListUsers(ctx, &storage.UserFilter{Page: 1, PageSize: 1})
	var firstUser *models.User
	if err == nil && len(users) > 0 {
		firstUser = users[0]
	}

	projects, projErr := c.storage.ListProjects(ctx)
	var project *models.Project
	if projErr == nil && len(projects) > 0 {
		project = projects[0]
	}

	envs, envErr := c.storage.ListEnvironments(ctx)
	if envErr != nil {
		envs = nil
	}

	return &BootstrapResult{
		AlreadyInitialized: true,
		User:               firstUser,
		Project:            project,
		Environments:       envs,
	}, nil
}

// SystemNeedsBootstrap reports whether the install has never completed
// initialisation (i.e. POST /system/init would seed the first admin). The server
// uses this at startup to decide whether to surface the bootstrap token to the
// operator. Checks the permanent systemInitializedKey marker first — see its doc
// comment — falling back to the live user count only for a pre-fix install that
// never wrote the marker.
func (c *KeyorixCore) SystemNeedsBootstrap(ctx context.Context) (bool, error) {
	if _, found, err := c.storage.GetSystemMetadata(ctx, systemInitializedKey); err != nil {
		return false, err
	} else if found {
		return false, nil
	}
	_, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{Page: 1, PageSize: 1})
	if err != nil {
		return false, err
	}
	return total == 0, nil
}

// GenerateBootstrapToken returns a fresh, high-entropy bootstrap token. The server
// uses it when no KEYORIX_BOOTSTRAP_TOKEN is configured, logging the value so the
// operator can initialise the (still-empty) install.
func GenerateBootstrapToken() (string, error) {
	return randToken()
}
