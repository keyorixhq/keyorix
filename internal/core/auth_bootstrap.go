// auth_bootstrap.go — First-boot system initialisation (BootstrapSystem).
//
// Seeds admin user, RBAC roles/permissions, default namespace/zone/environments.
// Idempotent: if users already exist, returns current state with AlreadyInitialized=true.
// For session auth see auth.go.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// BootstrapRequest holds credentials and display name for the initial bootstrap.
type BootstrapRequest struct {
	Username    string
	Email       string
	Password    string
	DisplayName string
}

// BootstrapResult is returned after a bootstrap call (first-time or idempotent repeat).
type BootstrapResult struct {
	AlreadyInitialized bool
	User               *models.User
	Namespace          *models.Namespace
	Zone               *models.Zone
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
}

// adminPermissions lists the permission names granted to the admin role.
var adminPermissions = []string{
	"secrets.read", "secrets.write", "secrets.delete",
	"users.read", "users.write", "users.delete",
	"roles.read", "roles.write", "roles.assign",
	"audit.read", "system.read",
}

// viewerPermissions lists the permission names granted to the viewer role.
var viewerPermissions = []string{"secrets.read", "users.read", "audit.read"}

// defaultEnvironmentNames is the ordered list of environment names created on first boot.
var defaultEnvironmentNames = []string{"development", "staging", "production"}

// BootstrapSystem ensures the server has a fully-configured initial state:
//   - admin user (with the supplied credentials)
//   - canonical RBAC roles and permissions (admin, viewer)
//   - default namespace and zone ("default")
//   - three default environments (development, staging, production)
//
// Idempotent: if users already exist, returns the current state with
// AlreadyInitialized=true and performs no writes.
func (c *KeyorixCore) BootstrapSystem(ctx context.Context, req *BootstrapRequest) (*BootstrapResult, error) {
	_, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{Page: 1, PageSize: 1})
	if err != nil {
		return nil, fmt.Errorf("failed to check existing users: %w", err)
	}
	if total > 0 {
		return c.currentBootstrapState(ctx)
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

	adminRole, err := c.storage.CreateRole(ctx, &models.Role{
		Name:        "admin",
		Description: "Administrator with full access",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create admin role: %w", err)
	}
	viewerRole, err := c.storage.CreateRole(ctx, &models.Role{
		Name:        "viewer",
		Description: "Read-only access",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create viewer role: %w", err)
	}

	for _, name := range adminPermissions {
		if err := c.storage.AssignPermissionToRole(ctx, adminRole.ID, permIDs[name]); err != nil {
			return nil, fmt.Errorf("failed to assign permission %s to admin role: %w", name, err)
		}
	}
	for _, name := range viewerPermissions {
		if err := c.storage.AssignPermissionToRole(ctx, viewerRole.ID, permIDs[name]); err != nil {
			return nil, fmt.Errorf("failed to assign permission %s to viewer role: %w", name, err)
		}
	}

	if err := c.storage.AssignRole(ctx, user.ID, adminRole.ID); err != nil {
		return nil, fmt.Errorf("failed to assign admin role to user: %w", err)
	}

	ns, err := c.storage.CreateNamespace(ctx, &models.Namespace{
		Name:        "default",
		Description: "Default namespace",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create default namespace: %w", err)
	}
	zone, err := c.storage.CreateZone(ctx, &models.Zone{
		Name:        "default",
		Description: "Default zone",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create default zone: %w", err)
	}

	envs := make([]*models.Environment, 0, len(defaultEnvironmentNames))
	for _, name := range defaultEnvironmentNames {
		env, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: name})
		if err != nil {
			return nil, fmt.Errorf("failed to create environment %s: %w", name, err)
		}
		envs = append(envs, env)
	}

	return &BootstrapResult{
		AlreadyInitialized: false,
		User:               user,
		Namespace:          ns,
		Zone:               zone,
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

	namespaces, nsErr := c.storage.ListNamespaces(ctx)
	var ns *models.Namespace
	if nsErr == nil && len(namespaces) > 0 {
		ns = namespaces[0]
	}

	zones, zErr := c.storage.ListZones(ctx)
	var zone *models.Zone
	if zErr == nil && len(zones) > 0 {
		zone = zones[0]
	}

	envs, envErr := c.storage.ListEnvironments(ctx)
	if envErr != nil {
		envs = nil
	}

	return &BootstrapResult{
		AlreadyInitialized: true,
		User:               firstUser,
		Namespace:          ns,
		Zone:               zone,
		Environments:       envs,
	}, nil
}
