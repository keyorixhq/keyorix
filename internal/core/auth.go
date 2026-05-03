package core

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"golang.org/x/crypto/bcrypt"
)

// LoginRequest holds credentials for login.
type LoginRequest struct {
	Username string
	Password string
}

// Login validates credentials, creates a session, and returns (session, user, error).
func (c *KeyorixCore) Login(ctx context.Context, req *LoginRequest) (*models.Session, *models.User, error) {
	user, err := c.storage.GetUserByUsername(ctx, req.Username)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, nil, fmt.Errorf("invalid credentials")
	}
	token, err := generateSecureToken()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate session token: %w", err)
	}
	expiresAt := c.now().Add(24 * time.Hour)
	session := &models.Session{
		UserID:       user.ID,
		SessionToken: token,
		ExpiresAt:    &expiresAt,
	}
	created, err := c.storage.CreateSession(ctx, session)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create session: %w", err)
	}
	return created, user, nil
}

// Logout invalidates the session identified by token.
func (c *KeyorixCore) Logout(ctx context.Context, token string) error {
	session, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return fmt.Errorf("session not found")
	}
	return c.storage.DeleteSession(ctx, session.ID)
}

// RefreshSession replaces an existing session with a new token.
func (c *KeyorixCore) RefreshSession(ctx context.Context, token string) (*models.Session, error) {
	old, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("session not found or expired")
	}
	newToken, err := generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	expiresAt := c.now().Add(24 * time.Hour)
	session := &models.Session{
		UserID:       old.UserID,
		SessionToken: newToken,
		ExpiresAt:    &expiresAt,
	}
	created, err := c.storage.CreateSession(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	_ = c.storage.DeleteSession(ctx, old.ID)
	return created, nil
}

// ValidateSessionToken looks up a session token, checks expiry, and returns the user and
// their role names. Used by the auth middleware to authenticate real session tokens.
func (c *KeyorixCore) ValidateSessionToken(ctx context.Context, token string) (*models.User, []string, error) {
	session, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return nil, nil, fmt.Errorf("session not found")
	}
	if session.ExpiresAt != nil && c.now().After(*session.ExpiresAt) {
		return nil, nil, fmt.Errorf("session expired")
	}
	user, err := c.storage.GetUser(ctx, session.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("user not found")
	}
	roles, err := c.storage.GetUserRoles(ctx, user.ID)
	if err != nil {
		return user, []string{}, nil
	}
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}
	return user, roleNames, nil
}

// RequestPasswordReset initiates a password reset for the given email (best-effort, no error on unknown email).
func (c *KeyorixCore) RequestPasswordReset(ctx context.Context, email string) error {
	_, err := c.storage.GetUserByEmail(ctx, email)
	if err != nil {
		return nil // Don't reveal whether the email exists.
	}
	// TODO: send reset email
	return nil
}

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
// Idempotent: if users already exist, returns the current bootstrap state with
// AlreadyInitialized=true and performs no writes.
func (c *KeyorixCore) BootstrapSystem(ctx context.Context, req *BootstrapRequest) (*BootstrapResult, error) {
	// ── Idempotency check ────────────────────────────────────────────────────
	_, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{Page: 1, PageSize: 1})
	if err != nil {
		return nil, fmt.Errorf("failed to check existing users: %w", err)
	}
	if total > 0 {
		return c.currentBootstrapState(ctx)
	}

	// ── Admin user ───────────────────────────────────────────────────────────
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

	// ── Permissions ──────────────────────────────────────────────────────────
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

	// ── Roles ────────────────────────────────────────────────────────────────
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

	// ── Role → permission assignments ────────────────────────────────────────
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

	// ── Admin user → admin role ──────────────────────────────────────────────
	if err := c.storage.AssignRole(ctx, user.ID, adminRole.ID); err != nil {
		return nil, fmt.Errorf("failed to assign admin role to user: %w", err)
	}

	// ── Default namespace and zone ───────────────────────────────────────────
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

	// ── Default environments ──────────────────────────────────────────────────
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

// currentBootstrapState returns an idempotent BootstrapResult for a system that
// has already been initialised. Best-effort: partial results are acceptable since
// the caller only uses this for display output, not for writes.
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

// generateSecureToken creates a cryptographically random hex token.
func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}
