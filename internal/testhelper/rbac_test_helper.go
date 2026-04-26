package testhelper

import (
	"context"
	"database/sql"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/local"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// RBACTestHelper provides consistent test setup for RBAC tests
type RBACTestHelper struct {
	CoreService *core.KeyorixCore
	DB          *gorm.DB
	SqlDB       *sql.DB
	Storage     *local.LocalStorage
}

// NewRBACTestHelper creates a new test helper with in-memory database and core service
func NewRBACTestHelper(t *testing.T) *RBACTestHelper {
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	// Create an in-memory database for testing
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Get underlying SQL DB for raw queries if needed
	sqlDB, err := db.DB()
	require.NoError(t, err)

	// Auto-migrate the schema with all RBAC tables
	err = db.AutoMigrate(
		&models.User{},
		&models.Role{},
		&models.UserRole{},
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
		&models.Namespace{},
		&models.Zone{},
		&models.Environment{},
		&models.SecretNode{},
		&models.ShareRecord{},
	)
	require.NoError(t, err)

	// Create storage and core service
	storage := local.NewLocalStorage(db)
	coreService := core.NewKeyorixCore(storage)

	helper := &RBACTestHelper{
		CoreService: coreService,
		DB:          db,
		SqlDB:       sqlDB,
		Storage:     storage,
	}

	// Seed basic test data
	helper.seedTestData(t)

	return helper
}

// seedTestData creates basic test data for RBAC tests
func (h *RBACTestHelper) seedTestData(t *testing.T) {
	// Create default namespaces
	namespaces := []models.Namespace{
		{ID: 1, Name: "default", Description: "Default namespace"},
		{ID: 2, Name: "production", Description: "Production namespace"},
		{ID: 3, Name: "staging", Description: "Staging namespace"},
	}
	for _, ns := range namespaces {
		result := h.DB.Create(&ns)
		require.NoError(t, result.Error)
	}

	// Create default zones
	zones := []models.Zone{
		{ID: 1, Name: "global", Description: "Global zone"},
		{ID: 2, Name: "us-east-1", Description: "US East 1 zone"},
	}
	for _, zone := range zones {
		result := h.DB.Create(&zone)
		require.NoError(t, result.Error)
	}

	// Create default environments
	environments := []models.Environment{
		{ID: 1, Name: "production"},
		{ID: 2, Name: "staging"},
		{ID: 3, Name: "development"},
	}
	for _, env := range environments {
		result := h.DB.Create(&env)
		require.NoError(t, result.Error)
	}

	// Create default roles using raw SQL to match migration structure
	roles := []struct {
		ID          uint
		Name        string
		Description string
	}{
		{1, "super_admin", "Super Administrator with full system access"},
		{2, "admin", "Administrator with full access to assigned namespaces"},
		{3, "editor", "Can create, read, update secrets in assigned namespaces"},
		{4, "viewer", "Read-only access to secrets in assigned namespaces"},
		{5, "auditor", "Can view audit logs and system information"},
	}

	for _, role := range roles {
		h.SqlDB.Exec("INSERT OR IGNORE INTO roles (id, name, description) VALUES (?, ?, ?)",
			role.ID, role.Name, role.Description)
	}

	// Create default permissions using raw SQL
	permissions := []struct {
		ID          uint
		Name        string
		Description string
		Resource    string
		Action      string
	}{
		{1, "secrets.read", "Read secrets", "secrets", "read"},
		{2, "secrets.write", "Create and update secrets", "secrets", "write"},
		{3, "secrets.delete", "Delete secrets", "secrets", "delete"},
		{4, "secrets.admin", "Full administrative access to secrets", "secrets", "admin"},
		{5, "users.read", "View user information", "users", "read"},
		{6, "users.write", "Create and update users", "users", "write"},
		{7, "users.delete", "Delete users", "users", "delete"},
		{8, "users.admin", "Full administrative access to users", "users", "admin"},
		{9, "roles.read", "View roles", "roles", "read"},
		{10, "roles.write", "Create and update roles", "roles", "write"},
		{11, "roles.delete", "Delete roles", "roles", "delete"},
		{12, "roles.admin", "Full administrative access to roles", "roles", "admin"},
		{13, "roles.assign", "Assign and remove roles from users", "roles", "assign"},
		{14, "system.read", "View system information", "system", "read"},
		{15, "system.write", "Modify system settings", "system", "write"},
		{16, "system.admin", "Full administrative access to system", "system", "admin"},
		{17, "audit.read", "View audit logs", "audit", "read"},
		{18, "audit.admin", "Full administrative access to audit system", "audit", "admin"},
	}

	// Create permissions table if it doesn't exist
	h.SqlDB.Exec(`CREATE TABLE IF NOT EXISTS permissions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		description TEXT,
		resource TEXT NOT NULL,
		action TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)

	// Create role_permissions table if it doesn't exist
	h.SqlDB.Exec(`CREATE TABLE IF NOT EXISTS role_permissions (
		role_id INTEGER NOT NULL,
		permission_id INTEGER NOT NULL,
		PRIMARY KEY (role_id, permission_id)
	)`)

	for _, perm := range permissions {
		h.SqlDB.Exec("INSERT OR IGNORE INTO permissions (id, name, description, resource, action) VALUES (?, ?, ?, ?, ?)",
			perm.ID, perm.Name, perm.Description, perm.Resource, perm.Action)
	}

	// Assign permissions to roles
	rolePermissions := map[string][]string{
		"super_admin": {"secrets.read", "secrets.write", "secrets.delete", "secrets.admin",
			"users.read", "users.write", "users.delete", "users.admin",
			"roles.read", "roles.write", "roles.delete", "roles.admin", "roles.assign",
			"system.read", "system.write", "system.admin",
			"audit.read", "audit.admin"},
		"admin": {"secrets.read", "secrets.write", "secrets.delete",
			"users.read", "users.write",
			"roles.read", "roles.assign",
			"system.read", "audit.read"},
		"editor":  {"secrets.read", "secrets.write", "users.read"},
		"viewer":  {"secrets.read", "users.read"},
		"auditor": {"audit.read", "audit.admin", "system.read", "users.read", "roles.read"},
	}

	for roleName, permNames := range rolePermissions {
		for _, permName := range permNames {
			h.SqlDB.Exec(`INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
				SELECT r.id, p.id FROM roles r, permissions p 
				WHERE r.name = ? AND p.name = ?`, roleName, permName)
		}
	}
}

// CreateTestUser creates a test user in the database
func (h *RBACTestHelper) CreateTestUser(t *testing.T, username string, userID uint) *models.User {
	user := &models.User{
		ID:       userID,
		Username: username,
		Email:    username + "@test.com",
	}

	result := h.DB.Create(user)
	require.NoError(t, result.Error)

	return user
}

// CreateTestRole creates a test role in the database
func (h *RBACTestHelper) CreateTestRole(t *testing.T, name, description string, roleID uint) *models.Role {
	role := &models.Role{
		ID:          roleID,
		Name:        name,
		Description: description,
	}

	result := h.DB.Create(role)
	require.NoError(t, result.Error)

	return role
}

// CreateTestGroup creates a test group in the database
func (h *RBACTestHelper) CreateTestGroup(t *testing.T, name, description string, groupID uint) *models.Group {
	group := &models.Group{
		ID:          groupID,
		Name:        name,
		Description: description,
	}

	result := h.DB.Create(group)
	require.NoError(t, result.Error)

	return group
}

// AssignUserRole assigns a role to a user
func (h *RBACTestHelper) AssignUserRole(t *testing.T, userID, roleID uint, namespaceID *uint) {
	userRole := &models.UserRole{
		UserID:      userID,
		RoleID:      roleID,
		NamespaceID: namespaceID,
	}

	result := h.DB.Create(userRole)
	require.NoError(t, result.Error)
}

// AssignUserToGroup assigns a user to a group
func (h *RBACTestHelper) AssignUserToGroup(t *testing.T, userID, groupID uint) {
	userGroup := &models.UserGroup{
		UserID:  userID,
		GroupID: groupID,
	}

	result := h.DB.Create(userGroup)
	require.NoError(t, result.Error)
}

// AssignGroupRole assigns a role to a group
func (h *RBACTestHelper) AssignGroupRole(t *testing.T, groupID, roleID uint, namespaceID *uint) {
	groupRole := &models.GroupRole{
		GroupID:     groupID,
		RoleID:      roleID,
		NamespaceID: namespaceID,
	}

	result := h.DB.Create(groupRole)
	require.NoError(t, result.Error)
}

// CreateTestSecret creates a test secret in the database
func (h *RBACTestHelper) CreateTestSecret(t *testing.T, name string, ownerID uint, secretID uint) *models.SecretNode {
	secret := &models.SecretNode{
		ID:            secretID,
		NamespaceID:   1, // default namespace
		ZoneID:        1, // global zone
		EnvironmentID: 1, // production environment
		Name:          name,
		IsSecret:      true,
		Type:          "text",
		OwnerID:       ownerID,
		CreatedBy:     "test",
		Status:        "active",
	}

	result := h.DB.Create(secret)
	require.NoError(t, result.Error)

	return secret
}

// GetUserRoles returns all roles assigned to a user
func (h *RBACTestHelper) GetUserRoles(t *testing.T, userID uint) []models.Role {
	var roles []models.Role
	result := h.DB.Table("roles").
		Joins("JOIN user_roles ON roles.id = user_roles.role_id").
		Where("user_roles.user_id = ?", userID).
		Find(&roles)
	require.NoError(t, result.Error)
	return roles
}

// GetUserPermissions returns all permissions for a user (direct and through groups)
func (h *RBACTestHelper) GetUserPermissions(t *testing.T, userID uint) []string {
	var permissions []string

	// Get direct permissions through user roles
	rows, err := h.SqlDB.Query(`
		SELECT DISTINCT p.name 
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN user_roles ur ON rp.role_id = ur.role_id
		WHERE ur.user_id = ?
	`, userID)
	require.NoError(t, err)
	defer rows.Close()

	for rows.Next() {
		var permission string
		err := rows.Scan(&permission)
		require.NoError(t, err)
		permissions = append(permissions, permission)
	}

	// Get permissions through group roles
	rows, err = h.SqlDB.Query(`
		SELECT DISTINCT p.name 
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN group_roles gr ON rp.role_id = gr.role_id
		JOIN user_groups ug ON gr.group_id = ug.group_id
		WHERE ug.user_id = ?
	`, userID)
	require.NoError(t, err)
	defer rows.Close()

	for rows.Next() {
		var permission string
		err := rows.Scan(&permission)
		require.NoError(t, err)
		permissions = append(permissions, permission)
	}

	return permissions
}

// HasPermission checks if a user has a specific permission
func (h *RBACTestHelper) HasPermission(t *testing.T, userID uint, permission string) bool {
	permissions := h.GetUserPermissions(t, userID)
	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// CreateTestContext creates a context with user information for testing
func (h *RBACTestHelper) CreateTestContext(userID uint, username string) context.Context {
	ctx := context.Background()
	// Add user context information that the core service expects
	ctx = context.WithValue(ctx, "user_id", userID)
	ctx = context.WithValue(ctx, "username", username)
	return ctx
}

// Cleanup cleans up test resources
func (h *RBACTestHelper) Cleanup() {
	if h.SqlDB != nil {
		h.SqlDB.Close()
	}
}

// ExecuteRawSQL executes raw SQL for complex test scenarios
func (h *RBACTestHelper) ExecuteRawSQL(t *testing.T, query string, args ...interface{}) {
	_, err := h.SqlDB.Exec(query, args...)
	require.NoError(t, err)
}

// QueryRawSQL executes a raw SQL query and returns results
func (h *RBACTestHelper) QueryRawSQL(t *testing.T, query string, args ...interface{}) *sql.Rows {
	rows, err := h.SqlDB.Query(query, args...)
	require.NoError(t, err)
	return rows
}
