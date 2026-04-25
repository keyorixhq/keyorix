package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Storage defines the unified interface for data persistence operations
// This interface abstracts away the underlying storage implementation,
// allowing for both local database access and remote API calls
type Storage interface {
	// Namespace / Zone / Environment management
	CreateNamespace(ctx context.Context, namespace *models.Namespace) (*models.Namespace, error)
	CreateZone(ctx context.Context, zone *models.Zone) (*models.Zone, error)
	CreateEnvironment(ctx context.Context, env *models.Environment) (*models.Environment, error)
	ListNamespaces(ctx context.Context) ([]*models.Namespace, error)
	ListZones(ctx context.Context) ([]*models.Zone, error)
	ListEnvironments(ctx context.Context) ([]*models.Environment, error)

	// Secret Management
	CreateSecret(ctx context.Context, secret *models.SecretNode) (*models.SecretNode, error)
	GetSecret(ctx context.Context, id uint) (*models.SecretNode, error)
	GetSecretByName(ctx context.Context, name string, namespaceID, zoneID, environmentID uint) (*models.SecretNode, error)
	UpdateSecret(ctx context.Context, secret *models.SecretNode) (*models.SecretNode, error)
	DeleteSecret(ctx context.Context, id uint) error
	ListSecrets(ctx context.Context, filter *SecretFilter) ([]*models.SecretNode, int64, error)
	GetSecretVersions(ctx context.Context, secretID uint) ([]*models.SecretVersion, error)
	CreateSecretVersion(ctx context.Context, version *models.SecretVersion) (*models.SecretVersion, error)
	GetLatestSecretVersion(ctx context.Context, secretID uint) (*models.SecretVersion, error)
	IncrementSecretReadCount(ctx context.Context, versionID uint) error
	
	// Secret Sharing Management
	CreateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error)
	GetShareRecord(ctx context.Context, shareID uint) (*models.ShareRecord, error)
	UpdateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error)
	DeleteShareRecord(ctx context.Context, shareID uint) error
	ListSharesBySecret(ctx context.Context, secretID uint) ([]*models.ShareRecord, error)
	ListSharesByUser(ctx context.Context, userID uint) ([]*models.ShareRecord, error)
	ListSharesByOwner(ctx context.Context, ownerID uint) ([]*models.ShareRecord, error)
	ListSharesByGroup(ctx context.Context, groupID uint) ([]*models.ShareRecord, error)
	ListSharedSecrets(ctx context.Context, userID uint) ([]*models.SecretNode, error)
	CheckSharePermission(ctx context.Context, secretID, userID uint) (string, error)

	// User Management
	CreateUser(ctx context.Context, user *models.User) (*models.User, error)
	GetUser(ctx context.Context, id uint) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) (*models.User, error)
	DeleteUser(ctx context.Context, id uint) error
	ListUsers(ctx context.Context, filter *UserFilter) ([]*models.User, int64, error)
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	GetUserGroups(ctx context.Context, userID uint) ([]*models.Group, error)

	// Group Management
	CreateGroup(ctx context.Context, group *models.Group) (*models.Group, error)
	GetGroup(ctx context.Context, id uint) (*models.Group, error)
	UpdateGroup(ctx context.Context, group *models.Group) (*models.Group, error)
	DeleteGroup(ctx context.Context, id uint) error
	ListGroups(ctx context.Context) ([]*models.Group, error)
	AddUserToGroup(ctx context.Context, userID, groupID uint) error
	RemoveUserFromGroup(ctx context.Context, userID, groupID uint) error
	ListGroupMembers(ctx context.Context, groupID uint) ([]*models.User, error)

	// Permission Management
	CreatePermission(ctx context.Context, permission *models.Permission) (*models.Permission, error)
	AssignPermissionToRole(ctx context.Context, roleID, permissionID uint) error

	// Role Management
	CreateRole(ctx context.Context, role *models.Role) (*models.Role, error)
	GetRole(ctx context.Context, id uint) (*models.Role, error)
	GetRoleByName(ctx context.Context, name string) (*models.Role, error)
	UpdateRole(ctx context.Context, role *models.Role) (*models.Role, error)
	DeleteRole(ctx context.Context, id uint) error
	ListRoles(ctx context.Context) ([]*models.Role, error)

	// RBAC Operations
	AssignRole(ctx context.Context, userID, roleID uint) error
	RemoveRole(ctx context.Context, userID, roleID uint) error
	GetUserRoles(ctx context.Context, userID uint) ([]*models.Role, error)
	CheckPermission(ctx context.Context, userID uint, resource, action string) (bool, error)
	GetUserPermissions(ctx context.Context, userID uint) ([]*Permission, error)

	// Stats Snapshots
	SaveStatsSnapshot(ctx context.Context, snapshot *models.StatsSnapshot) error
	GetPreviousStatsSnapshot(ctx context.Context, userID uint) (*models.StatsSnapshot, error)

	// Audit Logging
	LogAuditEvent(ctx context.Context, event *models.AuditEvent) error
	CreateSecretAccessLog(ctx context.Context, log *models.SecretAccessLog) error
	ListSecretAccessLogs(ctx context.Context, secretID uint, since time.Time) ([]models.SecretAccessLog, error)
	CreateAnomalyAlert(ctx context.Context, alert *models.AnomalyAlert) error
	ListAnomalyAlerts(ctx context.Context, unacknowledgedOnly bool) ([]models.AnomalyAlert, error)
	AcknowledgeAnomalyAlert(ctx context.Context, id uint) error
	GetAuditLogs(ctx context.Context, filter *AuditFilter) ([]*models.AuditEvent, int64, error)
	GetRBACAuditLogs(ctx context.Context, filter *RBACAuditFilter) ([]*RBACAuditLog, int64, error)

	// Session Management
	CreateSession(ctx context.Context, session *models.Session) (*models.Session, error)
	GetSession(ctx context.Context, token string) (*models.Session, error)
	DeleteSession(ctx context.Context, id uint) error
	CleanupExpiredSessions(ctx context.Context) error

	// API Client Management
	CreateAPIClient(ctx context.Context, client *models.APIClient) (*models.APIClient, error)
	GetAPIClient(ctx context.Context, clientID string) (*models.APIClient, error)
	RevokeAPIClient(ctx context.Context, clientID string) error

	// Health and Maintenance
	HealthCheck(ctx context.Context) error
	GetStats(ctx context.Context) (*StorageStats, error)
}

// SecretFilter defines filtering options for secret queries
type SecretFilter struct {
	NamespaceID   *uint
	ZoneID        *uint
	EnvironmentID *uint
	Type          *string
	Tags          []string
	CreatedBy     *string
	CreatedAfter  *time.Time
	CreatedBefore *time.Time
	Page          int
	PageSize      int
}

// UserFilter defines filtering options for user queries
type UserFilter struct {
	Search       *string // OR match across username and email (LIKE %search%)
	Username     *string
	Email        *string
	IsActive     *bool
	CreatedAfter *time.Time
	Page         int
	PageSize     int
}

// AuditFilter defines filtering options for audit log queries
type AuditFilter struct {
	UserID    *uint
	Action    *string
	Resource  *string
	Success   *bool
	StartTime *time.Time
	EndTime   *time.Time
	Page      int
	PageSize  int
}

// RBACAuditFilter defines filtering options for RBAC audit log queries
type RBACAuditFilter struct {
	UserID     *uint
	Action     *string
	TargetType *string
	TargetID   *uint
	StartTime  *time.Time
	EndTime    *time.Time
	Page       int
	PageSize   int
}

// Permission represents a fine-grained permission
type Permission struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
}

// RBACAuditLog represents an RBAC audit log entry
type RBACAuditLog struct {
	ID         uint      `json:"id"`
	UserID     *uint     `json:"user_id"`
	Username   string    `json:"username"`
	Action     string    `json:"action"`
	TargetType string    `json:"target_type"`
	TargetID   *uint     `json:"target_id"`
	TargetName string    `json:"target_name"`
	Details    string    `json:"details"`
	IPAddress  string    `json:"ip_address"`
	Success    bool      `json:"success"`
	Timestamp  time.Time `json:"timestamp"`
}

// StorageStats provides statistics about the storage system
type StorageStats struct {
	TotalSecrets   int64      `json:"total_secrets"`
	TotalUsers     int64      `json:"total_users"`
	TotalRoles     int64      `json:"total_roles"`
	TotalSessions  int64      `json:"total_sessions"`
	TotalAuditLogs int64      `json:"total_audit_logs"`
	DatabaseSize   int64      `json:"database_size_bytes"`
	LastBackup     *time.Time `json:"last_backup"`
}
