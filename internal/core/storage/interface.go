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
	// Project / Environment management
	CreateProject(ctx context.Context, project *models.Project) (*models.Project, error)
	GetProject(ctx context.Context, id uint) (*models.Project, error)
	UpdateProject(ctx context.Context, project *models.Project) (*models.Project, error)
	DeleteProject(ctx context.Context, id uint) error
	RestoreProject(ctx context.Context, id uint) error
	ListProjects(ctx context.Context) ([]*models.Project, error)
	ListProjectsWithCounts(ctx context.Context, includeDeleted bool) ([]ProjectWithCounts, error)
	CreateEnvironment(ctx context.Context, env *models.Environment) (*models.Environment, error)
	GetEnvironment(ctx context.Context, id uint) (*models.Environment, error)
	DeleteEnvironment(ctx context.Context, id uint) error
	RestoreEnvironment(ctx context.Context, id uint) error
	ListEnvironments(ctx context.Context) ([]*models.Environment, error)
	ListEnvironmentsByProject(ctx context.Context, projectID uint) ([]*models.Environment, error)
	ListEnvironmentsByProjectIncludingDeleted(ctx context.Context, projectID uint) ([]*models.Environment, error)
	ListProjectMembers(ctx context.Context, projectID uint) ([]ProjectMember, error)

	// Project invitations (ADR-024).
	CreateProjectInvitation(ctx context.Context, inv *models.ProjectInvitation) (*models.ProjectInvitation, error)
	GetProjectInvitation(ctx context.Context, id uint) (*models.ProjectInvitation, error)
	UpdateProjectInvitation(ctx context.Context, inv *models.ProjectInvitation) error
	ListProjectInvitations(ctx context.Context, projectID uint) ([]*models.ProjectInvitation, error)

	// Access requests (ADR-024).
	CreateAccessRequest(ctx context.Context, req *models.AccessRequest) (*models.AccessRequest, error)
	GetAccessRequest(ctx context.Context, id uint) (*models.AccessRequest, error)
	UpdateAccessRequest(ctx context.Context, req *models.AccessRequest) error
	ListAccessRequests(ctx context.Context, projectID uint) ([]*models.AccessRequest, error)

	// Secret Management
	CreateSecret(ctx context.Context, secret *models.SecretNode) (*models.SecretNode, error)
	GetSecret(ctx context.Context, id uint) (*models.SecretNode, error)
	GetSecretByName(ctx context.Context, name string, projectID, environmentID uint) (*models.SecretNode, error)
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
	// UpdateLastLogin stamps the user's last_login_at column without touching any
	// other field (no updated_at bump). Called on every successful login.
	UpdateLastLogin(ctx context.Context, userID uint, loginAt time.Time) error
	DeleteUser(ctx context.Context, id uint) error
	RestoreUser(ctx context.Context, id uint) error
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

	// RBAC Operations.
	// AssignRole/RemoveRole bind a role to a user at the given Scope
	// (zero Scope = global). GetUserRoleIDsAt / GetUserGroupRoleIDsAt return the
	// role IDs that apply at a target scope (directly, or via group membership),
	// and RoleSetHasPermission reports whether any of those roles grants a
	// permission. Together they back core.Authorize.
	AssignRole(ctx context.Context, userID, roleID uint, scope Scope) error
	RemoveRole(ctx context.Context, userID, roleID uint, scope Scope) error
	GetUserRoles(ctx context.Context, userID uint) ([]*models.Role, error)
	GetUserRoleIDsAt(ctx context.Context, userID uint, scope Scope) ([]uint, error)
	GetUserRoleIDsExact(ctx context.Context, userID uint, scope Scope) ([]uint, error)
	GetUserGroupRoleIDsAt(ctx context.Context, userID uint, scope Scope) ([]uint, error)
	RoleSetHasPermission(ctx context.Context, roleIDs []uint, permission string) (bool, error)
	CheckPermission(ctx context.Context, userID uint, resource, action string) (bool, error)
	GetUserPermissions(ctx context.Context, userID uint) ([]*Permission, error)

	// Permission queries
	ListPermissions(ctx context.Context) ([]*models.Permission, error)
	GetPermission(ctx context.Context, id uint) (*models.Permission, error)
	GetRolePermissions(ctx context.Context, roleID uint) ([]*models.Permission, error)
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID uint) error

	// Group-Role assignments. Assign/Remove bind a role to a group at the given
	// Scope (zero Scope = global).
	GetGroupRoles(ctx context.Context, groupID uint) ([]*models.Role, error)
	AssignRoleToGroup(ctx context.Context, groupID, roleID uint, scope Scope) error
	RemoveRoleFromGroup(ctx context.Context, groupID, roleID uint, scope Scope) error

	// Stats Snapshots
	SaveStatsSnapshot(ctx context.Context, snapshot *models.StatsSnapshot) error
	GetPreviousStatsSnapshot(ctx context.Context, userID uint) (*models.StatsSnapshot, error)

	// Audit Logging
	LogAuditEvent(ctx context.Context, event *models.AuditEvent) error
	CreateSecretAccessLog(ctx context.Context, log *models.SecretAccessLog) error
	ListSecretAccessLogs(ctx context.Context, secretID uint, since time.Time) ([]models.SecretAccessLog, error)
	CreateAnomalyAlert(ctx context.Context, alert *models.AnomalyAlert) error
	ListAnomalyAlerts(ctx context.Context, acknowledged *bool) ([]models.AnomalyAlert, error)
	AcknowledgeAnomalyAlert(ctx context.Context, id uint) error
	GetAuditLogs(ctx context.Context, filter *AuditFilter) ([]*models.AuditEvent, int64, error)
	GetRBACAuditLogs(ctx context.Context, filter *RBACAuditFilter) ([]*RBACAuditLog, int64, error)
	GetDistinctActiveUserIDs(ctx context.Context, since time.Time) ([]uint, error)
	// CountImpersonatedActions returns the number of impersonated audit events
	// recorded for actingAs by impersonator since `since`, excluding the
	// impersonation.start/impersonation.end markers themselves. Used to report
	// the action count on an impersonation.end event.
	CountImpersonatedActions(ctx context.Context, actingAs, impersonator uint, since time.Time) (int64, error)

	// Session Management
	CreateSession(ctx context.Context, session *models.Session) (*models.Session, error)
	GetSession(ctx context.Context, token string) (*models.Session, error)
	GetSessionByID(ctx context.Context, id uint) (*models.Session, error)
	ListSessionsByUser(ctx context.Context, userID uint) ([]*models.Session, error)
	DeleteSession(ctx context.Context, id uint) error
	// DeleteSessionsForUserExcept removes every session owned by userID except the
	// one with id exceptID. Used to drop other sessions on a password change.
	DeleteSessionsForUserExcept(ctx context.Context, userID, exceptID uint) error
	// TouchSession bumps last_seen_at only when it is older than the given staleness
	// window (no-op otherwise) so the auth hot path is not turned into a write per request.
	TouchSession(ctx context.Context, id uint, seenAt time.Time, staleness time.Duration) error
	CleanupExpiredSessions(ctx context.Context) error

	// Personal Access Token Management (ADR-027) — user-owned bearer credentials.
	CreatePersonalAccessToken(ctx context.Context, t *models.PersonalAccessToken) (*models.PersonalAccessToken, error)
	ListPersonalAccessTokensByUser(ctx context.Context, userID uint) ([]*models.PersonalAccessToken, error)
	GetPersonalAccessTokenByID(ctx context.Context, id uint) (*models.PersonalAccessToken, error)
	GetPersonalAccessTokenByHash(ctx context.Context, hash string) (*models.PersonalAccessToken, error)
	RevokePersonalAccessToken(ctx context.Context, id uint) error
	TouchPersonalAccessToken(ctx context.Context, id uint, usedAt time.Time, staleness time.Duration) error

	// API Client Management
	CreateAPIClient(ctx context.Context, client *models.APIClient) (*models.APIClient, error)
	GetAPIClient(ctx context.Context, clientID string) (*models.APIClient, error)
	RevokeAPIClient(ctx context.Context, clientID string) error
	ListAPIClients(ctx context.Context) ([]*models.APIClient, error)
	UpdateAPIClient(ctx context.Context, client *models.APIClient) (*models.APIClient, error)

	// API Token Management
	CreateAPIToken(ctx context.Context, token *models.APIToken) (*models.APIToken, error)
	GetAPIToken(ctx context.Context, id uint) (*models.APIToken, error)
	ListAPITokens(ctx context.Context, clientID *uint) ([]*models.APIToken, error)
	RevokeAPIToken(ctx context.Context, id uint) error

	// Rotation Policy Management
	CreateRotationPolicy(ctx context.Context, p *models.RotationPolicy) error
	GetRotationPolicy(ctx context.Context, id uint) (*models.RotationPolicy, error)
	ListRotationPolicies(ctx context.Context, projectID *uint, environmentID *uint) ([]*models.RotationPolicy, error)
	UpdateRotationPolicy(ctx context.Context, p *models.RotationPolicy) error
	DeleteRotationPolicy(ctx context.Context, id uint) error

	// Health and Maintenance
	HealthCheck(ctx context.Context) error
	GetStats(ctx context.Context) (*StorageStats, error)
}

// SecretFilter defines filtering options for secret queries
type SecretFilter struct {
	ProjectID     *uint
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
	// InactiveSince, when set, returns only users who have not logged in since the
	// given time — i.e. last_login_at IS NULL OR last_login_at < InactiveSince.
	InactiveSince  *time.Time
	IncludeDeleted bool // when true, also return soft-deleted users
	Page           int
	PageSize       int
}

// AuditFilter defines filtering options for audit log queries
type AuditFilter struct {
	ProjectID *uint
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

// Scope identifies the project/environment a role assignment or an
// authorization check applies to. It uses a 0 = global/unspecified sentinel,
// matching the stored user_roles/group_roles columns:
//
//	{0, 0}  global — every project and environment
//	{P, 0}  all environments in project P
//	{P, E}  only environment E of project P
//
// A stored assignment authorizes a target scope when its project is global or
// equal AND its environment is global or equal (see GetUserRoleIDsAt).
type Scope struct {
	ProjectID     uint
	EnvironmentID uint
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

// ProjectWithCounts is returned by ListProjectsWithCounts, adding aggregate
// counts so the frontend project list page can show secret/env totals.
type ProjectWithCounts struct {
	ID               uint   `json:"ID"`
	Name             string `json:"Name"`
	Description      string `json:"Description"`
	SecretCount      int64  `json:"secret_count"`
	EnvironmentCount int64  `json:"environment_count"`
	LastActivity     string `json:"last_activity,omitempty"` // most recent of project update or any secret change
	Deleted          bool   `json:"deleted"`                 // true when soft-deleted (only returned when includeDeleted)
	DeletedAt        string `json:"deleted_at,omitempty"`    // RFC3339 timestamp when soft-deleted
}

// ProjectMember is a user who holds a role at a project's scope (ADR-021).
type ProjectMember struct {
	UserID      uint   `json:"user_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	RoleID      uint   `json:"role_id"`
	RoleName    string `json:"role_name"`
}
