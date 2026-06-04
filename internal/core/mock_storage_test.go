package core

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
)

// MockStorage is a complete mock implementation of the Storage interface for testing
type MockStorage struct {
	mock.Mock
}

// Permission Management

func (m *MockStorage) CreatePermission(_ context.Context, permission *models.Permission) (*models.Permission, error) {
	return permission, nil
}

func (m *MockStorage) AssignPermissionToRole(_ context.Context, _, _ uint) error {
	return nil
}

// Project / Environment

func (m *MockStorage) CreateProject(_ context.Context, project *models.Project) (*models.Project, error) {
	return project, nil
}

func (m *MockStorage) CreateEnvironment(_ context.Context, env *models.Environment) (*models.Environment, error) {
	return env, nil
}

func (m *MockStorage) ListProjects(_ context.Context) ([]*models.Project, error) {
	return nil, nil
}

func (m *MockStorage) ListProjectsWithCounts(_ context.Context, _ bool) ([]storage.ProjectWithCounts, error) {
	return nil, nil
}

func (m *MockStorage) GetProject(_ context.Context, id uint) (*models.Project, error) {
	return &models.Project{}, nil
}

func (m *MockStorage) UpdateProject(_ context.Context, project *models.Project) (*models.Project, error) {
	return project, nil
}

func (m *MockStorage) DeleteProject(_ context.Context, _ uint) error {
	return nil
}

func (m *MockStorage) RestoreProject(_ context.Context, _ uint) error {
	return nil
}

func (m *MockStorage) ListEnvironments(_ context.Context) ([]*models.Environment, error) {
	return nil, nil
}

func (m *MockStorage) ListEnvironmentsByProject(_ context.Context, _ uint) ([]*models.Environment, error) {
	return nil, nil
}

func (m *MockStorage) ListEnvironmentsByProjectIncludingDeleted(_ context.Context, _ uint) ([]*models.Environment, error) {
	return nil, nil
}

func (m *MockStorage) ListProjectMembers(_ context.Context, _ uint) ([]storage.ProjectMember, error) {
	return nil, nil
}

func (m *MockStorage) CreateProjectInvitation(ctx context.Context, inv *models.ProjectInvitation) (*models.ProjectInvitation, error) {
	args := m.Called(ctx, inv)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ProjectInvitation), args.Error(1)
}

func (m *MockStorage) GetProjectInvitation(ctx context.Context, id uint) (*models.ProjectInvitation, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ProjectInvitation), args.Error(1)
}

func (m *MockStorage) UpdateProjectInvitation(ctx context.Context, inv *models.ProjectInvitation) error {
	args := m.Called(ctx, inv)
	return args.Error(0)
}

func (m *MockStorage) ListProjectInvitations(ctx context.Context, projectID uint) ([]*models.ProjectInvitation, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ProjectInvitation), args.Error(1)
}

func (m *MockStorage) CreateAccessRequest(ctx context.Context, req *models.AccessRequest) (*models.AccessRequest, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AccessRequest), args.Error(1)
}

func (m *MockStorage) GetAccessRequest(ctx context.Context, id uint) (*models.AccessRequest, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AccessRequest), args.Error(1)
}

func (m *MockStorage) UpdateAccessRequest(ctx context.Context, req *models.AccessRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockStorage) ListAccessRequests(ctx context.Context, projectID uint) ([]*models.AccessRequest, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.AccessRequest), args.Error(1)
}

func (m *MockStorage) GetEnvironment(_ context.Context, id uint) (*models.Environment, error) {
	return &models.Environment{ID: id, ProjectID: 1, Name: "test"}, nil
}

func (m *MockStorage) DeleteEnvironment(_ context.Context, _ uint) error {
	return nil
}

func (m *MockStorage) RestoreEnvironment(_ context.Context, _ uint) error {
	return nil
}

// Secret Management

func (m *MockStorage) CreateSecret(ctx context.Context, secret *models.SecretNode) (*models.SecretNode, error) {
	args := m.Called(ctx, secret)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretNode), args.Error(1)
}

func (m *MockStorage) GetSecret(ctx context.Context, id uint) (*models.SecretNode, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretNode), args.Error(1)
}

func (m *MockStorage) GetSecretByName(ctx context.Context, name string, projectID, environmentID uint) (*models.SecretNode, error) {
	args := m.Called(ctx, name, projectID, environmentID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretNode), args.Error(1)
}

func (m *MockStorage) UpdateSecret(ctx context.Context, secret *models.SecretNode) (*models.SecretNode, error) {
	args := m.Called(ctx, secret)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretNode), args.Error(1)
}

func (m *MockStorage) DeleteSecret(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockStorage) ListSecrets(ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*models.SecretNode), args.Get(1).(int64), args.Error(2)
}

func (m *MockStorage) GetSecretVersions(ctx context.Context, secretID uint) ([]*models.SecretVersion, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.SecretVersion), args.Error(1)
}

func (m *MockStorage) CreateSecretVersion(ctx context.Context, version *models.SecretVersion) (*models.SecretVersion, error) {
	args := m.Called(ctx, version)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretVersion), args.Error(1)
}

func (m *MockStorage) GetLatestSecretVersion(ctx context.Context, secretID uint) (*models.SecretVersion, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretVersion), args.Error(1)
}

func (m *MockStorage) IncrementSecretReadCount(ctx context.Context, versionID uint) error {
	args := m.Called(ctx, versionID)
	return args.Error(0)
}

// Secret Sharing Management

func (m *MockStorage) CreateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error) {
	args := m.Called(ctx, share)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ShareRecord), args.Error(1)
}

func (m *MockStorage) GetShareRecord(ctx context.Context, shareID uint) (*models.ShareRecord, error) {
	args := m.Called(ctx, shareID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ShareRecord), args.Error(1)
}

func (m *MockStorage) UpdateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error) {
	args := m.Called(ctx, share)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ShareRecord), args.Error(1)
}

func (m *MockStorage) DeleteShareRecord(ctx context.Context, shareID uint) error {
	args := m.Called(ctx, shareID)
	return args.Error(0)
}

func (m *MockStorage) ListSharesBySecret(ctx context.Context, secretID uint) ([]*models.ShareRecord, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ShareRecord), args.Error(1)
}

func (m *MockStorage) ListSharesByUser(ctx context.Context, userID uint) ([]*models.ShareRecord, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ShareRecord), args.Error(1)
}

func (m *MockStorage) ListSharesByOwner(ctx context.Context, ownerID uint) ([]*models.ShareRecord, error) {
	args := m.Called(ctx, ownerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ShareRecord), args.Error(1)
}

func (m *MockStorage) ListSharesByGroup(ctx context.Context, groupID uint) ([]*models.ShareRecord, error) {
	args := m.Called(ctx, groupID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ShareRecord), args.Error(1)
}

func (m *MockStorage) ListSharedSecrets(ctx context.Context, userID uint) ([]*models.SecretNode, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.SecretNode), args.Error(1)
}

func (m *MockStorage) CheckSharePermission(ctx context.Context, secretID, userID uint) (string, error) {
	args := m.Called(ctx, secretID, userID)
	return args.String(0), args.Error(1)
}

// User Management

func (m *MockStorage) CreateUser(ctx context.Context, user *models.User) (*models.User, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockStorage) GetUser(ctx context.Context, id uint) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockStorage) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockStorage) UpdateUser(ctx context.Context, user *models.User) (*models.User, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockStorage) UpdateLastLogin(ctx context.Context, userID uint, loginAt time.Time) error {
	args := m.Called(ctx, userID, loginAt)
	return args.Error(0)
}

func (m *MockStorage) DeleteUser(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockStorage) RestoreUser(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockStorage) ListUsers(ctx context.Context, filter *storage.UserFilter) ([]*models.User, int64, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*models.User), args.Get(1).(int64), args.Error(2)
}

func (m *MockStorage) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockStorage) GetUserGroups(ctx context.Context, userID uint) ([]*models.Group, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Group), args.Error(1)
}

func (m *MockStorage) CreateGroup(ctx context.Context, group *models.Group) (*models.Group, error) {
	args := m.Called(ctx, group)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Group), args.Error(1)
}

func (m *MockStorage) GetGroup(ctx context.Context, id uint) (*models.Group, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Group), args.Error(1)
}

func (m *MockStorage) UpdateGroup(ctx context.Context, group *models.Group) (*models.Group, error) {
	args := m.Called(ctx, group)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Group), args.Error(1)
}

func (m *MockStorage) DeleteGroup(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockStorage) ListGroups(ctx context.Context) ([]*models.Group, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Group), args.Error(1)
}

func (m *MockStorage) AddUserToGroup(ctx context.Context, userID, groupID uint) error {
	args := m.Called(ctx, userID, groupID)
	return args.Error(0)
}

func (m *MockStorage) RemoveUserFromGroup(ctx context.Context, userID, groupID uint) error {
	args := m.Called(ctx, userID, groupID)
	return args.Error(0)
}

func (m *MockStorage) ListGroupMembers(ctx context.Context, groupID uint) ([]*models.User, error) {
	args := m.Called(ctx, groupID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.User), args.Error(1)
}

// Role Management

func (m *MockStorage) CreateRole(ctx context.Context, role *models.Role) (*models.Role, error) {
	args := m.Called(ctx, role)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *MockStorage) GetRole(ctx context.Context, id uint) (*models.Role, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *MockStorage) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *MockStorage) UpdateRole(ctx context.Context, role *models.Role) (*models.Role, error) {
	args := m.Called(ctx, role)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Role), args.Error(1)
}

func (m *MockStorage) DeleteRole(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockStorage) ListRoles(ctx context.Context) ([]*models.Role, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Role), args.Error(1)
}

// RBAC Operations

func (m *MockStorage) AssignRole(ctx context.Context, userID, roleID uint, scope storage.Scope) error {
	args := m.Called(ctx, userID, roleID, scope)
	return args.Error(0)
}

func (m *MockStorage) RemoveRole(ctx context.Context, userID, roleID uint, scope storage.Scope) error {
	args := m.Called(ctx, userID, roleID, scope)
	return args.Error(0)
}

func (m *MockStorage) GetUserRoles(ctx context.Context, userID uint) ([]*models.Role, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Role), args.Error(1)
}

func (m *MockStorage) GetUserRoleIDsAt(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	args := m.Called(ctx, userID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uint), args.Error(1)
}

func (m *MockStorage) GetUserRoleIDsExact(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	args := m.Called(ctx, userID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uint), args.Error(1)
}

func (m *MockStorage) GetUserGroupRoleIDsAt(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	args := m.Called(ctx, userID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uint), args.Error(1)
}

func (m *MockStorage) RoleSetHasPermission(ctx context.Context, roleIDs []uint, permission string) (bool, error) {
	args := m.Called(ctx, roleIDs, permission)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) CheckPermission(ctx context.Context, userID uint, resource, action string) (bool, error) {
	args := m.Called(ctx, userID, resource, action)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) GetUserPermissions(ctx context.Context, userID uint) ([]*storage.Permission, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*storage.Permission), args.Error(1)
}

// Audit Logging

func (m *MockStorage) LogAuditEvent(ctx context.Context, event *models.AuditEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

func (m *MockStorage) CreateSecretAccessLog(ctx context.Context, log *models.SecretAccessLog) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

func (m *MockStorage) ListSecretAccessLogs(ctx context.Context, secretID uint, since time.Time) ([]models.SecretAccessLog, error) {
	args := m.Called(ctx, secretID, since)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.SecretAccessLog), args.Error(1)
}

func (m *MockStorage) CreateAnomalyAlert(ctx context.Context, alert *models.AnomalyAlert) error {
	args := m.Called(ctx, alert)
	return args.Error(0)
}

func (m *MockStorage) ListAnomalyAlerts(ctx context.Context, acknowledged *bool) ([]models.AnomalyAlert, error) {
	args := m.Called(ctx, acknowledged)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.AnomalyAlert), args.Error(1)
}

func (m *MockStorage) AcknowledgeAnomalyAlert(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockStorage) GetAuditLogs(ctx context.Context, filter *storage.AuditFilter) ([]*models.AuditEvent, int64, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*models.AuditEvent), args.Get(1).(int64), args.Error(2)
}

func (m *MockStorage) GetRBACAuditLogs(ctx context.Context, filter *storage.RBACAuditFilter) ([]*storage.RBACAuditLog, int64, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*storage.RBACAuditLog), args.Get(1).(int64), args.Error(2)
}

// Session Management

func (m *MockStorage) CreateSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	args := m.Called(ctx, session)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Session), args.Error(1)
}

func (m *MockStorage) GetSession(ctx context.Context, token string) (*models.Session, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Session), args.Error(1)
}

func (m *MockStorage) DeleteSession(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockStorage) CleanupExpiredSessions(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockStorage) GetSessionByID(ctx context.Context, id uint) (*models.Session, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Session), args.Error(1)
}

func (m *MockStorage) ListSessionsByUser(ctx context.Context, userID uint) ([]*models.Session, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Session), args.Error(1)
}

func (m *MockStorage) DeleteSessionsForUserExcept(ctx context.Context, userID, exceptID uint) error {
	args := m.Called(ctx, userID, exceptID)
	return args.Error(0)
}

func (m *MockStorage) TouchSession(ctx context.Context, id uint, seenAt time.Time, staleness time.Duration) error {
	args := m.Called(ctx, id, seenAt, staleness)
	return args.Error(0)
}

// Personal Access Token Management

func (m *MockStorage) CreatePersonalAccessToken(ctx context.Context, t *models.PersonalAccessToken) (*models.PersonalAccessToken, error) {
	args := m.Called(ctx, t)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.PersonalAccessToken), args.Error(1)
}

func (m *MockStorage) ListPersonalAccessTokensByUser(ctx context.Context, userID uint) ([]*models.PersonalAccessToken, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.PersonalAccessToken), args.Error(1)
}

func (m *MockStorage) GetPersonalAccessTokenByID(ctx context.Context, id uint) (*models.PersonalAccessToken, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.PersonalAccessToken), args.Error(1)
}

func (m *MockStorage) GetPersonalAccessTokenByHash(ctx context.Context, hash string) (*models.PersonalAccessToken, error) {
	args := m.Called(ctx, hash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.PersonalAccessToken), args.Error(1)
}

func (m *MockStorage) RevokePersonalAccessToken(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockStorage) TouchPersonalAccessToken(ctx context.Context, id uint, usedAt time.Time, staleness time.Duration) error {
	args := m.Called(ctx, id, usedAt, staleness)
	return args.Error(0)
}

// API Client Management

func (m *MockStorage) CreateAPIClient(ctx context.Context, client *models.APIClient) (*models.APIClient, error) {
	args := m.Called(ctx, client)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.APIClient), args.Error(1)
}

func (m *MockStorage) GetAPIClient(ctx context.Context, clientID string) (*models.APIClient, error) {
	args := m.Called(ctx, clientID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.APIClient), args.Error(1)
}

func (m *MockStorage) RevokeAPIClient(ctx context.Context, clientID string) error {
	args := m.Called(ctx, clientID)
	return args.Error(0)
}

func (m *MockStorage) ListAPIClients(_ context.Context) ([]*models.APIClient, error) {
	return nil, nil
}

func (m *MockStorage) UpdateAPIClient(_ context.Context, client *models.APIClient) (*models.APIClient, error) {
	return client, nil
}

// API Token Management

func (m *MockStorage) CreateAPIToken(_ context.Context, token *models.APIToken) (*models.APIToken, error) {
	return token, nil
}

func (m *MockStorage) GetAPIToken(_ context.Context, id uint) (*models.APIToken, error) {
	return &models.APIToken{ID: id}, nil
}

func (m *MockStorage) ListAPITokens(_ context.Context, _ *uint) ([]*models.APIToken, error) {
	return nil, nil
}

func (m *MockStorage) RevokeAPIToken(_ context.Context, _ uint) error {
	return nil
}

// Health and Maintenance

func (m *MockStorage) HealthCheck(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockStorage) GetStats(ctx context.Context) (*storage.StorageStats, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.StorageStats), args.Error(1)
}

func (m *MockStorage) SaveStatsSnapshot(ctx context.Context, snapshot *models.StatsSnapshot) error {
	args := m.Called(ctx, snapshot)
	return args.Error(0)
}

func (m *MockStorage) GetPreviousStatsSnapshot(ctx context.Context, userID uint) (*models.StatsSnapshot, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.StatsSnapshot), args.Error(1)
}

func (m *MockStorage) GetDistinctActiveUserIDs(_ context.Context, _ time.Time) ([]uint, error) {
	return nil, nil
}

// Permission queries

func (m *MockStorage) ListPermissions(_ context.Context) ([]*models.Permission, error) {
	return nil, nil
}

func (m *MockStorage) GetPermission(_ context.Context, id uint) (*models.Permission, error) {
	return &models.Permission{ID: id}, nil
}

func (m *MockStorage) GetRolePermissions(_ context.Context, _ uint) ([]*models.Permission, error) {
	return nil, nil
}

func (m *MockStorage) RemovePermissionFromRole(_ context.Context, _, _ uint) error {
	return nil
}

// Group-Role assignments

func (m *MockStorage) GetGroupRoles(_ context.Context, _ uint) ([]*models.Role, error) {
	return nil, nil
}

func (m *MockStorage) AssignRoleToGroup(_ context.Context, _, _ uint, _ storage.Scope) error {
	return nil
}

func (m *MockStorage) RemoveRoleFromGroup(_ context.Context, _, _ uint, _ storage.Scope) error {
	return nil
}

// Rotation Policy Management

func (m *MockStorage) CreateRotationPolicy(_ context.Context, _ *models.RotationPolicy) error {
	return nil
}

func (m *MockStorage) GetRotationPolicy(_ context.Context, id uint) (*models.RotationPolicy, error) {
	return &models.RotationPolicy{ID: id}, nil
}

func (m *MockStorage) ListRotationPolicies(_ context.Context, _ *uint, _ *uint) ([]*models.RotationPolicy, error) {
	return nil, nil
}

func (m *MockStorage) UpdateRotationPolicy(_ context.Context, _ *models.RotationPolicy) error {
	return nil
}

func (m *MockStorage) DeleteRotationPolicy(_ context.Context, _ uint) error {
	return nil
}
