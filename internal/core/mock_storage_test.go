package core

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
)

// MockStorage is a complete mock implementation of the Storage interface for testing
type MockStorage struct {
	mock.Mock
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

func (m *MockStorage) GetSecretByName(ctx context.Context, name string, namespaceID, zoneID, environmentID uint) (*models.SecretNode, error) {
	args := m.Called(ctx, name, namespaceID, zoneID, environmentID)
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

func (m *MockStorage) DeleteUser(ctx context.Context, id uint) error {
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

func (m *MockStorage) GetUserGroups(ctx context.Context, userID uint) ([]*models.Group, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Group), args.Error(1)
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

func (m *MockStorage) AssignRole(ctx context.Context, userID, roleID uint) error {
	args := m.Called(ctx, userID, roleID)
	return args.Error(0)
}

func (m *MockStorage) RemoveRole(ctx context.Context, userID, roleID uint) error {
	args := m.Called(ctx, userID, roleID)
	return args.Error(0)
}

func (m *MockStorage) GetUserRoles(ctx context.Context, userID uint) ([]*models.Role, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Role), args.Error(1)
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