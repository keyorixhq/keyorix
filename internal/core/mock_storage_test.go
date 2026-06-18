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

// WithSchedulerLock runs fn directly in tests (single instance, no DB lock).
func (m *MockStorage) WithSchedulerLock(_ context.Context, _ int64, fn func() error) (bool, error) {
	return true, fn()
}

// Login rate-limiting stubs (core rate-limit logic is tested against real SQLite).
func (m *MockStorage) RecordLoginAttempt(_ context.Context, _ string, _ time.Time) error { return nil }
func (m *MockStorage) CountRecentLoginAttempts(_ context.Context, _ string, _ time.Time) (int64, error) {
	return 0, nil
}
func (m *MockStorage) PruneLoginAttempts(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
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

func (m *MockStorage) ListEnvironmentsByProject(ctx context.Context, projectID uint) ([]*models.Environment, error) {
	if len(m.ExpectedCalls) == 0 {
		return nil, nil
	}
	for _, c := range m.ExpectedCalls {
		if c.Method == "ListEnvironmentsByProject" {
			args := m.Called(ctx, projectID)
			if args.Get(0) == nil {
				return nil, args.Error(1)
			}
			return args.Get(0).([]*models.Environment), args.Error(1)
		}
	}
	return nil, nil
}

func (m *MockStorage) ListEnvironmentsByProjectIncludingDeleted(_ context.Context, _ uint) ([]*models.Environment, error) {
	return nil, nil
}

func (m *MockStorage) ListProjectMembers(_ context.Context, _ uint) ([]storage.ProjectMember, error) {
	return nil, nil
}

func (m *MockStorage) ListProjectRoleAssignments(ctx context.Context, projectID uint) ([]storage.RoleAssignment, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.RoleAssignment), args.Error(1)
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

func (m *MockStorage) CreateAccessRequestApproval(ctx context.Context, a *models.AccessRequestApproval) error {
	args := m.Called(ctx, a)
	return args.Error(0)
}

func (m *MockStorage) ListAccessRequestApprovals(ctx context.Context, requestID uint) ([]*models.AccessRequestApproval, error) {
	args := m.Called(ctx, requestID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.AccessRequestApproval), args.Error(1)
}

func (m *MockStorage) CreateAccessReviewCampaign(ctx context.Context, c *models.AccessReviewCampaign) (*models.AccessReviewCampaign, error) {
	args := m.Called(ctx, c)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AccessReviewCampaign), args.Error(1)
}

func (m *MockStorage) GetAccessReviewCampaign(ctx context.Context, id uint) (*models.AccessReviewCampaign, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AccessReviewCampaign), args.Error(1)
}

func (m *MockStorage) ListAccessReviewCampaigns(ctx context.Context, projectID uint) ([]*models.AccessReviewCampaign, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.AccessReviewCampaign), args.Error(1)
}

func (m *MockStorage) UpdateAccessReviewCampaign(ctx context.Context, c *models.AccessReviewCampaign) error {
	args := m.Called(ctx, c)
	return args.Error(0)
}

func (m *MockStorage) CreateAccessReviewItems(ctx context.Context, items []*models.AccessReviewItem) error {
	args := m.Called(ctx, items)
	return args.Error(0)
}

func (m *MockStorage) ListAccessReviewItems(ctx context.Context, campaignID uint) ([]*models.AccessReviewItem, error) {
	args := m.Called(ctx, campaignID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.AccessReviewItem), args.Error(1)
}

func (m *MockStorage) GetAccessReviewItem(ctx context.Context, id uint) (*models.AccessReviewItem, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AccessReviewItem), args.Error(1)
}

func (m *MockStorage) UpdateAccessReviewItem(ctx context.Context, item *models.AccessReviewItem) error {
	args := m.Called(ctx, item)
	return args.Error(0)
}

func (m *MockStorage) LastUserSecretActivity(ctx context.Context, projectID uint) (map[uint]time.Time, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]time.Time), args.Error(1)
}

func (m *MockStorage) CreateSoDPolicy(ctx context.Context, p *models.SoDPolicy) (*models.SoDPolicy, error) {
	args := m.Called(ctx, p)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SoDPolicy), args.Error(1)
}

func (m *MockStorage) GetSoDPolicy(ctx context.Context, id uint) (*models.SoDPolicy, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SoDPolicy), args.Error(1)
}

func (m *MockStorage) ListSoDPolicies(ctx context.Context) ([]*models.SoDPolicy, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.SoDPolicy), args.Error(1)
}

func (m *MockStorage) DeleteSoDPolicy(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockStorage) CreateLegalHold(ctx context.Context, h *models.LegalHold) (*models.LegalHold, error) {
	args := m.Called(ctx, h)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.LegalHold), args.Error(1)
}

func (m *MockStorage) GetActiveLegalHold(ctx context.Context) (*models.LegalHold, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.LegalHold), args.Error(1)
}

func (m *MockStorage) UpdateLegalHold(ctx context.Context, h *models.LegalHold) error {
	args := m.Called(ctx, h)
	return args.Error(0)
}

func (m *MockStorage) CreateRiskException(ctx context.Context, e *models.RiskException) (*models.RiskException, error) {
	args := m.Called(ctx, e)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RiskException), args.Error(1)
}

func (m *MockStorage) ListRiskExceptions(ctx context.Context, activeOnly bool) ([]*models.RiskException, error) {
	args := m.Called(ctx, activeOnly)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.RiskException), args.Error(1)
}

func (m *MockStorage) GetRiskException(ctx context.Context, id uint) (*models.RiskException, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RiskException), args.Error(1)
}

func (m *MockStorage) UpdateRiskException(ctx context.Context, e *models.RiskException) error {
	args := m.Called(ctx, e)
	return args.Error(0)
}

func (m *MockStorage) CreateSSOLoginState(ctx context.Context, s *models.SSOLoginState) error {
	args := m.Called(ctx, s)
	return args.Error(0)
}

func (m *MockStorage) ConsumeSSOLoginState(ctx context.Context, state string) (*models.SSOLoginState, error) {
	args := m.Called(ctx, state)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SSOLoginState), args.Error(1)
}

func (m *MockStorage) CreateBreakGlassActivation(ctx context.Context, a *models.BreakGlassActivation) (*models.BreakGlassActivation, error) {
	args := m.Called(ctx, a)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.BreakGlassActivation), args.Error(1)
}

func (m *MockStorage) GetBreakGlassActivation(ctx context.Context, id uint) (*models.BreakGlassActivation, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.BreakGlassActivation), args.Error(1)
}

func (m *MockStorage) ListBreakGlassActivations(ctx context.Context, projectID uint) ([]*models.BreakGlassActivation, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.BreakGlassActivation), args.Error(1)
}

func (m *MockStorage) UpdateBreakGlassActivation(ctx context.Context, a *models.BreakGlassActivation) error {
	args := m.Called(ctx, a)
	return args.Error(0)
}

func (m *MockStorage) GetEnvironment(_ context.Context, id uint) (*models.Environment, error) {
	return &models.Environment{ID: id, ProjectID: 1, Name: "test"}, nil
}

func (m *MockStorage) DeleteEnvironment(_ context.Context, _ uint) error {
	return nil
}

func (m *MockStorage) RestoreEnvironment(_ context.Context, _, _ uint) error {
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

func (m *MockStorage) RestoreSecret(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockStorage) GetSecretIncludingDeleted(ctx context.Context, id uint) (*models.SecretNode, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretNode), args.Error(1)
}

func (m *MockStorage) PurgeDeletedSecretsBefore(ctx context.Context, before time.Time) (int64, error) {
	args := m.Called(ctx, before)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockStorage) DeleteAnomalyAlertsBefore(ctx context.Context, before time.Time) (int64, error) {
	args := m.Called(ctx, before)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockStorage) DeleteClosedAccessReviewsBefore(ctx context.Context, before time.Time) (int64, int64, error) {
	args := m.Called(ctx, before)
	return args.Get(0).(int64), args.Get(1).(int64), args.Error(2)
}

func (m *MockStorage) DeleteExpiredBreakGlassBefore(ctx context.Context, before time.Time) (int64, error) {
	args := m.Called(ctx, before)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockStorage) DeleteResolvedAccessRequestsBefore(ctx context.Context, before time.Time) (int64, int64, error) {
	args := m.Called(ctx, before)
	return args.Get(0).(int64), args.Get(1).(int64), args.Error(2)
}

func (m *MockStorage) ListSecrets(ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*models.SecretNode), args.Get(1).(int64), args.Error(2)
}

func (m *MockStorage) ListOrphanedSecrets(ctx context.Context, projectID uint) ([]*models.SecretNode, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.SecretNode), args.Error(1)
}

func (m *MockStorage) ListProjectSecretsForDrift(ctx context.Context, projectID uint) ([]storage.DriftSecretRow, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.DriftSecretRow), args.Error(1)
}

func (m *MockStorage) GetSecretTags(ctx context.Context, secretID uint) ([]string, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockStorage) SetSecretTags(ctx context.Context, secretID uint, tagNames []string) error {
	args := m.Called(ctx, secretID, tagNames)
	return args.Error(0)
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

func (m *MockStorage) DeleteExpiredShareRecords(ctx context.Context, before time.Time) ([]*models.ShareRecord, error) {
	args := m.Called(ctx, before)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ShareRecord), args.Error(1)
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

func (m *MockStorage) PurgeDeletedUsersBefore(ctx context.Context, before time.Time) (int64, error) {
	args := m.Called(ctx, before)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockStorage) PurgeDeletedProjectsBefore(ctx context.Context, before time.Time) (int64, error) {
	args := m.Called(ctx, before)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockStorage) PurgeDeletedEnvironmentsBefore(ctx context.Context, before time.Time) (int64, error) {
	args := m.Called(ctx, before)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockStorage) ListUsers(ctx context.Context, filter *storage.UserFilter) ([]*models.User, int64, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*models.User), args.Get(1).(int64), args.Error(2)
}

func (m *MockStorage) ListUsersInStateBefore(ctx context.Context, state string, before time.Time) ([]*models.User, error) {
	args := m.Called(ctx, state, before)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.User), args.Error(1)
}

func (m *MockStorage) CreateUserWithRoleGrants(ctx context.Context, user *models.User, grants []storage.RoleGrant) (*models.User, error) {
	args := m.Called(ctx, user, grants)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockStorage) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockStorage) GetUserByExternalID(ctx context.Context, externalID string) (*models.User, error) {
	args := m.Called(ctx, externalID)
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

func (m *MockStorage) AddPasswordHistory(ctx context.Context, userID uint, hash string, at time.Time) error {
	args := m.Called(ctx, userID, hash, at)
	return args.Error(0)
}

func (m *MockStorage) RecentPasswordHashes(ctx context.Context, userID uint, limit int) ([]string, error) {
	args := m.Called(ctx, userID, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockStorage) PrunePasswordHistory(ctx context.Context, userID uint, keep int) error {
	args := m.Called(ctx, userID, keep)
	return args.Error(0)
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

func (m *MockStorage) AssignRoleWithExpiry(ctx context.Context, userID, roleID uint, scope storage.Scope, expiresAt time.Time) error {
	args := m.Called(ctx, userID, roleID, scope, expiresAt)
	return args.Error(0)
}

func (m *MockStorage) RemoveRole(ctx context.Context, userID, roleID uint, scope storage.Scope) error {
	args := m.Called(ctx, userID, roleID, scope)
	return args.Error(0)
}

func (m *MockStorage) AssignRoleToGroupWithExpiry(ctx context.Context, groupID, roleID uint, scope storage.Scope, expiresAt time.Time) error {
	args := m.Called(ctx, groupID, roleID, scope, expiresAt)
	return args.Error(0)
}

func (m *MockStorage) DeleteExpiredRoleGrants(ctx context.Context, before time.Time) ([]storage.RoleAssignment, error) {
	args := m.Called(ctx, before)
	if v := args.Get(0); v != nil {
		return v.([]storage.RoleAssignment), args.Error(1)
	}
	return nil, args.Error(1)
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

func (m *MockStorage) MostAccessedSecrets(ctx context.Context, projectID *uint, since time.Time, limit int) ([]storage.SecretUsageStat, error) {
	args := m.Called(ctx, projectID, since, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.SecretUsageStat), args.Error(1)
}

func (m *MockStorage) AuditRetentionStats(ctx context.Context) (*storage.AuditRetentionStats, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.AuditRetentionStats), args.Error(1)
}

func (m *MockStorage) VerifyAuditChain(ctx context.Context) (*storage.AuditChainVerification, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.AuditChainVerification), args.Error(1)
}

func (m *MockStorage) CreateAuditCheckpoint(ctx context.Context, cp *models.AuditCheckpoint) error {
	args := m.Called(ctx, cp)
	return args.Error(0)
}

func (m *MockStorage) LatestAuditCheckpoint(ctx context.Context) (*models.AuditCheckpoint, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AuditCheckpoint), args.Error(1)
}

func (m *MockStorage) UpdateAuditCheckpointAnchor(ctx context.Context, id uint, token []byte, anchoredAt time.Time, provider string) error {
	args := m.Called(ctx, id, token, anchoredAt, provider)
	return args.Error(0)
}

func (m *MockStorage) AuditEntryHashByID(ctx context.Context, id uint) (string, bool, error) {
	args := m.Called(ctx, id)
	return args.String(0), args.Bool(1), args.Error(2)
}

func (m *MockStorage) UnusedSecrets(ctx context.Context, projectID *uint, notReadSince time.Time) ([]storage.UnusedSecretStat, error) {
	args := m.Called(ctx, projectID, notReadSince)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.UnusedSecretStat), args.Error(1)
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

func (m *MockStorage) ListUnalertedAnomalyAlerts(ctx context.Context) ([]models.AnomalyAlert, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.AnomalyAlert), args.Error(1)
}

func (m *MockStorage) MarkAnomalyAlertAlerted(ctx context.Context, id uint) error {
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

func (m *MockStorage) ListActivePersonalAccessTokens(ctx context.Context) ([]*models.PersonalAccessToken, error) {
	args := m.Called(ctx)
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

// Setup Token Management (ADR-028)

func (m *MockStorage) CreateSetupToken(ctx context.Context, t *models.SetupToken) (*models.SetupToken, error) {
	args := m.Called(ctx, t)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SetupToken), args.Error(1)
}

func (m *MockStorage) GetSetupTokenByHash(ctx context.Context, hash string) (*models.SetupToken, error) {
	args := m.Called(ctx, hash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SetupToken), args.Error(1)
}

func (m *MockStorage) SupersedeActiveSetupTokens(ctx context.Context, purpose, email string) error {
	args := m.Called(ctx, purpose, email)
	return args.Error(0)
}

func (m *MockStorage) MarkSetupTokenConsumed(ctx context.Context, id uint, consumedAt time.Time) (bool, error) {
	args := m.Called(ctx, id, consumedAt)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) MarkSetupTokenExpired(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockStorage) CountSetupTokensSince(ctx context.Context, purpose, email string, since time.Time) (int64, error) {
	args := m.Called(ctx, purpose, email, since)
	return args.Get(0).(int64), args.Error(1)
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

func (m *MockStorage) CountImpersonatedActions(_ context.Context, actingAs, impersonator uint, since time.Time) (int64, error) {
	args := m.Called(actingAs, impersonator, since)
	return args.Get(0).(int64), args.Error(1)
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

// Keyorix Connect per-reference grants (ADR-045) — core enforcement is tested against
// real SQLite, so these mock stubs just satisfy the interface.
func (m *MockStorage) ListConnectRefGrantsByConnector(_ context.Context, _ string) ([]*models.ConnectRefGrant, error) {
	return nil, nil
}
func (m *MockStorage) ListConnectRefGrants(_ context.Context) ([]*models.ConnectRefGrant, error) {
	return nil, nil
}
func (m *MockStorage) CreateConnectRefGrant(_ context.Context, grant *models.ConnectRefGrant) (*models.ConnectRefGrant, error) {
	return grant, nil
}
func (m *MockStorage) DeleteConnectRefGrant(_ context.Context, _ uint) error {
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

func (m *MockStorage) ListRotationPolicies(ctx context.Context, projectID *uint, environmentID *uint) ([]*models.RotationPolicy, error) {
	args := m.Called(ctx, projectID, environmentID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.RotationPolicy), args.Error(1)
}

func (m *MockStorage) UpdateRotationPolicy(_ context.Context, _ *models.RotationPolicy) error {
	return nil
}

func (m *MockStorage) DeleteRotationPolicy(_ context.Context, _ uint) error {
	return nil
}

// Machine identities (ADR-023).
func (m *MockStorage) CreateMachineIdentity(ctx context.Context, mi *models.MachineIdentity) (*models.MachineIdentity, error) {
	args := m.Called(ctx, mi)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentity), args.Error(1)
}

func (m *MockStorage) GetMachineIdentity(ctx context.Context, id uint) (*models.MachineIdentity, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentity), args.Error(1)
}

func (m *MockStorage) UpdateMachineIdentity(ctx context.Context, mi *models.MachineIdentity) error {
	args := m.Called(ctx, mi)
	return args.Error(0)
}

func (m *MockStorage) ListMachineIdentities(ctx context.Context, projectID uint) ([]*models.MachineIdentity, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.MachineIdentity), args.Error(1)
}

func (m *MockStorage) CountMachineIdentitiesByClassification(ctx context.Context) (map[string]int, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]int), args.Error(1)
}

func (m *MockStorage) CreateMachineIdentityCredential(ctx context.Context, c *models.MachineIdentityCredential) (*models.MachineIdentityCredential, error) {
	args := m.Called(ctx, c)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentityCredential), args.Error(1)
}

func (m *MockStorage) GetMachineIdentityCredentialByHash(ctx context.Context, hash string) (*models.MachineIdentityCredential, error) {
	args := m.Called(ctx, hash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentityCredential), args.Error(1)
}

func (m *MockStorage) GetMachineIdentityCredentialByID(ctx context.Context, id uint) (*models.MachineIdentityCredential, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentityCredential), args.Error(1)
}

func (m *MockStorage) ListMachineIdentityCredentials(ctx context.Context, machineID uint) ([]*models.MachineIdentityCredential, error) {
	args := m.Called(ctx, machineID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.MachineIdentityCredential), args.Error(1)
}

func (m *MockStorage) UpdateMachineIdentityCredential(ctx context.Context, c *models.MachineIdentityCredential) error {
	args := m.Called(ctx, c)
	return args.Error(0)
}

func (m *MockStorage) CountMachineIdentityCredentialsByClassification(ctx context.Context) (map[string]int, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]int), args.Error(1)
}

func (m *MockStorage) RevokeMachineIdentityCredential(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockStorage) TouchMachineIdentityCredential(ctx context.Context, id uint, usedAt time.Time, staleness time.Duration) error {
	// Best-effort on the auth hot path — tolerate tests that don't set an expectation.
	for _, c := range m.ExpectedCalls {
		if c.Method == "TouchMachineIdentityCredential" {
			return m.Called(ctx, id, usedAt, staleness).Error(0)
		}
	}
	return nil
}

func (m *MockStorage) AssignMachineRole(ctx context.Context, machineID, roleID uint, scope storage.Scope) error {
	args := m.Called(ctx, machineID, roleID, scope)
	return args.Error(0)
}

func (m *MockStorage) RemoveMachineRole(ctx context.Context, machineID, roleID uint, scope storage.Scope) error {
	args := m.Called(ctx, machineID, roleID, scope)
	return args.Error(0)
}

func (m *MockStorage) GetMachineRoleIDsAt(ctx context.Context, machineID uint, scope storage.Scope) ([]uint, error) {
	args := m.Called(ctx, machineID, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uint), args.Error(1)
}

func (m *MockStorage) GetMachineRoles(ctx context.Context, machineID uint) ([]*models.Role, error) {
	args := m.Called(ctx, machineID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Role), args.Error(1)
}

func (m *MockStorage) CreateOIDCBinding(ctx context.Context, b *models.MachineIdentityOIDCBinding) (*models.MachineIdentityOIDCBinding, error) {
	args := m.Called(ctx, b)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentityOIDCBinding), args.Error(1)
}

func (m *MockStorage) GetMachineByOIDCSubject(ctx context.Context, issuer, subject string) (*models.MachineIdentity, error) {
	args := m.Called(ctx, issuer, subject)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentity), args.Error(1)
}

func (m *MockStorage) ListOIDCBindings(ctx context.Context, machineID uint) ([]*models.MachineIdentityOIDCBinding, error) {
	args := m.Called(ctx, machineID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.MachineIdentityOIDCBinding), args.Error(1)
}

func (m *MockStorage) GetOIDCBindingByID(ctx context.Context, id uint) (*models.MachineIdentityOIDCBinding, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MachineIdentityOIDCBinding), args.Error(1)
}

func (m *MockStorage) DeleteOIDCBinding(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// Project membership lifecycle (ADR-022).
func (m *MockStorage) CreateProjectMembership(ctx context.Context, pm *models.ProjectMembership) (*models.ProjectMembership, error) {
	args := m.Called(ctx, pm)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ProjectMembership), args.Error(1)
}

func (m *MockStorage) GetProjectMembership(ctx context.Context, id uint) (*models.ProjectMembership, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ProjectMembership), args.Error(1)
}

func (m *MockStorage) UpdateProjectMembership(ctx context.Context, pm *models.ProjectMembership) error {
	args := m.Called(ctx, pm)
	return args.Error(0)
}

func (m *MockStorage) ListProjectMemberships(ctx context.Context, projectID uint) ([]*models.ProjectMembership, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ProjectMembership), args.Error(1)
}

func (m *MockStorage) GetActiveProjectMembership(ctx context.Context, projectID, userID uint) (*models.ProjectMembership, error) {
	args := m.Called(ctx, projectID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ProjectMembership), args.Error(1)
}

func (m *MockStorage) ListStaleInvitedMemberships(ctx context.Context, before time.Time) ([]*models.ProjectMembership, error) {
	args := m.Called(ctx, before)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ProjectMembership), args.Error(1)
}

func (m *MockStorage) ListUserProjectMemberships(ctx context.Context, userID uint) ([]*models.ProjectMembership, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ProjectMembership), args.Error(1)
}

func (m *MockStorage) CountProjectMembershipsByUsers(ctx context.Context, userIDs []uint) (map[uint]storage.MembershipCounts, error) {
	args := m.Called(ctx, userIDs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]storage.MembershipCounts), args.Error(1)
}

func (m *MockStorage) CreateNotification(ctx context.Context, n *models.Notification) (*models.Notification, error) {
	args := m.Called(ctx, n)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Notification), args.Error(1)
}

func (m *MockStorage) ListNotifications(ctx context.Context, userID uint, unreadOnly bool, limit int) ([]*models.Notification, error) {
	args := m.Called(ctx, userID, unreadOnly, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Notification), args.Error(1)
}

func (m *MockStorage) CountUnreadNotifications(ctx context.Context, userID uint) (int64, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockStorage) MarkNotificationRead(ctx context.Context, id, userID uint) error {
	return m.Called(ctx, id, userID).Error(0)
}

func (m *MockStorage) MarkAllNotificationsRead(ctx context.Context, userID uint) error {
	return m.Called(ctx, userID).Error(0)
}

// MFA stubs (MFA core logic is tested against real SQLite, not this mock).
func (m *MockStorage) UpsertMFASecret(_ context.Context, _ *models.MFASecret) error { return nil }
func (m *MockStorage) GetMFASecret(_ context.Context, _ uint) (*models.MFASecret, error) {
	return nil, nil
}
func (m *MockStorage) ActivateMFASecret(_ context.Context, _ uint) error         { return nil }
func (m *MockStorage) DeleteMFAForUser(_ context.Context, _ uint) error          { return nil }
func (m *MockStorage) SetUserMFAEnabled(_ context.Context, _ uint, _ bool) error { return nil }
func (m *MockStorage) CreateMFARecoveryCodes(_ context.Context, _ uint, _ []string) error {
	return nil
}
func (m *MockStorage) ConsumeMFARecoveryCode(_ context.Context, _ uint, _ string, _ time.Time) (bool, error) {
	return false, nil
}
func (m *MockStorage) CountUnusedMFARecoveryCodes(_ context.Context, _ uint) (int, error) {
	return 0, nil
}
func (m *MockStorage) DeleteMFARecoveryCodes(_ context.Context, _ uint) error             { return nil }
func (m *MockStorage) CreateMFAChallenge(_ context.Context, _ *models.MFAChallenge) error { return nil }
func (m *MockStorage) ConsumeMFAChallenge(_ context.Context, _ string, _ time.Time) (*models.MFAChallenge, error) {
	return nil, nil
}

// Dynamic-secrets stubs (the dynamic-secrets core logic is tested against real
// SQLite + a fake engine, not this mock).
func (m *MockStorage) CreateDynamicSecretConfig(_ context.Context, c *models.DynamicSecretConfig) (*models.DynamicSecretConfig, error) {
	return c, nil
}
func (m *MockStorage) GetDynamicSecretConfig(_ context.Context, _ uint) (*models.DynamicSecretConfig, error) {
	return nil, nil
}
func (m *MockStorage) ListDynamicSecretConfigs(_ context.Context, _, _ uint) ([]*models.DynamicSecretConfig, error) {
	return nil, nil
}
func (m *MockStorage) UpdateDynamicSecretConfig(_ context.Context, _ *models.DynamicSecretConfig) error {
	return nil
}
func (m *MockStorage) CountDynamicSecretConfigsByClassification(_ context.Context) (map[string]int, error) {
	return nil, nil
}
func (m *MockStorage) CreateDynamicSecretLease(_ context.Context, l *models.DynamicSecretLease) (*models.DynamicSecretLease, error) {
	return l, nil
}
func (m *MockStorage) GetDynamicSecretLease(_ context.Context, _ string) (*models.DynamicSecretLease, error) {
	return nil, nil
}
func (m *MockStorage) ListDynamicSecretLeases(_ context.Context, _ uint) ([]*models.DynamicSecretLease, error) {
	return nil, nil
}
func (m *MockStorage) UpdateDynamicSecretLease(_ context.Context, _ *models.DynamicSecretLease) error {
	return nil
}
func (m *MockStorage) ListExpiredActiveLeases(_ context.Context, _ time.Time) ([]*models.DynamicSecretLease, error) {
	return nil, nil
}

// WebAuthn stubs (the WebAuthn core logic is tested against real SQLite, not this mock).
func (m *MockStorage) GetActiveMFAChallenge(_ context.Context, _ string, _ time.Time) (*models.MFAChallenge, error) {
	return nil, nil
}
func (m *MockStorage) CreateWebAuthnCredential(_ context.Context, _ *models.WebAuthnCredential) error {
	return nil
}
func (m *MockStorage) ListWebAuthnCredentials(_ context.Context, _ uint) ([]*models.WebAuthnCredential, error) {
	return nil, nil
}
func (m *MockStorage) GetWebAuthnCredentialByCredID(_ context.Context, _ []byte) (*models.WebAuthnCredential, error) {
	return nil, nil
}
func (m *MockStorage) UpdateWebAuthnCredential(_ context.Context, _ *models.WebAuthnCredential) error {
	return nil
}
func (m *MockStorage) DeleteWebAuthnCredential(_ context.Context, _, _ uint) error { return nil }
func (m *MockStorage) CountWebAuthnCredentials(_ context.Context, _ uint) (int64, error) {
	return 0, nil
}
func (m *MockStorage) SetUserWebAuthnEnabled(_ context.Context, _ uint, _ bool) error { return nil }
func (m *MockStorage) CreateWebAuthnSession(_ context.Context, _ *models.WebAuthnSession) error {
	return nil
}
func (m *MockStorage) ConsumeWebAuthnSession(_ context.Context, _ string, _ time.Time) (*models.WebAuthnSession, error) {
	return nil, nil
}
