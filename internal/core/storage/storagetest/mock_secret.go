package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) CreateSecretDependency(ctx context.Context, d *models.SecretDependency) (*models.SecretDependency, error) {
	args := m.Called(ctx, d)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretDependency), args.Error(1)
}

func (m *MockStorage) GetSecretDependency(ctx context.Context, id uint) (*models.SecretDependency, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretDependency), args.Error(1)
}

func (m *MockStorage) ListSecretDependenciesForProject(ctx context.Context, projectID uint) ([]*models.SecretDependency, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.SecretDependency), args.Error(1)
}

// ListSecretDependenciesForProjectForUpdate has no row lock in the mock; it
// reuses the ListSecretDependenciesForProject expectation, mirroring
// LockUserForUpdate above.
func (m *MockStorage) ListSecretDependenciesForProjectForUpdate(ctx context.Context, projectID uint) ([]*models.SecretDependency, error) {
	return m.ListSecretDependenciesForProject(ctx, projectID)
}

func (m *MockStorage) DeleteSecretDependency(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) CreateSecretDependencyExclusive(ctx context.Context, d *models.SecretDependency) (*models.SecretDependency, error) {
	a := m.Called(ctx, d)
	v, _ := a.Get(0).(*models.SecretDependency)
	return v, a.Error(1)
}

// CreateSecret ignores the optional plaintextValue variadic (#499) — it is not
// forwarded to m.Called, so existing `.On("CreateSecret", ctx, secret)`
// expectations (2 args) keep matching regardless of what core passes.
func (m *MockStorage) CreateSecret(ctx context.Context, secret *models.SecretNode, _ ...string) (*models.SecretNode, error) {
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

func (m *MockStorage) GetSecretsByIDs(ctx context.Context, ids []uint) ([]*models.SecretNode, error) {
	args := m.Called(ctx, ids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.SecretNode), args.Error(1)
}

func (m *MockStorage) GetUsernamesByIDs(ctx context.Context, ids []uint) (map[uint]string, error) {
	return m.mockNameMap("GetUsernamesByIDs", ctx, ids)
}

func (m *MockStorage) GetUserBriefsByIDs(ctx context.Context, ids []uint) (map[uint]storage.UserBrief, error) {
	args := m.Called(ctx, ids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]storage.UserBrief), args.Error(1)
}

func (m *MockStorage) GetGroupNamesByIDs(ctx context.Context, ids []uint) (map[uint]string, error) {
	return m.mockNameMap("GetGroupNamesByIDs", ctx, ids)
}

func (m *MockStorage) GetMachineIdentityNamesByIDs(ctx context.Context, ids []uint) (map[uint]string, error) {
	return m.mockNameMap("GetMachineIdentityNamesByIDs", ctx, ids)
}

func (m *MockStorage) GetSecretTagsBySecretIDs(ctx context.Context, ids []uint) (map[uint][]string, error) {
	args := m.Called(ctx, ids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint][]string), args.Error(1)
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

func (m *MockStorage) UpdateSecretFields(ctx context.Context, id uint, f storage.SecretFieldUpdate) (bool, error) {
	args := m.Called(ctx, id, f)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) TransitionSecretStatus(ctx context.Context, secret *models.SecretNode, fromStatus string) (bool, error) {
	args := m.Called(ctx, secret, fromStatus)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) UpdateSecretRotationConfig(ctx context.Context, secret *models.SecretNode, fromBackend string) (bool, error) {
	args := m.Called(ctx, secret, fromBackend)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) DeleteSecret(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) RestoreSecret(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) GetSecretIncludingDeleted(ctx context.Context, id uint) (*models.SecretNode, error) {
	if !m.mockHasExpectation("GetSecretIncludingDeleted") {
		return nil, errMockLookupNotStubbed
	}
	a := m.Called(ctx, id)
	v, _ := a.Get(0).(*models.SecretNode)
	return v, a.Error(1)
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

func (m *MockStorage) CountOrphanedSecretsByProject(ctx context.Context, projectIDs []uint) (map[uint]int, error) {
	args := m.Called(ctx, projectIDs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]int), args.Error(1)
}

func (m *MockStorage) CountExpiringSecretsByProject(ctx context.Context, projectIDs []uint, expiresBefore time.Time) (map[uint]int, error) {
	args := m.Called(ctx, projectIDs, expiresBefore)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]int), args.Error(1)
}

func (m *MockStorage) CountSecretsByEnvironment(ctx context.Context, envIDs []uint) (map[uint]int64, error) {
	args := m.Called(ctx, envIDs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]int64), args.Error(1)
}

func (m *MockStorage) ListLiveSecretNamesByProject(ctx context.Context, projectIDs []uint, limit int) ([]storage.SecretNameRow, bool, error) {
	args := m.Called(ctx, projectIDs, limit)
	if args.Get(0) == nil {
		return nil, args.Bool(1), args.Error(2)
	}
	return args.Get(0).([]storage.SecretNameRow), args.Bool(1), args.Error(2)
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

func (m *MockStorage) SetSecretCertNotAfter(ctx context.Context, secretID uint, notAfter *time.Time) error {
	return m.Called(ctx, secretID, notAfter).Error(0)
}

func (m *MockStorage) SetRetentionOverride(ctx context.Context, secretID uint, days int) error {
	return m.Called(ctx, secretID, days).Error(0)
}

func (m *MockStorage) IncrementSecretReadCount(ctx context.Context, versionID uint) error {
	args := m.Called(ctx, versionID)
	return args.Error(0)
}

func (m *MockStorage) TryIncrementSecretReadCount(ctx context.Context, versionID uint, maxReads int) (bool, error) {
	args := m.Called(ctx, versionID, maxReads)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) TryIncrementSecretNodeReadCount(ctx context.Context, secretID uint, maxReads int) (bool, error) {
	args := m.Called(ctx, secretID, maxReads)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) ListSecretsWithQuota(ctx context.Context) ([]models.SecretNode, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.SecretNode), args.Error(1)
}

// Temporal access schedule — stubs return no schedule (nil, nil) by default,
// which enforces no restriction (fail-open on the check side).
func (m *MockStorage) GetSecretAccessSchedule(_ context.Context, _ uint) (*models.SecretAccessSchedule, error) {
	return nil, nil
}
func (m *MockStorage) SetSecretAccessSchedule(_ context.Context, _ *models.SecretAccessSchedule) error {
	return nil
}
func (m *MockStorage) DeleteSecretAccessSchedule(_ context.Context, _ uint) error {
	return nil
}

// GetSecretScheduleAndLatestVersion (PERF-FIX-4) is composed from the mock's own
// GetSecretAccessSchedule and GetLatestSecretVersion, so a test that stubs those
// two (On("GetLatestSecretVersion", …)) drives the combined read unchanged: the
// schedule error is the call's error, the version error is LatestVersionErr.
func (m *MockStorage) GetSecretScheduleAndLatestVersion(ctx context.Context, secretNodeID uint) (*storage.SecretScheduleAndLatestVersion, error) {
	sched, err := m.GetSecretAccessSchedule(ctx, secretNodeID)
	if err != nil {
		return nil, err
	}
	version, verr := m.GetLatestSecretVersion(ctx, secretNodeID)
	return &storage.SecretScheduleAndLatestVersion{Schedule: sched, LatestVersion: version, LatestVersionErr: verr}, nil
}

func (m *MockStorage) CreateSecretVersionComment(ctx context.Context, c *models.SecretVersionComment) error {
	args := m.Called(ctx, c)
	return args.Error(0)
}

func (m *MockStorage) ListSecretVersionComments(ctx context.Context, secretID, versionID uint) ([]models.SecretVersionComment, error) {
	args := m.Called(ctx, secretID, versionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.SecretVersionComment), args.Error(1)
}

func (m *MockStorage) DeleteSecretVersionComment(ctx context.Context, secretID, versionID, id uint) error {
	args := m.Called(ctx, secretID, versionID, id)
	return args.Error(0)
}
