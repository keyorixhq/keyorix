package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) GetSystemMetadata(ctx context.Context, key string) (string, bool, error) {
	args := m.Called(ctx, key)
	return args.String(0), args.Bool(1), args.Error(2)
}

func (m *MockStorage) SetSystemMetadata(ctx context.Context, key, value string) error {
	args := m.Called(ctx, key, value)
	return args.Error(0)
}

func (m *MockStorage) GetRecoveryKeyRecord(ctx context.Context) (*models.RecoveryKeyRecord, bool, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Bool(1), args.Error(2)
	}
	return args.Get(0).(*models.RecoveryKeyRecord), args.Bool(1), args.Error(2)
}

func (m *MockStorage) SetRecoveryKeyRecord(ctx context.Context, record *models.RecoveryKeyRecord) error {
	args := m.Called(ctx, record)
	return args.Error(0)
}

func (m *MockStorage) HealthCheck(ctx context.Context) error {
	return m.Called(ctx).Error(0)
}

func (m *MockStorage) GetStats(ctx context.Context) (*storage.StorageStats, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.StorageStats), args.Error(1)
}

func (m *MockStorage) GetProjectUsageStats(ctx context.Context, projectIDs []uint, windowDays int) ([]storage.ProjectUsageStat, error) {
	args := m.Called(ctx, projectIDs, windowDays)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.ProjectUsageStat), args.Error(1)
}

func (m *MockStorage) GetBillingReport(ctx context.Context, from, to time.Time, projectIDs []uint) (*storage.BillingReport, error) {
	args := m.Called(ctx, from, to, projectIDs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.BillingReport), args.Error(1)
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

func (m *MockStorage) SaveDeploymentStatsSnapshot(_ context.Context, _ *models.DeploymentStatsSnapshot) error {
	return nil
}

func (m *MockStorage) GetPreviousDeploymentStatsSnapshot(_ context.Context) (*models.DeploymentStatsSnapshot, error) {
	return nil, nil
}

// Compliance posture snapshot stubs — best-effort server-side writes; MockStorage
// tests that construct a core without a real DB can tolerate a no-op save and a
// nil prior snapshot (both represent "no history yet", which is the correct
// initial state for any fresh deployment).
func (m *MockStorage) SaveCompliancePostureSnapshot(_ context.Context, _ *models.CompliancePostureSnapshot) error {
	return nil
}

func (m *MockStorage) GetPreviousCompliancePostureSnapshot(_ context.Context, _ time.Time) (*models.CompliancePostureSnapshot, error) {
	return nil, nil
}

func (m *MockStorage) ListCompliancePostureSnapshots(ctx context.Context, limit int) ([]*models.CompliancePostureSnapshot, error) {
	args := m.Called(ctx, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.CompliancePostureSnapshot), args.Error(1)
}

// SaveHygieneTrendSnapshot implements storage.Storage for MockStorage.
func (m *MockStorage) SaveHygieneTrendSnapshot(ctx context.Context, snap *models.HygieneTrendSnapshot) error {
	args := m.Called(ctx, snap)
	return args.Error(0)
}

// ListHygieneTrendSnapshots implements storage.Storage for MockStorage.
func (m *MockStorage) ListHygieneTrendSnapshots(ctx context.Context, days int) ([]*models.HygieneTrendSnapshot, error) {
	args := m.Called(ctx, days)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.HygieneTrendSnapshot), args.Error(1)
}

// CountStalePATs implements storage.Storage for MockStorage.
func (m *MockStorage) CountStalePATs(ctx context.Context, threshold time.Time) (int, error) {
	args := m.Called(ctx, threshold)
	return args.Int(0), args.Error(1)
}

// CountExpiredPATs implements storage.Storage for MockStorage.
func (m *MockStorage) CountExpiredPATs(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

// CountStaleMachineCredentials implements storage.Storage for MockStorage.
func (m *MockStorage) CountStaleMachineCredentials(ctx context.Context, threshold time.Time) (int, error) {
	args := m.Called(ctx, threshold)
	return args.Int(0), args.Error(1)
}
