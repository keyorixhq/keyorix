package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) LastUserSecretActivity(ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error) {
	args := m.Called(ctx, projectID, since)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]time.Time), args.Error(1)
}

func (m *MockStorage) LastUserRoleManagementActivity(ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error) {
	a := m.Called(ctx, projectID, since)
	v, _ := a.Get(0).(map[uint]time.Time)
	return v, a.Error(1)
}

func (m *MockStorage) LastUserSecretDeletionActivity(ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error) {
	a := m.Called(ctx, projectID, since)
	v, _ := a.Get(0).(map[uint]time.Time)
	return v, a.Error(1)
}

func (m *MockStorage) LastUserSecretReadActivity(ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error) {
	a := m.Called(ctx, projectID, since)
	v, _ := a.Get(0).(map[uint]time.Time)
	return v, a.Error(1)
}

func (m *MockStorage) LastUserSecretWriteActivity(ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error) {
	a := m.Called(ctx, projectID, since)
	v, _ := a.Get(0).(map[uint]time.Time)
	return v, a.Error(1)
}

func (m *MockStorage) LogAuditEvent(ctx context.Context, event *models.AuditEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

func (m *MockStorage) LogAuditEventWithAccessLog(ctx context.Context, event *models.AuditEvent, accessLog *models.SecretAccessLog) error {
	args := m.Called(ctx, event, accessLog)
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

func (m *MockStorage) CountSecretReadsBySecretIDs(ctx context.Context, secretIDs []uint, since time.Time) (map[uint]int, error) {
	args := m.Called(ctx, secretIDs, since)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]int), args.Error(1)
}

func (m *MockStorage) ListSecretIDsAccessedSince(ctx context.Context, since time.Time) ([]uint, error) {
	args := m.Called(ctx, since)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uint), args.Error(1)
}

func (m *MockStorage) PrincipalSecretFirstSeen(ctx context.Context, since time.Time) (map[string]map[uint]time.Time, error) {
	args := m.Called(ctx, since)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]map[uint]time.Time), args.Error(1)
}

func (m *MockStorage) MostAccessedSecrets(ctx context.Context, projectID, environmentID *uint, since time.Time, limit int) ([]storage.SecretUsageStat, error) {
	args := m.Called(ctx, projectID, environmentID, since, limit)
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

func (m *MockStorage) DeleteAuditLogsBefore(ctx context.Context, cutoff time.Time) (int64, *storage.AuditChainAnchor, error) {
	args := m.Called(ctx, cutoff)
	var anchor *storage.AuditChainAnchor
	if args.Get(1) != nil {
		anchor = args.Get(1).(*storage.AuditChainAnchor)
	}
	return args.Get(0).(int64), anchor, args.Error(2)
}

func (m *MockStorage) VerifyAuditChain(ctx context.Context, anchor *storage.AuditChainAnchor) (*storage.AuditChainVerification, error) {
	args := m.Called(ctx, anchor)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.AuditChainVerification), args.Error(1)
}

func (m *MockStorage) VerifyAuditChainSegment(ctx context.Context, seg storage.AuditChainSegment) (*storage.AuditChainVerification, error) {
	args := m.Called(ctx, seg)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.AuditChainVerification), args.Error(1)
}

func (m *MockStorage) MigrateAuditChainEncoding(ctx context.Context, dryRun bool, anchor *storage.AuditChainAnchor) (*storage.AuditChainMigrationResult, error) {
	args := m.Called(ctx, dryRun, anchor)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.AuditChainMigrationResult), args.Error(1)
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

func (m *MockStorage) ListAuditCheckpoints(ctx context.Context, afterID uint, limit int) ([]*models.AuditCheckpoint, error) {
	args := m.Called(ctx, afterID, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.AuditCheckpoint), args.Error(1)
}

func (m *MockStorage) UpdateAuditCheckpointAnchor(ctx context.Context, id uint, token []byte, anchoredAt time.Time, provider string) error {
	args := m.Called(ctx, id, token, anchoredAt, provider)
	return args.Error(0)
}

func (m *MockStorage) AuditEntryHashByID(ctx context.Context, id uint) (string, bool, error) {
	args := m.Called(ctx, id)
	return args.String(0), args.Bool(1), args.Error(2)
}

func (m *MockStorage) CreatePendingAuditEvent(ctx context.Context, p *models.PendingAuditEvent) error {
	args := m.Called(ctx, p)
	return args.Error(0)
}

func (m *MockStorage) ListPendingAuditEvents(ctx context.Context, afterID uint, limit int) ([]*models.PendingAuditEvent, error) {
	args := m.Called(ctx, afterID, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.PendingAuditEvent), args.Error(1)
}

func (m *MockStorage) ClaimPendingAuditEvent(ctx context.Context, id uint) (bool, error) {
	args := m.Called(ctx, id)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) RecordPendingAuditEventFailure(ctx context.Context, id uint, reason string) error {
	args := m.Called(ctx, id, reason)
	return args.Error(0)
}

func (m *MockStorage) CountPendingAuditEvents(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockStorage) OldestPendingAuditEventAt(ctx context.Context) (time.Time, bool, error) {
	args := m.Called(ctx)
	return args.Get(0).(time.Time), args.Bool(1), args.Error(2)
}

func (m *MockStorage) UnusedSecrets(ctx context.Context, projectID, environmentID *uint, notReadSince time.Time) ([]storage.UnusedSecretStat, error) {
	args := m.Called(ctx, projectID, environmentID, notReadSince)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.UnusedSecretStat), args.Error(1)
}

func (m *MockStorage) CountUnusedSecretsByProject(ctx context.Context, projectIDs []uint, notReadSince time.Time) (map[uint]int, error) {
	args := m.Called(ctx, projectIDs, notReadSince)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]int), args.Error(1)
}

func (m *MockStorage) MaxAuditEventID(ctx context.Context) (uint, error) {
	args := m.Called(ctx)
	return args.Get(0).(uint), args.Error(1)
}

func (m *MockStorage) GetAuditLogs(ctx context.Context, filter *storage.AuditFilter) ([]*models.AuditEvent, int64, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*models.AuditEvent), args.Get(1).(int64), args.Error(2)
}

func (m *MockStorage) GetDistinctActiveUserIDs(_ context.Context, _ time.Time) ([]uint, error) {
	return nil, nil
}

func (m *MockStorage) CountImpersonatedActions(_ context.Context, actingAs, impersonator uint, since time.Time) (int64, error) {
	args := m.Called(actingAs, impersonator, since)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockStorage) GetSecretReadCounts(ctx context.Context, secretID uint, since, until time.Time, limit int) ([]storage.SecretReadEntry, error) {
	args := m.Called(ctx, secretID, since, until, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.SecretReadEntry), args.Error(1)
}
