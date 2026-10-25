package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

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

func (m *MockStorage) AcknowledgeAnomalyAlert(ctx context.Context, id, actorID uint, at time.Time) error {
	args := m.Called(ctx, id, actorID, at)
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
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) GetAnomalyConfig(ctx context.Context) (*models.AnomalyConfigRecord, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AnomalyConfigRecord), args.Error(1)
}

func (m *MockStorage) SaveAnomalyConfig(ctx context.Context, cfg *models.AnomalyConfigRecord) error {
	return m.Called(ctx, cfg).Error(0)
}

func (m *MockStorage) ListUnacknowledgedAnomalyAlertsBefore(ctx context.Context, threshold time.Time) ([]models.AnomalyAlert, error) {
	args := m.Called(ctx, threshold)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.AnomalyAlert), args.Error(1)
}
