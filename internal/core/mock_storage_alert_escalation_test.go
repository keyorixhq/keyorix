package core

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) CreateAlertEscalationPolicy(ctx context.Context, p *models.AlertEscalationPolicy) error {
	args := m.Called(ctx, p)
	return args.Error(0)
}

func (m *MockStorage) GetAlertEscalationPolicy(ctx context.Context, id uint) (*models.AlertEscalationPolicy, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AlertEscalationPolicy), args.Error(1)
}

func (m *MockStorage) ListAlertEscalationPolicies(ctx context.Context) ([]models.AlertEscalationPolicy, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.AlertEscalationPolicy), args.Error(1)
}

func (m *MockStorage) UpdateAlertEscalationPolicy(ctx context.Context, p *models.AlertEscalationPolicy) error {
	args := m.Called(ctx, p)
	return args.Error(0)
}

func (m *MockStorage) DeleteAlertEscalationPolicy(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockStorage) ListUnacknowledgedAnomalyAlertsBefore(ctx context.Context, threshold time.Time) ([]models.AnomalyAlert, error) {
	args := m.Called(ctx, threshold)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.AnomalyAlert), args.Error(1)
}
