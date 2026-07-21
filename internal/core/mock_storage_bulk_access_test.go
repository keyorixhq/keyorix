package core

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) CreateRejectionReasonTemplate(ctx context.Context, t *models.RejectionReasonTemplate) error {
	args := m.Called(ctx, t)
	return args.Error(0)
}

func (m *MockStorage) ListRejectionReasonTemplates(ctx context.Context) ([]models.RejectionReasonTemplate, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.RejectionReasonTemplate), args.Error(1)
}

func (m *MockStorage) DeleteRejectionReasonTemplate(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockStorage) ListAccessRequestsByIDs(ctx context.Context, ids []uint) ([]*models.AccessRequest, error) {
	args := m.Called(ctx, ids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.AccessRequest), args.Error(1)
}
