package core

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) UpsertMFAStepupToken(_ context.Context, _ uint, _ time.Time) error {
	return nil
}

func (m *MockStorage) HasActiveMFAStepup(_ context.Context, _ uint) (bool, error) {
	return false, nil
}

func (m *MockStorage) CreateMFAStepUpGrant(_ context.Context, _ *models.MFAStepUpGrant) error {
	return nil
}

func (m *MockStorage) GetActiveMFAStepUpGrant(_ context.Context, _ uint, _ time.Time) (*models.MFAStepUpGrant, error) {
	return nil, nil
}

func (m *MockStorage) DeleteMFAStepUpGrantsFor(_ context.Context, _ uint) error {
	return nil
}
