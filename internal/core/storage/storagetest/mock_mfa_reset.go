package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// MFA reset stubs (the MFA reset logic is tested against real SQLite, not this mock).
func (m *MockStorage) SetUserMFAEnrolmentRequired(_ context.Context, _ uint, _ bool) error {
	return nil
}
func (m *MockStorage) CreateMFAResetRequest(_ context.Context, r *models.MFAResetRequest) (*models.MFAResetRequest, error) {
	return r, nil
}
func (m *MockStorage) GetMFAResetRequest(_ context.Context, _ uint) (*models.MFAResetRequest, error) {
	return nil, storage.ErrMFAResetRequestNotFound
}
func (m *MockStorage) ListMFAResetRequests(_ context.Context, _ bool) ([]*models.MFAResetRequest, error) {
	return nil, nil
}
func (m *MockStorage) DecideMFAResetRequestIfPending(_ context.Context, _ uint, _ string, _ uint, _ time.Time) (bool, error) {
	return false, nil
}
