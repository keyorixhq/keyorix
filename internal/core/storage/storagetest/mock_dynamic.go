package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Dynamic-secrets stubs (the dynamic-secrets core logic is tested against real
// SQLite + a fake engine, not this mock). GetDynamicSecretConfig/
// TransitionDynamicSecretConfigDisabled below are FIXED stubs by default (see
// the GetDynamicSecretConfigFunc/TransitionDynamicSecretConfigDisabledFunc
// doc on the struct above for why they use a settable-func escape hatch
// instead of the usual testify .On()/m.Called() pattern).
func (m *MockStorage) CreateDynamicSecretConfig(_ context.Context, c *models.DynamicSecretConfig) (*models.DynamicSecretConfig, error) {
	return c, nil
}
func (m *MockStorage) GetDynamicSecretConfig(ctx context.Context, id uint) (*models.DynamicSecretConfig, error) {
	if m.GetDynamicSecretConfigFunc != nil {
		return m.GetDynamicSecretConfigFunc(ctx, id)
	}
	return nil, nil
}
func (m *MockStorage) ListDynamicSecretConfigs(_ context.Context, _, _ uint) ([]*models.DynamicSecretConfig, error) {
	return nil, nil
}
func (m *MockStorage) UpdateDynamicSecretConfig(_ context.Context, _ *models.DynamicSecretConfig) error {
	return nil
}
func (m *MockStorage) SetDynamicSecretConfigAdminDSN(_ context.Context, _ uint, _, _ []byte) error {
	return nil
}
func (m *MockStorage) SetDynamicSecretConfigClassification(_ context.Context, _ uint, _, _ string, _ time.Time) (bool, error) {
	return true, nil
}
func (m *MockStorage) TransitionDynamicSecretConfigDisabled(ctx context.Context, c *models.DynamicSecretConfig, fromDisabled bool) (bool, error) {
	if m.TransitionDynamicSecretConfigDisabledFunc != nil {
		return m.TransitionDynamicSecretConfigDisabledFunc(ctx, c, fromDisabled)
	}
	return true, nil
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
func (m *MockStorage) CountActiveLeases(_ context.Context, _ uint) (int64, error) {
	return 0, nil
}
func (m *MockStorage) ExtendDynamicSecretLeaseExpiry(_ context.Context, _ string, _ time.Time) (bool, error) {
	return true, nil
}
func (m *MockStorage) RecordDynamicSecretLeaseRevocation(_ context.Context, _, _, _, _ string, _ *time.Time) (bool, error) {
	return true, nil
}
func (m *MockStorage) ListExpiredActiveLeases(_ context.Context, _ time.Time) ([]*models.DynamicSecretLease, error) {
	return nil, nil
}
