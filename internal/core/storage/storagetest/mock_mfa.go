package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) PruneMFAStepUpGrants(ctx context.Context, before time.Time) (int64, error) {
	a := m.Called(ctx, before)
	return a.Get(0).(int64), a.Error(1)
}

// MFA stubs (MFA core logic is tested against real SQLite, not this mock).
func (m *MockStorage) UpsertMFASecret(_ context.Context, _ *models.MFASecret) error { return nil }
func (m *MockStorage) GetMFASecret(_ context.Context, _ uint) (*models.MFASecret, error) {
	return nil, nil
}
func (m *MockStorage) ActivateMFASecret(_ context.Context, _ uint, _ []byte) (bool, error) {
	return true, nil
}
func (m *MockStorage) MarkTOTPStepUsed(_ context.Context, _ uint, _ int64) (bool, error) {
	return true, nil
}
func (m *MockStorage) ReleaseTOTPStepIfUnchanged(_ context.Context, _ uint, _ int64) (bool, error) {
	return true, nil
}
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

// WebAuthn stubs (the WebAuthn core logic is tested against real SQLite, not this mock).
func (m *MockStorage) GetActiveMFAChallenge(_ context.Context, _ string, _ time.Time) (*models.MFAChallenge, error) {
	return nil, nil
}

func (m *MockStorage) UpsertMFAStepupToken(_ context.Context, _ uint, _ time.Time) error {
	return nil
}

func (m *MockStorage) HasActiveMFAStepup(_ context.Context, _ uint) (bool, error) {
	return false, nil
}

func (m *MockStorage) CreateMFAStepUpGrant(_ context.Context, _ *models.MFAStepUpGrant) error {
	return nil
}

func (m *MockStorage) GetActiveMFAStepUpGrant(_ context.Context, _ uint, _ models.MFAStepUpPurpose, _ time.Time) (*models.MFAStepUpGrant, error) {
	return nil, nil
}

func (m *MockStorage) ConsumeMFAStepUpGrant(_ context.Context, _ uint, _ models.MFAStepUpPurpose, _ time.Time) (bool, error) {
	return false, nil
}

func (m *MockStorage) DeleteMFAStepUpGrantsFor(_ context.Context, _ uint) error {
	return nil
}
