package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) CreateWebAuthnCredential(_ context.Context, _ *models.WebAuthnCredential) error {
	return nil
}
func (m *MockStorage) ListWebAuthnCredentials(_ context.Context, _ uint) ([]*models.WebAuthnCredential, error) {
	return nil, nil
}
func (m *MockStorage) GetWebAuthnCredentialByCredID(_ context.Context, _ []byte, _ uint) (*models.WebAuthnCredential, error) {
	return nil, nil
}
func (m *MockStorage) LockWebAuthnCredentialForUpdate(_ context.Context, _ []byte, _ uint) (*models.WebAuthnCredential, error) {
	return nil, nil
}
func (m *MockStorage) DisableWebAuthnCredential(_ context.Context, _ uint) (bool, error) {
	return true, nil
}
func (m *MockStorage) SetWebAuthnCredentialCounterState(_ context.Context, _ uint, _ []byte, _ time.Time) (bool, error) {
	return true, nil
}
func (m *MockStorage) AdvanceWebAuthnCredentialCounter(_ context.Context, _ []byte, _ uint, _ []byte, _ uint32, _ time.Time) (bool, error) {
	return false, nil
}
func (m *MockStorage) DeleteWebAuthnCredential(_ context.Context, _, _ uint) error { return nil }
func (m *MockStorage) CountWebAuthnCredentials(_ context.Context, _ uint) (int64, error) {
	return 0, nil
}
func (m *MockStorage) SetUserWebAuthnEnabled(_ context.Context, _ uint, _ bool) error { return nil }
func (m *MockStorage) CreateWebAuthnSession(_ context.Context, _ *models.WebAuthnSession) error {
	return nil
}
func (m *MockStorage) ConsumeWebAuthnSession(_ context.Context, _ string, _ time.Time) (*models.WebAuthnSession, error) {
	return nil, nil
}
