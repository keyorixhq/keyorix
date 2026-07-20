// mock_storage_token_expiry_test.go — MockStorage extensions for the new
// ListExpiringPATs and ListExpiringMachineCredentials storage methods.
//
// Do NOT add methods to mock_storage_test.go (that file is frozen). This file
// is in the same "core" test package and Go allows the method set to span files.
package core

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) ListExpiringPATs(ctx context.Context, cutoff time.Time) ([]models.PersonalAccessToken, error) {
	args := m.Called(ctx, cutoff)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.PersonalAccessToken), args.Error(1)
}

func (m *MockStorage) ListExpiringMachineCredentials(ctx context.Context, cutoff time.Time) ([]models.MachineIdentityCredential, error) {
	args := m.Called(ctx, cutoff)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.MachineIdentityCredential), args.Error(1)
}
