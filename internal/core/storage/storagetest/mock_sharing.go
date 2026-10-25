package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (m *MockStorage) CreateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error) {
	args := m.Called(ctx, share)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ShareRecord), args.Error(1)
}

func (m *MockStorage) GetShareRecord(ctx context.Context, shareID uint) (*models.ShareRecord, error) {
	args := m.Called(ctx, shareID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ShareRecord), args.Error(1)
}

// LockShareRecordForUpdate has no row lock in the mock; it reuses the GetShareRecord expectation.
func (m *MockStorage) LockShareRecordForUpdate(ctx context.Context, shareID uint) (*models.ShareRecord, error) {
	return m.GetShareRecord(ctx, shareID)
}

func (m *MockStorage) UpdateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error) {
	a := m.Called(ctx, share)
	v, _ := a.Get(0).(*models.ShareRecord)
	return v, a.Error(1)
}

func (m *MockStorage) DeleteShareRecord(ctx context.Context, shareID uint) error {
	args := m.Called(ctx, shareID)
	return args.Error(0)
}

// now (all seven methods below) is accepted for storage.Storage conformance
// but deliberately NOT forwarded to m.Called() -- these are mocking DB
// behavior, and the injected clock a caller passes is not something the
// existing ~90 .On(...) expectation setups across this test suite assert on
// (unlike DeleteExpiredShareRecords' `before`, which genuinely varies
// meaningfully between its own test cases below). Forwarding it would force
// every one of those setups to add a matching arg for no test-behavior gain.
func (m *MockStorage) ListSharesBySecret(ctx context.Context, secretID uint, now time.Time) ([]*models.ShareRecord, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ShareRecord), args.Error(1)
}

func (m *MockStorage) ListSharesBySecretIDs(ctx context.Context, secretIDs []uint, now time.Time) ([]*models.ShareRecord, error) {
	args := m.Called(ctx, secretIDs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ShareRecord), args.Error(1)
}

func (m *MockStorage) ListSharesByUser(ctx context.Context, userID uint, now time.Time) ([]*models.ShareRecord, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ShareRecord), args.Error(1)
}

func (m *MockStorage) ListSharesByOwner(ctx context.Context, ownerID uint, now time.Time) ([]*models.ShareRecord, error) {
	args := m.Called(ctx, ownerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ShareRecord), args.Error(1)
}

func (m *MockStorage) ListSharesByGroup(ctx context.Context, groupID uint, now time.Time) ([]*models.ShareRecord, error) {
	args := m.Called(ctx, groupID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ShareRecord), args.Error(1)
}

func (m *MockStorage) ListSharedSecrets(ctx context.Context, userID uint, now time.Time) ([]*models.SecretNode, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.SecretNode), args.Error(1)
}

func (m *MockStorage) CheckSharePermission(ctx context.Context, secretID, userID uint, now time.Time) (string, error) {
	args := m.Called(ctx, secretID, userID)
	return args.String(0), args.Error(1)
}

func (m *MockStorage) ReassignSecretShareOwner(ctx context.Context, secretID, newOwnerID uint) (int64, error) {
	args := m.Called(ctx, secretID, newOwnerID)
	return int64(args.Int(0)), args.Error(1)
}

func (m *MockStorage) DeleteExpiredShareRecords(ctx context.Context, before time.Time) ([]*models.ShareRecord, error) {
	args := m.Called(ctx, before)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.ShareRecord), args.Error(1)
}

// Per-secret / per-folder ACL stubs (ADR-058).
func (m *MockStorage) CreateOrUpdateSecretACL(_ context.Context, _ *models.SecretACL) error {
	return nil
}

func (m *MockStorage) GetSecretACL(ctx context.Context, secretID, userID uint) (*models.SecretACL, error) {
	args := m.Called(ctx, secretID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SecretACL), args.Error(1)
}

func (m *MockStorage) ListSecretACLs(_ context.Context, _ uint) ([]*models.SecretACL, error) {
	return nil, nil
}

func (m *MockStorage) ListSecretACLsByUser(ctx context.Context, userID uint) ([]*models.SecretACL, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.SecretACL), args.Error(1)
}

func (m *MockStorage) DeleteSecretACL(_ context.Context, _ uint) error {
	return nil
}

func (m *MockStorage) DeleteSecretACLsByUserAndProject(_ context.Context, _, _ uint) error {
	return nil
}

func (m *MockStorage) GetSecretAncestors(ctx context.Context, nodeID uint) ([]uint, error) {
	args := m.Called(ctx, nodeID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uint), args.Error(1)
}
