package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Login rate-limiting stubs (core rate-limit logic is tested against real SQLite).
func (m *MockStorage) RecordLoginAttempt(_ context.Context, _ string, _ time.Time) error { return nil }
func (m *MockStorage) CountRecentLoginAttempts(_ context.Context, _ string, _ time.Time) (int64, error) {
	return 0, nil
}
func (m *MockStorage) ReserveLoginAttempt(_ context.Context, _ string, _ time.Time, _ string) (uint, error) {
	return 0, nil
}
func (m *MockStorage) ReleaseLoginAttempt(_ context.Context, _ uint) error { return nil }
func (m *MockStorage) PruneLoginAttempts(ctx context.Context, before time.Time) (int64, error) {
	a := m.Called(ctx, before)
	return a.Get(0).(int64), a.Error(1)
}

func (m *MockStorage) CreateSSOLoginState(ctx context.Context, s *models.SSOLoginState) error {
	args := m.Called(ctx, s)
	return args.Error(0)
}

func (m *MockStorage) ConsumeSSOLoginState(ctx context.Context, state string) (*models.SSOLoginState, error) {
	args := m.Called(ctx, state)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SSOLoginState), args.Error(1)
}

func (m *MockStorage) CreateSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	args := m.Called(ctx, session)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Session), args.Error(1)
}

func (m *MockStorage) GetSession(ctx context.Context, token string) (*models.Session, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Session), args.Error(1)
}

func (m *MockStorage) GetSessionAny(ctx context.Context, token string) (*models.Session, error) {
	a := m.Called(ctx, token)
	v, _ := a.Get(0).(*models.Session)
	return v, a.Error(1)
}

func (m *MockStorage) RotateSession(ctx context.Context, oldID uint, newSession *models.Session, now time.Time) (*models.Session, bool, error) {
	args := m.Called(ctx, oldID, newSession, now)
	if args.Get(0) == nil {
		return nil, args.Bool(1), args.Error(2)
	}
	return args.Get(0).(*models.Session), args.Bool(1), args.Error(2)
}

func (m *MockStorage) ListSessionTokenHashesByFamily(ctx context.Context, familyID string) ([]string, error) {
	args := m.Called(ctx, familyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockStorage) DeleteSessionsByFamily(ctx context.Context, familyID string) error {
	args := m.Called(ctx, familyID)
	return args.Error(0)
}

func (m *MockStorage) DeleteSession(ctx context.Context, id uint) error {
	return m.Called(ctx, id).Error(0)
}

func (m *MockStorage) CleanupExpiredSessions(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockStorage) GetSessionByID(ctx context.Context, id uint) (*models.Session, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Session), args.Error(1)
}

func (m *MockStorage) ListSessionsByUser(ctx context.Context, userID uint) ([]*models.Session, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Session), args.Error(1)
}

func (m *MockStorage) EnforceSessionLimit(_ context.Context, _ uint, _ int) error { return nil }

func (m *MockStorage) DeleteSessionsForUserExcept(ctx context.Context, userID, exceptID uint) error {
	args := m.Called(ctx, userID, exceptID)
	return args.Error(0)
}

func (m *MockStorage) ListSessionTokenHashesForUser(ctx context.Context, userID uint) ([]string, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockStorage) TouchSession(ctx context.Context, id uint, seenAt time.Time, staleness time.Duration) error {
	args := m.Called(ctx, id, seenAt, staleness)
	return args.Error(0)
}

// GetSessionAuthLiveness (PERF-FIX-7) is composed from the mock's own
// GetUser and GetSessionByID (storage.ComposeSessionAuthLiveness, in the order
// the session cache-hit check used to call them), so a test that stubs those
// (On("GetUser"), On("GetSessionByID")) drives the combined read unchanged,
// errors included.
func (m *MockStorage) GetSessionAuthLiveness(ctx context.Context, userID, sessionID uint) (*storage.SessionAuthLiveness, error) {
	return storage.ComposeSessionAuthLiveness(ctx, m, userID, sessionID), nil
}
