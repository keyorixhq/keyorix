package storagetest

import (
	"context"
	"time"
)

func (m *MockStorage) PurgeDeletedSecretsBefore(ctx context.Context, before time.Time) (int64, error) {
	args := m.Called(ctx, before)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockStorage) DeleteAnomalyAlertsBefore(ctx context.Context, ackBefore, unackCeiling time.Time) (int64, error) {
	args := m.Called(ctx, ackBefore, unackCeiling)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockStorage) DeleteClosedAccessReviewsBefore(ctx context.Context, before time.Time) (int64, int64, error) {
	args := m.Called(ctx, before)
	return args.Get(0).(int64), args.Get(1).(int64), args.Error(2)
}

func (m *MockStorage) DeleteExpiredBreakGlassBefore(ctx context.Context, before time.Time) (int64, error) {
	a := m.Called(ctx, before)
	return a.Get(0).(int64), a.Error(1)
}

func (m *MockStorage) DeleteResolvedAccessRequestsBefore(ctx context.Context, before time.Time) (int64, int64, error) {
	a := m.Called(ctx, before)
	return a.Get(0).(int64), a.Get(1).(int64), a.Error(2)
}

func (m *MockStorage) PurgeDeletedUsersBefore(ctx context.Context, before time.Time) (int64, error) {
	a := m.Called(ctx, before)
	return a.Get(0).(int64), a.Error(1)
}

func (m *MockStorage) PurgeDeletedProjectsBefore(ctx context.Context, before time.Time) (int64, error) {
	a := m.Called(ctx, before)
	return a.Get(0).(int64), a.Error(1)
}

func (m *MockStorage) PurgeDeletedEnvironmentsBefore(ctx context.Context, before time.Time) (int64, error) {
	a := m.Called(ctx, before)
	return a.Get(0).(int64), a.Error(1)
}
