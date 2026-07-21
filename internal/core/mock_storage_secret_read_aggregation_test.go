package core

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

func (m *MockStorage) GetSecretReadCounts(ctx context.Context, secretID uint, since, until time.Time, limit int) ([]storage.SecretReadEntry, error) {
	args := m.Called(ctx, secretID, since, until, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.SecretReadEntry), args.Error(1)
}
