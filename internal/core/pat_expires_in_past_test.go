package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestCreateOwnPAT_RefusesExpiryNotInFuture: core refuses expires_at <= now with
// ErrPATExpiresInPast (an ErrInvalidInput) before any write, so every transport is
// covered (IDENTITY-INPUT-BOUNDS-1 item 3).
func TestCreateOwnPAT_RefusesExpiryNotInFuture(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	for name, at := range map[string]time.Time{
		"past":        now.Add(-time.Second),
		"exactly now": now,
		"long ago":    time.Unix(0, 0),
	} {
		t.Run(name, func(t *testing.T) {
			ms := new(MockStorage) // no expectations: any storage call fails the test
			c := NewKeyorixCore(ms)
			c.now = func() time.Time { return now }
			res, err := c.CreateOwnPAT(ctx, 1, "stale", &at, nil, 0, 0, nil)
			require.ErrorIs(t, err, ErrPATExpiresInPast)
			assert.ErrorIs(t, err, ErrInvalidInput)
			assert.Nil(t, res)
			ms.AssertNotCalled(t, "CreatePersonalAccessToken", mock.Anything, mock.Anything)
		})
	}

	t.Run("future and nil are accepted", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		c.now = func() time.Time { return now }
		ms.On("CreatePersonalAccessToken", ctx, mock.AnythingOfType("*models.PersonalAccessToken")).
			Return(&models.PersonalAccessToken{ID: 1}, nil)
		ms.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).Return(nil)
		future := now.Add(time.Second)
		_, err := c.CreateOwnPAT(ctx, 1, "future", &future, nil, 0, 0, nil)
		require.NoError(t, err)
		_, err = c.CreateOwnPAT(ctx, 1, "forever", nil, nil, 0, 0, nil)
		require.NoError(t, err)
	})
}
