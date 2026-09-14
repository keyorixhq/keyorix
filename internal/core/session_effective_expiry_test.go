// session_effective_expiry_test.go — SessionEffectiveExpiry, the slow-path helper the
// auth middleware uses to clamp a session's positive token-cache entry to the session's
// own expiry (F-TOK-1, 2026-09-14 review). Returns the EARLIEST of idle/absolute expiry,
// nil when neither is set or the session can't be resolved (nil ⇒ the middleware keeps the
// normal validTokenTTL window).
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestSessionEffectiveExpiry(t *testing.T) {
	t.Parallel()
	now := time.Now()
	early := now.Add(time.Minute)
	late := now.Add(time.Hour)

	coreWithSession := func(s *models.Session, err error) *KeyorixCore {
		ms := new(MockStorage)
		ms.On("GetSession", mock.Anything, "tok").Return(s, err)
		return NewKeyorixCore(ms)
	}

	t.Run("idle expiry when it is the earliest", func(t *testing.T) {
		got := coreWithSession(&models.Session{ExpiresAt: &early, AbsoluteExpiresAt: &late}, nil).
			SessionEffectiveExpiry(context.Background(), "tok")
		if assert.NotNil(t, got) {
			assert.True(t, got.Equal(early))
		}
	})
	t.Run("absolute expiry when it is the earliest", func(t *testing.T) {
		got := coreWithSession(&models.Session{ExpiresAt: &late, AbsoluteExpiresAt: &early}, nil).
			SessionEffectiveExpiry(context.Background(), "tok")
		if assert.NotNil(t, got) {
			assert.True(t, got.Equal(early))
		}
	})
	t.Run("the only expiry that is set", func(t *testing.T) {
		got := coreWithSession(&models.Session{ExpiresAt: &early}, nil).
			SessionEffectiveExpiry(context.Background(), "tok")
		if assert.NotNil(t, got) {
			assert.True(t, got.Equal(early))
		}
	})
	t.Run("nil when neither expiry is set", func(t *testing.T) {
		assert.Nil(t, coreWithSession(&models.Session{}, nil).SessionEffectiveExpiry(context.Background(), "tok"))
	})
	t.Run("nil when the session cannot be resolved", func(t *testing.T) {
		assert.Nil(t, coreWithSession(nil, errors.New("not found")).SessionEffectiveExpiry(context.Background(), "tok"))
	})
}
