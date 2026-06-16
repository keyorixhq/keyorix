package handlers

import (
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
)

func TestUserToAPIResponse_LoginLockout(t *testing.T) {
	t.Run("active lock is surfaced", func(t *testing.T) {
		until := time.Now().Add(30 * time.Minute)
		out := userToAPIResponse(&models.User{ID: 1, Username: "bob", LoginLockedUntil: &until})
		assert.Contains(t, out, "login_locked_until", "an active lockout must be visible to admins")
	})

	t.Run("no lock → field absent", func(t *testing.T) {
		out := userToAPIResponse(&models.User{ID: 1, Username: "bob"})
		assert.NotContains(t, out, "login_locked_until")
	})

	t.Run("expired lock → field absent", func(t *testing.T) {
		past := time.Now().Add(-time.Minute)
		out := userToAPIResponse(&models.User{ID: 1, Username: "bob", LoginLockedUntil: &past})
		assert.NotContains(t, out, "login_locked_until", "an expired lock reads as unlocked")
	})
}
