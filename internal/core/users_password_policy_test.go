package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// CreateUser must enforce the configured password policy on the admin-supplied
// password — the one path where a human picks the credential. Before the fix this
// path accepted any non-empty password, so an admin could seed a weak account.
func TestCreateUser_EnforcesPasswordPolicy(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	ctx := context.Background()

	t.Run("a weak password is rejected before any storage write", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		_, err := c.CreateUser(ctx, &CreateUserRequest{
			Username: "svc", Email: "svc@example.com", Password: "weak",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "password must")
		ms.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
	})

	t.Run("a password containing the username is rejected", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		// 16+ chars with all classes, but embeds the username.
		_, err := c.CreateUser(ctx, &CreateUserRequest{
			Username: "alice", Email: "alice@example.com", Password: "Alice#Passw0rd99!",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "password must")
		ms.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
	})
}
