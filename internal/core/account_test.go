package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

const acctTestUser = "alice"

func TestUpdateOwnProfile(t *testing.T) {
	ctx := context.Background()

	t.Run("updates display name and email", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		existing := &models.User{ID: 1, Username: acctTestUser, Email: "alice@old.com", DisplayName: "Alice"}

		ms.On("GetUser", ctx, uint(1)).Return(existing, nil)
		ms.On("GetUserByEmail", ctx, "alice@new.com").Return(nil, nil)
		ms.On("UpdateUser", ctx, mock.AnythingOfType("*models.User")).Return(existing, nil)

		_, err := c.UpdateOwnProfile(ctx, 1, "Alice New", "alice@new.com")
		require.NoError(t, err)
		assert.Equal(t, "alice@new.com", existing.Email)
		assert.Equal(t, "Alice New", existing.DisplayName)
		// Username is never touched by a self-service profile update.
		assert.Equal(t, "alice", existing.Username)
	})

	t.Run("rejects an email already used by another user", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		existing := &models.User{ID: 1, Username: acctTestUser, Email: "alice@old.com"}
		other := &models.User{ID: 2, Email: "taken@x.com"}

		ms.On("GetUser", ctx, uint(1)).Return(existing, nil)
		ms.On("GetUserByEmail", ctx, "taken@x.com").Return(other, nil)

		_, err := c.UpdateOwnProfile(ctx, 1, "", "taken@x.com")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})
}

func TestChangePassword(t *testing.T) {
	ctx := context.Background()
	oldHash, _ := bcrypt.GenerateFromPassword([]byte("oldpassword"), bcrypt.DefaultCost)

	t.Run("changes password and drops other sessions", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		user := &models.User{ID: 1, Username: acctTestUser, PasswordHash: string(oldHash)}

		ms.On("GetUser", ctx, uint(1)).Return(user, nil)
		ms.On("UpdateUser", ctx, mock.AnythingOfType("*models.User")).Return(user, nil)
		ms.On("GetSession", ctx, "current-token").Return(&models.Session{ID: 7, UserID: 1}, nil)
		ms.On("DeleteSessionsForUserExcept", ctx, uint(1), uint(7)).Return(nil)

		err := c.ChangePassword(ctx, 1, "oldpassword", "brandnewpassword", "current-token")
		require.NoError(t, err)
		// The new password verifies against the freshly stored hash.
		assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte("brandnewpassword")))
		ms.AssertCalled(t, "DeleteSessionsForUserExcept", ctx, uint(1), uint(7))
	})

	t.Run("rejects an incorrect current password without writing", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		user := &models.User{ID: 1, PasswordHash: string(oldHash)}
		ms.On("GetUser", ctx, uint(1)).Return(user, nil)

		err := c.ChangePassword(ctx, 1, "wrongpassword", "brandnewpassword", "current-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "incorrect")
		ms.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
	})

	t.Run("rejects a too-short new password", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		err := c.ChangePassword(ctx, 1, "oldpassword", "short", "current-token")
		require.Error(t, err)
		ms.AssertNotCalled(t, "GetUser", mock.Anything, mock.Anything)
	})
}

func TestRevokeOwnSession(t *testing.T) {
	ctx := context.Background()

	t.Run("revokes a session the caller owns", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetSessionByID", ctx, uint(5)).Return(&models.Session{ID: 5, UserID: 1}, nil)
		ms.On("DeleteSession", ctx, uint(5)).Return(nil)

		require.NoError(t, c.RevokeOwnSession(ctx, 1, 5))
		ms.AssertCalled(t, "DeleteSession", ctx, uint(5))
	})

	t.Run("will not revoke another user's session", func(t *testing.T) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		ms.On("GetSessionByID", ctx, uint(5)).Return(&models.Session{ID: 5, UserID: 2}, nil)

		err := c.RevokeOwnSession(ctx, 1, 5)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		ms.AssertNotCalled(t, "DeleteSession", mock.Anything, mock.Anything)
	})
}

func TestListOwnSessions(t *testing.T) {
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	want := []*models.Session{{ID: 1, UserID: 1}, {ID: 2, UserID: 1}}
	ms.On("ListSessionsByUser", ctx, uint(1)).Return(want, nil)

	got, err := c.ListOwnSessions(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, got, 2)
}
