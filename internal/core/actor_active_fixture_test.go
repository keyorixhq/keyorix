package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ensureActiveActor creates an active user row with id actorID unless one exists.
// A fixture that acts as actorID through a mutating core entry point needs the
// account to exist and be active: requireActorActive (#4159) refuses an actor whose
// account is missing or not active, as no transport-authenticated actor can be.
func ensureActiveActor(t *testing.T, st storage.Storage, actorID uint) {
	t.Helper()
	ctx := context.Background()
	if u, err := st.GetUser(ctx, actorID); err == nil && u != nil {
		return
	}
	name := fmt.Sprintf("fixture-actor-%d", actorID)
	u := foldedTestUser(t, name, name+"@example.com")
	u.ID = actorID
	_, err := st.CreateUser(ctx, u)
	require.NoError(t, err)
}

// stubActiveActors answers GetUser on a MockStorage with an active account for any
// ID not stubbed more specifically before it (testify matches expectations in
// registration order), for mock-backed tests of a mutating entry point that are not
// about the actor's account state (#4159).
func stubActiveActors(m *MockStorage) {
	m.On("GetUser", mock.Anything, mock.Anything).Return(&models.User{IsActive: true, AccountState: AccountActive}, nil).Maybe()
}
