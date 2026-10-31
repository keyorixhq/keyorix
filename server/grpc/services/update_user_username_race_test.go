package services

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// AUTHZ-ORACLE-TAILS-1 item 2 over gRPC: the loser of an UpdateUser rename race on one
// username answers AlreadyExists, like the sequential duplicate, and the refused rename
// changes nothing. A regression guard, not a red proof: mapUserError already typed
// ErrDuplicateUsername (the sentinel survives core's wrapping), so this passes without
// the core mapping; the core and REST tests carry the red/green proof.
func TestUpdateUser_UsernameRaceLoserAnswersAlreadyExists(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.CreateTestUser(t, "admin", 1)
	h.AssignUserRole(t, 1, 1, nil)
	h.CreateTestUser(t, "racer", 2)
	h.CreateTestUser(t, "bob", 3)
	// The production partial index (migrateDatabase); the helper's AutoMigrate lacks it.
	h.ExecuteRawSQL(t, "UPDATE users SET username_folded = lower(username) WHERE username_folded = ''")
	h.ExecuteRawSQL(t, "CREATE UNIQUE INDEX uniq_users_username_folded_active ON users (username_folded) WHERE deleted_at IS NULL")

	racing := core.NewKeyorixCore(storagetest.Hooked(h.Storage, &storagetest.StoreHooks{
		WrapTx: true,
		GetUserByUsername: func(_ corestorage.Storage, _ context.Context, _ string) (*models.User, error) {
			return nil, fmt.Errorf("lookup: %w", corestorage.ErrUserNotFound) // the winner has not committed yet
		},
	}))
	_, err := NewUserService(racing).UpdateUser(adminCtx(), &pb.UpdateUserRequest{Id: 3, Username: strPtr("racer")})
	require.Error(t, err)
	assert.Equal(t, codes.AlreadyExists, status.Code(err), "race loser: %v", err)

	got, gerr := h.Storage.GetUser(context.Background(), 3)
	require.NoError(t, gerr)
	assert.Equal(t, "bob", got.Username, "the refused rename changed nothing")
}
