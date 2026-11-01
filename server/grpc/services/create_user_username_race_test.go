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

// AUTHZ-ORACLE-1 item 4 (REVFIX-3790-1 leftover): the loser of a CreateUser race on
// one username used to answer Internal ("user operation failed"): its insert hit the
// users username unique index, which was not mapped to a sentinel. It must answer
// AlreadyExists, like the sequential duplicate. The race is made deterministic: the
// winner is committed, then the loser's GetUserByUsername pre-check is made to miss it.
func TestCreateUser_UsernameRaceLoserAnswersAlreadyExists(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.CreateTestUser(t, "admin", 1)
	h.AssignUserRole(t, 1, 1, nil)
	// The production partial index (migrateDatabase); the helper's AutoMigrate lacks it.
	h.ExecuteRawSQL(t, "UPDATE users SET username_folded = lower(username) WHERE username_folded = ''")
	h.ExecuteRawSQL(t, "CREATE UNIQUE INDEX uniq_users_username_folded_active ON users (username_folded) WHERE deleted_at IS NULL")

	_, err := NewUserService(h.CoreService).CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username: "racer", Email: "winner@example.com", Password: strPtr("Qr7#Kp2$Lm5@Vn9!"),
	})
	require.NoError(t, err)

	racing := core.NewKeyorixCore(storagetest.Hooked(h.Storage, &storagetest.StoreHooks{
		WrapTx: true,
		GetUserByUsername: func(_ corestorage.Storage, _ context.Context, _ string) (*models.User, error) {
			return nil, fmt.Errorf("lookup: %w", corestorage.ErrUserNotFound)
		},
	}))
	_, err = NewUserService(racing).CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username: "racer", Email: "loser@example.com", Password: strPtr("Qr7#Kp2$Lm5@Vn9!"),
	})
	require.Error(t, err)
	assert.Equal(t, codes.AlreadyExists, status.Code(err), "race loser: %v", err)
}
