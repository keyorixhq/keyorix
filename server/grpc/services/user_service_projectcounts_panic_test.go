// user_service_projectcounts_panic_test.go — deterministic unit test for
// docs/findings/2026-10-02-FINDING-grpc-createuser-usertoproto-projectcounts-panic-masks-commit.md:
// projectCounts' best-effort handling only covered a RETURNED error from
// ProjectMembershipCounts; a panic there propagated past the point where
// CreateUser's primary write had already committed, reporting a successful
// create as a failed RPC.
package services

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countProjectMembershipsPanicStub wraps a real storage.Storage and makes
// CountProjectMembershipsByUsers panic, mirroring this package's own
// fault-injection stub pattern used elsewhere in this campaign.
type countProjectMembershipsPanicStub struct {
	corestorage.Storage
}

func (s *countProjectMembershipsPanicStub) CountProjectMembershipsByUsers(ctx context.Context, userIDs []uint) (map[uint]corestorage.MembershipCounts, error) {
	panic("fault-fuzz injected failure")
}

// TestCreateUser_ProjectCountsPanicDoesNotMaskSuccess: a panic from
// CountProjectMembershipsByUsers (reached via userToProto's post-commit
// response enrichment) must not report CreateUser as failed — the user, its
// role grant, and its password-history seed already committed by the time
// this call runs.
func TestCreateUser_ProjectCountsPanicDoesNotMaskSuccess(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.CreateTestUser(t, "admin", 1)
	h.AssignUserRole(t, 1, 1, nil)

	faultyCore := core.NewKeyorixCore(&countProjectMembershipsPanicStub{Storage: h.Storage})
	svc := NewUserService(faultyCore)

	resp, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username: "panicuser", Email: "panicuser@example.com", Password: strPtr("Qr7#Kp2$Lm5@Vn9!"),
	})
	require.NoError(t, err, "a panic in the post-commit response enrichment must not fail the RPC")
	require.NotNil(t, resp)
	require.NotNil(t, resp.User)
	assert.Equal(t, "panicuser", resp.User.Username)
	// The best-effort counts are absent (zero) rather than resolved -- same
	// degraded-but-honest shape as the already-handled returned-error case.
	assert.Zero(t, resp.User.ProjectCount)

	// The user genuinely exists afterward -- this was a real commit, not an
	// error that happened to return a populated-looking response.
	u, err := h.CoreService.GetUser(adminCtx(), uint(resp.User.Id))
	require.NoError(t, err)
	assert.Equal(t, "panicuser", u.Username)
}
