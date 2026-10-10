package services

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/server/proto/pb"
)

// REISSUE-1: UserService.ReissueOneTimePassword.

func TestReissueOneTimePassword_ReturnsPasswordOnceWithExpiry(t *testing.T) {
	svc := newUserService(t)
	target := svc.mustCreate(t, "reissue_grpc", "reissue_grpc@example.com")

	before := time.Now()
	resp, err := svc.ReissueOneTimePassword(adminCtx(), &pb.ReissueOneTimePasswordRequest{Id: target.GetId()})
	require.NoError(t, err)
	assert.Equal(t, target.GetId(), resp.GetUserId())
	assert.Equal(t, "reissue_grpc@example.com", resp.GetEmail())
	require.NotEmpty(t, resp.GetOneTimePassword())
	exp, err := time.Parse(time.RFC3339, resp.GetOneTimePasswordExpiresAt())
	require.NoError(t, err)
	assert.Equal(t, time.UTC, exp.Location())
	assert.WithinDuration(t, before.Add(72*time.Hour), exp, time.Minute, "default one-time-password lifetime is 72h")
}

func TestReissueOneTimePassword_RequiresUsersWrite(t *testing.T) {
	svc := newUserService(t)
	target := svc.mustCreate(t, "reissue_denied", "reissue_denied@example.com")

	// A caller with users.read only, and one with nothing, are both refused -- the same
	// gate as CreateUser with generate_one_time_password.
	for _, ctx := range []struct {
		name string
		ctx  func() error
	}{
		{"ungranted user", func() error {
			_, err := svc.ReissueOneTimePassword(authCtx(7, "reader"), &pb.ReissueOneTimePasswordRequest{Id: target.GetId()})
			return err
		}},
		{"no user at all", func() error {
			_, err := svc.ReissueOneTimePassword(t.Context(), &pb.ReissueOneTimePasswordRequest{Id: target.GetId()})
			return err
		}},
	} {
		t.Run(ctx.name, func(t *testing.T) {
			err := ctx.ctx()
			require.Error(t, err)
			assert.Contains(t, []codes.Code{codes.PermissionDenied, codes.Unauthenticated}, status.Code(err))
		})
	}
}

func TestReissueOneTimePassword_RefusesOwnAccount(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.ReissueOneTimePassword(adminCtx(), &pb.ReissueOneTimePasswordRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.True(t, strings.Contains(status.Convert(err).Message(), "recover-admin"), "points at recover-admin: %q", status.Convert(err).Message())
}

func TestReissueOneTimePassword_InvalidAndMissingIDs(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.ReissueOneTimePassword(adminCtx(), &pb.ReissueOneTimePasswordRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = svc.ReissueOneTimePassword(adminCtx(), &pb.ReissueOneTimePasswordRequest{Id: 99999})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestReissueOneTimePassword_RefusesSuspendedUser(t *testing.T) {
	svc := newUserService(t)
	target := svc.mustCreate(t, "reissue_susp_grpc", "reissue_susp_grpc@example.com")
	require.NoError(t, svc.core.SuspendUser(t.Context(), 1, uint(target.GetId())))

	_, err := svc.ReissueOneTimePassword(adminCtx(), &pb.ReissueOneTimePasswordRequest{Id: target.GetId()})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}
