package services

// IDENTITY-INPUT-BOUNDS-1 item 2, gRPC twin: expires_in_days (uint32 on the wire,
// so no negatives) above core.MaxMachineTokenLifetimeDays is InvalidArgument and
// mints nothing; 0 stays "never expires".

import (
	"context"
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

func TestGRPCIssueMachineToken_ExpiresInDaysBounds(t *testing.T) {
	for _, tc := range []struct {
		days     uint32
		wantCode codes.Code
	}{
		{0, codes.OK},
		{36500, codes.OK},
		{36501, codes.InvalidArgument},
		{math.MaxInt32, codes.InvalidArgument},
		{math.MaxUint32, codes.InvalidArgument},
	} {
		t.Run(strconv.FormatUint(uint64(tc.days), 10), func(t *testing.T) {
			svc, coreService := newMachineCacheTestRig(t)
			admin := authCtx(1, "admin")
			m, err := svc.CreateMachineIdentity(admin, &pb.CreateMachineIdentityRequest{ProjectId: 1, Name: "lifetime", IdentityType: "ci"})
			require.NoError(t, err)

			res, err := svc.IssueMachineToken(admin, &pb.IssueMachineTokenRequest{ProjectId: 1, MachineId: m.GetId(), Name: "lt", ExpiresInDays: tc.days})
			require.Equal(t, tc.wantCode, status.Code(err), "%v", err)

			creds, lerr := coreService.Storage().ListMachineIdentityCredentials(context.Background(), uint(m.GetId()))
			require.NoError(t, lerr)
			if tc.wantCode != codes.OK {
				assert.Empty(t, creds, "a refused lifetime must not mint a token")
				return
			}
			require.Len(t, creds, 1)
			if tc.days == 0 {
				assert.Nil(t, creds[0].ExpiresAt, "0 = never expires")
				assert.Nil(t, res.GetExpiresAt())
				return
			}
			require.NotNil(t, creds[0].ExpiresAt)
			assert.WithinDuration(t, time.Now().AddDate(0, 0, int(tc.days)), *creds[0].ExpiresAt, time.Hour)
		})
	}
}
