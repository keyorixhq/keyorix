package services

// DYNAMIC-ADMIN-DSN-1 item 1, gRPC: UpdateConfigAdminDSN replaces the stored DSN
// under create's checks and answers refusals with their own codes, never echoing
// the DSN.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

const grpcADSNSecret = "grpc-adsn-S3cr3t-41d7"

func storedAdminDSNEnc(t *testing.T, svc *DynamicSecretGRPCService, id uint32) []byte {
	t.Helper()
	cfg, err := svc.core.GetDynamicSecretConfig(context.Background(), uint(id))
	require.NoError(t, err)
	return cfg.AdminDSNEnc
}

func TestUpdateConfigAdminDSN_GRPC(t *testing.T) {
	var faulty *faultstorage.FaultyStorage
	svc := newDynamicTestRigOn(t, func(st storage.Storage) storage.Storage {
		faulty = faultstorage.NewFaultyStorage(st, nil)
		return faulty
	})
	owner := authCtx(1, "owner")
	cfg, err := svc.CreateConfig(owner, dynamicCreateReq("adsn-grpc"))
	require.NoError(t, err)
	before := storedAdminDSNEnc(t, svc, cfg.GetId())

	update := func(ctx context.Context, adminDSN string) error {
		_, err := svc.UpdateConfigAdminDSN(ctx, &pb.UpdateDynamicConfigAdminDSNRequest{Id: cfg.GetId(), AdminDsn: adminDSN})
		if err != nil {
			assert.NotContains(t, err.Error(), grpcADSNSecret, "the DSN reached the client")
		}
		return err
	}

	t.Run("refused option", func(t *testing.T) {
		err := update(owner, "postgres://admin:"+grpcADSNSecret+"@localhost/db?sslrootcert=/etc/keyorix/ca.pem")
		require.Equal(t, codes.InvalidArgument, status.Code(err), "%v", err)
		assert.Contains(t, status.Convert(err).Message(), "sslrootcert", "name the refused option")
		assert.Equal(t, before, storedAdminDSNEnc(t, svc, cfg.GetId()))
	})
	t.Run("non-admin", func(t *testing.T) {
		err := update(authCtx(3, "writer-only"), "postgres://admin:"+grpcADSNSecret+"@localhost/db2")
		require.Equal(t, codes.PermissionDenied, status.Code(err), "%v", err)
		assert.Equal(t, before, storedAdminDSNEnc(t, svc, cfg.GetId()))
	})
	t.Run("empty", func(t *testing.T) {
		require.Equal(t, codes.InvalidArgument, status.Code(update(owner, "")))
	})
	t.Run("audit refused", func(t *testing.T) {
		faulty.Arm(&faultstorage.FaultSpec{Method: "LogAuditEvent", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected audit failure")})
		err := update(owner, "postgres://admin:"+grpcADSNSecret+"@localhost/db3")
		fired := faulty.Fired()
		faulty.Arm(nil)
		require.True(t, fired)
		require.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
		assert.Equal(t, before, storedAdminDSNEnc(t, svc, cfg.GetId()), "no audit row, no change")
	})
	t.Run("accepted", func(t *testing.T) {
		require.NoError(t, update(owner, "postgres://admin:"+grpcADSNSecret+"@localhost/db4"))
		assert.NotEqual(t, before, storedAdminDSNEnc(t, svc, cfg.GetId()), "the stored DSN changed")
		assert.NotContains(t, string(storedAdminDSNEnc(t, svc, cfg.GetId())), grpcADSNSecret, "stored encrypted")
	})
}
