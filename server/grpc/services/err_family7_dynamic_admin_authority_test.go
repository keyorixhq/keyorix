package services

// CORE-ERR-FAMILY-7 item 1: CreateConfig by a caller who holds secrets.write but not admin
// authority (#162) was an untyped core error, so mapDynamicError's default branch answered
// it Unavailable ("backend operation failed"), telling a refused caller to retry. It is
// PermissionDenied now. A storage fault while resolving the caller's roles is still
// Unavailable, with the storage_unavailable reason and no driver text.

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

func dynamicCreateReq(name string) *pb.CreateDynamicConfigRequest {
	return &pb.CreateDynamicConfigRequest{
		Name: name, ProjectId: 1, EnvironmentId: 1, BackendType: "postgres", AdminDsn: "postgres://admin:pw@localhost/db",
	}
}

func TestErrFamily7_CreateDynamicConfigWithoutAdminAuthorityIsPermissionDenied(t *testing.T) {
	svc := newDynamicTestRig(t)
	_, err := svc.CreateConfig(authCtx(3, "writer-only"), dynamicCreateReq("refused"))
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), err.Error())
}

func TestErrFamily7_CreateDynamicConfigAuthorityReadFaultIsUnavailable(t *testing.T) {
	var faulty *faultstorage.FaultyStorage
	svc := newDynamicTestRigOn(t, func(st storage.Storage) storage.Storage {
		faulty = faultstorage.NewFaultyStorage(st, nil)
		return faulty
	})
	ctx := authCtx(1, "owner")

	// Count the admin-flag reads of a clean create; the last one is the #162 check
	// (the earlier ones belong to the secrets.write authorization).
	_, err := svc.CreateConfig(ctx, dynamicCreateReq("dry-run"))
	require.NoError(t, err)
	n := 0
	for _, c := range faulty.Calls() {
		if c.Method == "RoleSetBypassesPermissionChecks" {
			n++
		}
	}
	require.Positive(t, n, "the admin check must read the admin flag")

	faulty.Arm(&faultstorage.FaultSpec{
		Method: "RoleSetBypassesPermissionChecks", NthCall: n, Kind: faultstorage.KindError,
		Err: errors.New("pq: terminating connection due to administrator command"),
	})
	_, err = svc.CreateConfig(ctx, dynamicCreateReq("faulted"))
	fired := faulty.Fired()
	faulty.Arm(nil)
	require.True(t, fired, "the admin-authority read must be reached")
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err), err.Error())
	assert.NotContains(t, err.Error(), "pq:", "the driver cause must not reach the client")
	var info *errdetails.ErrorInfo
	for _, d := range status.Convert(err).Details() {
		if i, ok := d.(*errdetails.ErrorInfo); ok {
			info = i
		}
	}
	require.NotNil(t, info, "an outage carries the storage_unavailable ErrorInfo")
	assert.Equal(t, storageUnavailableReason, info.Reason)
}
