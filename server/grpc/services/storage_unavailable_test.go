package services

// storage_unavailable_test.go — STORAGE-ERR-CLASS-1 item 5 (gRPC).
//
// A storage READ fault inside a revoke / suspend / lease revoke used to be folded
// into "not found" by core and answered codes.NotFound. Core now returns
// core.ErrStorageReadUnavailable and the services answer codes.Unavailable with an
// ErrorInfo (reason storage_unavailable), like an audit-log outage. A true
// not-found stays NotFound on the same RPCs.

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

func TestStorageUnavailableStatus(t *testing.T) {
	_, ok := storageUnavailableStatus(errors.New("boom"))
	assert.False(t, ok)
	_, ok = storageUnavailableStatus(nil)
	assert.False(t, ok)

	fault := core.ReadFault(errors.New("driver: connection refused"))
	require.NotNil(t, fault)
	out, ok := storageUnavailableStatus(fault)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, status.Code(out))
	assert.Equal(t, core.StorageReadUnavailableMessage, status.Convert(out).Message())
	assert.NotContains(t, status.Convert(out).Message(), "connection refused", "the driver cause must not reach the client")
	var info *errdetails.ErrorInfo
	for _, d := range status.Convert(out).Details() {
		if i, isInfo := d.(*errdetails.ErrorInfo); isInfo {
			info = i
		}
	}
	require.NotNil(t, info)
	assert.Equal(t, storageUnavailableReason, info.Reason)
	assert.Equal(t, storageUnavailableRetryAfterSeconds, info.Metadata["retry_after_seconds"])
}

func TestStorageUnavailable_RPCsAnswerUnavailable(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.AssignUserRole(t, 1, 1, nil) // user 1 = super_admin (global)

	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(h.DB), nil)
	cs := core.NewKeyorixCore(faulty)
	machines := NewMachineIdentityService(cs)
	dyn := NewDynamicSecretService(cs)
	ctx := authCtx(1, "admin", "roles.assign", "secrets.write", "users.read")

	require.NoError(t, h.DB.AutoMigrate(&models.MachineIdentity{}, &models.MachineIdentityCredential{},
		&models.MachineIdentityRole{}, &models.DynamicSecretConfig{}, &models.DynamicSecretLease{}))
	proj := &models.Project{Name: "su-grpc-proj"}
	require.NoError(t, h.DB.Create(proj).Error)
	machine := &models.MachineIdentity{ProjectID: proj.ID, Name: "su-m", IdentityType: "other", State: "active"}
	require.NoError(t, h.DB.Create(machine).Error)
	cred := &models.MachineIdentityCredential{MachineIdentityID: machine.ID, Name: "c", TokenHash: "su-h1", TokenPrefix: "kx_m"}
	require.NoError(t, h.DB.Create(cred).Error)
	lease := &models.DynamicSecretLease{LeaseID: "su-grpc-lease", ConfigID: 1, Status: "active"}
	require.NoError(t, h.DB.Create(lease).Error)

	cases := []struct {
		name  string
		fault string
		call  func() error
	}{
		{"RevokeMachineToken", "GetMachineIdentityCredentialByID", func() error {
			_, err := machines.RevokeMachineToken(ctx, &pb.RevokeMachineTokenRequest{ProjectId: uint32(proj.ID), MachineId: uint32(machine.ID), TokenId: uint32(cred.ID)})
			return err
		}},
		{"TransitionMachineIdentity (revoke)", "LockMachineIdentityForUpdate", func() error {
			_, err := machines.TransitionMachineIdentity(ctx, &pb.TransitionMachineIdentityRequest{ProjectId: uint32(proj.ID), MachineId: uint32(machine.ID), Action: "revoke"})
			return err
		}},
		{"RevokeLease (lookup)", "GetDynamicSecretLease", func() error {
			_, err := dyn.RevokeLease(ctx, &pb.RevokeLeaseRequest{LeaseId: lease.LeaseID})
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			faulty.Arm(&faultstorage.FaultSpec{Method: tc.fault, NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected: " + tc.fault)})
			err := tc.call()
			require.True(t, faulty.Fired(), "the read fault must be reached")
			require.Error(t, err)
			assert.Equal(t, codes.Unavailable, status.Code(err), "a storage read fault is Unavailable, not NotFound/Internal: %v", err)
			assert.NotContains(t, err.Error(), "injected", "the driver cause must not reach the client")
			faulty.Arm(nil)
		})
	}

	t.Run("a true not-found stays NotFound", func(t *testing.T) {
		_, err := machines.RevokeMachineToken(ctx, &pb.RevokeMachineTokenRequest{ProjectId: uint32(proj.ID), MachineId: uint32(machine.ID), TokenId: 9_999_999})
		require.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("the retried revoke succeeds after the fault clears", func(t *testing.T) {
		faulty.Arm(&faultstorage.FaultSpec{Method: "GetMachineIdentityCredentialByID", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected")})
		_, err := machines.RevokeMachineToken(ctx, &pb.RevokeMachineTokenRequest{ProjectId: uint32(proj.ID), MachineId: uint32(machine.ID), TokenId: uint32(cred.ID)})
		require.Equal(t, codes.Unavailable, status.Code(err))
		var row models.MachineIdentityCredential
		require.NoError(t, h.DB.First(&row, cred.ID).Error)
		assert.False(t, row.Revoked)
		_, err = machines.RevokeMachineToken(ctx, &pb.RevokeMachineTokenRequest{ProjectId: uint32(proj.ID), MachineId: uint32(machine.ID), TokenId: uint32(cred.ID)})
		require.NoError(t, err)
		require.NoError(t, h.DB.First(&row, cred.ID).Error)
		assert.True(t, row.Revoked)
	})
}
