package services

// CORE-GRPC-ERR-TAILS-1 item 1: the counterpart of TestGroupRPCs_MissingGroupIsNotFound.
// A storage fault under a group RPC is a server failure, not a missing group: it answers
// Internal with the static message, never NotFound (which would tell a caller the id does
// not exist) and never the raw storage text.

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

func TestGroupRPCs_StorageFaultIsInternal(t *testing.T) {
	_, h := newGroupServiceFull(t)
	fs := faultstorage.NewFaultyStorage(h.Storage, nil)
	svc := NewGroupService(core.NewKeyorixCore(fs))
	h.CreateTestUser(t, "alice", 2)
	g, err := h.CoreService.CreateGroup(groupCtx(), 1, &core.CreateGroupRequest{Name: "fault-target"})
	require.NoError(t, err)
	gid := uint32(g.ID)

	calls := map[string]struct {
		method string
		call   func() error
	}{
		"GetGroup": {"GetGroup", func() error { _, err := svc.GetGroup(groupCtx(), &pb.GetGroupRequest{Id: gid}); return err }},
		"UpdateGroup": {"GetGroup", func() error {
			_, err := svc.UpdateGroup(groupCtx(), &pb.UpdateGroupRequest{Id: gid, Name: "renamed"})
			return err
		}},
		"DeleteGroup": {"GetGroup", func() error { _, err := svc.DeleteGroup(groupCtx(), &pb.DeleteGroupRequest{Id: gid}); return err }},
		// AddUserToGroup's own GetGroup is only an audit-name lookup whose error is
		// dropped by design (audit_refs.go), so fault the membership write itself.
		"AddGroupMember": {"AddUserToGroup", func() error {
			_, err := svc.AddGroupMember(groupCtx(), &pb.GroupMemberRequest{GroupId: gid, UserId: 2})
			return err
		}},
	}
	for name, c := range calls {
		t.Run(name, func(t *testing.T) {
			fs.Arm(&faultstorage.FaultSpec{
				Method: c.method, NthCall: 1, Kind: faultstorage.KindError,
				Err: errors.New("injected " + c.method + " fault"),
			})
			err := c.call()
			fired := fs.Fired()
			fs.Arm(nil)
			require.True(t, fired, "the armed %s fault must have fired for %s", c.method, name)
			require.Error(t, err)
			assert.Equal(t, codes.Internal, status.Code(err), err.Error())
			assert.NotContains(t, err.Error(), "injected", "raw storage text must not reach the caller")
		})
	}
}
