package services

// ERRSTRING-CLASS-1 item 1: groupError must not steer the gRPC class by the words in an
// UNTYPED error. A Postgres "permission denied for table groups" is a database-role
// fault and a driver text that happens to contain "invalid"/"required" is not a
// validation refusal: both are server faults (Internal). Real typed refusals keep the
// class they always had.

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

func TestGroupRPCs_UntypedStorageTextDoesNotSteerClass(t *testing.T) {
	_, h := newGroupServiceFull(t)
	fs := faultstorage.NewFaultyStorage(h.Storage, nil)
	svc := NewGroupService(core.NewKeyorixCore(fs))
	h.CreateTestUser(t, "alice", 2)
	g, err := h.CoreService.CreateGroup(groupCtx(), 1, &core.CreateGroupRequest{Name: "steer-target"})
	require.NoError(t, err)
	gid := uint32(g.ID)

	calls := map[string]struct {
		method string
		call   func() error
	}{
		"GetGroup": {"GetGroup", func() error { _, err := svc.GetGroup(groupCtx(), &pb.GetGroupRequest{Id: gid}); return err }},
		"DeleteGroup": {"GetGroup", func() error {
			_, err := svc.DeleteGroup(groupCtx(), &pb.DeleteGroupRequest{Id: gid})
			return err
		}},
		"AddGroupMember": {"AddUserToGroup", func() error {
			_, err := svc.AddGroupMember(groupCtx(), &pb.GroupMemberRequest{GroupId: gid, UserId: 2})
			return err
		}},
	}
	texts := map[string]string{
		"db role fault":      "pq: permission denied for table groups",
		"driver validation":  "invalid input syntax for type bigint: group id is required",
		"length-ish message": "value exceeds the column limit",
	}
	for name, c := range calls {
		for tname, text := range texts {
			t.Run(name+"/"+tname, func(t *testing.T) {
				fs.Arm(&faultstorage.FaultSpec{
					Method: c.method, NthCall: 1, Kind: faultstorage.KindError, Err: errors.New(text),
				})
				err := c.call()
				fired := fs.Fired()
				fs.Arm(nil)
				require.True(t, fired, "the armed %s fault must have fired for %s", c.method, name)
				require.Error(t, err)
				assert.Equal(t, codes.Internal, status.Code(err), err.Error())
				assert.NotContains(t, err.Error(), text, "raw storage text must not reach the caller")
			})
		}
	}
}

// TestGroupRPCs_TypedValidationRefusalStaysInvalidArgument pins the other direction:
// the refusals core itself produces for a malformed request keep InvalidArgument.
func TestGroupRPCs_TypedValidationRefusalStaysInvalidArgument(t *testing.T) {
	svc, h := newGroupServiceFull(t)
	h.CreateTestUser(t, "alice", 2)

	calls := map[string]func() error{
		"CreateGroup empty name": func() error {
			_, err := svc.CreateGroup(groupCtx(), &pb.CreateGroupRequest{Name: ""})
			return err
		},
		"GetGroup zero id": func() error { _, err := svc.GetGroup(groupCtx(), &pb.GetGroupRequest{Id: 0}); return err },
		"UpdateGroup zero id": func() error {
			_, err := svc.UpdateGroup(groupCtx(), &pb.UpdateGroupRequest{Id: 0, Name: "x"})
			return err
		},
		"DeleteGroup zero id": func() error { _, err := svc.DeleteGroup(groupCtx(), &pb.DeleteGroupRequest{Id: 0}); return err },
		"AddGroupMember zero ids": func() error {
			_, err := svc.AddGroupMember(groupCtx(), &pb.GroupMemberRequest{GroupId: 0, UserId: 0})
			return err
		},
		"RemoveGroupMember zero ids": func() error {
			_, err := svc.RemoveGroupMember(groupCtx(), &pb.GroupMemberRequest{GroupId: 0, UserId: 0})
			return err
		},
		"GetGroupMembers zero id": func() error {
			_, err := svc.GetGroupMembers(groupCtx(), &pb.GetGroupMembersRequest{Id: 0})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call()
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err), err.Error())
			assert.Equal(t, "invalid group request", status.Convert(err).Message())
		})
	}
}

// TestGroupError_TypedPermissionAndTransient: a core authorization refusal
// (core.ErrPermissionDenied, however wrapped) is PermissionDenied; a transient
// authorization-storage fault (core.IsAuthTransient) is Unavailable, the retryable
// class, like AUDIT-503-MAP-1 / AUTHZ-OUTAGE-503-1; an untyped error saying
// "permission denied" is neither.
func TestGroupError_TypedPermissionAndTransient(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code codes.Code
		msg  string
	}{
		{"typed refusal", fmt.Errorf("add member: %w", core.ErrPermissionDenied), codes.PermissionDenied, "access denied"},
		{"typed SoD refusal", fmt.Errorf("add member: %w", core.ErrSoDPermissionDenied), codes.PermissionDenied, "access denied"},
		{"role resolution outage", fmt.Errorf("add member: %w", core.ErrRoleResolutionUnavailable), codes.Unavailable, ""},
		{"auth storage outage", fmt.Errorf("add member: %w", core.ErrAuthStorageUnavailable), codes.Unavailable, ""},
		{"untyped permission text", errors.New("pq: permission denied for table groups"), codes.Internal, "group operation failed"},
		{"untyped denied text", errors.New("access denied by upstream"), codes.Internal, "group operation failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := groupError(tc.err)
			assert.Equal(t, tc.code, status.Code(got), got.Error())
			if tc.msg != "" {
				assert.Equal(t, tc.msg, status.Convert(got).Message())
			}
			assert.NotContains(t, got.Error(), "groups", "raw error text must not reach the caller")
		})
	}
}
