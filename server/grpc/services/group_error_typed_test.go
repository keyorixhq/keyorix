package services

// AUDIT-503-MAP-1 item 3: groupError classifies core/storage errors by sentinel
// (errors.Is), not by matching err.Error(). Before, "not found" was a substring
// test, so (a) the last-administrator refusal (core.ErrLastAdminGroupGuard, whose
// text never contained "refusing to remove the last") answered Internal, and
// (b) any error that merely contained the words "not found" (a raw storage
// "record not found" for some other row) answered NotFound "group not found".

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

func TestGroupError_ClassifiesBySentinel(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code codes.Code
		msg  string
	}{
		{"missing group", fmt.Errorf("retrieval failed: %w", storage.ErrGroupNotFound), codes.NotFound, "group not found"},
		{"missing user", fmt.Errorf("lookup: %w", storage.ErrUserNotFound), codes.NotFound, "user not found"},
		{"duplicate name", fmt.Errorf("%w: UNIQUE constraint failed", storage.ErrDuplicateGroupName), codes.AlreadyExists, "group name already in use"},
		{"last admin (delete)", fmt.Errorf("refusing to delete group 7: it holds the install's last administrative role grant: %w", core.ErrLastAdminGroupGuard),
			codes.FailedPrecondition, "cannot remove the last administrator"},
		{"last admin (membership)", fmt.Errorf("storage failed: %w", core.ErrLastAdminGroupGuard),
			codes.FailedPrecondition, "cannot remove the last administrator"},
		// Untyped text is no longer trusted: a raw "not found" from another row is a
		// server fault, not a missing group.
		{"untyped record not found", errors.New("record not found"), codes.Internal, "group operation failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := groupError(tc.err)
			assert.Equal(t, tc.code, status.Code(got), got.Error())
			assert.Equal(t, tc.msg, status.Convert(got).Message())
		})
	}
}

// TestGroupRPCs_MissingGroupIsNotFound: every group RPC that takes a group id answers
// NotFound for one that does not exist. RemoveGroupMember is the exception by design:
// removing a membership is idempotent, so a missing group is not an error there.
func TestGroupRPCs_MissingGroupIsNotFound(t *testing.T) {
	svc, h := newGroupServiceFull(t)
	h.CreateTestUser(t, "alice", 2)
	const missing = 99999

	calls := map[string]func() error{
		"GetGroup": func() error { _, err := svc.GetGroup(groupCtx(), &pb.GetGroupRequest{Id: missing}); return err },
		"UpdateGroup": func() error {
			_, err := svc.UpdateGroup(groupCtx(), &pb.UpdateGroupRequest{Id: missing, Name: "renamed"})
			return err
		},
		"DeleteGroup":  func() error { _, err := svc.DeleteGroup(groupCtx(), &pb.DeleteGroupRequest{Id: missing}); return err },
		"RestoreGroup": func() error { _, err := svc.RestoreGroup(groupCtx(), &pb.RestoreGroupRequest{Id: missing}); return err },
		"GetGroupMembers": func() error {
			_, err := svc.GetGroupMembers(groupCtx(), &pb.GetGroupMembersRequest{Id: missing})
			return err
		},
		"AddGroupMember": func() error {
			_, err := svc.AddGroupMember(groupCtx(), &pb.GroupMemberRequest{GroupId: missing, UserId: 2})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call()
			require.Error(t, err)
			assert.Equal(t, codes.NotFound, status.Code(err), err.Error())
		})
	}

	t.Run("RemoveGroupMember is idempotent", func(t *testing.T) {
		_, err := svc.RemoveGroupMember(groupCtx(), &pb.GroupMemberRequest{GroupId: missing, UserId: 2})
		require.NoError(t, err)
	})
}
