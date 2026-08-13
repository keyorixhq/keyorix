package services

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testhelper"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func newGroupService(t *testing.T) (*GroupGRPCService, *testhelper.RBACTestHelper) {
	t.Helper()
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.AssignUserRole(t, 1, 1, nil) // user 1 = super_admin (global) → all global checks pass
	return NewGroupService(h.CoreService), h
}

func groupCtx() context.Context {
	return authCtx(1, "admin", "users.read", "users.write", "roles.assign")
}

func TestGroupService_CRUD(t *testing.T) {
	svc, _ := newGroupService(t)

	g, err := svc.CreateGroup(groupCtx(), &pb.CreateGroupRequest{Name: "platform", Description: "platform team"})
	require.NoError(t, err)
	assert.NotZero(t, g.GetId())
	assert.Equal(t, "platform", g.GetName())

	got, err := svc.GetGroup(groupCtx(), &pb.GetGroupRequest{Id: g.GetId()})
	require.NoError(t, err)
	assert.Equal(t, "platform", got.GetName())

	list, err := svc.ListGroups(groupCtx(), &emptypb.Empty{})
	require.NoError(t, err)
	require.NotEmpty(t, list.GetGroups())

	upd, err := svc.UpdateGroup(groupCtx(), &pb.UpdateGroupRequest{Id: g.GetId(), Name: "platform", Description: "renamed"})
	require.NoError(t, err)
	assert.Equal(t, "renamed", upd.GetDescription())

	_, err = svc.DeleteGroup(groupCtx(), &pb.DeleteGroupRequest{Id: g.GetId()})
	require.NoError(t, err)

	// Soft-deleted → restorable; restore returns the live group again.
	restored, err := svc.RestoreGroup(groupCtx(), &pb.RestoreGroupRequest{Id: g.GetId()})
	require.NoError(t, err)
	assert.Equal(t, g.GetId(), restored.GetId())
}

func TestGroupService_Members(t *testing.T) {
	svc, h := newGroupService(t)
	h.CreateTestUser(t, "bob", 2)
	g, err := svc.CreateGroup(groupCtx(), &pb.CreateGroupRequest{Name: "oncall"})
	require.NoError(t, err)

	_, err = svc.AddGroupMember(groupCtx(), &pb.GroupMemberRequest{GroupId: g.GetId(), UserId: 2})
	require.NoError(t, err)

	members, err := svc.GetGroupMembers(groupCtx(), &pb.GetGroupMembersRequest{Id: g.GetId()})
	require.NoError(t, err)
	require.Len(t, members.GetMembers(), 1)
	assert.Equal(t, "bob", members.GetMembers()[0].GetUsername())

	_, err = svc.RemoveGroupMember(groupCtx(), &pb.GroupMemberRequest{GroupId: g.GetId(), UserId: 2})
	require.NoError(t, err)
	members, err = svc.GetGroupMembers(groupCtx(), &pb.GetGroupMembersRequest{Id: g.GetId()})
	require.NoError(t, err)
	assert.Empty(t, members.GetMembers())
}

// TestGroupService_NameLengthMatchesHTTP verifies gRPC rejects an over-255-char Name
// with the same limit HTTP's `validate:"...,max=255"` tag enforces (backlog #190) —
// the core-layer CreateGroup/UpdateGroup validation both transports call must reject
// it, not just the (gRPC-bypassed) HTTP validator.
func TestGroupService_NameLengthMatchesHTTP(t *testing.T) {
	svc, _ := newGroupService(t)
	tooLong := strings.Repeat("a", 256)

	_, err := svc.CreateGroup(groupCtx(), &pb.CreateGroupRequest{Name: tooLong})
	require.Error(t, err, "a 256-char group name must be rejected over gRPC, matching HTTP's 255-char cap")

	// A name at exactly the limit is still accepted.
	g, err := svc.CreateGroup(groupCtx(), &pb.CreateGroupRequest{Name: strings.Repeat("a", 255)})
	require.NoError(t, err)

	// UpdateGroup enforces the same cap.
	_, err = svc.UpdateGroup(groupCtx(), &pb.UpdateGroupRequest{Id: g.GetId(), Name: tooLong})
	require.Error(t, err, "a 256-char rename must be rejected over gRPC, matching HTTP's 255-char cap")
}

func TestGroupService_Unauthenticated(t *testing.T) {
	svc, _ := newGroupService(t)
	_, err := svc.CreateGroup(context.Background(), &pb.CreateGroupRequest{Name: "x"})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// TestGroupService_RestoreGroup_RequiresRolesAssign is the G16 regression test:
// RestoreGroup reinstates every role grant the group carried at deletion (the
// same blast radius as a role grant), so it must require roles.assign — not
// users.write, which the HTTP sibling (POST /groups/{id}/restore, #147) never
// accepted either. A users.write-only holder must be refused; a roles.assign
// holder must succeed.
func TestGroupService_RestoreGroup_RequiresRolesAssign(t *testing.T) {
	svc, h := newGroupService(t)

	// A group to soft-delete + attempt restoring with an insufficient grant.
	g1, err := svc.CreateGroup(groupCtx(), &pb.CreateGroupRequest{Name: "team-a"})
	require.NoError(t, err)
	_, err = svc.DeleteGroup(groupCtx(), &pb.DeleteGroupRequest{Id: g1.GetId()})
	require.NoError(t, err)

	// A second group to soft-delete + restore with a sufficient grant.
	g2, err := svc.CreateGroup(groupCtx(), &pb.CreateGroupRequest{Name: "team-b"})
	require.NoError(t, err)
	_, err = svc.DeleteGroup(groupCtx(), &pb.DeleteGroupRequest{Id: g2.GetId()})
	require.NoError(t, err)

	// User 2 holds ONLY users.write (the old, too-weak gate) — must be refused.
	h.CreateTestUser(t, "writer-only", 2)
	writerRole := h.CreateTestRole(t, "writer_only", "users.write only", 100)
	h.ExecuteRawSQL(t, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT ?, id FROM permissions WHERE name = 'users.write'`, writerRole.ID)
	h.AssignUserRole(t, 2, writerRole.ID, nil)

	_, err = svc.RestoreGroup(authCtx(2, "writer-only"), &pb.RestoreGroupRequest{Id: g1.GetId()})
	require.Error(t, err, "users.write holder without roles.assign must NOT restore a group")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// User 3 holds roles.assign (the new, correct gate) — must succeed.
	h.CreateTestUser(t, "assigner", 3)
	assignerRole := h.CreateTestRole(t, "assigner_only", "roles.assign only", 101)
	h.ExecuteRawSQL(t, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT ?, id FROM permissions WHERE name = 'roles.assign'`, assignerRole.ID)
	h.AssignUserRole(t, 3, assignerRole.ID, nil)

	restored, err := svc.RestoreGroup(authCtx(3, "assigner"), &pb.RestoreGroupRequest{Id: g2.GetId()})
	require.NoError(t, err, "roles.assign holder should be allowed to restore a group")
	assert.Equal(t, g2.GetId(), restored.GetId())
}
