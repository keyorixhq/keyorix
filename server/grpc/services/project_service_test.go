package services

import (
	"context"
	"testing"

	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// newProjectTestRig reuses the secret rig's seeded core (project 1 "default" +
// env 1 "development" + user 1 holding a global writer role with
// secrets.read/write/delete) and exposes a ProjectService over it.
func newProjectTestRig(t *testing.T) *ProjectGRPCService {
	t.Helper()
	r := newSecretTestRig(t)
	return NewProjectService(r.svc.core)
}

func TestProjectService_CRUDAndList(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(1, "owner")

	// The seeded "default" project is listed.
	list, err := svc.ListProjects(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(list.GetProjects()), 1)

	// Create → Get round-trip.
	created, err := svc.CreateProject(ctx, &pb.CreateProjectRequest{Name: "billing", Description: "money"})
	require.NoError(t, err)
	assert.NotZero(t, created.GetId())
	assert.Equal(t, "billing", created.GetName())

	got, err := svc.GetProject(ctx, &pb.GetProjectRequest{Id: created.GetId()})
	require.NoError(t, err)
	assert.Equal(t, "billing", got.GetName())

	// Update name + require_mfa.
	mfa := true
	upd, err := svc.UpdateProject(ctx, &pb.UpdateProjectRequest{
		Id: created.GetId(), Name: "billing-prod", Description: "money", RequireMfa: &mfa,
	})
	require.NoError(t, err)
	assert.Equal(t, "billing-prod", upd.GetName())
	assert.True(t, upd.GetRequireMfa())

	// List environments of the seeded project.
	envs, err := svc.ListEnvironments(ctx, &pb.ListEnvironmentsRequest{ProjectId: 1})
	require.NoError(t, err)
	require.Len(t, envs.GetEnvironments(), 1)
	assert.Equal(t, "development", envs.GetEnvironments()[0].GetName())

	// Delete the created project.
	_, err = svc.DeleteProject(ctx, &pb.DeleteProjectRequest{Id: created.GetId()})
	require.NoError(t, err)
}

func TestProjectService_Unauthenticated(t *testing.T) {
	svc := newProjectTestRig(t)
	_, err := svc.ListProjects(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestProjectService_Unauthorized(t *testing.T) {
	svc := newProjectTestRig(t)
	// User 999 has no role grants → AuthorizePrincipal denies.
	ctx := authCtx(999, "nobody")
	_, err := svc.CreateProject(ctx, &pb.CreateProjectRequest{Name: "x"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	_, err = svc.GetProject(ctx, &pb.GetProjectRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestProjectService_InvalidArgument(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.GetProject(ctx, &pb.GetProjectRequest{Id: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = svc.CreateProject(ctx, &pb.CreateProjectRequest{Name: ""})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}
