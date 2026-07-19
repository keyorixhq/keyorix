package services

import (
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

// newRotationPlanRig reuses the secret rig (i18n + RBAC graph + project 1 / env 1 /
// user 1 granted secrets.read globally), adds the rotation tables, a 90-day policy,
// and two overdue secrets (one depending on the other), and returns a project gRPC
// service over the same store.
func newRotationPlanRig(t *testing.T) *ProjectGRPCService {
	t.Helper()
	rig := newSecretTestRig(t)
	db := rig.db
	require.NoError(t, db.AutoMigrate(&models.RotationPolicy{}, &models.SecretDependency{}))

	projectID := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		Name: "90-day", Scope: "project", ProjectID: &projectID, IntervalDays: 90, AlertDaysBefore: 14, IsActive: true,
	}).Error)
	// Real-clock-relative so the secrets are overdue regardless of wall-clock drift.
	mk := func(id uint, name string, daysAgo int) {
		last := time.Now().AddDate(0, 0, -daysAgo)
		require.NoError(t, db.Create(&models.SecretNode{
			ID: id, Name: name, ProjectID: projectID, EnvironmentID: 1, IsSecret: true, Status: "active", OwnerID: 1, LastRotatedAt: &last,
		}).Error)
	}
	mk(10, "db-password", 200) // overdue, foundational
	mk(11, "app-token", 120)   // overdue, depends on db-password

	svc := core.NewKeyorixCore(store.NewLocalStorage(db))
	// app-token depends on db-password → it must rotate in a later wave.
	_, err := svc.AddSecretDependency(t.Context(), 1, 11, 10, "")
	require.NoError(t, err)
	return NewProjectService(svc)
}

func TestGRPC_GetProjectRotationPlan(t *testing.T) {
	svc := newRotationPlanRig(t)

	resp, err := svc.GetProjectRotationPlan(authCtx(1, "owner", "secrets.read"), &pb.GetProjectRequest{Id: 1})
	require.NoError(t, err)
	assert.Equal(t, int32(2), resp.GetTotalSecrets())
	assert.Equal(t, int32(2), resp.GetOverdueCount())
	require.Len(t, resp.GetWaves(), 2, "the dependency forces a second wave")
	// Wave 0 = the dependency (db-password); wave 1 = app-token, which follows it.
	require.Len(t, resp.GetWaves()[0].GetSecrets(), 1)
	assert.Equal(t, "db-password", resp.GetWaves()[0].GetSecrets()[0].GetSecretName())
	w1 := resp.GetWaves()[1].GetSecrets()[0]
	assert.Equal(t, "app-token", w1.GetSecretName())
	assert.Equal(t, []uint32{10}, w1.GetAfterSecretIds())
	assert.NotEmpty(t, w1.GetReasons())
}

func TestGRPC_GetProjectRotationPlanRequiresAuth(t *testing.T) {
	svc := newRotationPlanRig(t)
	_, err := svc.GetProjectRotationPlan(t.Context(), &pb.GetProjectRequest{Id: 1})
	require.Error(t, err)
}

func TestGRPC_GetDeploymentRotationPlan(t *testing.T) {
	svc := newRotationPlanRig(t)
	resp, err := svc.GetDeploymentRotationPlan(authCtx(1, "owner", "secrets.read"), &emptypb.Empty{})
	require.NoError(t, err)
	assert.Equal(t, int32(1), resp.GetProjectsScanned())
	assert.Equal(t, int32(1), resp.GetProjectsWithWork())
	assert.Equal(t, int32(2), resp.GetTotalSecrets())
	assert.Equal(t, int32(2), resp.GetOverdueCount())
	require.Len(t, resp.GetProjects(), 1, "one project has work")
	assert.Empty(t, resp.GetBrokenProjects())
}

func TestGRPC_GetDeploymentRotationPlanRequiresAuth(t *testing.T) {
	svc := newRotationPlanRig(t)
	_, err := svc.GetDeploymentRotationPlan(t.Context(), &emptypb.Empty{})
	require.Error(t, err)
}
