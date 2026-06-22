package services

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedDepGraph adds the dependency table + three secrets (a→b→c chain) to a rig and
// returns their ids. service-cert (a) depends on intermediate (b) depends on root (c).
func seedDepGraph(t *testing.T, rig *secretTestRig) (a, b, c uint) {
	t.Helper()
	require.NoError(t, rig.db.AutoMigrate(&models.SecretDependency{}))
	mk := func(id uint, name string) {
		require.NoError(t, rig.db.Create(&models.SecretNode{
			ID: id, Name: name, ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active", OwnerID: 1,
		}).Error)
	}
	mk(10, "service-cert")
	mk(11, "intermediate")
	mk(12, "root-ca")
	require.NoError(t, rig.db.Create(&models.SecretDependency{ProjectID: 1, DependentSecretID: 10, DependsOnSecretID: 11}).Error)
	require.NoError(t, rig.db.Create(&models.SecretDependency{ProjectID: 1, DependentSecretID: 11, DependsOnSecretID: 12}).Error)
	return 10, 11, 12
}

func TestGRPC_ListSecretDependencies(t *testing.T) {
	rig := newSecretTestRig(t)
	mid := func() uint { _, b, _ := seedDepGraph(t, rig); return b }()

	resp, err := rig.svc.ListSecretDependencies(authCtx(1, "owner", "secrets.read"), &pb.GetSecretRequest{Id: uint32(mid)})
	require.NoError(t, err)
	require.Len(t, resp.GetDependsOn(), 1)
	assert.Equal(t, "root-ca", resp.GetDependsOn()[0].GetSecretName())
	require.Len(t, resp.GetDependents(), 1)
	assert.Equal(t, "service-cert", resp.GetDependents()[0].GetSecretName())
}

func TestGRPC_GetSecretImpact(t *testing.T) {
	rig := newSecretTestRig(t)
	_, _, root := seedDepGraph(t, rig)

	resp, err := rig.svc.GetSecretImpact(authCtx(1, "owner", "secrets.read"), &pb.GetSecretRequest{Id: uint32(root)})
	require.NoError(t, err)
	// Rotating root-ca impacts intermediate (depth 1) then service-cert (depth 2).
	require.Len(t, resp.GetAffected(), 2)
	assert.Equal(t, "intermediate", resp.GetAffected()[0].GetSecretName())
	assert.Equal(t, int32(1), resp.GetAffected()[0].GetDepth())
	assert.Equal(t, "service-cert", resp.GetAffected()[1].GetSecretName())
	assert.Equal(t, int32(2), resp.GetAffected()[1].GetDepth())
}

func TestGRPC_GetProjectRotationOrder(t *testing.T) {
	rig := newSecretTestRig(t)
	seedDepGraph(t, rig)
	projectSvc := NewProjectService(core.NewKeyorixCore(store.NewLocalStorage(rig.db)))

	resp, err := projectSvc.GetProjectRotationOrder(authCtx(1, "owner", "secrets.read"), &pb.GetProjectRequest{Id: 1})
	require.NoError(t, err)
	require.Len(t, resp.GetOrder(), 3)
	// Dependencies first: root-ca, then intermediate, then service-cert.
	assert.Equal(t, "root-ca", resp.GetOrder()[0].GetSecretName())
	assert.Equal(t, "intermediate", resp.GetOrder()[1].GetSecretName())
	assert.Equal(t, "service-cert", resp.GetOrder()[2].GetSecretName())
}

func TestGRPC_DependencyRequiresAuth(t *testing.T) {
	rig := newSecretTestRig(t)
	a, _, _ := seedDepGraph(t, rig)
	// No user in context → unauthenticated.
	_, err := rig.svc.ListSecretDependencies(t.Context(), &pb.GetSecretRequest{Id: uint32(a)})
	require.Error(t, err)
}
