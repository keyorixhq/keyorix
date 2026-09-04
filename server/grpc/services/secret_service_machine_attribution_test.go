// secret_service_machine_attribution_test.go — #1625 gRPC counterpart to
// server/http/handlers/secrets_crud_machine_attribution_test.go: the gRPC
// CreateSecret RPC had the identical unwired-OwnerMachineIdentityID gap as
// the HTTP handler. Drives the real gRPC service (not core.CreateSecret
// directly), matching the finding's own call-out that the original PR's test
// bypassed both real entry points.
package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// machineAuthCtx returns a context carrying a machine principal, as the auth
// interceptor would populate it for a real machine token (see
// server/middleware/auth.go's machineUserContext for the equivalent HTTP
// shape: Username set to the machine identity's own Name).
func machineAuthCtx(machineID uint, name string) context.Context {
	return context.WithValue(context.Background(), interceptors.GetUserContextKey(),
		&interceptors.UserContext{ActorType: core.ActorTypeMachine, MachineIdentityID: machineID, Username: name})
}

// TestSecretService_CreateSecret_MachineActor_AttributedToOwnerMachineIdentityID
// drives the real gRPC CreateSecret RPC as an authorized machine principal
// and confirms the persisted secret's OwnerMachineIdentityID is populated.
func TestSecretService_CreateSecret_MachineActor_AttributedToOwnerMachineIdentityID(t *testing.T) {
	r := newSecretTestRig(t)

	const machineID = uint(50)
	require.NoError(t, r.db.Create(&models.MachineIdentity{
		ID: machineID, ProjectID: 1, Name: "ci-runner-grpc", State: "active",
	}).Error)
	require.NoError(t, r.db.Create(&models.MachineIdentityRole{
		MachineIdentityID: machineID, RoleID: writerRoleID, ProjectID: 1, EnvironmentID: 0,
	}).Error)

	ctx := machineAuthCtx(machineID, "ci-runner-grpc")
	sec, err := r.svc.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name: "machine-created-secret-grpc", Value: "s3cr3t", ProjectId: 1, EnvironmentId: 1, Type: "password",
	})
	require.NoError(t, err)

	var created models.SecretNode
	require.NoError(t, r.db.Where("name = ?", "machine-created-secret-grpc").First(&created).Error)
	assert.Equal(t, uint(0), created.OwnerID, "a machine caller's UserID is 0 by convention (ADR-030) -- must not collide with a real user ID")
	assert.Equal(t, machineID, created.OwnerMachineIdentityID, "#1625: a machine-created secret over gRPC must record WHICH machine created it, not leave both owner columns at zero")
	assert.Equal(t, uint32(0), sec.GetOwnerId())
}
