// secrets_machine_permission_test.go — W1 sibling fix: SecretGRPCService's
// GetSecret, GetSecretValue, UpdateSecret, DeleteSecret, and GetSecretVersions
// all called a core *WithPermissionCheck function with user.UserID
// unconditionally, even though authorizeSecretScoped had already authorized
// the machine principal via AuthorizeSecretPrincipal. Since a machine
// caller's UserID is always 0 (ADR-030), every one of those five RPCs
// hard-failed a fully-authorized machine token with "user ID is required for
// permission checking" — a more complete version of the same gap Session S's
// benchmark found on the HTTP side (Bug 2), since gRPC had no isMachine split
// on ANY of its five (HTTP was missing it on 2 of 7).
package services

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// newSecretMachineTestRig seeds a project/environment, one secret, a role
// bundling secrets.read+write+delete, and a machine identity granted that
// role at the project's scope. Returns the SecretGRPCService, the secret's
// ID, and a context carrying that machine as the authenticated principal.
func newSecretMachineTestRig(t *testing.T) (*SecretGRPCService, uint, context.Context) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	// AllTestModels() (not a hand-picked subset): a hand-picked list silently
	// hides schema divergence the moment a code path this test exercises
	// touches one more table than the author anticipated (see PR #2037).
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	proj, err := cs.CreateProject(ctx, "grpc-machine-w1", "")
	require.NoError(t, err)
	env, err := cs.CreateEnvironment(ctx, proj.ID, "default")
	require.NoError(t, err)

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "admin@example.com"}).Error)

	secret, err := cs.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "grpc-w1-target", Value: []byte("v1-initial"),
		ProjectID: proj.ID, EnvironmentID: env.ID, Type: "generic",
		CreatedBy: "admin", OwnerID: 1,
	})
	require.NoError(t, err)

	role := &models.Role{Name: "grpc_w1_writer"}
	require.NoError(t, db.Create(role).Error)
	for _, permName := range []string{"secrets.read", "secrets.write", "secrets.delete"} {
		perm := &models.Permission{}
		if err := db.Where("name = ?", permName).First(perm).Error; err != nil {
			perm = &models.Permission{Name: permName, Resource: "secrets", Action: permName}
			require.NoError(t, db.Create(perm).Error)
		}
		require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	}

	mi, err := cs.CreateMachineIdentity(ctx, proj.ID, "grpc-w1-runner", "ci", "", "", 1, 0)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.MachineIdentityRole{
		MachineIdentityID: mi.ID, RoleID: role.ID, ProjectID: proj.ID, EnvironmentID: 0,
	}).Error)

	svc := NewSecretService(cs)
	// Real machine auth (interceptors/auth.go's validateGRPCMachineToken) sets
	// Username to the machine's own Name — UpdateSecretRequest.UpdatedBy is a
	// required field, so an empty Username here would fail validation for a
	// reason unrelated to the isMachine split under test.
	machineCtx := context.WithValue(context.Background(), interceptors.GetUserContextKey(),
		&interceptors.UserContext{ActorType: core.ActorTypeMachine, MachineIdentityID: mi.ID, Username: mi.Name})
	return svc, secret.ID, machineCtx
}

// TestSecretGRPC_MachineWithRole_NotBlockedByUserIDGuard sweeps the five RPCs
// that used to hard-fail a fully-authorized machine principal.
func TestSecretGRPC_MachineWithRole_NotBlockedByUserIDGuard(t *testing.T) {
	svc, secretID, ctx := newSecretMachineTestRig(t)

	_, err := svc.GetSecret(ctx, &pb.GetSecretRequest{Id: uint32(secretID)})
	require.NoError(t, err, "machine with secrets.read must be able to GetSecret")

	val, err := svc.GetSecretValue(ctx, &pb.GetSecretRequest{Id: uint32(secretID)})
	require.NoError(t, err, "machine with secrets.read must be able to GetSecretValue")
	assert.Equal(t, "v1-initial", val.GetValue())

	newValue := "v2-updated"
	updated, err := svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{Id: uint32(secretID), Value: &newValue})
	require.NoError(t, err, "machine with secrets.write must be able to UpdateSecret")
	assert.NotNil(t, updated)

	versions, err := svc.GetSecretVersions(ctx, &pb.GetSecretVersionsRequest{Id: uint32(secretID)})
	require.NoError(t, err, "machine with secrets.read must be able to GetSecretVersions")
	assert.NotEmpty(t, versions.GetVersions())

	_, err = svc.DeleteSecret(ctx, &pb.DeleteSecretRequest{Id: uint32(secretID)})
	require.NoError(t, err, "machine with secrets.delete must be able to DeleteSecret")
}

// TestSecretGRPC_MachineWithoutRole_Forbidden proves the fix does not open the
// RPCs for an unauthorized machine — a fresh machine identity with no role
// grant at all must still be denied at authorizeSecretScoped, before ever
// reaching the (now-fixed) core call.
func TestSecretGRPC_MachineWithoutRole_Forbidden(t *testing.T) {
	svc, secretID, _ := newSecretMachineTestRig(t)

	// A machine ID never granted any role in this fixture's DB — resolving
	// zero role IDs at scope must deny, not be treated as "no check needed".
	unauthCtx := context.WithValue(context.Background(), interceptors.GetUserContextKey(),
		&interceptors.UserContext{ActorType: core.ActorTypeMachine, MachineIdentityID: 999})

	badValue := "should-not-apply"
	_, err := svc.UpdateSecret(unauthCtx, &pb.UpdateSecretRequest{Id: uint32(secretID), Value: &badValue})
	require.Error(t, err, "a machine with no role grant must be denied")
	assert.NotContains(t, err.Error(), "user ID is required")
}
