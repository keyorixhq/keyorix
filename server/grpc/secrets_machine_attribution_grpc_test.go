// secrets_machine_attribution_grpc_test.go — gRPC counterpart to
// server/http's secrets_machine_attribution_test.go (coordinator follow-up on
// #2319, W1, 2026-09-29). Proves the SAME invariant server_integration_test.go's
// TestGRPCServer_EndToEnd style of test proves for other concerns: a machine
// caller's audit trail is attributed to the machine identity (ActorType
// machine_identity, MachineIdentityID set, UserID nil), not UserID 0 — driven
// through the REAL gRPC server (keyorixgrpc.NewServer, real auth interceptor,
// real bufconn wire) rather than a hand-built UserContext, so the interceptor's
// own context tagging (withAuditAttribution, server/grpc/interceptors/auth.go)
// is genuinely exercised, not assumed.
//
// gRPC has no Rotate/Rollback RPC on SecretService (see keyorix.proto) --
// rotate/rollback are HTTP-only, already covered by the HTTP-side test file --
// so this file covers UpdateSecret and DeleteSecret only.
package grpc_test

import (
	"context"
	"net"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	keyorixgrpc "github.com/keyorixhq/keyorix/server/grpc"
	"github.com/keyorixhq/keyorix/server/grpc/services"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	sqlite "gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// grpcMachineAttributionFixture starts a real gRPC server (all services, real
// auth interceptor) over bufconn, backed by a fully-migrated core, and returns
// a connected SecretServiceClient, a machine bearer token authorized
// secrets.read/write/delete at the secret's project, the secret's ID, the core
// service (to read the audit trail back), the bootstrap admin's ID, and the
// machine identity's ID.
func grpcMachineAttributionFixture(t *testing.T) (secrets pb.SecretServiceClient, token string, secretID uint, c *core.KeyorixCore, adminID, machineID uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	// AllTestModels(), not a hand-picked subset -- see PR #2037: a hand-picked
	// list silently hides schema divergence the moment a code path this test
	// exercises (BootstrapSystem's full RBAC seed, audit writes, ...) touches
	// one more table than anticipated.
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	// AllTestModels() doesn't include SecretAccessLog -- without it, the
	// update/delete access-log write (a separate, best-effort call alongside
	// the audit_events write this test cares about) fails with a noisy
	// "no such table" log line on every run.
	require.NoError(t, db.AutoMigrate(&models.SecretAccessLog{}))

	c = core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	c.SetBootstrapToken("test-bootstrap-token")
	_, err = c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "testadmin", Email: "testadmin@example.com",
		Password: "TestPassword123!", Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	admin, err := c.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)

	projects, err := c.ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects)
	project := projects[0]
	envs, err := c.ListEnvironments(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	env := envs[0]

	secret, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "w1-grpc-attribution-target", Value: []byte("v1-initial"),
		ProjectID: project.ID, EnvironmentID: env.ID, Type: "generic",
		CreatedBy: admin.Username, OwnerID: admin.ID,
	})
	require.NoError(t, err)

	mi, err := c.CreateMachineIdentity(ctx, project.ID, "w1-grpc-attribution-runner", "ci", "", "", admin.ID, 0)
	require.NoError(t, err)
	tok, err := c.IssueMachineToken(ctx, project.ID, mi.ID, admin.ID, core.IssueMachineTokenParams{Name: "w1-grpc-attribution-token"})
	require.NoError(t, err)

	roles, err := c.Storage().ListRoles(ctx)
	require.NoError(t, err)
	var roleID uint
	for _, r := range roles {
		if r.Name == "project_developer" {
			roleID = r.ID
			break
		}
	}
	require.NotZero(t, roleID, "builtin role project_developer must exist")
	require.NoError(t, c.AssignMachineRole(ctx, mi.ID, roleID, core.Scope{ProjectID: project.ID}, admin.ID, false))

	srv, err := keyorixgrpc.NewServer(&config.Config{}, c)
	require.NoError(t, err)
	lis := bufconn.Listen(1024 * 1024)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return pb.NewSecretServiceClient(conn), tok.PlainToken, secret.ID, c, admin.ID, mi.ID
}

func bearerCtx(token string) context.Context {
	return metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
}

// TestSecretGRPC_UpdateSecret_MachineActor_AuditAttributedToMachine mirrors
// server/http's TestUpdateSecret_MachineActor_AuditAttributedToMachine: the
// same audit choke point (core.emitAudit) is shared by both transports, but
// only the interceptor that tags the context differs (withAuditAttribution
// here vs buildRequestContext on HTTP) -- both must be proven independently,
// since either one alone missing the tag reproduces the #1530 gap for its
// transport only.
func TestSecretGRPC_UpdateSecret_MachineActor_AuditAttributedToMachine(t *testing.T) {
	secrets, token, secretID, c, adminID, machineID := grpcMachineAttributionFixture(t)

	newValue := "v2-grpc-machine-updated"
	_, err := secrets.UpdateSecret(bearerCtx(token), &pb.UpdateSecretRequest{Id: uint32(secretID), Value: &newValue})
	require.NoError(t, err, "machine with secrets.write must be able to UpdateSecret")

	services.DrainBackgroundGoroutines()
	core.DrainBackgroundGoroutines()

	events, err := c.ListSecretAuditEvents(context.Background(), secretID, adminID, 10)
	require.NoError(t, err)

	ev := findGRPCAuditEvent(events, "secret.updated")
	if !assert.NotNil(t, ev, "expected a secret.updated audit event") {
		return
	}
	assert.Equal(t, core.ActorTypeMachine, ev.ActorType)
	if assert.NotNil(t, ev.MachineIdentityID) {
		assert.Equal(t, machineID, *ev.MachineIdentityID)
	}
	assert.Nil(t, ev.UserID, "UserID must be nil for a machine actor, never user 0")
}

// TestSecretGRPC_DeleteSecret_MachineActor_AuditAttributedToMachine is the
// delete counterpart.
func TestSecretGRPC_DeleteSecret_MachineActor_AuditAttributedToMachine(t *testing.T) {
	secrets, token, secretID, c, _, machineID := grpcMachineAttributionFixture(t)

	_, err := secrets.DeleteSecret(bearerCtx(token), &pb.DeleteSecretRequest{Id: uint32(secretID)})
	require.NoError(t, err, "machine with secrets.delete must be able to DeleteSecret")

	services.DrainBackgroundGoroutines()
	core.DrainBackgroundGoroutines()

	// DeleteSecret is a hard delete, so the secret row is gone and
	// ListSecretAuditEvents' own permission check (which needs to load the
	// secret) would fail -- read the audit_events row straight from storage
	// instead, same as the HTTP-side delete test.
	events, _, err := c.Storage().GetAuditLogs(context.Background(), &coreStorage.AuditFilter{SecretID: &secretID, PageSize: 10})
	require.NoError(t, err)

	ev := findGRPCAuditEvent(events, "secret.deleted")
	if !assert.NotNil(t, ev, "expected a secret.deleted audit event") {
		return
	}
	assert.Equal(t, core.ActorTypeMachine, ev.ActorType)
	if assert.NotNil(t, ev.MachineIdentityID) {
		assert.Equal(t, machineID, *ev.MachineIdentityID)
	}
	assert.Nil(t, ev.UserID, "UserID must be nil for a machine actor, never user 0")
}

func findGRPCAuditEvent(events []*models.AuditEvent, eventType string) *models.AuditEvent {
	for _, e := range events {
		if e.EventType == eventType {
			return e
		}
	}
	return nil
}
