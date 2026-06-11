package services

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// secretTestRig is a real core service over an in-memory DB with a seeded
// project/environment, plus the gRPC SecretService under test.
type secretTestRig struct {
	svc *SecretGRPCService
	db  *gorm.DB
}

func newSecretTestRig(t *testing.T) *secretTestRig {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.SecretVersion{}, &models.User{}, &models.Role{}, &models.ShareRecord{},
		&models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "default"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "development"}).Error)
	// The owner user (id 1) — ListSecretsWithSharingInfo resolves owner usernames.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "owner@example.com"}).Error)

	// CreateSecret authorizes secrets.write at the target scope via the RBAC graph
	// (mirroring the HTTP handler), so the test DB needs real grants — the flat
	// UserContext.Permissions no longer gate creation. Seed a "writer" role that
	// grants secrets.read/write/delete and assign user 1 globally so the owner can
	// create/read/update/delete in every test below.
	require.NoError(t, db.Create(&models.Role{ID: writerRoleID, Name: "writer"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 2, Name: "secrets.write", Resource: "secrets", Action: "write"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 3, Name: "secrets.delete", Resource: "secrets", Action: "delete"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: writerRoleID, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: writerRoleID, PermissionID: 2}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: writerRoleID, PermissionID: 3}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: writerRoleID}).Error) // global (project 0, env 0)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	return &secretTestRig{svc: NewSecretService(coreService), db: db}
}

// writerRoleID is the seeded role granting secrets.read/write/delete in the rig.
const writerRoleID = 1

// authCtx returns a context carrying a user with the given permissions, as the
// auth interceptor would populate after validating a session.
func authCtx(userID uint, username string, perms ...string) context.Context {
	return context.WithValue(context.Background(), interceptors.GetUserContextKey(),
		&interceptors.UserContext{UserID: userID, Username: username, Permissions: perms})
}

func (r *secretTestRig) createSecret(t *testing.T, ctx context.Context, name, value string) *pb.Secret {
	t.Helper()
	sec, err := r.svc.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name: name, Value: value, ProjectId: 1, EnvironmentId: 1, Type: "password",
	})
	require.NoError(t, err)
	return sec
}

func TestSecretService_CreateSecret(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "writer", "secrets.write", "secrets.read")

	sec := r.createSecret(t, ctx, "db-password", "s3cr3t")
	assert.NotZero(t, sec.GetId())
	assert.Equal(t, "db-password", sec.GetName())
	assert.Equal(t, uint32(1), sec.GetProjectId())
	assert.Equal(t, uint32(1), sec.GetEnvironmentId())
	assert.Equal(t, uint32(1), sec.GetOwnerId())
	assert.Equal(t, "active", sec.GetStatus())
}

func TestSecretService_CreateSecret_Unauthenticated(t *testing.T) {
	r := newSecretTestRig(t)
	_, err := r.svc.CreateSecret(context.Background(), &pb.CreateSecretRequest{
		Name: "x", Value: "y", ProjectId: 1, EnvironmentId: 1, Type: "password",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestSecretService_CreateSecret_PermissionDenied(t *testing.T) {
	r := newSecretTestRig(t)
	// User 2 holds no RBAC role, so Authorize denies regardless of any flat
	// permission claimed in the context.
	ctx := authCtx(2, "reader", "secrets.read") // no write grant
	_, err := r.svc.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name: "x", Value: "y", ProjectId: 1, EnvironmentId: 1, Type: "password",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// Regression (gRPC scoped-authz hardening): CreateSecret must authorize
// secrets.write at the TARGET project/environment, not against the flat global
// permission set. A user whose secrets.write is granted only in project 1 must
// not be able to create a secret in project 2 — even though their flat
// UserContext.Permissions advertise secrets.write. Previously the gRPC handler
// checked only the flat list and let a project-scoped writer create anywhere.
func TestSecretService_CreateSecret_ScopedToOtherProjectDenied(t *testing.T) {
	r := newSecretTestRig(t)
	// A second project/environment the scoped writer has no grant in.
	require.NoError(t, r.db.Create(&models.Project{ID: 2, Name: "other"}).Error)
	require.NoError(t, r.db.Create(&models.Environment{ID: 2, ProjectID: 2, Name: "development"}).Error)
	// User 3: writer role scoped to project 1 only (env 0 = all envs in project 1).
	require.NoError(t, r.db.Create(&models.User{ID: 3, Username: "scoped", Email: "scoped@example.com"}).Error)
	require.NoError(t, r.db.Create(&models.UserRole{UserID: 3, RoleID: writerRoleID, ProjectID: 1}).Error)

	// The flat list advertises write — the bug would have honoured it everywhere.
	ctx := authCtx(3, "scoped", "secrets.write", "secrets.read")

	// In-scope (project 1): allowed.
	_, err := r.svc.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name: "in-scope", Value: "v", ProjectId: 1, EnvironmentId: 1, Type: "password",
	})
	require.NoError(t, err)

	// Out-of-scope (project 2): denied.
	_, err = r.svc.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name: "cross-project", Value: "v", ProjectId: 2, EnvironmentId: 2, Type: "password",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// Regression (gRPC scoped-authz hardening): per-secret reads/writes/deletes must
// authorize at the SECRET'S project/environment, not the flat global permission
// set. A user who even OWNS a secret in a project where they hold no RBAC grant
// must still be denied over gRPC — matching the HTTP scoped gate. Previously the
// flat secrets.* check passed and the downstream owner check let them through, so
// a project-1 writer could read/update/delete their secret sitting in project 2.
func TestSecretService_PerSecretOps_ScopedToOtherProjectDenied(t *testing.T) {
	r := newSecretTestRig(t)
	require.NoError(t, r.db.Create(&models.Project{ID: 2, Name: "other"}).Error)
	require.NoError(t, r.db.Create(&models.Environment{ID: 2, ProjectID: 2, Name: "development"}).Error)
	// User 3: writer scoped to project 1 only — no grant in project 2.
	require.NoError(t, r.db.Create(&models.User{ID: 3, Username: "scoped", Email: "scoped@example.com"}).Error)
	require.NoError(t, r.db.Create(&models.UserRole{UserID: 3, RoleID: writerRoleID, ProjectID: 1}).Error)
	// A secret in project 2 that user 3 OWNS (so the owner check alone would pass).
	require.NoError(t, r.db.Create(&models.SecretNode{
		ID: 50, Name: "p2-secret", ProjectID: 2, EnvironmentID: 2, OwnerID: 3, Status: "active", Type: "password",
	}).Error)

	// Flat list advertises every permission — the bug would have honoured it.
	ctx := authCtx(3, "scoped", "secrets.read", "secrets.write", "secrets.delete")

	_, err := r.svc.GetSecret(ctx, &pb.GetSecretRequest{Id: 50})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "GetSecret cross-project")

	_, err = r.svc.GetSecretValue(ctx, &pb.GetSecretRequest{Id: 50})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "GetSecretValue cross-project")

	_, err = r.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{Id: 50})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "UpdateSecret cross-project")

	_, err = r.svc.DeleteSecret(ctx, &pb.DeleteSecretRequest{Id: 50})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "DeleteSecret cross-project")

	_, err = r.svc.GetSecretVersions(ctx, &pb.GetSecretVersionsRequest{Id: 50})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "GetSecretVersions cross-project")
}

// A scoped user CAN operate on a secret within a project where they hold the
// grant — confirming the scoped check didn't over-restrict legitimate access.
func TestSecretService_PerSecretOps_InScopeAllowed(t *testing.T) {
	r := newSecretTestRig(t)
	require.NoError(t, r.db.Create(&models.User{ID: 3, Username: "scoped", Email: "scoped@example.com"}).Error)
	require.NoError(t, r.db.Create(&models.UserRole{UserID: 3, RoleID: writerRoleID, ProjectID: 1}).Error)
	ctx := authCtx(3, "scoped", "secrets.read", "secrets.write")

	created := r.createSecret(t, ctx, "in-scope", "v") // project 1, where user 3 has the grant
	got, err := r.svc.GetSecret(ctx, &pb.GetSecretRequest{Id: created.GetId()})
	require.NoError(t, err)
	assert.Equal(t, "in-scope", got.GetName())
}

func TestSecretService_CreateSecret_Validation(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "writer", "secrets.write")
	_, err := r.svc.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name: "", Value: "y", ProjectId: 1, EnvironmentId: 1, Type: "password",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestSecretService_GetSecret(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read")
	created := r.createSecret(t, ctx, "api-key", "abc123")

	got, err := r.svc.GetSecret(ctx, &pb.GetSecretRequest{Id: created.GetId()})
	require.NoError(t, err)
	assert.Equal(t, created.GetId(), got.GetId())
	assert.Equal(t, "api-key", got.GetName())
}

func TestSecretService_GetSecret_NotFound(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "reader", "secrets.read")
	_, err := r.svc.GetSecret(ctx, &pb.GetSecretRequest{Id: 9999})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestSecretService_GetSecretValue(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read")
	created := r.createSecret(t, ctx, "token", "the-value")

	val, err := r.svc.GetSecretValue(ctx, &pb.GetSecretRequest{Id: created.GetId()})
	require.NoError(t, err)
	assert.Equal(t, "the-value", val.GetValue())
	assert.Equal(t, "token", val.GetName())
}

func TestSecretService_UpdateSecret(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read")
	created := r.createSecret(t, ctx, "rotate-me", "old")

	updated, err := r.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{
		Id: created.GetId(), Value: strPtr("new-value"),
	})
	require.NoError(t, err)
	assert.Equal(t, created.GetId(), updated.GetId())

	val, err := r.svc.GetSecretValue(ctx, &pb.GetSecretRequest{Id: created.GetId()})
	require.NoError(t, err)
	assert.Equal(t, "new-value", val.GetValue())
}

func TestSecretService_DeleteSecret(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read", "secrets.delete")
	created := r.createSecret(t, ctx, "temp", "v")

	_, err := r.svc.DeleteSecret(ctx, &pb.DeleteSecretRequest{Id: created.GetId()})
	require.NoError(t, err)

	_, err = r.svc.GetSecret(ctx, &pb.GetSecretRequest{Id: created.GetId()})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestSecretService_ListSecrets(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read")
	r.createSecret(t, ctx, "one", "a")
	r.createSecret(t, ctx, "two", "b")

	resp, err := r.svc.ListSecrets(ctx, &pb.ListSecretsRequest{})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.GetSecrets()), 2)
	assert.GreaterOrEqual(t, resp.GetTotal(), uint32(2))
}

func TestSecretService_GetSecretVersions(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read")
	created := r.createSecret(t, ctx, "versioned", "v1")

	resp, err := r.svc.GetSecretVersions(ctx, &pb.GetSecretVersionsRequest{Id: created.GetId()})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.GetVersions()), 1)
}

func strPtr(s string) *string { return &s }
