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
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "default"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "development"}).Error)
	// The owner user (id 1) — ListSecretsWithSharingInfo resolves owner usernames.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "owner@example.com"}).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	return &secretTestRig{svc: NewSecretService(coreService), db: db}
}

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
	ctx := authCtx(1, "reader", "secrets.read") // no write
	_, err := r.svc.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name: "x", Value: "y", ProjectId: 1, EnvironmentId: 1, Type: "password",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
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
