package services

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type shareTestRig struct {
	svc      *ShareGRPCService
	core     *core.KeyorixCore
	secretID uint32
}

// newShareTestRig builds a real core with a seeded secret (owned by user 1) and
// a recipient user (id 2), plus the gRPC ShareService under test.
func newShareTestRig(t *testing.T) *shareTestRig {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.SecretVersion{}, &models.User{}, &models.Role{}, &models.ShareRecord{},
		&models.Group{}, &models.UserGroup{}, // ListSharedSecrets joins user_groups
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "default"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "development"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "owner@example.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "recipient", Email: "rcpt@example.com"}).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	secret, err := coreService.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: "shared-secret", Value: []byte("v"), ProjectID: 1, EnvironmentID: 1,
		Type: "password", CreatedBy: "owner", OwnerID: 1,
	})
	require.NoError(t, err)

	return &shareTestRig{
		svc:      NewShareService(coreService),
		core:     coreService,
		secretID: intToU32(int(secret.ID)),
	}
}

func ownerCtx() context.Context {
	return authCtx(1, "owner", "secrets.write", "secrets.read")
}

func (r *shareTestRig) share(t *testing.T, perm string) *pb.ShareRecord {
	t.Helper()
	rec, err := r.svc.ShareSecret(ownerCtx(), &pb.ShareSecretRequest{
		SecretId: r.secretID, RecipientId: 2, Permission: perm,
	})
	require.NoError(t, err)
	return rec
}

func TestShareService_ShareSecret(t *testing.T) {
	r := newShareTestRig(t)
	rec := r.share(t, "read")
	assert.NotZero(t, rec.GetId())
	assert.Equal(t, r.secretID, rec.GetSecretId())
	assert.Equal(t, uint32(2), rec.GetRecipientId())
	assert.Equal(t, "read", rec.GetPermission())
}

func TestShareService_ShareSecret_Unauthenticated(t *testing.T) {
	r := newShareTestRig(t)
	_, err := r.svc.ShareSecret(context.Background(), &pb.ShareSecretRequest{
		SecretId: r.secretID, RecipientId: 2, Permission: "read",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestShareService_ShareSecret_PermissionDenied(t *testing.T) {
	r := newShareTestRig(t)
	ctx := authCtx(1, "owner", "secrets.read") // no write
	_, err := r.svc.ShareSecret(ctx, &pb.ShareSecretRequest{
		SecretId: r.secretID, RecipientId: 2, Permission: "read",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestShareService_ShareSecret_InvalidPermission(t *testing.T) {
	r := newShareTestRig(t)
	_, err := r.svc.ShareSecret(ownerCtx(), &pb.ShareSecretRequest{
		SecretId: r.secretID, RecipientId: 2, Permission: "admin",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestShareService_ListSecretShares(t *testing.T) {
	r := newShareTestRig(t)
	r.share(t, "read")

	resp, err := r.svc.ListSecretShares(ownerCtx(), &pb.ListSecretSharesRequest{SecretId: r.secretID})
	require.NoError(t, err)
	require.Len(t, resp.GetShares(), 1)
	assert.Equal(t, uint32(2), resp.GetShares()[0].GetRecipientId())
}

func TestShareService_UpdateSharePermission(t *testing.T) {
	r := newShareTestRig(t)
	rec := r.share(t, "read")

	updated, err := r.svc.UpdateSharePermission(ownerCtx(), &pb.UpdateSharePermissionRequest{
		ShareId: rec.GetId(), Permission: "write",
	})
	require.NoError(t, err)
	assert.Equal(t, "write", updated.GetPermission())
}

func TestShareService_RevokeShare(t *testing.T) {
	r := newShareTestRig(t)
	rec := r.share(t, "read")

	_, err := r.svc.RevokeShare(ownerCtx(), &pb.RevokeShareRequest{ShareId: rec.GetId()})
	require.NoError(t, err)

	resp, err := r.svc.ListSecretShares(ownerCtx(), &pb.ListSecretSharesRequest{SecretId: r.secretID})
	require.NoError(t, err)
	assert.Empty(t, resp.GetShares())
}

func TestShareService_ListUserShares(t *testing.T) {
	r := newShareTestRig(t)
	r.share(t, "read")

	resp, err := r.svc.ListUserShares(ownerCtx(), &pb.ListUserSharesRequest{})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.GetShares()), 1)
}

func TestShareService_ListSharedSecrets(t *testing.T) {
	r := newShareTestRig(t)
	r.share(t, "read")

	// Listed from the recipient's perspective (user 2).
	ctx := authCtx(2, "recipient", "secrets.read")
	resp, err := r.svc.ListSharedSecrets(ctx, &pb.ListSharedSecretsRequest{})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp.GetSecrets()), 1)
	assert.Equal(t, "shared-secret", resp.GetSecrets()[0].GetName())
}
