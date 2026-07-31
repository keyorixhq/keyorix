package services

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// newDynamicTestRig seeds a real core with encryption (for the admin-DSN ciphertext),
// a fake credential engine (so Issue/Revoke/Renew don't touch a real DB), and a
// user (id 1) holding a global writer role with secrets.read/write/delete.
func newDynamicTestRig(t *testing.T) *DynamicSecretGRPCService {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.User{}, &models.Role{},
		&models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.AuditEvent{},
		&models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "default"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "dev"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "writer"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 2, Name: "secrets.write", Resource: "secrets", Action: "write"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 2}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error)
	// #162: binding a dynamic-secret backend needs admin authority, not just
	// secrets.write — grant user 1 (also, separately from "writer") a global admin role.
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "admin"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 2}).Error)

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	coreService.SetAuthEncryptor(enc)
	coreService.SetDynamicAllowPrivateTargets(true) // tests use localhost DSNs; real SSRF guard tested in dynamic_secrets_ssrf_test.go
	fake := &dynamic.FakeEngine{NativeExpiry: true}
	coreService.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })
	return NewDynamicSecretService(coreService)
}

func TestDynamicSecretService_ConfigAndLeaseFlow(t *testing.T) {
	svc := newDynamicTestRig(t)
	ctx := authCtx(1, "owner")

	// Create a config — admin DSN encrypted server-side, never returned.
	cfg, err := svc.CreateConfig(ctx, &pb.CreateDynamicConfigRequest{
		Name: "analytics-ro", ProjectId: 1, EnvironmentId: 1, BackendType: "postgres",
		AdminDsn: "postgres://admin:pw@localhost/db", CreationTemplate: "GRANT SELECT TO {{name}};",
		DefaultTtlSeconds: 3600, MaxTtlSeconds: 86400, Classification: "confidential",
	})
	require.NoError(t, err)
	assert.NotZero(t, cfg.GetId())
	assert.Equal(t, "confidential", cfg.GetClassification())

	// Get + List.
	got, err := svc.GetConfig(ctx, &pb.GetDynamicConfigRequest{Id: cfg.GetId()})
	require.NoError(t, err)
	assert.Equal(t, "analytics-ro", got.GetName())

	list, err := svc.ListConfigs(ctx, &pb.ListDynamicConfigsRequest{ProjectId: 1, EnvironmentId: 1})
	require.NoError(t, err)
	require.Len(t, list.GetConfigs(), 1)

	// Reclassify.
	rc, err := svc.ClassifyConfig(ctx, &pb.ClassifyDynamicConfigRequest{Id: cfg.GetId(), Classification: "restricted"})
	require.NoError(t, err)
	assert.Equal(t, "restricted", rc.GetClassification())

	// Issue a lease — credential returned once.
	cred, err := svc.IssueLease(ctx, &pb.IssueLeaseRequest{ConfigId: cfg.GetId()})
	require.NoError(t, err)
	assert.NotEmpty(t, cred.GetLeaseId())
	assert.NotEmpty(t, cred.GetUsername())
	assert.NotEmpty(t, cred.GetPassword())

	// List leases shows it active.
	leases, err := svc.ListLeases(ctx, &pb.ListLeasesRequest{ConfigId: cfg.GetId()})
	require.NoError(t, err)
	require.Len(t, leases.GetLeases(), 1)
	assert.Equal(t, "active", leases.GetLeases()[0].GetStatus())

	// Renew with a longer TTL than the default 3600s so it actually extends.
	_, err = svc.RenewLease(ctx, &pb.RenewLeaseRequest{LeaseId: cred.GetLeaseId(), TtlSeconds: 7200})
	require.NoError(t, err)
	_, err = svc.RevokeLease(ctx, &pb.RevokeLeaseRequest{LeaseId: cred.GetLeaseId()})
	require.NoError(t, err)
}

func TestDynamicSecretService_AuthzAndValidation(t *testing.T) {
	svc := newDynamicTestRig(t)

	// Unauthenticated.
	_, err := svc.ListConfigs(context.Background(), &pb.ListDynamicConfigsRequest{ProjectId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	// No grants → permission denied on create.
	nobody := authCtx(999, "nobody")
	_, err = svc.CreateConfig(nobody, &pb.CreateDynamicConfigRequest{
		Name: "x", ProjectId: 1, EnvironmentId: 1, BackendType: "postgres", AdminDsn: "postgres://x",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// Missing required fields.
	owner := authCtx(1, "owner")
	_, err = svc.CreateConfig(owner, &pb.CreateDynamicConfigRequest{Name: "", ProjectId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	// Unknown lease → not found.
	_, err = svc.RevokeLease(owner, &pb.RevokeLeaseRequest{LeaseId: "nope"})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))

	// RevokeAll on an empty config is a no-op success once a config exists.
	cfg, err := svc.CreateConfig(owner, &pb.CreateDynamicConfigRequest{
		Name: "c", ProjectId: 1, EnvironmentId: 1, BackendType: "postgres", AdminDsn: "postgres://x",
	})
	require.NoError(t, err)
	res, err := svc.RevokeAllLeases(owner, &pb.RevokeAllLeasesRequest{ConfigId: cfg.GetId()})
	require.NoError(t, err)
	assert.Equal(t, uint32(0), res.GetRevoked())
}
