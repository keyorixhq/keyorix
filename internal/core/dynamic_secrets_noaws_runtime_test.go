//go:build noaws

package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestIssueLease_NoAWSBuild_StoredAWSSTSConfig_FailsClosedNoLeak is B1's
// (ADR-109 step 6, S2) runtime no-leak proof: a DynamicSecretConfig with
// BackendType "aws-sts" — created on some earlier, full build — must fail
// closed at IssueLease time when read back on a server actually running a
// noaws build, with NO secret material or success leak. Wires the REAL
// dynamic.New-backed factory (server/main.go's wireDynamicSecrets shape), not
// a test fake, so this exercises the same "not available in this build" path
// a production noaws server hits.
func TestIssueLease_NoAWSBuild_StoredAWSSTSConfig_FailsClosedNoLeak(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.DynamicSecretConfig{}, &models.DynamicSecretLease{}, &models.AuditEvent{},
		&models.Role{}, &models.UserRole{}, &models.Project{}, &models.Environment{},
	))
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: testAdminActorID, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "noaws-runtime-project"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, ProjectID: 1, Name: "noaws-runtime-env"}).Error)

	// Simulate a config that was created against a FULL build (aws-sts was
	// available then) and is now being read back on a noaws server — insert
	// the row directly rather than through CreateDynamicSecretConfig, which
	// itself would refuse to create an aws-sts config on this build (the
	// config-creation-time fail-closed path, already covered by
	// TestDynamicSecrets_NoFactoryConfigured_FailsClosed's sibling
	// assertions). AdminDSNEnc/Meta are left empty: dynamicEngine's
	// not-available error fires before IssueLease ever reaches the decrypt
	// step (see IssueLease's call order in dynamic_secrets.go), so no valid
	// ciphertext is needed to prove this path fails before touching it.
	cfg := &models.DynamicSecretConfig{
		Name: "legacy-aws-sts-cfg", ProjectID: 1, EnvironmentID: 2, BackendType: "aws-sts",
	}
	require.NoError(t, db.Create(cfg).Error)

	fixed := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return fixed }, passwordPolicy: DefaultPasswordPolicy()}
	// The real production wiring shape (server/main.go's wireDynamicSecrets),
	// not a test fake — this is the whole point of the test.
	c.SetDynamicEngineFactory(func(backendType string) (dynamic.CredentialEngine, error) {
		return dynamic.New(backendType, false, false)
	})

	lease, err := c.IssueLease(context.Background(), cfg.ID, 0, testAdminActorID)

	require.Error(t, err, "IssueLease must fail closed for a compiled-out backend, not silently succeed")
	assert.Contains(t, err.Error(), "not available in this build")
	assert.Contains(t, err.Error(), "aws-sts")
	assert.Nil(t, lease, "no credential material may be returned when the backend is unavailable")

	active, cerr := c.storage.CountActiveLeases(context.Background(), cfg.ID)
	require.NoError(t, cerr)
	assert.Zero(t, active, "no lease may be persisted when the backend is unavailable")
}

// TestCreateDynamicSecretConfig_NoAWSBuild_AWSSTS_FailsClosedNoLeak is the
// config-CREATION-time counterpart: attempting to bind a NEW aws-sts config
// on a noaws build must also fail closed, before any row is persisted.
func TestCreateDynamicSecretConfig_NoAWSBuild_AWSSTS_FailsClosedNoLeak(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.DynamicSecretConfig{}, &models.AuditEvent{},
		&models.Role{}, &models.UserRole{}, &models.Project{}, &models.Environment{},
	))
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: testAdminActorID, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "noaws-create-project"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, ProjectID: 1, Name: "noaws-create-env"}).Error)

	fixed := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return fixed }, passwordPolicy: DefaultPasswordPolicy()}
	c.SetDynamicEngineFactory(func(backendType string) (dynamic.CredentialEngine, error) {
		return dynamic.New(backendType, false, false)
	})

	cfg, err := c.CreateDynamicSecretConfig(context.Background(), &CreateDynamicSecretConfigRequest{
		Name: "new-aws-sts-cfg", ProjectID: 1, EnvironmentID: 2, BackendType: "aws-sts",
		AdminDSN: "unused-for-cloud-iam-backends", ActorID: testAdminActorID,
	})
	require.Error(t, err, "config creation must fail closed for a compiled-out backend")
	assert.True(t, strings.Contains(err.Error(), "not available in this build"))
	assert.Nil(t, cfg)

	var count int64
	require.NoError(t, db.Model(&models.DynamicSecretConfig{}).Count(&count).Error)
	assert.Zero(t, count, "no config row may be persisted when the backend is unavailable")
}
