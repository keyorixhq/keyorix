//go:build noaws

package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// dynamic_secrets_failclosed_noaws_test.go is the ADR-109 step 6 S2 proof,
// for the noaws tag, of the ONE genuinely runtime (not just boot-time)
// "config enables a backend whose implementation isn't compiled in" path in
// this track: dynamic secrets have no top-level enabled flag resolved once
// at boot (wireDynamicSecrets wires the factory unconditionally; each
// DynamicSecretConfig opts in individually, and the concrete engine is only
// resolved the moment a config is created or a lease is issued against it —
// see internal/core/dynamic_secrets.go's own doc comments). That makes THIS
// the literal "API call reaches an unregistered backend" case the track spec
// names, distinct from connect/rotation/encryption's boot-time Fatalf checks
// (see server/adr109_failclosed_noaws_test.go).

// TestCreateDynamicSecretConfig_AWSSTS_NoAWSBuild_FailsClosed proves the
// earliest possible rejection point: an admin trying to CREATE a
// dynamic-secret config naming the aws-sts backend in a noaws build gets a
// clear error and nothing is persisted — the config row never exists, so no
// later call can ever reach IssueLease against it.
func TestCreateDynamicSecretConfig_AWSSTS_NoAWSBuild_FailsClosed(t *testing.T) {
	c, db := newFailClosedTestCore(t)

	_, err := c.CreateDynamicSecretConfig(context.Background(), &CreateDynamicSecretConfigRequest{
		Name: "prod-aws-sts", ProjectID: 1, EnvironmentID: 2, BackendType: "aws-sts",
		AdminDSN: "unused", ActorID: testAdminActorID,
	})
	require.Error(t, err, "creating an aws-sts dynamic-secret config must fail closed in a noaws build")
	assert.Contains(t, err.Error(), "aws-sts")
	assert.Contains(t, err.Error(), "not available in this build")

	var count int64
	require.NoError(t, db.Model(&models.DynamicSecretConfig{}).Count(&count).Error)
	assert.Zero(t, count, "no config row must be persisted when creation was refused")
}

// TestIssueLease_AWSSTS_PreExistingConfig_NoAWSBuild_FailsClosed covers the
// track spec's exact example shape — "a stored connect config for AWS SM on
// an air-gapped build" — for dynamic secrets: a DynamicSecretConfig row that
// already exists (e.g. created before this binary was rebuilt with -tags
// noaws, or migrated from a full-build install), inserted directly here to
// bypass CreateDynamicSecretConfig's own up-front check and isolate
// IssueLease's. No admin DSN ciphertext is set up (AdminDSNEnc/Meta are left
// nil) — engine.Issue is never reached before the AdminDSN decrypt step in
// IssueLease's own source order, and this test's zero-byte fields would fail
// obviously and loudly if it somehow ever did.
func TestIssueLease_AWSSTS_PreExistingConfig_NoAWSBuild_FailsClosed(t *testing.T) {
	c, db := newFailClosedTestCore(t)

	cfg := &models.DynamicSecretConfig{
		Name: "legacy-aws-sts", ProjectID: 1, EnvironmentID: 2, BackendType: "aws-sts",
		DefaultTTLSeconds: 900,
	}
	require.NoError(t, db.Create(cfg).Error)

	issued, err := c.IssueLease(context.Background(), cfg.ID, 0, testAdminActorID)
	require.Error(t, err, "issuing a lease against a stored aws-sts config must fail closed in a noaws build")
	assert.Nil(t, issued, "no lease value may be returned alongside the error")
	assert.Contains(t, err.Error(), "aws-sts")
	assert.Contains(t, err.Error(), "not available in this build")

	var leaseCount int64
	require.NoError(t, db.Model(&models.DynamicSecretLease{}).Count(&leaseCount).Error)
	assert.Zero(t, leaseCount, "no lease row (and so no encrypted credential) must be persisted")
}

// newFailClosedTestCore builds a *KeyorixCore wired exactly as
// server/main.go's DefaultIntegrations wires production (the real
// dynamic.New factory, ADR-109 step 3), with one admin-bypass user and one
// live project/environment (row IDs 1/2, matched by the two tests above) —
// everything IssueLease's requireLiveProjectAndEnvironment and
// CreateDynamicSecretConfig's own checks need to get PAST those and reach
// the backend-availability check this file is actually proving.
func newFailClosedTestCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.DynamicSecretConfig{}, &models.DynamicSecretLease{}, &models.AuditEvent{},
		&models.Role{}, &models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{},
	))
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: testAdminActorID, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "failclosed-project"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, ProjectID: 1, Name: "failclosed-env"}).Error)
	fixed := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return fixed }, passwordPolicy: DefaultPasswordPolicy()}
	c.SetDynamicEngineFactory(func(bt string) (dynamic.CredentialEngine, error) { return dynamic.New(bt, false, false) })
	return c, db
}
