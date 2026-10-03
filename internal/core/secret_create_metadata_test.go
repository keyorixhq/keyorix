package core

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestCreateSecret_MetadataPersists is the regression test for a gap MIG-1's
// vault-migration-fidelity harness found: CreateSecretRequest.Metadata was
// validated and decoded all the way from the HTTP/gRPC request body down into
// core.CreateSecret, but never written onto the *models.SecretNode being
// created -- applyUpdateSecretFields (used only by UpdateSecret) has always
// done this correctly; CreateSecret had no equivalent. Before this fix, every
// metadata key a caller set at creation time was silently discarded, which in
// turn breaks keyorix-migrate's documented "re-running is safe" guarantee:
// its idempotency check reads a secret's stored metadata back to tell "I
// created this before" (skip) from "something else has this name" (conflict)
// -- with metadata always empty on create, every already-migrated secret
// would misclassify as a conflict on a second run, not a skip.
func TestCreateSecret_MetadataPersists(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{}))

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	proj, err := c.storage.CreateProject(ctx, &models.Project{Name: "p"})
	require.NoError(t, err)
	env, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: proj.ID})
	require.NoError(t, err)

	created, err := c.CreateSecret(ctx, &CreateSecretRequest{
		Name:          "db-password",
		Value:         []byte("s3cr3t-value-长度足够"),
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		Type:          "generic",
		CreatedBy:     "migrator",
		Metadata: map[string]string{
			"migrate.source":    "vault",
			"migrate.source-id": "deadbeef",
			"vault.owner":       "payments-team",
		},
	})
	require.NoError(t, err)

	// Immediately-returned value.
	gotImmediate := map[string]string{}
	require.NoError(t, json.Unmarshal(created.Metadata, &gotImmediate))
	assert.Equal(t, "vault", gotImmediate["migrate.source"])
	assert.Equal(t, "deadbeef", gotImmediate["migrate.source-id"])
	assert.Equal(t, "payments-team", gotImmediate["vault.owner"])

	// Re-read from storage -- proves it was actually persisted, not merely
	// echoed back from the in-memory request.
	reread, err := c.storage.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	gotReread := map[string]string{}
	require.NoError(t, json.Unmarshal(reread.Metadata, &gotReread))
	assert.Equal(t, "vault", gotReread["migrate.source"])
	assert.Equal(t, "deadbeef", gotReread["migrate.source-id"])
	assert.Equal(t, "payments-team", gotReread["vault.owner"])
}

// TestCreateSecret_NoMetadataLeavesFieldEmpty proves the fix is additive --
// a create request with no Metadata at all still produces a secret with no
// metadata (nil/empty), not an empty-but-present `{}` or a crash from a nil
// map being marshaled.
func TestCreateSecret_NoMetadataLeavesFieldEmpty(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{}))

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	proj, err := c.storage.CreateProject(ctx, &models.Project{Name: "p"})
	require.NoError(t, err)
	env, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: proj.ID})
	require.NoError(t, err)

	created, err := c.CreateSecret(ctx, &CreateSecretRequest{
		Name: "plain", Value: []byte("just-a-value"), ProjectID: proj.ID, EnvironmentID: env.ID,
		Type: "generic", CreatedBy: "u",
	})
	require.NoError(t, err)
	assert.Empty(t, created.Metadata)
}
