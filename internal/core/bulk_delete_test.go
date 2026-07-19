package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupBulkDeleteDB opens an in-memory SQLite DB, migrates the necessary models,
// and returns a core instance plus a factory for creating test secrets.
func setupBulkDeleteDB(t *testing.T) (*KeyorixCore, func(name string) uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())

	// Use a unique in-memory DSN per test to avoid shared state across tests.
	dsn := "file:bulkdelete_" + t.Name() + "?mode=memory&cache=shared&_busy_timeout=5000"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)

	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.Project{},
		&models.Environment{},
		&models.AuditEvent{},
		&models.SecretAccessLog{},
		&models.ShareRecord{},
	))

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()

	p, err := c.storage.CreateProject(ctx, &models.Project{Name: "proj-bulk-delete"})
	require.NoError(t, err)
	env, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "test", ProjectID: p.ID})
	require.NoError(t, err)

	projectID := p.ID
	envID := env.ID

	mk := func(name string) uint {
		s, e := c.storage.CreateSecret(ctx, &models.SecretNode{
			Name:          name,
			ProjectID:     projectID,
			EnvironmentID: envID,
			Type:          "password",
			OwnerID:       1,
			IsSecret:      true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		})
		require.NoError(t, e)
		return s.ID
	}

	return c, mk
}

func TestBulkDeleteSecrets_Success(t *testing.T) {
	c, mk := setupBulkDeleteDB(t)
	ctx := context.Background()

	id1 := mk("secret-a")
	id2 := mk("secret-b")
	id3 := mk("secret-c")

	req := BulkDeleteRequest{SecretIDs: []uint{id1, id2, id3}}
	result, err := c.BulkDeleteSecrets(ctx, req, 0, "tester", 1, "", "")
	require.NoError(t, err)
	assert.Len(t, result.Deleted, 3)
	assert.Empty(t, result.Failed)
	assert.Equal(t, 3, result.Total)
}

func TestBulkDeleteSecrets_PartialFailure(t *testing.T) {
	c, mk := setupBulkDeleteDB(t)
	ctx := context.Background()

	id1 := mk("partial-a")
	id2 := mk("partial-b")
	missingID := uint(99999)

	req := BulkDeleteRequest{SecretIDs: []uint{id1, missingID, id2}}
	result, err := c.BulkDeleteSecrets(ctx, req, 0, "tester", 1, "", "")
	require.NoError(t, err)

	// Two should succeed, one should fail.
	assert.Len(t, result.Deleted, 2)
	require.Len(t, result.Failed, 1)
	assert.Equal(t, missingID, result.Failed[0].SecretID)
	assert.Contains(t, result.Failed[0].Error, "not found")
	assert.Equal(t, 3, result.Total)
}

func TestBulkDeleteSecrets_EmptyRequest(t *testing.T) {
	c, _ := setupBulkDeleteDB(t)
	ctx := context.Background()

	req := BulkDeleteRequest{SecretIDs: nil}
	_, err := c.BulkDeleteSecrets(ctx, req, 0, "tester", 1, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestBulkDeleteSecrets_AlreadyDeleted(t *testing.T) {
	c, mk := setupBulkDeleteDB(t)
	ctx := context.Background()

	id := mk("to-delete-twice")

	// First deletion should succeed.
	req := BulkDeleteRequest{SecretIDs: []uint{id}}
	result, err := c.BulkDeleteSecrets(ctx, req, 0, "tester", 1, "", "")
	require.NoError(t, err)
	assert.Len(t, result.Deleted, 1)
	assert.Empty(t, result.Failed)

	// Second attempt on the same (now-deleted) ID must not panic; it should fail gracefully.
	result2, err := c.BulkDeleteSecrets(ctx, req, 0, "tester", 1, "", "")
	require.NoError(t, err)
	assert.Empty(t, result2.Deleted)
	require.Len(t, result2.Failed, 1)
	assert.Equal(t, id, result2.Failed[0].SecretID)
}

func TestBulkDeleteSecrets_VerifyCleanup(t *testing.T) {
	c, mk := setupBulkDeleteDB(t)
	ctx := context.Background()

	id1 := mk("cleanup-a")
	id2 := mk("cleanup-b")
	id3 := mk("cleanup-c-keep") // this one stays

	req := BulkDeleteRequest{SecretIDs: []uint{id1, id2}}
	result, err := c.BulkDeleteSecrets(ctx, req, 0, "tester", 1, "", "")
	require.NoError(t, err)
	assert.Len(t, result.Deleted, 2)

	// After bulk delete, deleted secrets must no longer appear in ListSecrets.
	secrets, _, err := c.ListSecrets(ctx, &coreStorage.SecretFilter{PageSize: 100})
	require.NoError(t, err)

	liveIDs := make(map[uint]bool)
	for _, s := range secrets {
		liveIDs[s.ID] = true
	}
	assert.False(t, liveIDs[id1], "id1 should not appear in ListSecrets after delete")
	assert.False(t, liveIDs[id2], "id2 should not appear in ListSecrets after delete")
	assert.True(t, liveIDs[id3], "id3 should still appear in ListSecrets")
}
