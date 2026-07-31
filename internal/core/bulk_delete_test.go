package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
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
		&models.SecretACL{},
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

func TestBulkDeleteSecrets_ZeroID(t *testing.T) {
	c, _ := setupBulkDeleteDB(t)
	ctx := context.Background()

	// SecretID=0 is explicitly rejected before any storage call.
	req := BulkDeleteRequest{SecretIDs: []uint{0, 1}}
	result, err := c.BulkDeleteSecrets(ctx, req, 0, "tester", 1, "", "")
	require.NoError(t, err)

	// ID 0 must appear in Failed; ID 1 is not found.
	zeroFailed := false
	for _, f := range result.Failed {
		if f.SecretID == 0 {
			zeroFailed = true
			assert.Contains(t, f.Error, "non-zero")
		}
	}
	assert.True(t, zeroFailed, "ID 0 must be in the failed list")
}

// TestBulkDeleteSecrets_CrossProjectGuard covers the cross-project guard branch
// (bulk_delete.go lines 74-80): a secret that belongs to project B must be
// rejected when the caller passes projectID=A, even if the caller holds a token
// with broad permissions.
func TestBulkDeleteSecrets_CrossProjectGuard(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	ctx := context.Background()

	dsn := "file:bulkdelete_crossproject_" + t.Name() + "?mode=memory&cache=shared&_busy_timeout=5000"
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
		&models.SecretACL{},
	))

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}

	// Create two distinct projects.
	proj1, err := c.storage.CreateProject(ctx, &models.Project{Name: "project-one"})
	require.NoError(t, err)
	proj2, err := c.storage.CreateProject(ctx, &models.Project{Name: "project-two"})
	require.NoError(t, err)

	env1, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "env1", ProjectID: proj1.ID})
	require.NoError(t, err)
	env2, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "env2", ProjectID: proj2.ID})
	require.NoError(t, err)

	// Create a secret in project 1 and a secret in project 2.
	secretInProj1, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "secret-p1", ProjectID: proj1.ID, EnvironmentID: env1.ID,
		Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	secretInProj2, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "secret-p2", ProjectID: proj2.ID, EnvironmentID: env2.ID,
		Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	// Attempt to bulk-delete both secrets while scoped to project 1.
	// secret-p1 should succeed; secret-p2 must be rejected by the guard.
	req := BulkDeleteRequest{SecretIDs: []uint{secretInProj1.ID, secretInProj2.ID}}
	result, err := c.BulkDeleteSecrets(ctx, req, proj1.ID, "tester", 1, "127.0.0.1", "test-agent")
	require.NoError(t, err)

	// Exactly one deleted (the one in project 1).
	require.Len(t, result.Deleted, 1, "only the in-scope secret should be deleted")
	assert.Equal(t, secretInProj1.ID, result.Deleted[0])

	// Exactly one failure: the cross-project secret.
	require.Len(t, result.Failed, 1, "the out-of-scope secret must appear in Failed")
	assert.Equal(t, secretInProj2.ID, result.Failed[0].SecretID)
	assert.Equal(t, "secret-p2", result.Failed[0].Name)
	assert.Contains(t, result.Failed[0].Error, "does not belong to this project")
	assert.Equal(t, 2, result.Total)
}

// TestBulkDeleteSecrets_DeleteSecretRuntimeError covers the branch where
// BulkDeleteSecrets successfully pre-fetches a secret but the underlying
// DeleteSecret call returns a runtime error (bulk_delete.go lines 86-92).
// This is exercised via MockStorage so the storage.DeleteSecret can be made
// to return an error while storage.GetSecret succeeds.
func TestBulkDeleteSecrets_DeleteSecretRuntimeError(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	ctx := context.Background()

	const secretID = uint(42)
	secret := &models.SecretNode{
		ID:        secretID,
		Name:      "my-secret",
		ProjectID: 1,
	}
	storageErr := fmt.Errorf("disk I/O error")

	ms := new(MockStorage)
	// First GetSecret call: BulkDeleteSecrets pre-fetch.
	ms.On("GetSecret", mock.Anything, secretID).Return(secret, nil).Once()
	// Second GetSecret call: inside DeleteSecret itself.
	ms.On("GetSecret", mock.Anything, secretID).Return(secret, nil).Once()
	// DeleteSecret returns a runtime error.
	ms.On("DeleteSecret", mock.Anything, secretID).Return(storageErr)

	c := NewKeyorixCore(ms)

	req := BulkDeleteRequest{SecretIDs: []uint{secretID}}
	result, err := c.BulkDeleteSecrets(ctx, req, 0, "tester", 1, "", "")
	require.NoError(t, err, "BulkDeleteSecrets itself must not error on individual failures")

	assert.Empty(t, result.Deleted, "nothing should be in Deleted when DeleteSecret errors")
	require.Len(t, result.Failed, 1, "the failed deletion must appear in Failed")
	assert.Equal(t, secretID, result.Failed[0].SecretID)
	assert.Equal(t, "my-secret", result.Failed[0].Name)
	assert.NotEmpty(t, result.Failed[0].Error)
	assert.Equal(t, 1, result.Total)

	ms.AssertExpectations(t)
}
