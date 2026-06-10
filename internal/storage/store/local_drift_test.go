package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newDriftTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Environment{}, &models.SecretNode{}))
	return NewLocalStorage(db)
}

func TestListProjectSecretsForDrift(t *testing.T) {
	ls := newDriftTestStore(t)
	ctx := context.Background()
	const projectID = uint(1)

	// Two live environments + one soft-deleted environment in the project.
	envs := []*models.Environment{
		{ID: 10, ProjectID: projectID, Name: "dev"},
		{ID: 20, ProjectID: projectID, Name: "prod"},
		{ID: 30, ProjectID: projectID, Name: "old"},
	}
	for _, e := range envs {
		require.NoError(t, ls.db.Create(e).Error)
	}
	require.NoError(t, ls.db.Delete(&models.Environment{}, 30).Error) // soft-delete "old"

	maxR := 5
	exp := time.Now().Add(24 * time.Hour)
	nodes := []*models.SecretNode{
		{ProjectID: projectID, EnvironmentID: 10, Name: "DB_PASSWORD", IsSecret: true, Type: "password"},
		{ProjectID: projectID, EnvironmentID: 20, Name: "DB_PASSWORD", IsSecret: true, Type: "password", MaxReads: &maxR, Expiration: &exp},
		{ProjectID: projectID, EnvironmentID: 10, Name: "a-folder", IsSecret: false}, // folder excluded
		{ProjectID: projectID, EnvironmentID: 30, Name: "GHOST", IsSecret: true},     // in deleted env, excluded
	}
	for _, n := range nodes {
		require.NoError(t, ls.db.Create(n).Error)
	}

	rows, err := ls.ListProjectSecretsForDrift(ctx, projectID)
	require.NoError(t, err)
	require.Len(t, rows, 2, "folders and secrets in soft-deleted environments are excluded")

	// Ordered by name then environment id.
	assert.Equal(t, "DB_PASSWORD", rows[0].Name)
	assert.Equal(t, uint(10), rows[0].EnvironmentID)
	assert.False(t, rows[0].HasExpiration)
	assert.False(t, rows[0].HasMaxReads)

	assert.Equal(t, uint(20), rows[1].EnvironmentID)
	assert.True(t, rows[1].HasExpiration, "prod secret has expiration set")
	assert.True(t, rows[1].HasMaxReads, "prod secret has max_reads set")
}
