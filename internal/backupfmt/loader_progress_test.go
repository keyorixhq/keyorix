package backupfmt

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestLoadArchiveWithProgress_ReportsEveryTableBoundary drives the real
// loader and checks each loaded table announces its start and its finish with
// the manifest's row count, and that rows still land.
func TestLoadArchiveWithProgress_ReportsEveryTableBoundary(t *testing.T) {
	src := openTestDB(t)
	require.NoError(t, src.Create(&models.Project{Name: "proj-1"}).Error)
	require.NoError(t, src.Create(&models.User{Username: "alice", Email: "a@example.com", PasswordHash: "h1"}).Error)
	require.NoError(t, src.Create(&models.User{Username: "bob", Email: "b@example.com", PasswordHash: "h2"}).Error)

	var archive bytes.Buffer
	_, err := writeBackupModels(src, []any{&models.Project{}, &models.User{}}, 5, "", testManifestKey(), nil, nil, &archive)
	require.NoError(t, err)
	stagingDir := t.TempDir()
	manifest, err := ExtractArchive(&archive, stagingDir, 0, 0)
	require.NoError(t, err)

	var events []LoadProgress
	dst := openTestDB(t)
	require.NoError(t, dst.Transaction(func(tx *gorm.DB) error {
		return LoadArchiveWithProgress(tx, manifest, stagingDir, func(p LoadProgress) { events = append(events, p) })
	}))

	starts := map[string]bool{}
	finishes := map[string]LoadProgress{}
	for _, e := range events {
		require.Equal(t, len(manifest.Tables), e.TablesTotal)
		if e.Start {
			starts[e.Table] = true
		}
		if e.Finished {
			finishes[e.Table] = e
		}
	}
	for _, te := range manifest.Tables {
		require.True(t, starts[te.Name], "no start event for %s", te.Name)
		require.Equal(t, te.RowCount, finishes[te.Name].TableRows, "finish rows for %s", te.Name)
	}
	var n int64
	require.NoError(t, dst.Model(&models.User{}).Count(&n).Error)
	require.EqualValues(t, 2, n)
}
