package backupfmt

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestRoundTrip_WriteExtractVerifyLoad is the full backupfmt-level round
// trip design §11.1 asks for, scoped to a small model subset (the full
// 78-table registry round trip is H5's job): write a backup from a seeded
// source DB, extract it to a staging directory, verify the manifest
// signature against the staged bytes, wipe/re-migrate a fresh target DB,
// load the staged data into it inside a transaction, and assert the
// restored rows match the source exactly.
func TestRoundTrip_WriteExtractVerifyLoad(t *testing.T) {
	src := openTestDB(t)
	require.NoError(t, src.Create(&models.Project{Name: "proj-1"}).Error)
	require.NoError(t, src.Create(&models.User{Username: "alice", Email: "a@example.com", PasswordHash: "x"}).Error)
	require.NoError(t, src.Create(&models.User{Username: "bob", Email: "b@example.com", PasswordHash: "x"}).Error)

	testModels := []any{&models.Project{}, &models.Environment{}, &models.User{}}
	key := testManifestKey()

	var archive bytes.Buffer
	writtenManifest, err := writeBackupModels(src, testModels, 5, "", key,
		[]KeyFileEntry{{OriginalPath: "dek.key", TarName: "keyfiles/0", Mode: 0600, SHA256: "b5d54c39e66671c9731b9f471e585d8262cd4f54963f0c93082d8dcf334d4c78", Size: 4}},
		[][]byte{[]byte("fake")}, &archive)
	require.NoError(t, err)

	stagingDir := t.TempDir()
	extractedManifest, err := ExtractArchive(&archive, stagingDir, 0, 0)
	require.NoError(t, err)
	require.Equal(t, writtenManifest.Tables, extractedManifest.Tables)
	require.True(t, VerifyManifestSignature(extractedManifest, key))

	// Staged key file bytes must be byte-identical to what was written.
	stagedKey, err := readStagedFile(t, stagingDir, "keyfiles/0")
	require.NoError(t, err)
	require.Equal(t, []byte("fake"), stagedKey)

	dst := openTestDB(t) // fresh, already-migrated target (§3.4: "run normal migrations first")
	require.NoError(t, dst.Transaction(func(tx *gorm.DB) error {
		return LoadArchive(tx, extractedManifest, stagingDir)
	}))

	var users []models.User
	require.NoError(t, dst.Order("id ASC").Find(&users).Error)
	require.Len(t, users, 2)
	require.Equal(t, "alice", users[0].Username)
	require.Equal(t, "bob", users[1].Username)

	var projects []models.Project
	require.NoError(t, dst.Find(&projects).Error)
	require.Len(t, projects, 1)
	require.Equal(t, "proj-1", projects[0].Name)
}

// TestLoadArchive_RefusesDanglingReferenceInLoadedData is the mandatory,
// no-skip-flag enforcement design §3.4's corrected text requires: restore
// must refuse (and the transaction must roll back, leaving the target
// untouched) if the data it just loaded contains a reference to a row that
// doesn't exist.
func TestLoadArchive_RefusesDanglingReferenceInLoadedData(t *testing.T) {
	src := openTestDB(t)
	env := models.Environment{Name: "prod", ProjectID: 99999} // dangling on purpose -- no such project
	require.NoError(t, src.Create(&env).Error)

	testModels := []any{&models.Project{}, &models.Environment{}}
	var archive bytes.Buffer
	_, err := writeBackupModels(src, testModels, 1, "", testManifestKey(), nil, nil, &archive)
	require.NoError(t, err) // backup itself only WARNS (manifest.DanglingReferences), never refuses

	stagingDir := t.TempDir()
	manifest, err := ExtractArchive(&archive, stagingDir, 0, 0)
	require.NoError(t, err)
	require.Len(t, manifest.DanglingReferences, 1, "backup-time warning must have recorded it")

	dst := openTestDB(t)
	loadErr := dst.Transaction(func(tx *gorm.DB) error {
		return LoadArchive(tx, manifest, stagingDir)
	})
	require.Error(t, loadErr)
	require.Contains(t, loadErr.Error(), "dangling reference")

	var count int64
	require.NoError(t, dst.Model(&models.Environment{}).Count(&count).Error)
	require.Zero(t, count, "the transaction must have rolled back -- target left untouched")
}

// TestLoadArchive_RefusesUnrecognizedColumn is design §3.5's detection
// layer: a manifest table entry declaring a column the current model
// doesn't have (and that isn't on the known-removed allowlist) must refuse
// the whole restore rather than silently drop it.
func TestLoadArchive_RefusesUnrecognizedColumn(t *testing.T) {
	manifest := Manifest{
		FormatVersion: FormatVersion,
		Backend:       Backend,
		Tables: []TableEntry{
			{Name: "projects", TarName: "tables/projects.ndjson", RowCount: 0, Columns: []string{"id", "name", "a_column_that_was_renamed"}},
		},
	}
	stagingDir := t.TempDir()
	require.NoError(t, stageEmptyTableFile(t, stagingDir, "tables/projects.ndjson"))

	dst := openTestDB(t)
	err := dst.Transaction(func(tx *gorm.DB) error {
		return LoadArchive(tx, manifest, stagingDir)
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "a_column_that_was_renamed")
}

func readStagedFile(t *testing.T, stagingDir, name string) ([]byte, error) {
	t.Helper()
	return os.ReadFile(filepath.Join(stagingDir, name)) // #nosec G304 -- test-controlled path
}

func stageEmptyTableFile(t *testing.T, stagingDir, name string) error {
	t.Helper()
	return stageFile(stagingDir, name, nil)
}
