package backupfmt

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

// testManifestKey is a fixed stand-in for auditverify.DeriveBackupManifestKey's
// output -- these tests exercise WriteBackup's own mechanics, not key
// derivation itself (covered by internal/auditverify's own tests).
func testManifestKey() []byte {
	return bytes.Repeat([]byte{0x5a}, 32)
}

// openTestDB opens a fresh SQLite database and runs the SAME migration path
// the rest of the storage package's tests use (via DefaultStorageFactory,
// exercised indirectly through package storage's own tests) -- reached here
// through internal/storage's exported gormConfig-equivalent construction
// isn't available across the package boundary, so this test builds its own
// minimal schema for just the tables it needs, using AutoMigrate directly
// (GORM's own migration, not migrateDatabase's SQLite-workaround wrapping --
// fine for a handful of plain tables with no legacy-column history).
func openTestDB(t testing.TB) *gorm.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "backupfmt_writer_test.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.User{}, &models.Role{}))
	return db
}

// testSeedModels is the small model subset openTestDB migrates, in a valid
// restore-order-respecting sequence (Project before Environment, which
// references it) -- shared by every fuzz target in this package that needs
// a real archive built from a real (if tiny) database rather than the full
// 78-table registry.
func testSeedModels() []any {
	return []any{&models.Project{}, &models.Environment{}, &models.User{}, &models.Role{}}
}

func TestWriteBackup_RoundTripsRowsAndManifest(t *testing.T) {
	db := openTestDB(t)

	require.NoError(t, db.Create(&models.User{Username: "alice", Email: "alice@example.com", PasswordHash: "x"}).Error)
	require.NoError(t, db.Create(&models.User{Username: "bob", Email: "bob@example.com", PasswordHash: "x"}).Error)
	require.NoError(t, db.Create(&models.Project{Name: "proj-1"}).Error)

	var buf bytes.Buffer
	manifest, err := writeBackupModels(db, []any{&models.Project{}, &models.Environment{}, &models.User{}}, 1, "", testManifestKey(), nil, nil, &buf)
	require.NoError(t, err)

	require.Equal(t, FormatVersion, manifest.FormatVersion)
	require.Equal(t, Backend, manifest.Backend)
	require.Len(t, manifest.Tables, 3)
	require.NotEmpty(t, manifest.Signature)
	require.True(t, VerifyManifestSignature(manifest, testManifestKey()))
	require.False(t, VerifyManifestSignature(manifest, testManifestKey()[:31]),
		"a different key must not verify")

	var userEntry, projectEntry TableEntry
	for _, te := range manifest.Tables {
		switch te.Name {
		case "users":
			userEntry = te
		case "projects":
			projectEntry = te
		}
	}
	require.Equal(t, int64(2), userEntry.RowCount)
	require.Equal(t, int64(1), projectEntry.RowCount)

	// Parse the actual archive bytes and verify: MANIFEST.json is the first
	// entry, its declared hash/size for "users" matches the real NDJSON
	// bytes that follow, and a row's content survives the round trip.
	gz, err := gzip.NewReader(&buf)
	require.NoError(t, err)
	tr := tar.NewReader(gz)

	hdr, err := tr.Next()
	require.NoError(t, err)
	require.Equal(t, "MANIFEST.json", hdr.Name)
	manifestBytes, err := io.ReadAll(tr)
	require.NoError(t, err)
	var parsedManifest Manifest
	require.NoError(t, json.Unmarshal(manifestBytes, &parsedManifest))
	require.Equal(t, manifest.Tables, parsedManifest.Tables)
	require.True(t, VerifyManifestSignature(parsedManifest, testManifestKey()),
		"the manifest bytes actually written into the archive must themselves verify, not just the in-memory struct")

	foundUsersEntry := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if hdr.Name != userEntry.TarName {
			continue
		}
		foundUsersEntry = true
		data, err := io.ReadAll(tr)
		require.NoError(t, err)
		require.Equal(t, userEntry.UncompressedSize, int64(len(data)))

		lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
		require.Len(t, lines, 2)
		var first models.User
		require.NoError(t, json.Unmarshal(lines[0], &first))
		require.Equal(t, "alice", first.Username)
		var second models.User
		require.NoError(t, json.Unmarshal(lines[1], &second))
		require.Equal(t, "bob", second.Username)
		require.Less(t, first.ID, second.ID, "rows must be written in primary-key-ascending order (§3.3)")
	}
	require.True(t, foundUsersEntry)
}

func TestWriteBackup_EmptyTableProducesZeroRowEntry(t *testing.T) {
	db := openTestDB(t)
	var buf bytes.Buffer
	manifest, err := writeBackupModels(db, []any{&models.Environment{}}, 1, "", testManifestKey(), nil, nil, &buf)
	require.NoError(t, err)
	require.Len(t, manifest.Tables, 1)
	require.Equal(t, int64(0), manifest.Tables[0].RowCount)
	require.Equal(t, int64(0), manifest.Tables[0].UncompressedSize)
	emptySum := sha256.Sum256(nil)
	require.Equal(t, hex.EncodeToString(emptySum[:]), manifest.Tables[0].SHA256,
		"an empty table's NDJSON is zero bytes -- SHA-256 of an empty input")
}

// TestWriteBackup_DetectsDanglingReference is the positive control for
// CheckDanglingReferences: a clean database (every test above) proves
// nothing about whether the check can actually catch a real violation.
// This one inserts an Environment row whose ProjectID points at a project
// that was never created, and asserts the manifest's DanglingReferences
// names exactly that row -- design §3.4's backup-time warning.
func TestWriteBackup_DetectsDanglingReference(t *testing.T) {
	db := openTestDB(t)
	env := models.Environment{Name: "prod", ProjectID: 99999}
	require.NoError(t, db.Create(&env).Error)

	var buf bytes.Buffer
	manifest, err := writeBackupModels(db, []any{&models.Project{}, &models.Environment{}}, 1, "", testManifestKey(), nil, nil, &buf)
	require.NoError(t, err)

	require.Len(t, manifest.DanglingReferences, 1)
	d := manifest.DanglingReferences[0]
	require.Equal(t, "environments", d.Table)
	require.Equal(t, "project_id", d.Column)
	require.Equal(t, env.ID, d.RowID)
	require.Equal(t, "projects", d.RefTable)
	require.Equal(t, uint(99999), d.MissingID)
}
