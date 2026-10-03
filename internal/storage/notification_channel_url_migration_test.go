// notification_channel_url_migration_test.go — regression coverage for
// #2433's migrateDatabase addition: an existing install's notification_channels
// table (pre-dating url_enc/url_meta) must gain those columns, have its
// existing plaintext url values backfilled into url_enc (the "plaintext
// marker" convention -- nil/empty url_meta -- internal/core/secret_value_crypto.go
// already defines for a disabled-encryption write), and have the plaintext
// url column itself cleared so the credential no longer sits there at rest.
package storage

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrateDatabase_NotificationChannelURL_BackfillsAndClearsPlaintext(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "notifchan-url-migration.db"))
	require.NoError(t, err)

	// Pre-create the table in its OLD shape: no url_enc/url_meta, a plaintext
	// url column already holding a real webhook URL -- exactly what an
	// upgraded, pre-#2433 install looks like.
	require.NoError(t, db.Exec(`CREATE TABLE notification_channels (
		id         INTEGER PRIMARY KEY,
		name       TEXT,
		type       TEXT,
		enabled    BOOLEAN,
		url        TEXT,
		email      TEXT,
		events     TEXT,
		created_at DATETIME,
		updated_at DATETIME,
		created_by TEXT
	)`).Error)
	require.NoError(t, db.Exec(
		`INSERT INTO notification_channels (id, name, type, enabled, url, events) VALUES (1, 'legacy-webhook', 'webhook', 1, 'https://legacy.example.com/hook', 'secret.rotated')`,
	).Error)

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))

	assert.True(t, columnExists(db, "notification_channels", "url_enc"), "url_enc column must be added")
	assert.True(t, columnExists(db, "notification_channels", "url_meta"), "url_meta column must be added")

	var row struct {
		URL    string
		URLEnc []byte
	}
	require.NoError(t, db.Raw("SELECT url, url_enc FROM notification_channels WHERE id = 1").Scan(&row).Error)
	assert.Equal(t, "https://legacy.example.com/hook", string(row.URLEnc),
		"the existing plaintext url must be backfilled into url_enc")
	assert.Empty(t, row.URL, "the plaintext url column must be cleared once its value has moved to url_enc")

	// Idempotent: a second migration run must not clobber the now-migrated row
	// (url_enc stays populated, the backfill condition no longer matches).
	require.NoError(t, f.migrateDatabase(db))
	require.NoError(t, db.Raw("SELECT url, url_enc FROM notification_channels WHERE id = 1").Scan(&row).Error)
	assert.Equal(t, "https://legacy.example.com/hook", string(row.URLEnc), "re-running the migration must not alter an already-migrated row")
}
