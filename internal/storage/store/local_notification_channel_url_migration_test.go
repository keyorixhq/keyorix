// local_notification_channel_url_migration_test.go — coverage for the
// one-time backfill that moves NotificationChannel's legacy plaintext `url`
// column into the encrypted url_enc/url_meta columns (#2433).
package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// newUpgradedNotificationChannelTestStore builds a store whose
// notification_channels table starts in the pre-#2433 shape -- a real `url`
// column, no url_enc/url_meta at all -- then runs AutoMigrate against the
// CURRENT model, exactly the upgrade path TestMigrateDatabase_
// EveryModelGetsATable_UpgradedInstall exercises for the whole schema:
// AutoMigrate only ADDS missing columns, it never drops the legacy `url`
// column, so both old and new columns coexist until this migration runs.
// models.NotificationChannel.URL is gorm:"-" as of #2433, so a plain
// db.AutoMigrate from an EMPTY table (newNotificationChannelTestStore) would
// never create a `url` column at all -- this raw CREATE TABLE is what makes
// the legacy column exist to begin with, simulating a genuine existing row.
func newUpgradedNotificationChannelTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.Exec(`CREATE TABLE notification_channels (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name VARCHAR UNIQUE NOT NULL,
		type VARCHAR NOT NULL,
		enabled BOOL DEFAULT true,
		url VARCHAR,
		email VARCHAR,
		events VARCHAR,
		max_retries INTEGER DEFAULT 3,
		retry_backoff_ms INTEGER DEFAULT 1000,
		created_at DATETIME,
		updated_at DATETIME,
		created_by VARCHAR
	)`).Error)
	require.NoError(t, db.AutoMigrate(&models.NotificationChannel{}))
	return NewLocalStorage(db)
}

// seedLegacyPlaintextChannel inserts a NotificationChannel row the way a
// pre-#2433 binary would have: the raw `url` column holds plaintext, and
// url_enc/url_meta are never written at all. models.NotificationChannel.URL
// is gorm:"-" (not persisted) as of #2433, so a normal db.Create can no
// longer reach that column -- this goes around the model with a raw UPDATE
// after creating the row with its other fields, exactly simulating what an
// existing row from before this fix looks like on disk.
func seedLegacyPlaintextChannel(t *testing.T, db *gorm.DB, name, legacyURL string) uint {
	t.Helper()
	ch := &models.NotificationChannel{Name: name, Type: "webhook", Enabled: true}
	require.NoError(t, db.Create(ch).Error)
	require.NoError(t, db.Exec("UPDATE notification_channels SET url = ? WHERE id = ?", legacyURL, ch.ID).Error)
	return ch.ID
}

func TestMigrateNotificationChannelURLsToEncrypted_NoEncryptor_CopiesThrough(t *testing.T) {
	ls := newUpgradedNotificationChannelTestStore(t)
	db := ls.db
	ctx := context.Background()

	id := seedLegacyPlaintextChannel(t, db, "legacy-1", "https://hooks.example.com/legacy-1")

	n, err := ls.MigrateNotificationChannelURLsToEncrypted(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	got, err := ls.GetNotificationChannel(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, []byte("https://hooks.example.com/legacy-1"), got.URLEnc,
		"with no encryptor wired, the legacy plaintext is copied through as-is -- the same passthrough encryptAuthSecret itself uses")
	assert.Empty(t, got.URLMeta)

	var legacyURL string
	require.NoError(t, db.Raw("SELECT url FROM notification_channels WHERE id = ?", id).Scan(&legacyURL).Error)
	assert.Empty(t, legacyURL, "the legacy plaintext column must be cleared once its encrypted replacement is durable")
}

func TestMigrateNotificationChannelURLsToEncrypted_WithEncryptor_EncryptsAndRoundTrips(t *testing.T) {
	ls := newUpgradedNotificationChannelTestStore(t)
	db := ls.db
	ctx := context.Background()

	id := seedLegacyPlaintextChannel(t, db, "legacy-2", "https://hooks.example.com/legacy-2")

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))

	n, err := ls.MigrateNotificationChannelURLsToEncrypted(ctx, enc)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	got, err := ls.GetNotificationChannel(ctx, id)
	require.NoError(t, err)
	assert.NotEqual(t, []byte("https://hooks.example.com/legacy-2"), got.URLEnc,
		"with a real encryptor wired, url_enc must hold ciphertext, not the plaintext bytes verbatim")
	assert.NotEmpty(t, got.URLMeta)

	plain, err := enc.DecryptSecretWithAAD(got.URLEnc, ports.NotificationChannelURLAAD(id))
	require.NoError(t, err)
	assert.Equal(t, "https://hooks.example.com/legacy-2", string(plain),
		"the migrated ciphertext must decrypt back to the original legacy URL under the channel's own AAD")

	var legacyURL string
	require.NoError(t, db.Raw("SELECT url FROM notification_channels WHERE id = ?", id).Scan(&legacyURL).Error)
	assert.Empty(t, legacyURL)
}

func TestMigrateNotificationChannelURLsToEncrypted_Idempotent(t *testing.T) {
	ls := newUpgradedNotificationChannelTestStore(t)
	db := ls.db
	ctx := context.Background()

	id := seedLegacyPlaintextChannel(t, db, "legacy-3", "https://hooks.example.com/legacy-3")

	n1, err := ls.MigrateNotificationChannelURLsToEncrypted(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, n1)

	// A second run (e.g. the next server restart) must not re-process a row
	// it already migrated -- url_enc is now non-empty, so the selection query
	// no longer matches it.
	n2, err := ls.MigrateNotificationChannelURLsToEncrypted(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, n2)

	got, err := ls.GetNotificationChannel(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, []byte("https://hooks.example.com/legacy-3"), got.URLEnc)
	_ = id
}

func TestMigrateNotificationChannelURLsToEncrypted_SkipsAlreadyEncryptedRow(t *testing.T) {
	ls := newNotificationChannelTestStore(t)
	ctx := context.Background()

	// A channel created the normal way post-#2433 already has url_enc set and
	// no legacy plaintext at all -- the migration's selection query must not
	// touch it.
	ch := &models.NotificationChannel{Name: "already-encrypted", Type: "webhook", Enabled: true, URLEnc: []byte("ciphertext-bytes")}
	require.NoError(t, ls.CreateNotificationChannel(ctx, ch))

	n, err := ls.MigrateNotificationChannelURLsToEncrypted(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, n)

	got, err := ls.GetNotificationChannel(ctx, ch.ID)
	require.NoError(t, err)
	assert.Equal(t, []byte("ciphertext-bytes"), got.URLEnc, "an already-migrated row must be left untouched")
}

func TestMigrateNotificationChannelURLsToEncrypted_NoLegacyRows_NoOp(t *testing.T) {
	ls := newNotificationChannelTestStore(t)
	ctx := context.Background()

	n, err := ls.MigrateNotificationChannelURLsToEncrypted(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}
