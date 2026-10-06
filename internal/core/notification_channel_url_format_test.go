// notification_channel_url_format_test.go — coordinator-review regression
// coverage for #2468's blocking defects in the NotificationChannel.URL
// at-rest encryption (#2433):
//
//  1. An UPGRADED install's email channel carries url=” in the legacy
//     plaintext column. The original backfill's `url != ”` predicate skipped
//     it, leaving url_enc empty; with encryption on, the read path then fed
//     those zero bytes to DecryptSecretWithAAD, which fails — and because
//     ListNotificationChannels is (correctly) fail-closed, ONE such row broke
//     the WHOLE list, taking the channel UI, the CRUD API and
//     RunRecoverAdminAlerting down with it.
//  2. CreateNotificationChannel inserted the row, then encrypted and persisted
//     url_enc in a SECOND, untransacted write. An encrypt or update failure
//     therefore left a durable row whose url_enc was empty — the same broken
//     shape as (1), reachable without any upgrade at all.
//  3. With encryption OFF the backfill copied raw plaintext into url_enc with
//     no marker distinguishing it from ciphertext. Turning encryption on later
//     left those rows undecryptable AND hard-failed the whole DEK-rotation
//     sweep at DeserializeEncryptedData. url_enc is now self-describing (a
//     one-byte format tag) so plaintext-passthrough and envelope rows are
//     told apart without guessing, and the startup backfill upgrades the
//     former in place the first time encryption is enabled.
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// newPreUpgradeNotificationChannelDB builds a notification_channels table in
// the pre-#2433 on-disk shape — a real plaintext `url` column and no
// url_enc/url_meta — and then runs the CURRENT model's AutoMigrate over it,
// which is exactly what an upgrading install does: AutoMigrate only ADDS the
// two new columns, it never drops the legacy one. models.NotificationChannel.URL
// is gorm:"-" now, so AutoMigrate alone on an empty DB would never create a
// `url` column at all; the raw CREATE TABLE is what makes a genuine legacy row
// expressible. Mirrors newUpgradedNotificationChannelTestStore in
// internal/storage/store.
func newPreUpgradeNotificationChannelDB(t *testing.T) *gorm.DB {
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
	require.NoError(t, db.AutoMigrate(&models.NotificationChannel{}, &models.AuditEvent{}))
	return db
}

// seedPreUpgradeChannel inserts a row the way a pre-#2433 binary would: the
// legacy `url` column holds whatever plaintext that channel type had (the
// empty string, for an email channel), url_enc/url_meta are never written.
func seedPreUpgradeChannel(t *testing.T, db *gorm.DB, name, chType, legacyURL, email string) uint {
	t.Helper()
	ch := &models.NotificationChannel{Name: name, Type: chType, Enabled: true, Email: email}
	require.NoError(t, db.Create(ch).Error)
	require.NoError(t, db.Exec("UPDATE notification_channels SET url = ? WHERE id = ?", legacyURL, ch.ID).Error)
	return ch.ID
}

// plaintextURLEnc builds the value storage holds for a channel URL when no
// encryptor is wired: a plaintext-TAGGED payload, not the bare bytes.
//
// Shared by every mock-storage fixture in this package that stands in for a
// stored row. Before the format tag (#2468) those fixtures could write
// []byte("https://...") directly; now a raw URL there is an unrecognised
// format byte (0x68, 'h') and the read path correctly refuses it — which is
// the whole point, so the fixtures say which format they mean instead of the
// reader being made lenient to accommodate them.
func plaintextURLEnc(url string) []byte {
	return ports.WrapNotificationChannelURL(ports.NotificationChannelURLTagPlaintext, []byte(url))
}

func newTestEncryptionService(t *testing.T) *encryption.Service {
	t.Helper()
	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))
	return enc
}

// TestListNotificationChannels_UpgradedEmailChannelWithEmptyURLStillLists is
// the regression test for blocking defect (1). An email channel legitimately
// has no URL. On an upgraded install with encryption enabled, listing had to
// keep working — and had to keep working for the WEBHOOK channel sitting next
// to it, which is the part a fail-closed list breaks.
func TestListNotificationChannels_UpgradedEmailChannelWithEmptyURLStillLists(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db := newPreUpgradeNotificationChannelDB(t)
	ctx := context.Background()

	emailID := seedPreUpgradeChannel(t, db, "ops-email", "email", "", "ops@example.com")
	hookID := seedPreUpgradeChannel(t, db, "ops-hook", "webhook", "https://hooks.example.com/ops", "")

	ls := store.NewLocalStorage(db)
	enc := newTestEncryptionService(t)

	n, err := ls.MigrateNotificationChannelURLsToEncrypted(ctx, enc)
	require.NoError(t, err, "the backfill must handle EVERY row, including one whose legacy URL is empty")
	assert.Equal(t, 2, n, "both rows need a url_enc written: the webhook's ciphertext and the email channel's explicit empty value")

	c := NewKeyorixCore(ls)
	c.SetAuthEncryptor(enc)

	got, err := c.ListNotificationChannels(ctx)
	require.NoError(t, err, "one URL-less email channel must not fail the whole fail-closed list")
	require.Len(t, got, 2)

	byID := map[uint]*models.NotificationChannel{}
	for _, ch := range got {
		byID[ch.ID] = ch
	}
	assert.Equal(t, "", byID[emailID].URL, "an email channel has no URL; it must read back as the empty string, not as an error")
	assert.Equal(t, "https://hooks.example.com/ops", byID[hookID].URL)

	// The single-row read path must agree with the list path.
	one, err := c.GetNotificationChannel(ctx, emailID)
	require.NoError(t, err)
	assert.Equal(t, "", one.URL)
}

// failingEncryptor is an enabled, initialised ports.EncryptionProvider whose
// encrypt step always fails — the fault CreateNotificationChannel's second,
// untransacted write turned into a durable half-written row.
type failingEncryptor struct{ err error }

func (f failingEncryptor) IsEnabled() bool     { return true }
func (f failingEncryptor) IsInitialized() bool { return true }
func (f failingEncryptor) EncryptSecretWithAAD(_, _ []byte) ([]byte, []byte, error) {
	return nil, nil, f.err
}
func (f failingEncryptor) DecryptSecretWithAAD(_, _ []byte) ([]byte, error) { return nil, f.err }

// TestCreateNotificationChannel_EncryptFailurePersistsNoRow is the regression
// test for blocking defect (2): the insert and the encrypted-URL write now
// share ONE transaction, so an encrypt failure rolls the insert back instead
// of leaving a row whose url_enc is empty (which, per defect (1), would then
// fail every subsequent List).
func TestCreateNotificationChannel_EncryptFailurePersistsNoRow(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.NotificationChannel{}, &models.AuditEvent{}))

	ls := store.NewLocalStorage(db)
	c := NewKeyorixCore(ls)
	c.webhookURLValidator = noopWebhookURLValidator
	c.SetAuthEncryptor(failingEncryptor{err: errors.New("kms unavailable")})
	ctx := context.Background()

	_, err = c.CreateNotificationChannel(ctx,
		&models.NotificationChannel{Name: "half-written", Type: "webhook", URL: "https://hooks.example.com/x"},
		"admin", 1)
	require.Error(t, err, "an encrypt failure must be reported")

	var count int64
	require.NoError(t, db.Model(&models.NotificationChannel{}).Count(&count).Error)
	assert.Equal(t, int64(0), count,
		"the insert must roll back with the failed encrypted-URL write; a persisted row with an empty url_enc is the exact shape that breaks the fail-closed list")
}

// TestNotificationChannelURL_EncryptionOffThenOn is the regression test for
// blocking defect (3): a row written while encryption was OFF is stored as a
// self-describing plaintext-passthrough value, and the next startup backfill
// with encryption ON upgrades it in place to a real envelope. Before the
// format tag existed, those raw plaintext bytes were indistinguishable from
// ciphertext, so the read path fed them to DecryptSecretWithAAD (fail) and the
// DEK-rotation sweep fed them to DeserializeEncryptedData (hard-failing the
// ENTIRE sweep, not just this table).
func TestNotificationChannelURL_EncryptionOffThenOn(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.NotificationChannel{}, &models.AuditEvent{}))

	ls := store.NewLocalStorage(db)
	ctx := context.Background()

	// Phase 1: encryption OFF. No authEncryptor is wired at all.
	off := NewKeyorixCore(ls)
	off.webhookURLValidator = noopWebhookURLValidator
	created, err := off.CreateNotificationChannel(ctx,
		&models.NotificationChannel{Name: "plain-era", Type: "webhook", URL: "https://hooks.example.com/plain-era"},
		"admin", 1)
	require.NoError(t, err)

	raw, err := ls.GetNotificationChannel(ctx, created.ID)
	require.NoError(t, err)
	tag, payload, err := ports.UnwrapNotificationChannelURL(raw.URLEnc)
	require.NoError(t, err)
	assert.Equal(t, ports.NotificationChannelURLTagPlaintext, tag,
		"with encryption off the stored value must SAY it is plaintext, not look like ciphertext")
	assert.Equal(t, "https://hooks.example.com/plain-era", string(payload))

	// Phase 2: the operator enables encryption and restarts. The startup
	// backfill must upgrade the passthrough row rather than strand it.
	enc := newTestEncryptionService(t)
	n, err := ls.MigrateNotificationChannelURLsToEncrypted(ctx, enc)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "enabling encryption must re-run the backfill over plaintext-passthrough rows")

	raw, err = ls.GetNotificationChannel(ctx, created.ID)
	require.NoError(t, err)
	tag, payload, err = ports.UnwrapNotificationChannelURL(raw.URLEnc)
	require.NoError(t, err)
	require.Equal(t, ports.NotificationChannelURLTagEncrypted, tag)
	assert.NotContains(t, string(payload), "hooks.example.com",
		"the upgraded payload must be a real envelope, not the plaintext URL")

	on := NewKeyorixCore(ls)
	on.SetAuthEncryptor(enc)
	got, err := on.GetNotificationChannel(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "https://hooks.example.com/plain-era", got.URL,
		"the URL must still be readable after the off -> on upgrade")
}

// TestGetNotificationChannel_EncryptedRowWithEncryptionOffFailsClosed pins the
// on -> off direction. decryptAuthSecret's passthrough branch would otherwise
// hand the caller the raw envelope JSON AS the URL — a silent corruption that
// alert dispatch would then try to dial. A self-describing tag makes this
// detectable, and the only safe answer is to refuse.
func TestGetNotificationChannel_EncryptedRowWithEncryptionOffFailsClosed(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.NotificationChannel{}, &models.AuditEvent{}))

	ls := store.NewLocalStorage(db)
	ctx := context.Background()
	enc := newTestEncryptionService(t)

	on := NewKeyorixCore(ls)
	on.webhookURLValidator = noopWebhookURLValidator
	on.SetAuthEncryptor(enc)
	created, err := on.CreateNotificationChannel(ctx,
		&models.NotificationChannel{Name: "enc-era", Type: "webhook", URL: "https://hooks.example.com/enc-era"},
		"admin", 1)
	require.NoError(t, err)

	off := NewKeyorixCore(ls)
	_, err = off.GetNotificationChannel(ctx, created.ID)
	require.Error(t, err, "an encrypted row read with encryption disabled must fail closed, never return the envelope as a URL")
	assert.Contains(t, err.Error(), "encryption is disabled")
}

// TestNotificationChannelURLFormat_MigrationAndCoreAgree is the derived check
// behind the two separate encoders — internal/core's
// encryptNotificationChannelURL and internal/storage/store's
// encodeNotificationChannelURL. They must produce the same tagged shape for the
// same encryptor state, or a row one of them wrote is a row the other (and the
// shared reader) rejects. Rather than assert they are textually similar, this
// drives BOTH writers at both encryptor states and requires core's reader to
// round-trip all four results.
func TestNotificationChannelURLFormat_MigrationAndCoreAgree(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())

	for _, tc := range []struct {
		name      string
		encrypted bool
		wantTag   byte
	}{
		{"encryption off", false, ports.NotificationChannelURLTagPlaintext},
		{"encryption on", true, ports.NotificationChannelURLTagEncrypted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			db := newPreUpgradeNotificationChannelDB(t)
			ls := store.NewLocalStorage(db)
			ctx := context.Background()

			var enc *encryption.Service
			if tc.encrypted {
				enc = newTestEncryptionService(t)
			}

			c := NewKeyorixCore(ls)
			c.webhookURLValidator = noopWebhookURLValidator
			if enc != nil {
				c.SetAuthEncryptor(enc)
			}

			// Writer A: the live core CRUD path.
			viaCore, err := c.CreateNotificationChannel(ctx,
				&models.NotificationChannel{Name: "via-core", Type: "webhook", URL: "https://hooks.example.com/via-core"},
				"admin", 1)
			require.NoError(t, err)

			// Writer B: the startup backfill, over a legacy row.
			viaMigration := seedPreUpgradeChannel(t, db, "via-migration", "webhook", "https://hooks.example.com/via-migration", "")
			var encryptor ports.EncryptionProvider
			if enc != nil {
				encryptor = enc
			}
			_, err = ls.MigrateNotificationChannelURLsToEncrypted(ctx, encryptor)
			require.NoError(t, err)

			for _, id := range []uint{viaCore.ID, viaMigration} {
				raw, rerr := ls.GetNotificationChannel(ctx, id)
				require.NoError(t, rerr)
				tag, _, uerr := ports.UnwrapNotificationChannelURL(raw.URLEnc)
				require.NoError(t, uerr)
				assert.Equal(t, tc.wantTag, tag, "channel %d: both writers must agree on the stored format tag", id)

				got, gerr := c.GetNotificationChannel(ctx, id)
				require.NoError(t, gerr, "channel %d: the shared reader must accept what either writer produced", id)
				assert.Contains(t, got.URL, "https://hooks.example.com/via-")
			}
		})
	}
}

// TestUnwrapNotificationChannelURL_UnknownTagFailsClosed pins the codec's own
// fail-closed behaviour: an unrecognised format byte is an error, never a
// best-effort guess at which half of the value is the URL.
func TestUnwrapNotificationChannelURL_UnknownTagFailsClosed(t *testing.T) {
	t.Parallel()

	tag, payload, err := ports.UnwrapNotificationChannelURL(nil)
	require.NoError(t, err, "an absent value is a legitimate no-URL row, not a corrupt one")
	assert.Equal(t, ports.NotificationChannelURLTagAbsent, tag)
	assert.Empty(t, payload)

	_, _, err = ports.UnwrapNotificationChannelURL([]byte{0x7f, 'x'})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unrecognised")
}
