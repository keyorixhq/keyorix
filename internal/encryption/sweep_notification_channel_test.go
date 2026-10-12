// sweep_notification_channel_test.go — coverage for
// sweepNotificationChannels' handling of the self-describing url_enc format
// (#2468).
//
// The defect this pins: notification_channels is the ONE encrypted auth-secret
// column whose write path does not refuse when encryption is off (the feature
// predates encryption here), so url_enc can legitimately hold a plaintext
// passthrough value. The original sweep fed those bytes straight to
// DeserializeEncryptedData and returned its error — and SweepAllTables
// propagates, so a single such row hard-failed the DEK rotation for EVERY
// table. Any install that had ever run with encryption off and then enabled it
// could not rotate its DEK at all.
package encryption

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSweepNotificationChannels_PlaintextPassthroughRowIsEncryptedNotFatal(t *testing.T) {
	db := newTestDB(t)
	oldSvc, _ := newTestService(t, "old-passphrase")
	newSvc, _ := newTestService(t, "new-passphrase")

	// A row written while encryption was off: tagged plaintext, no metadata.
	plainRow := &models.NotificationChannel{
		Name: "written-while-off", Type: "webhook", Enabled: true,
		URLEnc: NotificationChannelURLWrap(NotificationChannelURLTagPlaintext, []byte("https://hooks.example.com/off-era")),
	}
	require.NoError(t, db.Create(plainRow).Error)

	// A normal encrypted row beside it, so the test also proves the sweep
	// still does its actual job while tolerating the plaintext one.
	env, meta, err := oldSvc.EncryptSecretWithAAD([]byte("https://hooks.example.com/enc-era"), NotificationChannelURLAAD(2))
	require.NoError(t, err)
	encRow := &models.NotificationChannel{
		ID: 2, Name: "written-while-on", Type: "webhook", Enabled: true,
		URLEnc: NotificationChannelURLWrap(NotificationChannelURLTagEncrypted, env), URLMeta: meta,
	}
	require.NoError(t, db.Create(encRow).Error)

	swept, legacy, err := sweepNotificationChannels(db, oldSvc.encryptionService, newSvc.encryptionService, newSvc.keyManager.GetKeyVersion(), false)
	require.NoError(t, err,
		"a plaintext-passthrough row must not fail the sweep -- SweepAllTables propagates, so this used to break DEK rotation for every table")
	assert.Equal(t, 2, swept)
	assert.Equal(t, 0, legacy)

	// Both rows must now be envelope-tagged and decryptable under the NEW key.
	for _, id := range []uint{plainRow.ID, encRow.ID} {
		var got models.NotificationChannel
		require.NoError(t, db.First(&got, id).Error)
		tag, payload, uerr := NotificationChannelURLUnwrap(got.URLEnc)
		require.NoError(t, uerr)
		require.Equal(t, NotificationChannelURLTagEncrypted, tag,
			"after a rotation every row must be a real envelope under the new key; leaving the plaintext one as-is would silently break the sweep's own contract")
		plain, derr := newSvc.DecryptSecretWithAAD(payload, NotificationChannelURLAAD(id))
		require.NoError(t, derr)
		assert.Contains(t, string(plain), "https://hooks.example.com/")
	}
}

func TestSweepNotificationChannels_UnknownFormatTagFailsClosed(t *testing.T) {
	db := newTestDB(t)
	oldSvc, _ := newTestService(t, "old-passphrase")
	newSvc, _ := newTestService(t, "new-passphrase")

	require.NoError(t, db.Create(&models.NotificationChannel{
		Name: "from-the-future", Type: "webhook", Enabled: true, URLEnc: []byte{0x7f, 'x'},
	}).Error)

	_, _, err := sweepNotificationChannels(db, oldSvc.encryptionService, newSvc.encryptionService, newSvc.keyManager.GetKeyVersion(), false)
	require.Error(t, err, "an unrecognised format byte must stop the rotation, not be silently re-encrypted as if it were plaintext")
	assert.Contains(t, err.Error(), "unrecognised at-rest format tag")
}

// TestSweepNotificationChannels_NonAADEnvelopeRefused is the sweep-side half of
// #2468 round 2's decryption-oracle fix. Unlike every sibling sweep in this
// file, notification_channels gets NO legacy no-AAD fallback: url_enc is new as
// of #2468, so an envelope here with no aad_version is ciphertext somebody
// copied in from elsewhere. Decrypting it without AAD would make the rotation
// the same oracle the read path stopped being -- and would then RE-ENCRYPT the
// result as a properly AAD-bound channel URL, laundering it.
func TestSweepNotificationChannels_NonAADEnvelopeRefused(t *testing.T) {
	db := newTestDB(t)
	oldSvc, _ := newTestService(t, "old-passphrase")
	newSvc, _ := newTestService(t, "new-passphrase")

	// A valid envelope under the install's own DEK, but with no aad_version --
	// exactly what EncryptSecret (the pre-#94 shape) produces.
	stolen, meta, err := oldSvc.EncryptSecret([]byte("super-secret-value-from-another-table"))
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.NotificationChannel{
		Name: "planted", Type: "webhook", Enabled: true,
		URLEnc:  NotificationChannelURLWrap(NotificationChannelURLTagEncrypted, stolen),
		URLMeta: meta,
	}).Error)

	_, _, serr := sweepNotificationChannels(db, oldSvc.encryptionService, newSvc.encryptionService, newSvc.keyManager.GetKeyVersion(), false)
	require.Error(t, serr, "a no-AAD envelope must stop the rotation for this column, not be silently re-keyed into an AAD-bound one")
	assert.Contains(t, serr.Error(), "declares no AAD version")
	assert.NotContains(t, serr.Error(), "super-secret-value-from-another-table",
		"the refusal must not leak the plaintext it declined to re-encrypt")
}

func TestSweepNotificationChannels_AbsentURLIsSkipped(t *testing.T) {
	db := newTestDB(t)
	oldSvc, _ := newTestService(t, "old-passphrase")
	newSvc, _ := newTestService(t, "new-passphrase")

	// An upgrading install's not-yet-backfilled row, and an email channel.
	require.NoError(t, db.Create(&models.NotificationChannel{Name: "no-url-yet", Type: "email", Enabled: true, Email: "ops@example.com"}).Error)

	swept, legacy, err := sweepNotificationChannels(db, oldSvc.encryptionService, newSvc.encryptionService, newSvc.keyManager.GetKeyVersion(), false)
	require.NoError(t, err)
	assert.Equal(t, 0, swept)
	assert.Equal(t, 0, legacy)
}
