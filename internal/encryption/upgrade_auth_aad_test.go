package encryption

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpgradeAuthAAD_BindsLegacyRowsWithoutRotatingDEK proves the #94 standalone
// upgrade path: legacy (no-AAD) rows in mfa_secrets, dynamic_secret_configs, and
// dynamic_secret_leases are re-encrypted with per-row AAD UNDER THE SAME DEK — no
// key rotation. This is the mechanism an operator uses to close the AAD-transplant
// exposure without the disruption of a full, write-locking DEK rotation.
func TestUpgradeAuthAAD_BindsLegacyRowsWithoutRotatingDEK(t *testing.T) {
	db := newTestDB(t)
	svc, _ := newTestService(t, "test-passphrase")

	encSecret := func(v string) ([]byte, []byte) {
		enc, meta, err := svc.EncryptSecret([]byte(v))
		require.NoError(t, err)
		return enc, meta
	}

	totpEnc, totpMeta := encSecret("TOTP-SEED-XYZ")
	require.NoError(t, db.Create(&models.MFASecret{UserID: 1, SecretEnc: totpEnc, SecretMeta: totpMeta}).Error)
	dsnEnc, dsnMeta := encSecret("postgres://admin:pw@db/app")
	require.NoError(t, db.Create(&models.DynamicSecretConfig{Name: "pg", ProjectID: 1, EnvironmentID: 2, AdminDSNEnc: dsnEnc, AdminDSNMeta: dsnMeta}).Error)
	credEnc, credMeta := encSecret(`{"user":"x","pass":"y"}`)
	require.NoError(t, db.Create(&models.DynamicSecretLease{LeaseID: "l-1", ConfigID: 9, CredentialEnc: credEnc, CredentialMeta: credMeta}).Error)

	keyVersionBefore := svc.GetKeyVersion()

	result, err := svc.UpgradeAuthAAD(db)
	require.NoError(t, err)
	assert.Equal(t, 1, result.MFASecretsSwept)
	assert.Equal(t, 1, result.DynamicSecretConfigsSwept)
	assert.Equal(t, 1, result.DynamicSecretLeasesSwept)
	assert.Equal(t, 3, result.LegacyAADUpgraded, "all 3 seeded rows were legacy (no-AAD)")

	// The DEK/key version is unchanged — this is not a rotation.
	assert.Equal(t, keyVersionBefore, svc.GetKeyVersion(), "UpgradeAuthAAD must not rotate the DEK")

	// Each row now decrypts correctly WITH its reconstructed AAD...
	var mfa models.MFASecret
	require.NoError(t, db.First(&mfa, "user_id = ?", 1).Error)
	got, err := svc.DecryptSecretWithAAD(mfa.SecretEnc, MFASecretAAD(1))
	require.NoError(t, err)
	assert.Equal(t, "TOTP-SEED-XYZ", string(got))

	var cfg models.DynamicSecretConfig
	require.NoError(t, db.First(&cfg, "name = ?", "pg").Error)
	got, err = svc.DecryptSecretWithAAD(cfg.AdminDSNEnc, DynamicSecretConfigAAD(cfg.ID, 1, 2))
	require.NoError(t, err)
	assert.Equal(t, "postgres://admin:pw@db/app", string(got))

	var lease models.DynamicSecretLease
	require.NoError(t, db.First(&lease, "lease_id = ?", "l-1").Error)
	got, err = svc.DecryptSecretWithAAD(lease.CredentialEnc, DynamicSecretLeaseAAD("l-1", 9))
	require.NoError(t, err)
	assert.Equal(t, `{"user":"x","pass":"y"}`, string(got))

	// ...and no longer transplants: a ciphertext from a DIFFERENT row's AAD must fail.
	_, err = svc.DecryptSecretWithAAD(mfa.SecretEnc, MFASecretAAD(2))
	require.Error(t, err, "post-upgrade, the mfa_secret ciphertext must be AAD-bound to its true owner")
}

// TestUpgradeAuthAAD_IsIdempotent proves a second run over already-AAD-bound rows is
// safe (fresh nonce, same AAD, no error) — an operator should be able to re-run this
// on a schedule without needing to track which rows were already upgraded.
func TestUpgradeAuthAAD_IsIdempotent(t *testing.T) {
	db := newTestDB(t)
	svc, _ := newTestService(t, "test-passphrase")

	enc, meta, err := svc.EncryptSecret([]byte("TOTP-SEED"))
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.MFASecret{UserID: 5, SecretEnc: enc, SecretMeta: meta}).Error)

	_, err = svc.UpgradeAuthAAD(db)
	require.NoError(t, err)

	result, err := svc.UpgradeAuthAAD(db)
	require.NoError(t, err)
	assert.Equal(t, 1, result.MFASecretsSwept)
	assert.Equal(t, 0, result.LegacyAADUpgraded, "the second pass finds nothing legacy left to upgrade")

	var mfa models.MFASecret
	require.NoError(t, db.First(&mfa, "user_id = ?", 5).Error)
	got, err := svc.DecryptSecretWithAAD(mfa.SecretEnc, MFASecretAAD(5))
	require.NoError(t, err)
	assert.Equal(t, "TOTP-SEED", string(got))
}
