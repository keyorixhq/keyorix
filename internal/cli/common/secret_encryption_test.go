package common

import (
	"bytes"
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func encEnabledCfg(storageType string) *config.Config {
	return &config.Config{
		Storage: config.StorageConfig{
			Type: storageType,
			Encryption: config.EncryptionConfig{
				Enabled:  true,
				DEKPath:  "dek.json",
				SaltPath: "salt.bin",
			},
		},
	}
}

// TestWireSecretEncryption_LocalEncryptsAtRest proves that in embedded (local) mode
// with encryption enabled and a master password set, wireSecretEncryption engages the
// encryptor and a secret created through the CLI's core is ciphertext at rest — the
// CLI no longer writes plaintext into the same DB the server encrypts.
func TestWireSecretEncryption_LocalEncryptsAtRest(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "cli-embedded-passphrase")

	db, err := gorm.Open(sqlite.Open("secrets.db"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{}))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "e"}).Error)

	svc := core.NewKeyorixCore(store.NewLocalStorage(db))
	require.NoError(t, wireSecretEncryption(svc, encEnabledCfg("local")))
	require.True(t, svc.SecretValueEncryptionActive())

	ctx := context.Background()
	const plaintext = "cli-written-secret"
	secret, err := svc.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "s", Value: []byte(plaintext), ProjectID: 1, EnvironmentID: 1,
		Type: "password", CreatedBy: "cli",
	})
	require.NoError(t, err)

	var version models.SecretVersion
	require.NoError(t, db.Where("secret_node_id = ?", secret.ID).First(&version).Error)
	assert.False(t, bytes.Equal(version.EncryptedValue, []byte(plaintext)), "CLI-written value must be ciphertext at rest")

	got, err := svc.GetSecretValue(ctx, secret.ID)
	require.NoError(t, err)
	assert.Equal(t, plaintext, string(got))
}

// TestWireSecretEncryption_FailsClosedWithoutPassphrase proves the CLI refuses to run
// embedded with encryption enabled but no master password, rather than silently
// writing plaintext.
func TestWireSecretEncryption_FailsClosedWithoutPassphrase(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")

	svc := core.NewKeyorixCore(nil)
	err := wireSecretEncryption(svc, encEnabledCfg("local"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYORIX_MASTER_PASSWORD")
	assert.False(t, svc.SecretValueEncryptionActive())
}

// TestWireSecretEncryption_RemoteAndDisabledAreNoops proves the CLI does NOT wire an
// encryptor for remote storage (the upstream server encrypts) or when encryption is
// disabled — no double-encryption, no spurious key requirement.
func TestWireSecretEncryption_RemoteAndDisabledAreNoops(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")

	remote := core.NewKeyorixCore(nil)
	require.NoError(t, wireSecretEncryption(remote, encEnabledCfg("remote")))
	assert.False(t, remote.SecretValueEncryptionActive(), "remote CLI must not wire a local encryptor")

	disabled := core.NewKeyorixCore(nil)
	require.NoError(t, wireSecretEncryption(disabled, &config.Config{Storage: config.StorageConfig{Type: "local"}}))
	assert.False(t, disabled.SecretValueEncryptionActive())
}
