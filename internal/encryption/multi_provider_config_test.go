package encryption_test

import (
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeyProviderFromConfig_Fallback(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt",
		KeyProvider: config.KeyProviderConfig{
			Type:     "file",
			FilePath: filepath.Join(dir, "nonexistent.key"),
			Fallbacks: []config.KeyProviderConfig{
				{Type: "password"},
			},
		},
	}
	p, err := encryption.NewKeyProviderFromConfig(cfg, dir, "test-passphrase")
	require.NoError(t, err)
	assert.Contains(t, p.Name(), "multi(")
	key, err := p.KEK()
	require.NoError(t, err)
	assert.Len(t, key, 32)
}

func TestNewKeyProviderFromConfig_NoFallback(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt",
		KeyProvider: config.KeyProviderConfig{Type: "password"},
	}
	p, err := encryption.NewKeyProviderFromConfig(cfg, dir, "pass")
	require.NoError(t, err)
	assert.NotContains(t, p.Name(), "multi(")
}

func TestNewKeyProviderFromConfig_BadFallbackType(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt",
		KeyProvider: config.KeyProviderConfig{
			Type: "password",
			Fallbacks: []config.KeyProviderConfig{{Type: "invalid-type"}},
		},
	}
	_, err := encryption.NewKeyProviderFromConfig(cfg, dir, "pass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown")
}
