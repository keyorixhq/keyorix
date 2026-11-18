package keyfiles

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

func TestUnusedSaltPath(t *testing.T) {
	dir := t.TempDir()
	enc := func(typ, salt string, fallbacks ...config.KeyProviderConfig) *config.EncryptionConfig {
		return &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: salt,
			KeyProvider: config.KeyProviderConfig{Type: typ, Fallbacks: fallbacks}}
	}
	require.Equal(t, filepath.Join(dir, "kek.salt"), UnusedSaltPath(enc("env", "./kek.salt"), dir))
	require.Equal(t, "/abs/kek.salt", UnusedSaltPath(enc("tpm", "/abs/kek.salt"), dir))
	require.Empty(t, UnusedSaltPath(enc("env", ""), dir))
	require.Empty(t, UnusedSaltPath(enc("password", "kek.salt"), dir))
	require.Empty(t, UnusedSaltPath(enc("env", "kek.salt", config.KeyProviderConfig{Type: "password"}), dir))
}
