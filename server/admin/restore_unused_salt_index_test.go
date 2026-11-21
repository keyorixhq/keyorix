package admin

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/backupfmt"
	"github.com/keyorixhq/keyorix/internal/config"
)

// The guard stays on: an archive whose extra entry is not the configured
// salt is still refused.
func TestUnusedArchivedSaltIndex(t *testing.T) {
	env := func(salt string, fallbacks ...config.KeyProviderConfig) *config.Config {
		cfg := &config.Config{}
		cfg.Storage.Encryption = config.EncryptionConfig{Enabled: true, DEKPath: "keys/dek.key", SaltPath: salt,
			KeyProvider: config.KeyProviderConfig{Type: "env", EnvVar: "X", Fallbacks: fallbacks}}
		return cfg
	}
	archived := []string{"keys/kek.salt", "keys/dek.key"}
	at := func(i int) string { return archived[i] }
	require.Equal(t, 0, unusedArchivedSaltIndex(env("keys/kek.salt"), len(archived), at))
	require.Equal(t, 0, unusedArchivedSaltIndex(env("./keys/kek.salt"), len(archived), at), "matched after Clean, like Registry")
	require.Equal(t, -1, unusedArchivedSaltIndex(env(""), len(archived), at), "no salt_path: nothing to match")
	require.Equal(t, -1, unusedArchivedSaltIndex(env("keys/other.salt"), len(archived), at), "another path is not the salt")
	require.Equal(t, -1, unusedArchivedSaltIndex(env("keys/kek.salt", config.KeyProviderConfig{Type: "password"}), len(archived), at),
		"a password fallback reads the salt: it stays in the set")

	err := validateKeyFileSetV2([]backupfmt.KeyFileEntry{{OriginalPath: "keys/other"}, {OriginalPath: "keys/dek.key"}},
		[]string{"keys/dek.key"})
	require.ErrorContains(t, err, "restore refuses a partial/mismatched key-file set")
}
