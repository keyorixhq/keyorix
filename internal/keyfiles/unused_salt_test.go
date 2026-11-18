package keyfiles

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

// #4395 class guard: every enumeration of the key set drops a salt_path that no
// provider uses, and keeps it for the password provider.
func TestKeySetEnumerations_UnusedSaltPath(t *testing.T) {
	dir := t.TempDir()
	salt := filepath.Join(dir, "kek.salt")
	for _, tc := range []struct {
		name     string
		kp       config.KeyProviderConfig
		wantSalt bool
	}{
		{"password", config.KeyProviderConfig{Type: "password"}, true},
		{"env", config.KeyProviderConfig{Type: "env", EnvVar: "X"}, false},
		{"file", config.KeyProviderConfig{Type: "file", FilePath: "/k"}, false},
		{"env with password fallback", config.KeyProviderConfig{Type: "env", Fallbacks: []config.KeyProviderConfig{{Type: "password"}}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enc := &config.EncryptionConfig{
				Enabled: true, DEKPath: filepath.Join(dir, "dek.key"), SaltPath: salt, KeyProvider: tc.kp,
			}
			required, err := RequiredKeyFilePaths(enc, dir)
			require.NoError(t, err)
			require.Equal(t, tc.wantSalt, slices.Contains(required, salt))

			// Registry requires existence of a listed file, so an unused salt
			// that was never created must not make it fail closed.
			specs, err := Registry(enc, dir)
			require.NoError(t, err)
			found := false
			for _, s := range specs {
				found = found || s.Path == salt
			}
			require.Equal(t, tc.wantSalt, found)
		})
	}
}
