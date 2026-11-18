package encryption

// vestigial_salt_test.go — #4395: a salt_path left in the config while the key
// provider is not password-based must not refuse the boot. The salt is only
// read by the password provider (or a password fallback); for env/file it is
// never generated, so every boot step that treated "salt_path set" as "salt
// file must exist" bricked the install forever.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

// bootLikeServer runs the same Service steps server/boot_encryption.go runs
// around Initialize, minus the database-bound ones.
func bootLikeServer(t *testing.T, cfg *config.EncryptionConfig, dir, passphrase string) error {
	t.Helper()
	svc := NewService(cfg, dir)
	if err := svc.AcquireExclusiveKeyLock(); err != nil {
		return err
	}
	defer svc.Shutdown() // release the lock so the next boot can take it
	if err := svc.ReconcileKeySet(); err != nil {
		return err
	}
	return svc.Initialize(passphrase)
}

func TestBoot_NonPasswordProvider_VestigialSaltPathIsIgnored(t *testing.T) {
	const kek = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name string
		kp   func(dir string, t *testing.T) config.KeyProviderConfig
	}{
		{"env", func(string, *testing.T) config.KeyProviderConfig {
			t.Setenv("KEYORIX_TEST_VESTIGIAL_KEK", kek)
			return config.KeyProviderConfig{Type: "env", EnvVar: "KEYORIX_TEST_VESTIGIAL_KEK"}
		}},
		{"file", func(dir string, t *testing.T) config.KeyProviderConfig {
			p := filepath.Join(dir, "kek.key")
			require.NoError(t, os.WriteFile(p, []byte(kek), 0o600))
			return config.KeyProviderConfig{Type: "file", FilePath: p}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := &config.EncryptionConfig{
				Enabled:     true,
				DEKPath:     "dek.key",
				SaltPath:    "kek.salt", // vestigial: never created, never read
				KeyProvider: tc.kp(dir, t),
			}
			require.NoError(t, bootLikeServer(t, cfg, dir, ""))
			_, err := os.Stat(filepath.Join(dir, "kek.salt"))
			require.True(t, os.IsNotExist(err), "an unused salt_path must not be generated either")

			// A second boot (the DEK now exists) must succeed too.
			require.NoError(t, bootLikeServer(t, cfg, dir, ""))
		})
	}
}

func TestBoot_PasswordProvider_MissingSaltOnExistingDEKIsStillRefused(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	require.NoError(t, bootLikeServer(t, cfg, dir, "correct horse battery staple"))

	// The salt is genuinely used here: losing it must stay a refusal.
	require.NoError(t, os.Remove(filepath.Join(dir, "kek.salt")))
	err := bootLikeServer(t, cfg, dir, "correct horse battery staple")
	require.Error(t, err)
	require.False(t, strings.Contains(err.Error(), "unused by provider"))
}
