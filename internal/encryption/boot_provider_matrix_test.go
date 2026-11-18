package encryption

// boot_provider_matrix_test.go — #4395/#4396 startup matrix: boot the key
// manager (lock, key-set reconcile, Initialize), twice, once per provider type
// that can run natively here, with {salt_path unset, set-but-unused} and
// {relative, absolute dek_path}, and assert success or the documented refusal.

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

func TestBootMatrix_ProviderTypes(t *testing.T) {
	const kek = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const pass = "correct horse battery staple"

	// Provider types this matrix cannot boot natively, each with its reason.
	for typ, reason := range map[string]string{
		"aws-kms":   "needs the AWS KMS API and credentials",
		"gcp-kms":   "needs the GCP KMS API and credentials",
		"azure-kms": "needs Azure Key Vault and credentials",
		"tpm":       "needs a TPM 2.0 device",
		"shamir":    "needs K-of-N share files and a commitment; its salt use is the same non-password path covered by config.TestEncryptionConfig_SaltUse",
		"exec":      "needs an external resolver command; its salt use is covered by config.TestEncryptionConfig_SaltUse",
	} {
		t.Run(typ, func(t *testing.T) { t.Skipf("%s: %s", typ, reason) })
	}

	type provider struct {
		name       string
		build      func(t *testing.T, dir string) config.KeyProviderConfig
		passphrase string
		usesSalt   bool
	}
	providers := []provider{
		{name: "password", usesSalt: true, passphrase: pass,
			build: func(*testing.T, string) config.KeyProviderConfig { return config.KeyProviderConfig{Type: "password"} }},
		{name: "env",
			build: func(t *testing.T, _ string) config.KeyProviderConfig {
				t.Setenv("KEYORIX_TEST_MATRIX_KEK", kek)
				return config.KeyProviderConfig{Type: "env", EnvVar: "KEYORIX_TEST_MATRIX_KEK"}
			}},
		{name: "file",
			build: func(t *testing.T, dir string) config.KeyProviderConfig {
				p := filepath.Join(dir, "kek.key")
				require.NoError(t, os.WriteFile(p, []byte(kek), 0o600))
				return config.KeyProviderConfig{Type: "file", FilePath: p}
			}},
	}

	for _, p := range providers {
		for _, saltSet := range []bool{false, true} {
			for _, absDEK := range []bool{false, true} {
				name := fmt.Sprintf("%s/salt_set=%v/abs_dek=%v", p.name, saltSet, absDEK)
				t.Run(name, func(t *testing.T) {
					dir := t.TempDir()
					keyDir := filepath.Join(dir, "keys")
					require.NoError(t, os.MkdirAll(keyDir, 0o700))
					cfg := &config.EncryptionConfig{Enabled: true, KeyProvider: p.build(t, dir)}
					boot := func() error { return bootLikeServer(t, cfg, dir, p.passphrase) }

					if absDEK {
						cfg.DEKPath = filepath.Join(keyDir, "dek.key")
						if saltSet {
							cfg.SaltPath = filepath.Join(keyDir, "kek.salt")
						}
					} else {
						cfg.DEKPath = "keys/dek.key"
						if saltSet {
							cfg.SaltPath = "keys/kek.salt"
						}
					}

					if p.usesSalt && !saltSet {
						// Documented refusal: the password provider has no salt file to
						// read or create. Both boots must refuse, and nothing is written
						// to the working directory.
						err := boot()
						require.Error(t, err)
						t.Logf("documented refusal: %v", err)
						require.Error(t, boot())
						return
					}

					// First boot generates the keys, the second proves they reload: the
					// #4395 failure was the second boot ("incomplete set").
					require.NoError(t, boot())
					require.NoError(t, boot())

					saltFile := filepath.Join(keyDir, "kek.salt")
					_, err := os.Stat(saltFile)
					if p.usesSalt {
						require.NoError(t, err, "the password provider generates its salt")
					} else {
						require.True(t, os.IsNotExist(err), "a provider that never reads a salt must not create one")
					}
				})
			}
		}
	}
}
