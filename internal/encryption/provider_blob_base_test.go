package encryption

// provider_blob_base_test.go — #4504 F1/F3: a tpm/*-kms wrapped_key_path is
// written, reloaded and permission-checked at one place, the key base
// keyfiles resolves it against, for every dek_path/salt_path shape, and the
// key-file permission audit runs on a salt-less key set.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
)

// tagKMS is an in-memory envelope cipher: Decrypt(Encrypt(x)) == x.
type tagKMS struct{}

func (tagKMS) Encrypt(_ context.Context, pt []byte) ([]byte, error) {
	return append([]byte("cmk|"), pt...), nil
}

func (tagKMS) Decrypt(_ context.Context, ct []byte) ([]byte, error) {
	if len(ct) < 4 || string(ct[:4]) != "cmk|" {
		return nil, errors.New("tagKMS: not wrapped by this key")
	}
	return ct[4:], nil
}

// useFakeAWSKMS makes "aws-kms" the real crypto.KMSKeyProvider over tagKMS,
// built on the baseDir buildSingleProvider hands it, like the real ctor.
func useFakeAWSKMS(t *testing.T) {
	t.Helper()
	orig, had := cloudKMSProviders["aws-kms"]
	cloudKMSProviders["aws-kms"] = func(_ context.Context, kp *config.KeyProviderConfig, baseDir string, _ KMSFallbackHook) (crypto.KeyProvider, error) {
		return crypto.NewKMSKeyProvider(tagKMS{}, "aws-kms", baseDir, kp.WrappedKeyPath), nil
	}
	t.Cleanup(func() {
		if had {
			cloudKMSProviders["aws-kms"] = orig
		} else {
			delete(cloudKMSProviders, "aws-kms")
		}
	})
}

func TestBoot_KMSWrappedKeyPath_OneBaseForEveryKeyPathShape(t *testing.T) {
	useFakeAWSKMS(t)
	for _, absDEK := range []bool{false, true} {
		for _, salt := range []string{"unset", "relative", "absolute"} {
			t.Run(fmt.Sprintf("abs_dek=%v/salt=%s", absDEK, salt), func(t *testing.T) {
				dir := t.TempDir()
				keyDir := filepath.Join(dir, "keys")
				require.NoError(t, os.MkdirAll(keyDir, 0o700))
				cfg := &config.EncryptionConfig{
					Enabled:     true,
					DEKPath:     "keys/dek.key",
					KeyProvider: config.KeyProviderConfig{Type: "aws-kms", WrappedKeyPath: "kek.wrapped"},
				}
				if absDEK {
					cfg.DEKPath = filepath.Join(keyDir, "dek.key")
				}
				switch salt {
				case "relative":
					cfg.SaltPath = "keys/kek.salt"
				case "absolute":
					cfg.SaltPath = filepath.Join(keyDir, "kek.salt")
				}

				// Boot 1 generates the DEK and the blob; boot 2 reloads them. The
				// F1 failure was boot 2: "key material is an incomplete set".
				require.NoError(t, bootLikeServer(t, cfg, dir, ""))
				require.NoError(t, bootLikeServer(t, cfg, dir, ""))

				// The blob is where keyfiles (backup, restore, reconcile) looks.
				_, err := os.Stat(filepath.Join(dir, "kek.wrapped"))
				require.NoError(t, err, "wrapped KEK must be under the key base")
				_, err = os.Stat(filepath.Join(keyDir, "kek.wrapped"))
				require.True(t, os.IsNotExist(err), "no second blob beside the DEK")

				svc := NewService(cfg, dir)
				require.NoError(t, svc.ValidateKeyFiles())
				require.NoError(t, svc.FixKeyFilePermissions())
			})
		}
	}
}

// F3: the permission audit and fixer on a non-password install, with a
// vestigial salt_path and with none. Both used to refuse the key directory
// itself as "not a regular file".
func TestKeyFilePerms_NonPasswordProvider_NoSaltEntry(t *testing.T) {
	const kek = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, salt := range []string{"kek.salt", ""} {
		t.Run(fmt.Sprintf("salt_path=%q", salt), func(t *testing.T) {
			t.Setenv("KEYORIX_TEST_PERMS_KEK", kek)
			dir := t.TempDir()
			cfg := &config.EncryptionConfig{
				Enabled:     true,
				DEKPath:     "dek.key",
				SaltPath:    salt,
				KeyProvider: config.KeyProviderConfig{Type: "env", EnvVar: "KEYORIX_TEST_PERMS_KEK"},
			}
			require.NoError(t, bootLikeServer(t, cfg, dir, ""))
			svc := NewService(cfg, dir)
			require.NoError(t, svc.ValidateKeyFiles())
			require.NoError(t, svc.FixKeyFilePermissions())
		})
	}
}
