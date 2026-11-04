// key_lock_refusal_message_test.go — MSG-ACCURACY-1 item 1 follow-up (#3742,
// REVIEW-3933-DEEP-1 F2): `admin diagnose`, the audit-export checkpoint key
// and `admin backup` added "a live server / another process is using it" to
// ANY key-lock failure, including a missing key directory. Only real lock
// contention may blame another process.
//
// Not t.Parallel(): package convention (see backup_restore_integration_test.go).
package admin

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

const keyLockTestPassphrase = "test-passphrase-1234"

func keyLockCallers() map[string]func(cfg *config.Config) error {
	pass := func() ([]byte, error) { return []byte(keyLockTestPassphrase), nil }
	return map[string]func(cfg *config.Config) error{
		"diagnose": func(cfg *config.Config) error { return diagnoseEncryption(cfg) },
		"checkpoint key": func(cfg *config.Config) error {
			svc, err := unlockEncryptionService(cfg, pass)
			if err == nil {
				svc.Shutdown()
			}
			return err
		},
		"backup": func(cfg *config.Config) error {
			_, err := unwrapManifestKeyWith(cfg, ".", pass, nil)
			return err
		},
	}
}

func TestAdminKeyLockRefusal_MessageMatchesTheCause(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", keyLockTestPassphrase)
	encCfg := config.EncryptionConfig{Enabled: true, DEKPath: "keys/dek.key", SaltPath: "keys/kek.salt"}
	cfg := &config.Config{Storage: config.StorageConfig{Type: "local", Encryption: encCfg}}
	blame := []string{"live server", "stop the", "another process", "is using"}

	for name, call := range keyLockCallers() {
		t.Run(name+"/missing key directory", func(t *testing.T) {
			chdirTest(t, t.TempDir())
			err := call(cfg)
			require.Error(t, err)
			msg := err.Error()
			require.Contains(t, msg, "does not exist")
			for _, b := range blame {
				require.NotContains(t, msg, b, "a missing key directory is not contention")
			}
		})
		t.Run(name+"/lock contention", func(t *testing.T) {
			dir := t.TempDir()
			chdirTest(t, dir)
			require.NoError(t, os.Mkdir("keys", 0o700))
			holder := encryption.NewService(&encCfg, dir)
			require.NoError(t, holder.AcquireExclusiveKeyLock())
			defer holder.Shutdown()

			err := call(cfg)
			require.Error(t, err)
			msg := err.Error()
			require.True(t, strings.Contains(msg, "live server") || strings.Contains(msg, "stop the") || strings.Contains(msg, "another process"),
				"real contention must name the likely holder: %q", msg)
		})
	}
}
