package encryptionops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// KEYMATERIAL-RESCUE-1 item 3 (the leftover of KEYMATERIAL-TAILS-1 item 5, the
// #3523 family): the auth-encryption commands that work on existing keys refuse
// missing keys BEFORE they open the database. Opening a SQLite path creates the
// file, so a run from the wrong directory (or with a wrong dek_path) refused for
// missing keys but left a fresh empty database behind, which the next server
// start from that directory then took for its own.
func TestAuthEncryptionCommands_MissingKeys_CreateNoDatabase(t *testing.T) {
	ops := []struct {
		name string
		run  func(cfg *config.Config) error
	}{
		{"status", func(cfg *config.Config) error { return AuthStatusWithConfig(cfg, zeroPassSrc()) }},
		{"validate", func(cfg *config.Config) error { return ValidateAuthEncryptionWithConfig(cfg, false, zeroPassSrc()) }},
		{"rotate", func(cfg *config.Config) error { return RotateAuthEncryptionWithConfig(cfg, true, zeroPassSrc()) }},
		{"migrate", func(cfg *config.Config) error { return MigrateAuthDataWithConfig(cfg, false, zeroPassSrc()) }},
	}
	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			dir := chdirTemp(t)
			setPassphraseEnv(t, testBaselinePassphrase)
			cfg := testConfig(true)
			if cfg.Storage.Type != "local" {
				t.Fatalf("testConfig storage type %q: this test needs local SQLite, whose open creates the file", cfg.Storage.Type)
			}
			out, err := captureOutput(t, func() error { return op.run(cfg) })
			if err == nil {
				t.Fatalf("auth-encryption %s with no key files succeeded; output:\n%s", op.name, out)
			}
			if !strings.Contains(err.Error(), "does not create keys") {
				t.Errorf("auth-encryption %s: refusal %q is not the missing-keys one", op.name, err)
			}
			for _, f := range []string{testDBFile, testDBFile + "-wal", testDBFile + "-shm", "dek.key", "kek.salt"} {
				if _, serr := os.Stat(filepath.Join(dir, f)); serr == nil {
					t.Errorf("auth-encryption %s refused for missing keys but left %s behind", op.name, f)
				}
			}
		})
	}
}
