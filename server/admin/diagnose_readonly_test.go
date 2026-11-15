// diagnose_readonly_test.go — PILOT-KEYPATHS-NOV-1 item 2 (PILOT-RUNBOOK-WALK-3,
// j7-troubleshooting #5): `admin diagnose` created key files (salt, wrapped DEK,
// dek.lock) when they were missing, because its KEK check ran the same
// Initialize the server runs on first boot. A diagnose command is read-only: a
// missing key must be reported as missing and nothing may appear on disk.
//
// Not t.Parallel(): package convention (chdirTest changes the process cwd).
package admin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// dirEntries lists every path under root (relative), so a created file or
// directory shows up as a difference.
func dirEntries(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	require.NoError(t, filepath.WalkDir(root, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		out = append(out, rel)
		return nil
	}))
	return out
}

func TestDiagnoseEncryption_MissingKeys_ReportsMissingAndCreatesNothing(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", keyLockTestPassphrase)

	writeFile := func(name string, size int) func(t *testing.T, _ string, _ *config.EncryptionConfig) {
		return func(t *testing.T, _ string, _ *config.EncryptionConfig) {
			require.NoError(t, os.WriteFile(name, make([]byte, size), 0o600))
		}
	}
	absPaths := func(mkdir bool) func(t *testing.T, dir string, enc *config.EncryptionConfig) {
		return func(t *testing.T, dir string, enc *config.EncryptionConfig) {
			enc.DEKPath = filepath.Join(dir, "abs", "dek.key")
			enc.SaltPath = filepath.Join(dir, "abs", "kek.salt")
			if mkdir {
				require.NoError(t, os.Mkdir("abs", 0o700))
			}
		}
	}
	for _, tc := range []struct {
		name  string
		enc   config.EncryptionConfig
		setup func(t *testing.T, dir string, enc *config.EncryptionConfig)
	}{
		{name: "key directory missing", enc: config.EncryptionConfig{Enabled: true, DEKPath: "keys/dek.key", SaltPath: "keys/kek.salt"}},
		{name: "keys in the data dir", enc: config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}},
		{
			name: "key directory is empty", enc: config.EncryptionConfig{Enabled: true, DEKPath: "keys/dek.key", SaltPath: "keys/kek.salt"},
			setup: func(t *testing.T, _ string, _ *config.EncryptionConfig) { require.NoError(t, os.Mkdir("keys", 0o700)) },
		},
		{name: "salt only, DEK missing", enc: config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, setup: writeFile("kek.salt", 32)},
		{name: "DEK only, salt missing", enc: config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, setup: writeFile("dek.key", 60)},
		{name: "absolute key paths", enc: config.EncryptionConfig{Enabled: true}, setup: absPaths(true)},
		{name: "absolute, dir not there", enc: config.EncryptionConfig{Enabled: true}, setup: absPaths(false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			chdirTest(t, dir)
			enc := tc.enc
			if tc.setup != nil {
				tc.setup(t, dir, &enc)
			}
			cfg := &config.Config{Storage: config.StorageConfig{Type: "local", Encryption: enc}}

			before := dirEntries(t, dir)
			err := diagnoseEncryption(cfg)
			require.Error(t, err, "missing key files are a failed check, not a silent first boot")
			require.Contains(t, err.Error(), "does not exist")
			require.Contains(t, err.Error(), "read-only")
			require.Contains(t, err.Error(), "`keyorix-server admin encryption init` creates the keys",
				"the remedy must name the command that creates keys (`admin init` does not)")
			require.Equal(t, before, dirEntries(t, dir),
				"diagnose is read-only: no salt, DEK, lock or directory may be created")
		})
	}
}
