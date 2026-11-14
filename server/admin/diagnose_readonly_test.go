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

	for name, enc := range map[string]config.EncryptionConfig{
		"key directory missing":   {Enabled: true, DEKPath: "keys/dek.key", SaltPath: "keys/kek.salt"},
		"keys in the data dir":    {Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"},
		"key directory is empty":  {Enabled: true, DEKPath: "keys/dek.key", SaltPath: "keys/kek.salt"},
		"salt only, DEK missing":  {Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"},
		"DEK only, salt missing":  {Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"},
		"absolute key paths":      {Enabled: true},
		"absolute, dir not there": {Enabled: true},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			chdirTest(t, dir)
			switch name {
			case "key directory is empty":
				require.NoError(t, os.Mkdir("keys", 0o700))
			case "salt only, DEK missing":
				require.NoError(t, os.WriteFile("kek.salt", make([]byte, 32), 0o600))
			case "DEK only, salt missing":
				require.NoError(t, os.WriteFile("dek.key", make([]byte, 60), 0o600))
			case "absolute key paths":
				enc.DEKPath = filepath.Join(dir, "abs", "dek.key")
				enc.SaltPath = filepath.Join(dir, "abs", "kek.salt")
				require.NoError(t, os.Mkdir("abs", 0o700))
			case "absolute, dir not there":
				enc.DEKPath = filepath.Join(dir, "abs", "dek.key")
				enc.SaltPath = filepath.Join(dir, "abs", "kek.salt")
			}
			cfg := &config.Config{Storage: config.StorageConfig{Type: "local", Encryption: enc}}

			before := dirEntries(t, dir)
			err := diagnoseEncryption(cfg)
			require.Error(t, err, "missing key files are a failed check, not a silent first boot")
			require.Contains(t, err.Error(), "does not exist")
			require.Contains(t, err.Error(), "read-only")
			require.Equal(t, before, dirEntries(t, dir),
				"diagnose is read-only: no salt, DEK, lock or directory may be created")
		})
	}
}
