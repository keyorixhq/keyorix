package encryption

// #4249: with a relative storage.encryption.dek_path, the DEK lock (dek.lock,
// beside the DEK) landed in each process's working directory. Two servers on
// the same config started from two directories took two different lock files,
// so neither refused the other and both served the same database. The test
// drives the issue's repro through config.Load, the path every server and
// `admin` command takes: one server reads the config from its own directory by
// a relative config path, the other by its absolute path from an unrelated cwd
// (the issue's repo clone). Whichever starts second must not get the key set.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/require"
)

const relativeKeyPathsConfig = "storage:\n  encryption:\n    enabled: true\n    dek_path: data.key\n    salt_path: kek.salt\n"

type keyLockInstance struct{ cwd, configPath string }

// startKeyLockInstance is the key-lock part of a server start from inst.cwd:
// config.Load, then the DEK lock initializeEncryption takes before touching a
// key file. It returns the first refusal, and releases the lock at test end.
func startKeyLockInstance(t *testing.T, inst keyLockInstance) error {
	t.Helper()
	t.Chdir(inst.cwd)
	cfg, err := config.Load(inst.configPath)
	if err != nil {
		return err
	}
	svc := NewService(&cfg.Storage.Encryption, ".")
	t.Cleanup(svc.Shutdown)
	return svc.AcquireExclusiveKeyLock()
}

func TestRelativeDEKPath_TwoServersFromDifferentCwd_SecondIsRefused(t *testing.T) {
	dataDir, cloneDir := t.TempDir(), t.TempDir()
	cfgPath := filepath.Join(dataDir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(relativeKeyPathsConfig), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "second.yaml"), []byte(relativeKeyPathsConfig), 0o600))
	inDataDir := keyLockInstance{cwd: dataDir, configPath: "second.yaml"}
	inClone := keyLockInstance{cwd: cloneDir, configPath: cfgPath}

	for name, order := range map[string][2]keyLockInstance{
		"config dir first": {inDataDir, inClone},
		"clone first":      {inClone, inDataDir},
	} {
		t.Run(name, func(t *testing.T) {
			first := startKeyLockInstance(t, order[0])
			second := startKeyLockInstance(t, order[1])
			require.False(t, first == nil && second == nil,
				"two servers on one key set from different working directories both started")
			require.ErrorContains(t, startKeyLockInstance(t, inClone), "#4249",
				"the instance outside the config's directory is refused with the fix")
			_, err := os.Stat(filepath.Join(cloneDir, serverLockFileName))
			require.ErrorIs(t, err, os.ErrNotExist, "no DEK lock may be created in the other working directory")
		})
	}
}

// Control: from the same (config) directory the second server is refused by
// the DEK lock itself, as before.
func TestRelativeDEKPath_TwoServersFromConfigDir_SecondRefusedByLock(t *testing.T) {
	dataDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "keyorix.yaml"), []byte(relativeKeyPathsConfig), 0o600))
	inst := keyLockInstance{cwd: dataDir, configPath: filepath.Join(dataDir, "keyorix.yaml")}

	require.NoError(t, startKeyLockInstance(t, inst))
	require.ErrorContains(t, startKeyLockInstance(t, inst), "already holds the DEK lock")
	require.FileExists(t, filepath.Join(dataDir, serverLockFileName), "the lock lives beside the key it protects")
}
