// backup_roundtrip_rotation_fork_test.go closes the committed fuzzer's op-9
// limitation: a COMPLETED DEK rotation (full re-encryption sweep) and a KEK
// rotation (passphrase change) cannot be driven in-process alongside a live
// storage handle because RotateDEKWithSweep / openKeyWriter take the EXCLUSIVE
// key-directory lock for their lifetime -- the subsequent in-process `admin
// backup` then deadlocks on that same lock. The CLI serialises the two as
// SEPARATE processes; these tests do the same, running the real
// encryptionops.RotateWithConfig / RotateKEKWithConfig in a child process, then
// backing up and restoring and asserting the round-trip oracles still hold over
// the rotated key material. This is the faithful, deterministic form of op 9;
// it is kept OUT of the metamorphic fuzz loop on purpose (a per-exec fork would
// dominate the already-heavy per-exec cost and add no new logical state the
// standalone tests do not already cover).
package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/encryptionops"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	bkRotateKindEnv = "KEYORIX_BK_ROTATE_KIND" // "dek" | "kek"; empty => not the helper
	bkRotateCfgEnv  = "KEYORIX_BK_ROTATE_CFG"
	bkRotateErrExit = 88
)

// TestBackupRoundtripRotateHelperProcess is NOT a test: run as a child process
// by forkRotate, it performs a real DEK or KEK rotation against the config named
// by KEYORIX_BK_ROTATE_CFG in the working directory the parent set (cmd.Dir,
// which the rotation uses as its key-directory base), inheriting
// KEYORIX_MASTER_PASSWORD (+ KEYORIX_NEW_MASTER_PASSWORD for kek). It exits the
// process directly, like TestAdminRestoreKillPointHelper.
func TestBackupRoundtripRotateHelperProcess(t *testing.T) {
	kind := os.Getenv(bkRotateKindEnv)
	if kind == "" {
		t.Skip("child-process helper for the rotation round-trip tests")
	}
	require.NoError(t, i18n.InitializeForTesting())
	configPathFlag = os.Getenv(bkRotateCfgEnv)
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper loadConfig: %v\n", err)
		os.Exit(bkRotateErrExit)
	}
	switch kind {
	case "dek":
		err = encryptionops.RotateWithConfig(cfg, true, false, crypto.PassphraseSource{})
	case "kek":
		err = encryptionops.RotateKEKWithConfig(cfg, true, crypto.PassphraseSource{}, crypto.PassphraseSource{})
	default:
		fmt.Fprintf(os.Stderr, "unknown rotate kind %q\n", kind)
		os.Exit(bkRotateErrExit)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper rotate(%s): %v\n", kind, err)
		os.Exit(bkRotateErrExit)
	}
	os.Exit(0)
}

// forkRotate runs one rotation in a child process against dir/cfgPath.
func forkRotate(t *testing.T, kind, dir, cfgPath string, extraEnv ...string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestBackupRoundtripRotateHelperProcess$", "-test.count=1") // #nosec G204 -- the test binary itself
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), bkRotateKindEnv+"="+kind, bkRotateCfgEnv+"="+cfgPath)
	cmd.Env = append(cmd.Env, extraEnv...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "rotation child (%s) failed; output:\n%s", kind, out)
}

// rotateWorld is a minimal seeded, encrypted SQLite source for the rotation
// round-trip tests: one project + one secret with a known plaintext.
type rotateWorld struct {
	dir       string
	cfgPath   string
	known     []knownVersion
	dekKeySHA string // sha256 of dek.key BEFORE the fork, to prove rotation really ran
}

// fileSHA returns the hex sha256 of a file's bytes (meaningfulness guard: a real
// rotation rewrites the key material, so this value must change after the fork).
func fileSHA(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	require.NoError(t, err)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func setupRotateWorld(t *testing.T) *rotateWorld {
	t.Helper()
	dir := t.TempDir()
	chdirTest(t, dir)
	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	enc := encryption.NewService(encCfg, dir)
	require.NoError(t, enc.Initialize(roundTripPassphrase))
	cfgPath := writeBackupRestoreTestConfig(t, dir, filepath.Join(dir, "secrets.db"))
	configPathFlag = cfgPath
	cfg, err := loadConfig()
	require.NoError(t, err)
	store, err := storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	gdb, err := storage.OpenGormDB(cfg)
	require.NoError(t, err)
	c := core.NewKeyorixCore(store)
	c.SetSecretValueEncryptor(enc)
	require.True(t, c.SecretValueEncryptionActive())

	ctx := context.Background()
	actor := &models.User{Username: "rot-actor", UsernameFolded: "rot-actor"}
	require.NoError(t, gdb.Create(actor).Error)
	p, err := c.CreateProject(ctx, "rot-proj", "d")
	require.NoError(t, err)
	envs, err := c.ListEnvironmentsByProject(ctx, p.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	pt := []byte("pre-rotation-plaintext-value")
	node, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "rot-secret", Value: pt, ProjectID: p.ID, EnvironmentID: envs[0].ID,
		Type: "password", CreatedBy: "rot",
	})
	require.NoError(t, err)

	// Release the parent's key-directory lock and DB handle so the child can take
	// the EXCLUSIVE rotation lock and own the re-encryption transaction.
	enc.Shutdown()
	if sqlDB, derr := gdb.DB(); derr == nil {
		_ = sqlDB.Close()
	}
	if closer, ok := store.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	return &rotateWorld{
		dir:       dir,
		cfgPath:   cfgPath,
		known:     []knownVersion{{nodeID: node.ID, projectID: p.ID, version: 1, plaintext: pt}},
		dekKeySHA: fileSHA(t, filepath.Join(dir, "dek.key")),
	}
}

// TestBackupRoundtripDEKRotation_Fork: a real DEK rotation + sweep in a child
// process, then backup -> restore. The known plaintext must still decrypt under
// the RESTORED, post-rotation key files (oracle 2), and the store must
// round-trip (oracle 1). DEK rotation re-wraps under the SAME passphrase, so the
// restore path needs no new passphrase.
func TestBackupRoundtripDEKRotation_Fork(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", roundTripPassphrase)

	w := setupRotateWorld(t)
	forkRotate(t, "dek", w.dir, w.cfgPath)

	// Meaningfulness guard: a real DEK rotation rewrites dek.key. If this did not
	// change, the fork was a no-op and oracle 2 below would pass vacuously.
	require.NotEqual(t, w.dekKeySHA, fileSHA(t, filepath.Join(w.dir, "dek.key")),
		"DEK rotation must rewrite dek.key (else the round-trip oracle is vacuous)")

	// chdir back into the source (the child may have changed nothing, but
	// restoreInto/backupTables rely on the process CWD being the source dir).
	chdirTest(t, w.dir)
	configPathFlag = w.cfgPath

	archive := filepath.Join(t.TempDir(), "rot.tar.gz")
	_, tables1, _, err := backupTables(t, archive)
	require.NoError(t, err, "backup after DEK rotation")

	dstDir, restoreOut, rerr := restoreInto(t, "sqlite", "", archive)
	require.NoError(t, rerr, "restore after DEK rotation: %s", restoreOut)
	require.Contains(t, restoreOut, "verify-audit on the restored database: VALID")
	dstCfg, err := loadConfig()
	require.NoError(t, err)

	oracleDecrypt(t, dstDir, dstCfg, w.known) // oracle 2 under the rotated+restored DEK

	archive2 := filepath.Join(t.TempDir(), "rot2.tar.gz")
	_, tables2, _, err := backupTables(t, archive2)
	require.NoError(t, err, "re-backup of restored rotated store")
	assertLogicalEqual(t, tables1, tables2, "DEK-rotation round-trip oracle1")
}

// TestBackupRoundtripKEKRotation_Fork: a real KEK rotation (passphrase change,
// re-wraps the DEK, no DB re-encryption) in a child process. After it, the key
// files open ONLY under the NEW passphrase -- so the backup/restore and oracle-2
// decrypt all run under KEYORIX_NEW_MASTER_PASSWORD. The known plaintext (its
// ciphertext unchanged by a KEK rotation) must still decrypt under the restored
// key files unwrapped with the new passphrase (oracle 2), and the store must
// round-trip (oracle 1).
func TestBackupRoundtripKEKRotation_Fork(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	const newPass = "metamorphic-passphrase-ROTATED-5678"
	t.Setenv("KEYORIX_MASTER_PASSWORD", roundTripPassphrase)

	w := setupRotateWorld(t)
	forkRotate(t, "kek", w.dir, w.cfgPath, encryptionops.NewMasterPassphraseEnvVar+"="+newPass)

	// Meaningfulness guard: a KEK rotation re-wraps the DEK under the new KEK, so
	// dek.key's on-disk (wrapped) bytes must change even though the DEK itself is
	// unchanged. If not, the fork was a no-op and oracle 2 would pass vacuously.
	require.NotEqual(t, w.dekKeySHA, fileSHA(t, filepath.Join(w.dir, "dek.key")),
		"KEK rotation must re-wrap dek.key under the new passphrase")

	// From here the key files require the NEW passphrase. Point the current-master
	// env at it so backup/restore/decrypt all unwrap correctly.
	t.Setenv("KEYORIX_MASTER_PASSWORD", newPass)
	chdirTest(t, w.dir)
	configPathFlag = w.cfgPath

	archive := filepath.Join(t.TempDir(), "kek.tar.gz")
	_, tables1, _, err := backupTables(t, archive)
	require.NoError(t, err, "backup after KEK rotation")

	dstDir, restoreOut, rerr := restoreInto(t, "sqlite", "", archive)
	require.NoError(t, rerr, "restore after KEK rotation: %s", restoreOut)
	require.Contains(t, restoreOut, "verify-audit on the restored database: VALID")
	dstCfg, err := loadConfig()
	require.NoError(t, err)

	oracleDecryptPass(t, dstDir, dstCfg, w.known, newPass) // oracle 2 under the new passphrase

	archive2 := filepath.Join(t.TempDir(), "kek2.tar.gz")
	_, tables2, _, err := backupTables(t, archive2)
	require.NoError(t, err, "re-backup of restored KEK-rotated store")
	assertLogicalEqual(t, tables1, tables2, "KEK-rotation round-trip oracle1")
}

// oracleDecryptPass is oracleDecrypt with an explicit passphrase (the committed
// oracleDecrypt hardcodes roundTripPassphrase; a KEK rotation changes it).
func oracleDecryptPass(t *testing.T, dstDir string, dstCfg *config.Config, known []knownVersion, passphrase string) {
	t.Helper()
	if len(known) == 0 {
		return
	}
	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	enc := encryption.NewService(encCfg, dstDir)
	require.NoError(t, enc.Initialize(passphrase), "re-init encryption over restored key files")
	gdb, err := storage.OpenGormDB(dstCfg)
	require.NoError(t, err)
	for _, kv := range known {
		var row models.SecretVersion
		if gdb.Where("secret_node_id = ? AND version_number = ?", kv.nodeID, kv.version).First(&row).Error != nil {
			continue
		}
		aad := encryption.SecretAAD(kv.nodeID, kv.projectID, kv.version)
		got, derr := enc.DecryptSecretWithAAD(row.EncryptedValue, aad)
		require.NoError(t, derr, "oracle2(kek): restored version (node=%d ver=%d) failed to decrypt", kv.nodeID, kv.version)
		require.True(t, bytesEqualConst(got, kv.plaintext), "oracle2(kek): restored plaintext mismatch node=%d ver=%d", kv.nodeID, kv.version)
	}
}
