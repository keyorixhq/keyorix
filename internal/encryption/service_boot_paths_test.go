// service_boot_paths_test.go — regression tests for the Docker Compose / Helm
// chart crash-loop: an absolute dek_path/salt_path (in the same directory, the
// shape both keyorix.docker.yaml and the Helm chart ship) failed the REAL boot
// path with "failed to write salt: access denied: path %q must be relative".
//
// absolute_key_paths_test.go already covers KeyManager.Initialize directly, but
// that only exercises deriveKEK's legacy km.keyProvider==nil branch
// (ensureSaltExists) — documented as "unreachable from any live production
// caller today" (Service.NewService always calls SetKeyProvider first). The
// real boot path goes through Service.Initialize -> buildKeyProvider ->
// crypto.NewPasswordKeyProvider, which is what actually crash-looped: it was
// built with cfg.SaltPath (the Service's raw, un-normalized config field) even
// though the baseDir alongside it was already the normalized km.baseDir — two
// different views of the same configured path, only one of them reconciled.
// These tests go through Service.Initialize end to end so they only pass once
// every consumer sees normalizeKeyPaths' output, not just KeyManager's own
// fields.
package encryption

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The exact shape keyorix.docker.yaml and the Helm chart's server-config.yaml
// both ship: absolute dek_path/salt_path in the same directory (e.g.
// /app/keys/data.key, /app/keys/kek.salt). Before the fix this crash-looped
// every boot with "failed to write salt: access denied: path ... must be
// relative" — this test fails the same way if the regression reappears.
func TestService_Initialize_AbsoluteKeyPaths_SameDirectory_BootsEndToEnd(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  filepath.Join(dir, "data.key"),
		SaltPath: filepath.Join(dir, "kek.salt"),
	}
	svc := NewService(cfg, ".")

	require.NoError(t, svc.Initialize("correct horse battery staple"),
		"first boot with absolute dek_path/salt_path in one directory must succeed, not crash-loop")
	assert.True(t, svc.IsInitialized())
	assert.FileExists(t, filepath.Join(dir, "data.key"))
	assert.FileExists(t, filepath.Join(dir, "kek.salt"))

	// The server lock (dek.lock) must land beside the keys too, in the SAME
	// directory as the PVC/bind mount that's actually writable — not at
	// baseDir's root ("."), which under a readOnlyRootFilesystem deployment
	// (the Helm chart's own default) is read-only.
	require.NoError(t, svc.AcquireExclusiveKeyLock())
	assert.FileExists(t, filepath.Join(dir, "dek.lock"))
}

// A second, independent Service instance (simulating a restart, or the
// `keyorix-server admin encryption ...` CLI operating on the same key
// directory) must be able to re-derive the same KEK/DEK from disk, not just
// perform first-boot generation.
func TestService_Initialize_AbsoluteKeyPaths_SecondBootUnwrapsExistingDEK(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  filepath.Join(dir, "data.key"),
		SaltPath: filepath.Join(dir, "kek.salt"),
	}
	const passphrase = "correct horse battery staple"

	first := NewService(cfg, ".")
	require.NoError(t, first.Initialize(passphrase))
	encBytes, _, err := first.EncryptSecret([]byte("hunter2"))
	require.NoError(t, err)

	second := NewService(cfg, ".")
	require.NoError(t, second.Initialize(passphrase),
		"a second Service against the same absolute key paths must unwrap the existing DEK")
	plain, err := second.DecryptSecret(encBytes)
	require.NoError(t, err)
	assert.Equal(t, "hunter2", string(plain))
}

// The Helm chart's readOnlyRootFilesystem: true setting only mounts the keys
// directory itself writable — its PARENT is not. dek.lock must land inside the
// (writable) keys directory even for the historically-default RELATIVE
// dek_path/salt_path convention (e.g. "keys/data.key"), where baseDir is "."
// (the container WORKDIR) and normalizeKeyPaths deliberately leaves baseDir
// unchanged. Before this fix dek.lock was placed at join(baseDir, "dek.lock")
// unconditionally — i.e. beside the config file, one level above the actual
// keys — which a read-only parent refuses to create.
func TestService_AcquireExclusiveKeyLock_RelativeKeyPaths_ReadOnlyParent_LockInsideKeysDir(t *testing.T) {
	root := t.TempDir()
	keysDir := filepath.Join(root, "keys")
	require.NoError(t, os.Mkdir(keysDir, 0o700))

	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "keys/data.key",
		SaltPath: "keys/kek.salt",
	}
	svc := NewService(cfg, root)
	require.NoError(t, svc.Initialize("correct horse battery staple"))

	// Lock permissions down to what the chart's readOnlyRootFilesystem actually
	// grants: the keys directory is writable, its parent is not.
	require.NoError(t, os.Chmod(root, 0o500))
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })

	require.NoError(t, svc.AcquireExclusiveKeyLock(),
		"dek.lock must be creatable inside the writable keys directory even when its parent is read-only")
	assert.FileExists(t, filepath.Join(keysDir, "dek.lock"))
}
