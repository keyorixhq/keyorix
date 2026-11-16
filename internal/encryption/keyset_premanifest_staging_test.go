package encryption

// #2424 / #2900 criterion 4, end to end with real keys: a pre-manifest install
// (no keyset.manifest.json) whose rotate-kek was interrupted. The two states
// #2900 describes have the same file layout (kek.salt.pending present, no
// dek.key.pending):
//
//   - harmful: interrupted between the DEK and the salt rename, so the active
//     set is the OLD salt with the NEW DEK, and kek.salt.pending holds the new
//     salt. No passphrase opens it. The runbook's fix is to rename the staged
//     salt into place. That fixed set must then boot: had the first (failing)
//     start adopted the broken set as generation 1, the fixed salt would be
//     refused as a file from another generation.
//   - harmless: interrupted before any rename; kek.salt.pending is garbage.
//     The start opens the set and adopts it (manifest + audit event) in that
//     same start, so the install does not stay without a manifest for as long
//     as the leftover file stays (boot never deletes it, #4105).
//
// Both drive the boot sequence's Service calls: ReconcileKeySet, then
// Initialize.

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// provisionPreManifestInstall writes a real key set for pass into dir/keys, as
// an older binary leaves it: no manifest.
func provisionPreManifestInstall(t *testing.T, dir, pass string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "keys"), 0o700))
	svc := NewService(passwordEncConfig(), dir)
	require.NoError(t, svc.Initialize(pass))
	svc.Shutdown()
	require.NoError(t, os.Remove(filepath.Join(dir, "keys", keyfiles.ManifestFileName)))
}

// bootKeySet runs boot's key steps on dir and returns the audit event types
// recorded and Initialize's error.
func bootKeySet(t *testing.T, dir, pass string) ([]string, error) {
	t.Helper()
	require.NoError(t, keyfiles.VerifyKeySetConsistency(passwordEncConfig(), dir), "boot refusal")
	var mu sync.Mutex
	var events []string
	svc := NewService(passwordEncConfig(), dir)
	svc.SetAuditSink(func(_ context.Context, e *models.AuditEvent) error {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e.EventType)
		return nil
	})
	t.Cleanup(svc.Shutdown)
	require.NoError(t, svc.ReconcileKeySet())
	err := svc.Initialize(pass)
	mu.Lock()
	defer mu.Unlock()
	return events, err
}

func TestPreManifestInterruptedRotateKEK_HarmfulState_FixedSetBoots(t *testing.T) {
	oldDir, newDir := t.TempDir(), t.TempDir()
	provisionPreManifestInstall(t, oldDir, "old passphrase for 2424")
	provisionPreManifestInstall(t, newDir, "new passphrase for 2424")
	keys := filepath.Join(oldDir, "keys")
	// rotate-kek renamed the new DEK into place, then stopped before the salt.
	copyKeyFile(t, filepath.Join(newDir, "keys", "dek.key"), filepath.Join(keys, "dek.key"))
	copyKeyFile(t, filepath.Join(newDir, "keys", "kek.salt"), filepath.Join(keys, "kek.salt.pending"))

	_, err := bootKeySet(t, oldDir, "new passphrase for 2424")
	require.Error(t, err, "old salt + new DEK must not open")
	assert.NoFileExists(t, filepath.Join(keys, keyfiles.ManifestFileName),
		"a start that could not open the set must not record it as generation 1")

	// The runbook's fix for this state: the staged salt goes into place.
	require.NoError(t, os.Rename(filepath.Join(keys, "kek.salt.pending"), filepath.Join(keys, "kek.salt")))
	events, err := bootKeySet(t, oldDir, "new passphrase for 2424")
	require.NoError(t, err, "the fixed set must boot")
	require.Equal(t, []string{EventKeySetManifestAdopted}, events)
	require.FileExists(t, filepath.Join(keys, keyfiles.ManifestFileName))
}

func TestPreManifestInterruptedRotateKEK_HarmlessState_AdoptedOnceOpened(t *testing.T) {
	dir := t.TempDir()
	provisionPreManifestInstall(t, dir, "only passphrase for 2424")
	keys := filepath.Join(dir, "keys")
	staged := filepath.Join(keys, "kek.salt.pending")
	require.NoError(t, os.WriteFile(staged, []byte("half-written salt"), 0o600))

	events, err := bootKeySet(t, dir, "only passphrase for 2424")
	require.NoError(t, err)
	require.Equal(t, []string{EventKeySetManifestAdopted}, events, "adopted in the same start, after Initialize")
	m, err := keyfiles.LoadManifest(filepath.Join(keys, keyfiles.ManifestFileName))
	require.NoError(t, err)
	require.Len(t, m.Files, 2, "the salt and the DEK, never the staging file")
	require.FileExists(t, staged, "boot never deletes the salt staging file (#4105)")

	events, err = bootKeySet(t, dir, "only passphrase for 2424")
	require.NoError(t, err)
	require.Empty(t, events, "the next start adopts nothing")
}

func copyKeyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(dst, data, 0o600))
}
