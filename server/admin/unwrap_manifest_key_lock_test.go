// unwrap_manifest_key_lock_test.go — SESSION-AT AT1 area 3/4: `admin backup`
// used to call unwrapManifestKey (derive the KEK, acquire+release the
// exclusive key lock) and THEN, as a wholly separate, unlocked step, call
// readKeyFilesForBackup to read the live key-material files into the
// archive. AcquireExclusiveKeyLock's own doc comment states its purpose is
// to serialize against "an in-progress rotation/migrate-provider" -- but
// releasing it before the key-file read defeats that purpose for exactly
// the operation (backup) that most needs a self-consistent key-material
// snapshot: a concurrent rotation could acquire the lock, rewrite some (not
// necessarily all) of the key files, and release, landing entirely inside
// the gap between unwrapManifestKey's return and readKeyFilesForBackup's
// read -- archiving a key-material SET that is individually well-formed
// per file but mutually inconsistent, unusable by a later restore.
//
// Fix: unwrapManifestKey takes an onLocked callback, run while the
// exclusive lock from the KEK derivation is still held; admin backup now
// passes readKeyFilesForBackup there instead of calling it separately
// after unwrapManifestKey returns.
//
// Not t.Parallel(): package convention (see backup_restore_integration_test.go).
package admin

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

func setupLockTestKeyMaterial(t *testing.T) (dir string, encCfg *config.EncryptionConfig, cfg *config.Config) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	dir = t.TempDir()
	chdirTest(t, dir)
	encCfg = &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	require.NoError(t, encryption.NewService(encCfg, dir).Initialize("test-passphrase-1234"))
	cfg = &config.Config{Storage: config.StorageConfig{Type: "local", Encryption: *encCfg}}
	return dir, encCfg, cfg
}

// TestUnwrapManifestKey_OldCallShape_ReleasesLockBeforeCallerActsOnIt is the
// red-proof: it exercises the EXACT call shape `runAdminBackup` used before
// this fix -- call unwrapManifestKey with no onLocked (nil), THEN,
// separately, act as if doing the key-file read -- and shows a second,
// independent caller's AcquireExclusiveKeyLock can already succeed by that
// point, proving the lock was free during the exact window the old code
// left its own key-file read unprotected in.
func TestUnwrapManifestKey_OldCallShape_ReleasesLockBeforeCallerActsOnIt(t *testing.T) {
	_, _, cfg := setupLockTestKeyMaterial(t)
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-passphrase-1234")

	key, err := unwrapManifestKey(cfg, ".", crypto.PassphraseSource{}, nil)
	require.NoError(t, err)
	require.NotEmpty(t, key)

	// Simulates a concurrent `admin encryption rotate-kek` landing in the
	// gap the old runAdminBackup left between unwrapManifestKey returning
	// and its own, separate readKeyFilesForBackup call.
	rotator := encryption.NewService(&cfg.Storage.Encryption, ".")
	lockErr := rotator.AcquireExclusiveKeyLock()
	assert.NoError(t, lockErr, "demonstrates the gap this PR closes: a second caller's exclusive-lock "+
		"acquisition succeeds immediately after unwrapManifestKey(onLocked=nil) returns -- a concurrent "+
		"rotation could land here, before any key-file read happens, and the old code had no protection "+
		"against exactly this")
	if lockErr == nil {
		rotator.Shutdown()
	}
}

// TestUnwrapManifestKey_OnLocked_RunsWhileExclusiveLockStillHeld is the
// green-proof: admin backup's actual current call shape (onLocked non-nil,
// running readKeyFilesForBackup) keeps the SAME exclusive lock held for the
// callback's entire duration -- a second, independent caller's
// AcquireExclusiveKeyLock attempt fails while onLocked is still running,
// and only succeeds once it returns.
func TestUnwrapManifestKey_OnLocked_RunsWhileExclusiveLockStillHeld(t *testing.T) {
	_, _, cfg := setupLockTestKeyMaterial(t)
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-passphrase-1234")

	entered := make(chan struct{})
	proceed := make(chan struct{})
	done := make(chan error, 1)

	go func() {
		_, err := unwrapManifestKey(cfg, ".", crypto.PassphraseSource{}, func() error {
			close(entered)
			<-proceed
			return nil
		})
		done <- err
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("onLocked never started")
	}

	rotator := encryption.NewService(&cfg.Storage.Encryption, ".")
	lockErr := rotator.AcquireExclusiveKeyLock()
	assert.Error(t, lockErr, "a second caller's exclusive-lock acquisition must fail while onLocked "+
		"(standing in for readKeyFilesForBackup) is still running -- the fix's whole point")

	close(proceed)
	require.NoError(t, <-done)

	// Once onLocked has returned and unwrapManifestKey's own Shutdown has
	// run, the lock must be free again -- the fix holds it longer, not
	// forever.
	rotator2 := encryption.NewService(&cfg.Storage.Encryption, ".")
	require.NoError(t, rotator2.AcquireExclusiveKeyLock(), "the lock must release once unwrapManifestKey returns")
	rotator2.Shutdown()
}

// TestUnwrapManifestKeyWithOnLocked_PropagatesCallbackError confirms a
// failing onLocked (readKeyFilesForBackup returning an error) surfaces as
// unwrapManifestKey's own error, so runAdminBackup's existing `if err !=
// nil { return err }` handling after the call covers it -- no separate
// error-handling path needed at the call site.
func TestUnwrapManifestKeyWithOnLocked_PropagatesCallbackError(t *testing.T) {
	_, _, cfg := setupLockTestKeyMaterial(t)
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-passphrase-1234")

	sentinel := assert.AnError
	_, err := unwrapManifestKey(cfg, ".", crypto.PassphraseSource{}, func() error {
		return sentinel
	})
	require.ErrorIs(t, err, sentinel)
}
