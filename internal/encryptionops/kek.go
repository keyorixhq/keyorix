// kek.go — the testable core of `encryption rotate-kek`.
//
// Changes the master passphrase by re-wrapping the current DEK under a new KEK
// derived from the new passphrase + a freshly generated salt. Unlike DEK
// rotation, no database rows are re-encrypted and no database connection is
// required — only the key files are updated.
package encryptionops

import (
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
)

// RotateKEKWithConfig is the testable core of `encryption rotate-kek`. All
// validation gates (encryption disabled, remote storage, missing passphrases,
// --confirm) return before any key-file work so tests don't need real key
// files.
//
// Crash safety: RotateKEKPassphrase re-wraps the DEK under the new KEK and
// writes it via the same atomic write-then-rename pattern the rest of this
// package's key-file writes use — a kill mid-write leaves either the OLD
// wrapped DEK (rename never happened) or the fully-written NEW one on disk,
// never a torn/partial file. Because the DEK's VALUE never changes here (only
// its wrapping), a kill leaves the database fully readable under whichever of
// the old or new passphrase matches whichever wrapped-DEK file survived —
// never a state where no passphrase works.
func RotateKEKWithConfig(cfg *config.Config, confirm bool, oldSrc, newSrc crypto.PassphraseSource) error {
	if !cfg.Storage.Encryption.Enabled {
		return fmt.Errorf("encryption is disabled in configuration")
	}
	if cfg.Storage.Type == "remote" {
		return fmt.Errorf("KEK rotation must run on the server host. Current storage type is 'remote' — connect to the server and run this command there")
	}
	if !confirm {
		return fmt.Errorf("this changes the master passphrase and re-wraps the DEK. Re-run with --confirm")
	}

	oldPassphrase, err := MasterPassphrase(cfg, oldSrc)
	if err != nil {
		return err
	}

	newPassphraseBytes, err := crypto.ResolvePassphrase(newSrc, NewMasterPassphraseEnvVar)
	if err != nil {
		return err
	}
	defer crypto.WipeBytes(newPassphraseBytes)
	newPassphrase := string(newPassphraseBytes)
	if oldPassphrase == newPassphrase {
		return fmt.Errorf("new passphrase must differ from the old passphrase")
	}

	baseDir, _ := os.Getwd()
	service := encryption.NewService(&cfg.Storage.Encryption, baseDir)

	service.CleanPendingDEK()
	if err := service.Initialize(oldPassphrase); err != nil {
		return fmt.Errorf("failed to initialize encryption (wrong old passphrase?): %w", err)
	}
	defer service.Shutdown()

	// Acquire the exclusive key lock to prevent a concurrent server or rotation
	// from interfering. RotateKEKPassphrase also acquires the lock internally
	// (cross-process flock), but we call AcquireExclusiveKeyLock here first so
	// a live server fails fast with a clear message rather than silently waiting.
	if err := service.AcquireExclusiveKeyLock(); err != nil {
		return fmt.Errorf("refusing to rotate KEK: %w — stop the running server before rotating", err)
	}

	fmt.Println("Rotating KEK — re-wrapping DEK under new passphrase...")
	if err := service.RotateKEKPassphrase(oldPassphrase, newPassphrase); err != nil {
		return fmt.Errorf("KEK rotation failed: %w", err)
	}

	// EvidenceSignKey/AuditCheckpointKey return fresh copies of the raw 32-byte
	// HMAC key material (KeyManager.GetEvidenceSignKey/GetAuditCheckpointKey) —
	// only the fingerprint is needed here, so wipe each copy immediately rather
	// than letting it sit unwiped in memory until the GC gets to it.
	eskKey, eskID, ok := service.EvidenceSignKey()
	if !ok {
		eskID = "(unavailable)"
	}
	crypto.WipeBytes(eskKey)
	ackKey, ackID, ok := service.AuditCheckpointKey()
	if !ok {
		ackID = "(unavailable)"
	}
	crypto.WipeBytes(ackKey)

	fmt.Println("KEK rotation complete.")
	fmt.Println()
	fmt.Printf("  Evidence-signing key fingerprint:      %s\n", eskID)
	fmt.Printf("  Audit-checkpoint key fingerprint:      %s\n", ackID)
	fmt.Println()
	fmt.Println("Update the master passphrase in your deployment configuration to the new value before restarting the server.")
	fmt.Println()
	fmt.Println("Note: evidence packs and audit checkpoints signed before this rotation will")
	fmt.Println("report as 'superseded key version' (not tampered) under `compliance verify`.")
	return nil
}
