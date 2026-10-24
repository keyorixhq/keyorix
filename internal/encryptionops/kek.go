// kek.go — the testable core of `encryption rotate-kek`.
//
// Changes the master passphrase by re-wrapping the current DEK under a new KEK
// derived from the new passphrase + a freshly generated salt. Unlike DEK
// rotation, no database rows are re-encrypted — only the key files are
// updated; the database is read only for DEK-rotation crash recovery.
package encryptionops

import (
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
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
	// Only the password provider has a passphrase to rotate. With any other
	// provider this used to open the database and key files and then fail on an
	// empty old passphrase (REVIEW-ENCRYPTIONOPS-1 F4).
	if t := cfg.Storage.Encryption.KeyProvider.Type; t != "" && t != "password" {
		return fmt.Errorf("rotate-kek changes the master passphrase of the password key provider; this install uses key_provider.type %q. Use `migrate-provider` to move the DEK to a new KEK", t)
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
	// The exclusive key lock first, so a live server fails fast with a clear
	// message (RotateKEKPassphrase also takes the key-file rewrite lock
	// internally). Then crash recovery: the re-wrap writes dek.key.pending, which
	// after an interrupted DEK rotation holds the only copy of the new DEK. The
	// database is opened only to read that rotation's redo marker.
	service, db, err := openKeyWriter(cfg, baseDir, oldPassphrase, "rotate KEK")
	if err != nil {
		return err
	}
	defer service.Shutdown()
	closeGormDB(db)

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
	warnLeftoverMigrateBackups(cfg, baseDir)
	return nil
}

// warnLeftoverMigrateBackups names the <dek_path>.migrate-backup.* files left by
// earlier migrate-provider runs. Each is the DEK wrapped under an older KEK, so
// whoever holds the old passphrase (or old provider) and such a file still
// unwraps the live DEK: rotating the KEK does not retire them (F3).
func warnLeftoverMigrateBackups(cfg *config.Config, baseDir string) {
	backups, err := FindMigrateBackups(baseDir, cfg.Storage.Encryption.DEKPath)
	if err != nil {
		fmt.Printf("⚠️  Could not check for leftover migrate-backup files: %v\n", err)
		return
	}
	if len(backups) == 0 {
		return
	}
	fmt.Println()
	fmt.Printf("⚠️  %d migrate-backup file(s) still hold the DEK wrapped under an OLDER KEK:\n", len(backups))
	for _, b := range backups {
		fmt.Printf("     %s\n", b)
	}
	fmt.Println("   The old passphrase (or old provider) plus any of these still unwraps the DEK.")
	fmt.Println("   If you rotated because the old passphrase leaked, run")
	fmt.Println("   `migrate-provider cleanup --confirm` now.")
}
