// rotate_kek.go — `keyorix encryption rotate-kek`.
//
// Changes the master passphrase by re-wrapping the current DEK under a new KEK
// derived from the new passphrase + a freshly generated salt. Unlike
// `encryption rotate`, no database rows are re-encrypted and no database
// connection is required — only the key files are updated.
package encryption

import (
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/spf13/cobra"
)

// newMasterPasswordEnvKEK is the env var that carries the new master passphrase
// for KEK rotation. Intentionally the same constant as migrate_provider.go uses
// so the two commands share the same "new password" convention, but we reference
// it by name here to keep the compile dependency explicit.
const newMasterPasswordEnvKEK = "KEYORIX_NEW_MASTER_PASSWORD" // #nosec G101 -- env var name, not a credential

var rotateKEKCmd = &cobra.Command{
	Use:   "rotate-kek",
	Short: "Change the master passphrase (re-wraps DEK, no database re-encryption)",
	Long: `Derives a new KEK from a new master passphrase and re-wraps the existing
Data Encryption Key (DEK) under it. Unlike 'encryption rotate', this does NOT
re-encrypt any database rows — the DEK itself is unchanged. The server must be
stopped before running this command.

The new passphrase is read from KEYORIX_NEW_MASTER_PASSWORD (required).
The old passphrase is read from KEYORIX_MASTER_PASSWORD (required).

After this command succeeds, update KEYORIX_MASTER_PASSWORD in your deployment
configuration to the new passphrase before restarting the server.

Note: the evidence-signing key fingerprint (esk-...) and audit-checkpoint key
fingerprint (ack-...) will change, because both are derived from the KEK.`,
	RunE: runRotateKEK,
}

var rotateKEKConfirm bool

func init() {
	EncryptionCmd.AddCommand(rotateKEKCmd)
	rotateKEKCmd.Flags().BoolVar(&rotateKEKConfirm, "confirm", false,
		"required acknowledgement that the master passphrase will be changed")
}

func runRotateKEK(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	return rotateKEKWithConfig(cfg, rotateKEKConfirm)
}

// rotateKEKWithConfig is the testable core of runRotateKEK. It does no config
// loading and no flag parsing — callers pass an explicit confirm bool. All
// validation gates (encryption disabled, remote storage, missing env vars,
// --confirm) return before any key-file work so tests don't need real key files.
func rotateKEKWithConfig(cfg *config.Config, confirm bool) error {
	if !cfg.Storage.Encryption.Enabled {
		return fmt.Errorf("encryption is disabled in configuration")
	}
	if cfg.Storage.Type == "remote" {
		return fmt.Errorf("KEK rotation must run on the server host. Current storage type is 'remote' — connect to the server and run this command there")
	}
	if !confirm {
		return fmt.Errorf("this changes the master passphrase and re-wraps the DEK. Re-run with --confirm")
	}

	oldPassphrase, err := masterPassphrase(cfg)
	if err != nil {
		return err
	}

	newPassphrase := os.Getenv(newMasterPasswordEnvKEK)
	if newPassphrase == "" {
		return fmt.Errorf("%s environment variable is not set — set it to the new master passphrase", newMasterPasswordEnvKEK)
	}
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

	_, eskID, ok := service.EvidenceSignKey()
	if !ok {
		eskID = "(unavailable)"
	}
	_, ackID, ok := service.AuditCheckpointKey()
	if !ok {
		ackID = "(unavailable)"
	}

	fmt.Println("KEK rotation complete.")
	fmt.Println()
	fmt.Printf("  Evidence-signing key fingerprint:      %s\n", eskID)
	fmt.Printf("  Audit-checkpoint key fingerprint:      %s\n", ackID)
	fmt.Println()
	fmt.Println("Update KEYORIX_MASTER_PASSWORD to the new value before restarting the server.")
	fmt.Println()
	fmt.Println("Note: evidence packs and audit checkpoints signed before this rotation will")
	fmt.Println("report as 'superseded key version' (not tampered) under `keyorix compliance verify`.")
	return nil
}
