// recovery_key.go implements `keyorix-server admin recovery-key rotate`
// (docs/design-b2-recover-admin.md §2): generates or rotates the local
// admin recovery key, the offline second factor `recover-admin` (§3)
// consumes to restore a locked-out admin account. Separate command group
// from recover-admin itself: rotating the key is a standalone
// administrative action, not tied to any account being locked out (§9
// review addendum 3's "existing installs with no recovery key" retrofit
// path uses this exact same command).
package admin

import (
	"context"
	"fmt"
	"time"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/recoverykey"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var recoveryKeyCmd = &cobra.Command{
	Use:   "recovery-key",
	Short: "Manage the local admin recovery key",
	Long: `The recovery key is a 256-bit offline second factor: host access ("something
you are") plus this key ("something you have") let 'keyorix-server admin
recover-admin' restore a locked-out admin account with no network path. Only
a SHA-256 verifier of the key is ever stored server-side -- the key itself
is shown once, at generation/rotation time, and nowhere else.`,
}

var rotateRecoveryKeyCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Generate a fresh recovery key, replacing any existing one",
	Long: `Generates a new 256-bit recovery key and overwrites the stored verifier in one
write, bumping the key generation counter. If no key exists yet (an install
that predates this feature), this generates the FIRST one -- same command,
same rules.

The new key is printed to stdout exactly once. It is never written to a log
file or the audit chain in plaintext, and cannot be recovered if lost --
losing it just means running 'rotate' again. The OLD key stops verifying the
instant this command completes; there is no grace window.`,
	RunE: runRotateRecoveryKey,
}

func init() {
	recoveryKeyCmd.AddCommand(rotateRecoveryKeyCmd)
	rootCmd.AddCommand(recoveryKeyCmd)
}

func runRotateRecoveryKey(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	// Held for the WHOLE run (design §2: "under the exclusive admin lock, so
	// a concurrent recover-admin run can't observe a half-rotated state") --
	// acquired before generating the key, released only on return.
	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck

	rawKey, err := recoverykey.Generate()
	if err != nil {
		return fmt.Errorf("generate recovery key: %w", err)
	}

	var isFirstGeneration bool
	var newVersion int
	err = withUsableStorage(cfg, func(store corestorage.Storage) error {
		existing, found, err := store.GetRecoveryKeyRecord(context.Background())
		if err != nil {
			return fmt.Errorf("read existing recovery-key record: %w", err)
		}
		isFirstGeneration = !found
		newVersion = 1
		now := time.Now()
		record := &models.RecoveryKeyRecord{
			KeyHash:    recoverykey.Hash(rawKey),
			KeyVersion: newVersion,
			CreatedAt:  now,
		}
		if found {
			newVersion = existing.KeyVersion + 1
			record.KeyVersion = newVersion
			record.RotatedAt = &now
		}
		return store.SetRecoveryKeyRecord(context.Background(), record)
	})
	if err != nil {
		return fmt.Errorf("store recovery key: %w", err)
	}

	action := "rotated"
	if isFirstGeneration {
		action = "generated"
	}
	fmt.Printf("Recovery key %s (generation %d).\n\n", action, newVersion)
	fmt.Println("=====================================================================")
	fmt.Println("  RECORD THIS KEY NOW -- it is shown exactly once and cannot be")
	fmt.Println("  recovered later. Store it offline (password manager, sealed")
	fmt.Println("  envelope) -- NOT in this terminal's scrollback or a log file.")
	fmt.Println()
	fmt.Printf("  %s\n", rawKey)
	fmt.Println("=====================================================================")
	fmt.Println()
	fmt.Println("On a local-KEK-file install (storage.encryption.key_provider.type: file " +
		"or unset), this key does not protect your secrets from host root -- it " +
		"protects your admin account from anyone who is not you.")

	// Admin-notification fan-out ("fires the same admin-notification path as
	// a recovery event," design §2) is intentionally NOT wired here: it needs
	// the same shared helper recover-admin's own PR builds (design §4), and
	// building it twice would duplicate logic this PR would then have to
	// reconcile. Deferred to that PR; this action's audit event below is
	// still written regardless, so the rotation is never silently unrecorded
	// in the interim.
	recordAdminAction(cfg, "admin.recovery_key."+action,
		fmt.Sprintf("%s the recovery key (now generation %d)", action, newVersion), true)

	return nil
}
