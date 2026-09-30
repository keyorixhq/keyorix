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
	"os"
	"time"

	"filippo.io/age"

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

var (
	rotateRecoveryKeyRecipient string
	rotateRecoveryKeyOutput    string
)

var rotateRecoveryKeyCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Generate a fresh recovery key, replacing any existing one",
	Long: `Generates a new 256-bit recovery key and overwrites the stored verifier in one
write, bumping the key generation counter. If no key exists yet (an install
that predates this feature), this generates the FIRST one -- same command,
same rules.

By default the new key is printed to stdout in PLAINTEXT, exactly once. It
is never written to a log file or the audit chain in plaintext, and cannot
be recovered if lost -- losing it just means running 'rotate' again. The
OLD key stops verifying the instant this command completes; there is no
grace window.

--recipient <age1... key | path to an ssh-ed25519 public key file> makes
this print the key ONLY age-encrypted to that recipient -- the plaintext
key is never written to the terminal at all in this mode. Decrypt with:
age -d -i <identity file> <output>. --output <file> writes the encrypted
result to that file (mode 0600, refuses to overwrite an existing file)
instead of stdout; --output requires --recipient (this command never
writes the PLAINTEXT key to a file). --output's path is checked (and
reserved) BEFORE the key is rotated, so an --output failure -- the path
already exists, or its parent directory isn't writable -- leaves the OLD
key valid instead of burning a rotation you never received.`,
	RunE: runRotateRecoveryKey,
}

func init() {
	rotateRecoveryKeyCmd.Flags().StringVar(&rotateRecoveryKeyRecipient, "recipient", "",
		`Encrypt the printed key to this age1... recipient, or to the ssh-ed25519 public key in this file, instead of printing it in plaintext`)
	rotateRecoveryKeyCmd.Flags().StringVar(&rotateRecoveryKeyOutput, "output", "",
		`Write the --recipient-encrypted key to this file (0600, refuses to overwrite) instead of stdout; requires --recipient`)
	recoveryKeyCmd.AddCommand(rotateRecoveryKeyCmd)
	rootCmd.AddCommand(recoveryKeyCmd)
}

func runRotateRecoveryKey(cmd *cobra.Command, args []string) error {
	if rotateRecoveryKeyOutput != "" && rotateRecoveryKeyRecipient == "" {
		return fmt.Errorf("--output requires --recipient: this command never writes the plaintext key to a file")
	}

	// Parse/validate the recipient BEFORE touching any state below: a bad
	// --recipient must fail with the OLD key still valid, not after the new
	// key has already been generated and the old one invalidated (F8).
	var recipient age.Recipient
	if rotateRecoveryKeyRecipient != "" {
		var rerr error
		recipient, rerr = parseRecoveryKeyRecipient(rotateRecoveryKeyRecipient)
		if rerr != nil {
			return fmt.Errorf("--recipient: %w", rerr)
		}
	}

	// Reserve --output BEFORE rotating too, for the same reason: an --output
	// failure (the path already exists, or its parent directory isn't
	// writable) must leave the OLD key valid, not be discovered only after
	// the key has already been rotated. See reserveRecoveryKeyOutputFile's
	// own doc comment for why O_EXCL-creating now is the right shape. Removed
	// again on any later failure (the deferred cleanup below) so a retry
	// doesn't immediately hit a stale "already exists" against this run's own
	// empty reservation.
	var outputFile *os.File
	outputCommitted := false
	if rotateRecoveryKeyOutput != "" {
		var operr error
		outputFile, operr = reserveRecoveryKeyOutputFile(rotateRecoveryKeyOutput)
		if operr != nil {
			return fmt.Errorf("--output: %w", operr)
		}
		defer func() {
			if !outputCommitted {
				_ = outputFile.Close()
				_ = os.Remove(rotateRecoveryKeyOutput)
			}
		}()
	}

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

	if recipient != nil {
		encrypted, eerr := encryptRecoveryKeyForRecipient(rawKey, recipient)
		if eerr != nil {
			// The key is already rotated and stored at this point -- the OLD key
			// is gone regardless. Report the failure loudly rather than falling
			// back to printing the plaintext: a silent fallback would violate
			// the operator's explicit --recipient request without them noticing.
			return fmt.Errorf("encrypt recovery key for --recipient (the key WAS rotated -- generation %d is now active, "+
				"but could not be delivered encrypted): %w", newVersion, eerr)
		}
		if rotateRecoveryKeyOutput != "" {
			if werr := finishRecoveryKeyOutputFile(outputFile, rotateRecoveryKeyOutput, encrypted); werr != nil {
				// The key IS rotated and the ciphertext is sitting in memory --
				// losing the write (ENOSPC, EIO, permissions changing mid-run)
				// must not also lose the only copy of it. The deferred cleanup
				// above removes the failed/partial --output file, so print the
				// armored ciphertext to stdout now: it's already safe to display
				// (age-encrypted, not plaintext) and this is the operator's last
				// chance to capture it before the process exits.
				fmt.Println("=====================================================================")
				fmt.Println("  --output WRITE FAILED, BUT THE KEY WAS ALREADY ROTATED. RECORD THIS")
				fmt.Println("  ENCRYPTED KEY NOW -- it is shown exactly once. Decrypt with:")
				fmt.Println("  age -d -i <identity file> <this output>")
				fmt.Println()
				fmt.Print(string(encrypted))
				fmt.Println("=====================================================================")
				return fmt.Errorf("recovery key WAS rotated (generation %d) but could not be written to --output "+
					"(printed the encrypted key to stdout instead -- record it now): %w", newVersion, werr)
			}
			outputCommitted = true
			fmt.Printf("The age-encrypted key was written to %s (mode 0600).\n", rotateRecoveryKeyOutput)
		} else {
			fmt.Println("=====================================================================")
			fmt.Println("  RECORD THIS ENCRYPTED KEY NOW -- it is shown exactly once. Decrypt")
			fmt.Println("  with: age -d -i <identity file> <this output>")
			fmt.Println()
			fmt.Print(string(encrypted))
			fmt.Println("=====================================================================")
		}
	} else {
		fmt.Println("=====================================================================")
		fmt.Println("  RECORD THIS KEY NOW -- it is shown exactly once and cannot be")
		fmt.Println("  recovered later. Store it offline (password manager, sealed")
		fmt.Println("  envelope) -- NOT in this terminal's scrollback or a log file.")
		fmt.Println()
		fmt.Printf("  %s\n", rawKey)
		fmt.Println("=====================================================================")
	}
	fmt.Println()
	fmt.Println("On a local-KEK-file install (storage.encryption.key_provider.type: file " +
		"or unset), this key does not protect your secrets from host root -- it " +
		"protects your admin account from anyone who is not you.")

	// "Fires the same admin-notification path as a recovery event" (design
	// §2) -- a key rotation is exactly the kind of event every admin should
	// see, not just recovery itself. Best-effort: opened separately from the
	// key-storage transaction above, same convention recordAdminAction below
	// uses for its own post-action storage open.
	notifyErr := withUsableStorage(cfg, func(store corestorage.Storage) error {
		notifyAllAdmins(store, "Recovery key "+action,
			fmt.Sprintf("The local admin recovery key was %s on this host (now generation %d). "+
				"If you did not expect this, investigate immediately.", action, newVersion))
		return nil
	})
	if notifyErr != nil {
		fmt.Printf("note: could not notify admins (%v)\n", notifyErr)
	}

	recordAdminAction(cfg, "admin.recovery_key."+action,
		fmt.Sprintf("%s the recovery key (now generation %d)", action, newVersion), true)

	return nil
}
