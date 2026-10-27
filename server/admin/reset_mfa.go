// reset_mfa.go implements `keyorix-server admin reset-mfa` (RECOVERY-MFA-RESET-1,
// docs/design/recovery-options.md §1 option C): the host-side reset of a local
// non-admin user's second factor, for a user who lost the authenticator and has
// no recovery code. It is the fallback of the two-admin online reset
// (POST /api/v1/mfa-reset-requests), for installs with fewer than two eligible
// admins and for air-gapped hosts.
//
// Like recover-admin it calls storage directly (there is no Keyorix identity to
// attribute a host action to; the actor is the host OS user), needs the recovery
// key, and holds the exclusive database lock for the whole run, so it refuses
// while a server is running on the same database.
package admin

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var (
	resetMFAUser string
	resetMFAKey  string
)

var resetMFACmd = &cobra.Command{
	Use:   "reset-mfa",
	Short: "Reset a local user's lost second factor using the local recovery key",
	Long: `reset-mfa resets the second factor of ONE local, non-admin account whose
owner lost the authenticator and has no recovery code. It is a full credential
reset, never "MFA off": in one transaction it removes the TOTP secret, every
recovery code and every WebAuthn credential, revokes every session and personal
access token, replaces the password with a one-time password (printed once) and
marks the account as owing a new MFA enrolment.

Requires host access AND the local recovery key (read from stdin, never an
argument: --recovery-key must be exactly "-"; omit it only when
security.recover_admin.insecure_keyless_admin_recovery is enabled). Stop the
server first: the command holds this tree's exclusive database-presence lock
for its whole run and refuses while a server holds it.

Refused, with nothing changed: a global-admin account (use recover-admin), an
SSO/SCIM account (its identity provider owns the factor), a suspended or
inactive account, a machine identity, and a wrong recovery key. Every run writes
admin.reset_mfa (or admin.reset_mfa_failed) to the audit trail in the same
transaction, and notifies the user and every admin.

Exit codes: 0 on success, 1 on any failure (see the printed error message).`,
	RunE: runResetMFA,
}

func init() {
	resetMFACmd.Flags().StringVar(&resetMFAUser, "user", "", "The account to reset: username, email address or numeric user ID (required)")
	resetMFACmd.Flags().StringVar(&resetMFAKey, "recovery-key", "", `Must be "-" -- the key is read from stdin, never a CLI argument (required unless security.recover_admin.insecure_keyless_admin_recovery is enabled)`)
	rootCmd.AddCommand(resetMFACmd)
}

func runResetMFA(cmd *cobra.Command, args []string) error {
	if resetMFAUser == "" {
		return fmt.Errorf("--user is required (username, email address or numeric user ID)")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	keyless := cfg.Security.RecoverAdmin.KeylessMode
	var rawKey string
	if keyless {
		fmt.Fprintln(os.Stderr, "WARNING: keyless mode is enabled (security.recover_admin.insecure_keyless_admin_recovery) -- "+
			"proceeding on HOST ACCESS ALONE, no recovery key required or checked.")
		if resetMFAKey != "" && resetMFAKey != "-" {
			return fmt.Errorf(`--recovery-key must be exactly "-", or omitted entirely in keyless mode`)
		}
	} else {
		if resetMFAKey != "-" {
			return fmt.Errorf(`--recovery-key must be exactly "-" -- the key is read from stdin, never passed as a value here`)
		}
		if rawKey, err = readRecoveryKeyFromStdin(); err != nil {
			return err
		}
	}

	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck

	fmt.Fprintf(os.Stderr, "Resetting the second factor of %q...\n", resetMFAUser)
	var summary *resetMFASummary
	err = withUsableStorage(cfg, func(store corestorage.Storage) error {
		s, err := performResetMFA(context.Background(), store, resetMFAUser, rawKey, keyless,
			cfg.Security.GetRecoveryOneTimePasswordExpiry())
		summary = s
		return err
	})
	if err != nil {
		return fmt.Errorf("reset-mfa: %w", err)
	}

	e := summary.effect
	totp := "no TOTP factor"
	if e.TOTPCleared {
		totp = "the TOTP factor"
	}
	fmt.Printf("MFA reset for %s (user id %d).\n", summary.username, summary.userID)
	fmt.Printf("Removed: %s, %d recovery code(s), %d WebAuthn credential(s). Revoked: %d session(s), %d personal access token(s).\n",
		totp, e.RecoveryCodesCleared, e.WebAuthnCredentialsCleared, e.SessionsRevoked, e.PATsRevoked)
	fmt.Println()
	fmt.Println("One-time password (shown once — copy it now, it cannot be retrieved again):")
	// Intentional one-time display to the operator (same contract as recover-admin).
	// codeql[go/clear-text-logging]
	fmt.Printf("  %s\n", summary.oneTimePassword)
	fmt.Printf("Expires: %s (UTC). Give it to the user out of band, after confirming who they are.\n",
		summary.oneTimePasswordExpiresAt.UTC().Format(time.RFC3339))
	fmt.Printf("They sign in as %q with it, set a new password, and must enrol a new second factor.\n", summary.username)
	if summary.chainNote != "" {
		fmt.Fprintf(os.Stderr, "WARNING: %s\n", summary.chainNote[4:])
	}

	notifyErr := withUsableStorage(cfg, func(store corestorage.Storage) error {
		msg := fmt.Sprintf("keyorix-server admin reset-mfa, run by host user %s, reset the second factor of %q (user id %d) using %s. "+
			"If you did not expect this, investigate immediately.", summary.operator, summary.username, summary.userID, resetMFAKeyDetail(summary))
		notifyAllAdmins(store, "MFA reset on the server host", msg)
		notifyResetMFATarget(store, summary.userID, "Your second factor was reset",
			"An administrator reset your MFA on the server host. Sign in with the one-time password you were given, "+
				"choose a new password and enrol a new authenticator. If you did not ask for this, contact your administrator now.")
		return nil
	})
	if notifyErr != nil {
		fmt.Printf("note: could not notify (%v)\n", notifyErr)
	}
	return nil
}

// notifyResetMFATarget leaves an in-app notification for the reset user, shown
// after their next sign-in. Best effort: the reset has already committed.
func notifyResetMFATarget(store corestorage.Storage, userID uint, title, message string) {
	if _, err := store.CreateNotification(context.Background(), &models.Notification{
		UserID:   userID,
		Type:     core.EventMFAReset,
		Title:    title,
		Message:  message,
		Severity: models.NotificationSeverityCritical,
	}); err != nil {
		fmt.Printf("note: could not write the in-app notification for user %d (%v)\n", userID, err)
	}
}
