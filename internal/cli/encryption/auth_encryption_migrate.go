// auth_encryption_migrate.go — runMigrateAuthData and per-table migrate helpers.
//
// Migrates plaintext auth tokens to encrypted storage.
// For validation see auth_encryption_validate.go.
package encryption

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

func runMigrateAuthData(cmd *cobra.Command, args []string) error {
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	cfg, err := config.Load("")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	return migrateAuthDataWithConfig(cfg, dryRun)
}

// migrateAuthDataWithConfig is the testable core of runMigrateAuthData: no flag
// parsing, no config.Load — callers pass an explicit cfg and dryRun bool.
func migrateAuthDataWithConfig(cfg *config.Config, dryRun bool) error {
	db, err := openDatabase(cfg)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	authEnc := encryption.NewAuthEncryption(&cfg.Storage.Encryption, ".", db)
	passphrase, _ := masterPassphrase(cfg)
	if err := authEnc.Initialize(passphrase); err != nil {
		return fmt.Errorf("failed to initialize auth encryption: %w", err)
	}
	// #292/G62: take the same cross-process shared DEK lock the sibling DEK
	// commands (status/validate/fix-perms/upgrade-aad) already require — migrate
	// writes under the current DEK without rotating it, exactly like upgrade-aad,
	// so this fails fast instead of racing a concurrent migrate-provider/rotate.
	if err := authEnc.AcquireSharedKeyLock(); err != nil {
		authEnc.Shutdown()
		return fmt.Errorf("%w — a live server or an in-progress rotation/migrate-provider is using this key directory; stop it or wait for it to finish, then retry", err)
	}
	defer authEnc.Shutdown()

	if dryRun {
		fmt.Println("🔍 DRY RUN: Analyzing authentication data for migration...")
	} else {
		fmt.Println("🔄 Migrating authentication data to encrypted storage...")
	}

	// Sessions are deliberately NOT run through this migration. Unlike (at the
	// time) api_clients/api_tokens/password_resets, sessions.session_token has
	// NEVER stored a plaintext value: store.CreateSession/RotateSession (see
	// internal/storage/store/local_auth.go) hash the token with SHA-256 before
	// writing it, and GetSession/GetSessionAny look sessions up by recomputing
	// that hash and matching it against this same column. There is no plaintext
	// state for this migration to move out of that column.
	//
	// A prior version of this file DID call a migrateSessions here. It matched
	// on "session_token != ''" — which is true for every live session, since the
	// column always holds a hash — "encrypted" the hash value as if it were a
	// real secret, and then set session_token to NULL in the same UPDATE. That
	// NULL landed on the exact column GetSession/GetSessionAny key their WHERE
	// clause on, so every live session became permanently unfindable: an
	// operator running this migration against a production database silently
	// mass-invalidated every logged-in user's session while the CLI reported
	// success. See git history for the removed migrateSessions/validateSessions
	// (the latter had the identical false premise) if this ever needs revisiting.
	//
	// API clients and API tokens are ALSO not run through this migration, for
	// the identical reason — this was missed when the sessions fix above landed.
	// Per models.APIClient.ClientSecret and models.APIToken.Token (see
	// internal/storage/models/models.go), both columns hold a SHA-256 HASH of
	// the credential, never plaintext — the credential is shown once at
	// creation and never persisted in recoverable form. (The issuance/auth
	// routes for these credential types were themselves removed in an earlier
	// finding; see git history around #131 — but that's incidental: the columns
	// were never plaintext even while those routes existed.)
	//
	// migrateAPIClients/migrateAPITokens used to match on "client_secret != ''"
	// / "token != ''" — true for every row, since the column always holds a
	// hash — "encrypted" that hash value as if it were a real secret, and then
	// set the column to NULL in the same UPDATE. For any pre-existing row (e.g.
	// carried forward from an older database predating #131's route removal),
	// that NULL permanently destroyed the only stored credential-verification
	// data for the row, with the CLI reporting success. There was never a
	// plaintext state for this migration to move out of either column — the
	// same false premise validateSessions had, and the same one
	// validateAPIClients/validateAPITokens (see auth_encryption_validate.go)
	// shared. See git history for the removed migrateAPIClients/migrateAPITokens
	// if this ever needs revisiting.
	if err := migratePasswordResetTokens(db, authEnc, dryRun); err != nil {
		return fmt.Errorf("failed to migrate password reset tokens: %w", err)
	}

	if dryRun {
		fmt.Println("✅ Dry run completed. Use without --dry-run to perform actual migration")
	} else {
		fmt.Println("✅ Authentication data migration completed successfully")
	}
	return nil
}

func migratePasswordResetTokens(db *gorm.DB, authEnc *encryption.AuthEncryption, dryRun bool) error {
	var resets []models.PasswordReset
	if err := db.Where("token != '' AND encrypted_token IS NULL").Find(&resets).Error; err != nil {
		return err
	}
	fmt.Printf("🔄 Found %d password reset tokens to migrate\n", len(resets))
	if dryRun {
		return nil
	}
	for _, reset := range resets {
		enc, meta, err := authEnc.EncryptPasswordResetToken(reset.Token, reset.UserID)
		if err != nil {
			return fmt.Errorf("failed to encrypt password reset token %d: %w", reset.ID, err)
		}
		// The plaintext column is cleared (set to NULL, not "") in the same update
		// as the encrypted write: leaving it populated after a "successful"
		// migration defeats the point (a readable plaintext column sitting right
		// next to its encrypted replacement), and NULL — not "" — avoids colliding
		// with the unique index on this column when a second row is migrated (NULL
		// is exempt from uniqueness checks on every backend this CLI targets).
		// Unlike this column, password_resets.token is a genuine legacy plaintext
		// column (see models.PasswordReset), not a hash — see the comment above
		// this function's call site for why api_clients/api_tokens/sessions are
		// deliberately excluded from this migration.
		if err := db.Model(&reset).Updates(map[string]interface{}{
			"encrypted_token": enc,
			"token_metadata":  meta,
			"token":           nil,
		}).Error; err != nil {
			return fmt.Errorf("failed to update password reset token %d: %w", reset.ID, err)
		}
	}
	return nil
}
