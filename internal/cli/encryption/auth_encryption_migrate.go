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
	db, err := openDatabase(cfg)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	authEnc := encryption.NewAuthEncryption(&cfg.Storage.Encryption, ".", db)
	passphrase, _ := masterPassphrase(cfg)
	if err := authEnc.Initialize(passphrase); err != nil {
		return fmt.Errorf("failed to initialize auth encryption: %w", err)
	}

	if dryRun {
		fmt.Println("🔍 DRY RUN: Analyzing authentication data for migration...")
	} else {
		fmt.Println("🔄 Migrating authentication data to encrypted storage...")
	}

	if err := migrateAPIClients(db, authEnc, dryRun); err != nil {
		return fmt.Errorf("failed to migrate API clients: %w", err)
	}
	// Sessions are deliberately NOT run through this migration. Unlike
	// api_clients/api_tokens/password_resets, sessions.session_token has NEVER
	// stored a plaintext value: store.CreateSession/RotateSession (see
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
	if err := migrateAPITokens(db, authEnc, dryRun); err != nil {
		return fmt.Errorf("failed to migrate API tokens: %w", err)
	}
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

func migrateAPIClients(db *gorm.DB, authEnc *encryption.AuthEncryption, dryRun bool) error {
	var clients []models.APIClient
	if err := db.Where("client_secret != '' AND encrypted_client_secret IS NULL").Find(&clients).Error; err != nil {
		return err
	}
	fmt.Printf("🔑 Found %d API clients to migrate\n", len(clients))
	if dryRun {
		return nil
	}
	for _, client := range clients {
		enc, meta, err := authEnc.EncryptClientSecret(client.ClientSecret)
		if err != nil {
			return fmt.Errorf("failed to encrypt client secret for client %s: %w", client.ClientID, err)
		}
		// Clear the plaintext column in the same update that writes the encrypted
		// value — leaving it populated after a "successful" migration defeats the
		// point: the #278 compromise surface (a readable plaintext column) would
		// still be sitting right next to its encrypted replacement. NULL, not "",
		// since a second migrated row with "" would collide with any unique index
		// on the column; NULL is exempt from uniqueness checks on every backend
		// this CLI targets (sqlite/postgres).
		if err := db.Model(&client).Updates(map[string]interface{}{
			"encrypted_client_secret": enc,
			"client_secret_metadata":  meta,
			"client_secret":           nil,
		}).Error; err != nil {
			return fmt.Errorf("failed to update client %s: %w", client.ClientID, err)
		}
	}
	return nil
}

func migrateAPITokens(db *gorm.DB, authEnc *encryption.AuthEncryption, dryRun bool) error {
	var tokens []models.APIToken
	if err := db.Where("token != '' AND encrypted_token IS NULL").Find(&tokens).Error; err != nil {
		return err
	}
	fmt.Printf("🎟️  Found %d API tokens to migrate\n", len(tokens))
	if dryRun {
		return nil
	}
	for _, token := range tokens {
		var migrateTokenUserID uint
		if token.UserID != nil {
			migrateTokenUserID = *token.UserID
		}
		enc, meta, err := authEnc.EncryptAPIToken(token.Token, migrateTokenUserID)
		if err != nil {
			return fmt.Errorf("failed to encrypt API token %d: %w", token.ID, err)
		}
		// See migrateAPIClients for why the plaintext column is cleared (set to
		// NULL, not "") in the same update as the encrypted write.
		if err := db.Model(&token).Updates(map[string]interface{}{
			"encrypted_token": enc,
			"token_metadata":  meta,
			"token":           nil,
		}).Error; err != nil {
			return fmt.Errorf("failed to update API token %d: %w", token.ID, err)
		}
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
		// See migrateAPIClients for why the plaintext column is cleared (set to
		// NULL, not "") in the same update as the encrypted write.
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
