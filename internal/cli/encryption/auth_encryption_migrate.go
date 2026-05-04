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
	passphrase, _ := masterPassphrase()
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
	if err := migrateSessions(db, authEnc, dryRun); err != nil {
		return fmt.Errorf("failed to migrate sessions: %w", err)
	}
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
		if err := db.Model(&client).Updates(map[string]interface{}{
			"encrypted_client_secret": enc,
			"client_secret_metadata":  meta,
		}).Error; err != nil {
			return fmt.Errorf("failed to update client %s: %w", client.ClientID, err)
		}
	}
	return nil
}

func migrateSessions(db *gorm.DB, authEnc *encryption.AuthEncryption, dryRun bool) error {
	var sessions []models.Session
	if err := db.Where("session_token != '' AND encrypted_session_token IS NULL").Find(&sessions).Error; err != nil {
		return err
	}
	fmt.Printf("🎫 Found %d sessions to migrate\n", len(sessions))
	if dryRun {
		return nil
	}
	for _, session := range sessions {
		enc, meta, err := authEnc.EncryptSessionToken(session.SessionToken)
		if err != nil {
			return fmt.Errorf("failed to encrypt session token for session %d: %w", session.ID, err)
		}
		if err := db.Model(&session).Updates(map[string]interface{}{
			"encrypted_session_token": enc,
			"session_token_metadata":  meta,
		}).Error; err != nil {
			return fmt.Errorf("failed to update session %d: %w", session.ID, err)
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
		enc, meta, err := authEnc.EncryptAPIToken(token.Token)
		if err != nil {
			return fmt.Errorf("failed to encrypt API token %d: %w", token.ID, err)
		}
		if err := db.Model(&token).Updates(map[string]interface{}{
			"encrypted_token": enc,
			"token_metadata":  meta,
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
		enc, meta, err := authEnc.EncryptPasswordResetToken(reset.Token)
		if err != nil {
			return fmt.Errorf("failed to encrypt password reset token %d: %w", reset.ID, err)
		}
		if err := db.Model(&reset).Updates(map[string]interface{}{
			"encrypted_token": enc,
			"token_metadata":  meta,
		}).Error; err != nil {
			return fmt.Errorf("failed to update password reset token %d: %w", reset.ID, err)
		}
	}
	return nil
}
