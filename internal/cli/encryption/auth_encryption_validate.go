// auth_encryption_validate.go — runValidateAuthEncryption and per-table validate helpers.
//
// Decrypts every encrypted auth row to confirm keys are working.
// For migration see auth_encryption_migrate.go.
package encryption

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

func runValidateAuthEncryption(cmd *cobra.Command, args []string) error {
	verbose, _ := cmd.Flags().GetBool("verbose")
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

	fmt.Println("🔍 Validating authentication encryption...")

	if err := validateAPIClients(db, authEnc, verbose); err != nil {
		return fmt.Errorf("API client validation failed: %w", err)
	}
	if err := validateSessions(db, authEnc, verbose); err != nil {
		return fmt.Errorf("session validation failed: %w", err)
	}
	if err := validateAPITokens(db, authEnc, verbose); err != nil {
		return fmt.Errorf("API token validation failed: %w", err)
	}
	if err := validatePasswordResetTokens(db, authEnc, verbose); err != nil {
		return fmt.Errorf("password reset token validation failed: %w", err)
	}

	fmt.Println("✅ All authentication encryption validation checks passed")
	return nil
}

func validateAPIClients(db *gorm.DB, authEnc *encryption.AuthEncryption, verbose bool) error {
	var clients []models.APIClient
	if err := db.Where("encrypted_client_secret IS NOT NULL").Find(&clients).Error; err != nil {
		return err
	}
	if verbose {
		fmt.Printf("🔑 Validating %d encrypted API clients...\n", len(clients))
	}
	for _, client := range clients {
		if _, err := authEnc.DecryptClientSecret(client.EncryptedClientSecret, []byte(client.ClientSecretMetadata)); err != nil {
			return fmt.Errorf("failed to decrypt client secret for client %s: %w", client.ClientID, err)
		}
		if verbose {
			fmt.Printf("  ✅ Client %s: OK\n", client.ClientID)
		}
	}
	return nil
}

func validateSessions(db *gorm.DB, authEnc *encryption.AuthEncryption, verbose bool) error {
	var sessions []models.Session
	if err := db.Where("encrypted_session_token IS NOT NULL").Find(&sessions).Error; err != nil {
		return err
	}
	if verbose {
		fmt.Printf("🎫 Validating %d encrypted sessions...\n", len(sessions))
	}
	for _, session := range sessions {
		if _, err := authEnc.DecryptSessionToken(session.EncryptedSessionToken, []byte(session.SessionTokenMetadata)); err != nil {
			return fmt.Errorf("failed to decrypt session token for session %d: %w", session.ID, err)
		}
		if verbose {
			fmt.Printf("  ✅ Session %d: OK\n", session.ID)
		}
	}
	return nil
}

func validateAPITokens(db *gorm.DB, authEnc *encryption.AuthEncryption, verbose bool) error {
	var tokens []models.APIToken
	if err := db.Where("encrypted_token IS NOT NULL").Find(&tokens).Error; err != nil {
		return err
	}
	if verbose {
		fmt.Printf("🎟️  Validating %d encrypted API tokens...\n", len(tokens))
	}
	for _, token := range tokens {
		if _, err := authEnc.DecryptAPIToken(token.EncryptedToken, []byte(token.TokenMetadata)); err != nil {
			return fmt.Errorf("failed to decrypt API token %d: %w", token.ID, err)
		}
		if verbose {
			fmt.Printf("  ✅ API Token %d: OK\n", token.ID)
		}
	}
	return nil
}

func validatePasswordResetTokens(db *gorm.DB, authEnc *encryption.AuthEncryption, verbose bool) error {
	var resets []models.PasswordReset
	if err := db.Where("encrypted_token IS NOT NULL").Find(&resets).Error; err != nil {
		return err
	}
	if verbose {
		fmt.Printf("🔄 Validating %d encrypted password reset tokens...\n", len(resets))
	}
	for _, reset := range resets {
		if _, err := authEnc.DecryptPasswordResetToken(reset.EncryptedToken, []byte(reset.TokenMetadata)); err != nil {
			return fmt.Errorf("failed to decrypt password reset token %d: %w", reset.ID, err)
		}
		if verbose {
			fmt.Printf("  ✅ Reset Token %d: OK\n", reset.ID)
		}
	}
	return nil
}
