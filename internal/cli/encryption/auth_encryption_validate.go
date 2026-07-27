// auth_encryption_validate.go — runValidateAuthEncryption and per-table validate helpers.
//
// Decrypts every encrypted auth row to confirm keys are working, and separately
// flags any row that still holds a plaintext value with no corresponding
// Encrypted* value (i.e. one 'auth-encryption migrate' hasn't reached yet).
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
	passphrase, _ := masterPassphrase(cfg)
	if err := authEnc.Initialize(passphrase); err != nil {
		return fmt.Errorf("failed to initialize auth encryption: %w", err)
	}

	fmt.Println("🔍 Validating authentication encryption...")

	var unmigrated int

	n, err := validateAPIClients(db, authEnc, verbose)
	if err != nil {
		return fmt.Errorf("API client validation failed: %w", err)
	}
	unmigrated += n

	n, err = validateSessions(db, authEnc, verbose)
	if err != nil {
		return fmt.Errorf("session validation failed: %w", err)
	}
	unmigrated += n

	n, err = validateAPITokens(db, authEnc, verbose)
	if err != nil {
		return fmt.Errorf("API token validation failed: %w", err)
	}
	unmigrated += n

	n, err = validatePasswordResetTokens(db, authEnc, verbose)
	if err != nil {
		return fmt.Errorf("password reset token validation failed: %w", err)
	}
	unmigrated += n

	// #292: previously this printed the all-clear message unconditionally,
	// regardless of how many rows had a plaintext value with no Encrypted*
	// counterpart at all (invisible to the decrypt-only checks above, since those
	// only ever query "Encrypted* IS NOT NULL") — the same false-clean shape as
	// the posture-fails-open family (#136/#145/#149). Fail loud instead: a
	// non-zero unmigrated count is reported per-row above and turns this into a
	// non-zero exit rather than a silent pass.
	if unmigrated > 0 {
		fmt.Printf("❌ %d authentication row(s) still hold a plaintext value with no encrypted counterpart — run 'keyorix encryption auth-encryption migrate'\n", unmigrated)
		return fmt.Errorf("%d authentication row(s) need migration to encrypted storage", unmigrated)
	}

	fmt.Println("✅ All authentication encryption validation checks passed")
	return nil
}

// validateAPIClients decrypts every already-encrypted API client row (proving
// the current keys work), then separately reports and counts rows that still
// hold a plaintext client_secret with no Encrypted* counterpart — those are
// invisible to the decrypt check above since it only ever queries
// "encrypted_client_secret IS NOT NULL".
func validateAPIClients(db *gorm.DB, authEnc *encryption.AuthEncryption, verbose bool) (int, error) {
	var clients []models.APIClient
	if err := db.Where("encrypted_client_secret IS NOT NULL").Find(&clients).Error; err != nil {
		return 0, err
	}
	if verbose {
		fmt.Printf("🔑 Validating %d encrypted API clients...\n", len(clients))
	}
	for _, client := range clients {
		if _, err := authEnc.DecryptClientSecret(client.EncryptedClientSecret, []byte(client.ClientSecretMetadata)); err != nil {
			return 0, fmt.Errorf("failed to decrypt client secret for client %s: %w", client.ClientID, err)
		}
		if verbose {
			fmt.Printf("  ✅ Client %s: OK\n", client.ClientID)
		}
	}

	var unmigrated []models.APIClient
	if err := db.Where("client_secret != '' AND client_secret IS NOT NULL AND encrypted_client_secret IS NULL").Find(&unmigrated).Error; err != nil {
		return 0, err
	}
	for _, client := range unmigrated {
		fmt.Printf("  ⚠️  Client %s: plaintext client_secret with no encrypted counterpart — needs migration\n", client.ClientID)
	}
	return len(unmigrated), nil
}

func validateSessions(db *gorm.DB, authEnc *encryption.AuthEncryption, verbose bool) (int, error) {
	var sessions []models.Session
	if err := db.Where("encrypted_session_token IS NOT NULL").Find(&sessions).Error; err != nil {
		return 0, err
	}
	if verbose {
		fmt.Printf("🎫 Validating %d encrypted sessions...\n", len(sessions))
	}
	for _, session := range sessions {
		if _, err := authEnc.DecryptSessionToken(session.EncryptedSessionToken, []byte(session.SessionTokenMetadata), session.UserID); err != nil {
			return 0, fmt.Errorf("failed to decrypt session token for session %d: %w", session.ID, err)
		}
		if verbose {
			fmt.Printf("  ✅ Session %d: OK\n", session.ID)
		}
	}

	var unmigrated []models.Session
	if err := db.Where("session_token != '' AND session_token IS NOT NULL AND encrypted_session_token IS NULL").Find(&unmigrated).Error; err != nil {
		return 0, err
	}
	for _, session := range unmigrated {
		fmt.Printf("  ⚠️  Session %d: plaintext session_token with no encrypted counterpart — needs migration\n", session.ID)
	}
	return len(unmigrated), nil
}

func validateAPITokens(db *gorm.DB, authEnc *encryption.AuthEncryption, verbose bool) (int, error) {
	var tokens []models.APIToken
	if err := db.Where("encrypted_token IS NOT NULL").Find(&tokens).Error; err != nil {
		return 0, err
	}
	if verbose {
		fmt.Printf("🎟️  Validating %d encrypted API tokens...\n", len(tokens))
	}
	for _, token := range tokens {
		var validateTokenUserID uint
		if token.UserID != nil {
			validateTokenUserID = *token.UserID
		}
		if _, err := authEnc.DecryptAPIToken(token.EncryptedToken, []byte(token.TokenMetadata), validateTokenUserID); err != nil {
			return 0, fmt.Errorf("failed to decrypt API token %d: %w", token.ID, err)
		}
		if verbose {
			fmt.Printf("  ✅ API Token %d: OK\n", token.ID)
		}
	}

	var unmigrated []models.APIToken
	if err := db.Where("token != '' AND token IS NOT NULL AND encrypted_token IS NULL").Find(&unmigrated).Error; err != nil {
		return 0, err
	}
	for _, token := range unmigrated {
		fmt.Printf("  ⚠️  API Token %d: plaintext token with no encrypted counterpart — needs migration\n", token.ID)
	}
	return len(unmigrated), nil
}

func validatePasswordResetTokens(db *gorm.DB, authEnc *encryption.AuthEncryption, verbose bool) (int, error) {
	var resets []models.PasswordReset
	if err := db.Where("encrypted_token IS NOT NULL").Find(&resets).Error; err != nil {
		return 0, err
	}
	if verbose {
		fmt.Printf("🔄 Validating %d encrypted password reset tokens...\n", len(resets))
	}
	for _, reset := range resets {
		if _, err := authEnc.DecryptPasswordResetToken(reset.EncryptedToken, []byte(reset.TokenMetadata), reset.UserID); err != nil {
			return 0, fmt.Errorf("failed to decrypt password reset token %d: %w", reset.ID, err)
		}
		if verbose {
			fmt.Printf("  ✅ Reset Token %d: OK\n", reset.ID)
		}
	}

	var unmigrated []models.PasswordReset
	if err := db.Where("token != '' AND token IS NOT NULL AND encrypted_token IS NULL").Find(&unmigrated).Error; err != nil {
		return 0, err
	}
	for _, reset := range unmigrated {
		fmt.Printf("  ⚠️  Reset Token %d: plaintext token with no encrypted counterpart — needs migration\n", reset.ID)
	}
	return len(unmigrated), nil
}
