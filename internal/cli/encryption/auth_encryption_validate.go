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
	return validateAuthEncryptionWithConfig(cfg, verbose)
}

// validateAuthEncryptionWithConfig is the testable core of runValidateAuthEncryption:
// no flag parsing, no config.Load — callers pass an explicit cfg and verbose bool.
func validateAuthEncryptionWithConfig(cfg *config.Config, verbose bool) error {
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
	// commands (status/validate/fix-perms/upgrade-aad) already require, so this
	// fails fast instead of racing a concurrent migrate-provider/rotate.
	if err := authEnc.AcquireSharedKeyLock(); err != nil {
		authEnc.Shutdown()
		return fmt.Errorf("%w — a live server or an in-progress rotation/migrate-provider is using this key directory; stop it or wait for it to finish, then retry", err)
	}
	defer authEnc.Shutdown()

	fmt.Println("🔍 Validating authentication encryption...")

	var unmigrated int

	n, err := validateAPIClients(db, authEnc, verbose)
	if err != nil {
		return fmt.Errorf("API client validation failed: %w", err)
	}
	unmigrated += n

	// Sessions are deliberately not validated here — see the comment in
	// auth_encryption_migrate.go's runMigrateAuthData for why: session_token
	// stores a SHA-256 hash, never plaintext, so there is no "unmigrated
	// plaintext" state for a session row to be in. A prior validateSessions
	// queried "session_token != ''" (true for every live session) and reported
	// every one of them as needing migration — a permanent false positive that
	// would fail this command on any deployment with active sessions.

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
