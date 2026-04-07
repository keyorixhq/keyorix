package encryption

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// AuthEncryptionCmd represents the auth encryption command
var AuthEncryptionCmd = &cobra.Command{
	Use:   "auth-encryption",
	Short: "Manage authentication data encryption",
	Long: `Manage encryption for authentication-related data including:
- API client secrets
- Session tokens
- API tokens
- Password reset tokens

This command allows you to enable encryption, check status, and rotate keys for authentication data.`,
}

var authStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show authentication encryption status",
	Long:  "Display the current status of authentication data encryption including enabled state and key version.",
	RunE:  runAuthEncryptionStatus,
}

var enableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable authentication encryption",
	Long:  "Enable encryption for authentication data. This will encrypt new authentication tokens and secrets.",
	RunE:  runEnableAuthEncryption,
}

var authRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate authentication encryption keys",
	Long:  "Rotate encryption keys for all authentication data. This will re-encrypt all stored tokens and secrets with new keys.",
	RunE:  runRotateAuthEncryption,
}

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate existing plaintext auth data to encrypted storage",
	Long:  "Migrate existing plaintext authentication data to encrypted storage. This is useful when enabling encryption on an existing system.",
	RunE:  runMigrateAuthData,
}

var authValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate authentication encryption setup",
	Long:  "Validate that authentication encryption is properly configured and all encrypted data can be decrypted.",
	RunE:  runValidateAuthEncryption,
}

func init() {
	AuthEncryptionCmd.AddCommand(authStatusCmd)
	AuthEncryptionCmd.AddCommand(enableCmd)
	AuthEncryptionCmd.AddCommand(authRotateCmd)
	AuthEncryptionCmd.AddCommand(migrateCmd)
	AuthEncryptionCmd.AddCommand(authValidateCmd)

	// Add flags
	enableCmd.Flags().Bool("force", false, "Force enable encryption even if already enabled")
	authRotateCmd.Flags().Bool("confirm", false, "Confirm key rotation (required)")
	migrateCmd.Flags().Bool("dry-run", false, "Show what would be migrated without making changes")
	authValidateCmd.Flags().Bool("verbose", false, "Show detailed validation results")
}

func runAuthEncryptionStatus(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load("")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	db, err := openDatabase(cfg)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	authEnc := encryption.NewAuthEncryption(&cfg.Storage.Encryption, ".", db)
	if err := authEnc.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize auth encryption: %w", err)
	}

	status := authEnc.GetAuthEncryptionStatus()

	fmt.Println("🔐 Authentication Encryption Status")
	fmt.Println("=" + string(make([]rune, 35)))

	if status["enabled"].(bool) {
		fmt.Println("✅ Status: ENABLED")
	} else {
		fmt.Println("❌ Status: DISABLED")
	}

	if status["initialized"].(bool) {
		fmt.Println("✅ Initialized: YES")
		if keyVersion, ok := status["key_version"]; ok {
			fmt.Printf("🔑 Key Version: %s\n", keyVersion)
		}
	} else {
		fmt.Println("❌ Initialized: NO")
	}

	// Show statistics
	if err := showAuthEncryptionStats(db, status["enabled"].(bool)); err != nil {
		fmt.Printf("⚠️  Warning: Could not retrieve statistics: %v\n", err)
	}

	return nil
}

func runEnableAuthEncryption(cmd *cobra.Command, args []string) error {
	force, _ := cmd.Flags().GetBool("force")

	cfg, err := config.Load("")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if !cfg.Storage.Encryption.Enabled && !force {
		return fmt.Errorf("encryption is disabled in configuration. Enable it in config or use --force flag")
	}

	db, err := openDatabase(cfg)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	authEnc := encryption.NewAuthEncryption(&cfg.Storage.Encryption, ".", db)

	// Check if already enabled
	status := authEnc.GetAuthEncryptionStatus()
	if status["enabled"].(bool) && status["initialized"].(bool) && !force {
		fmt.Println("✅ Authentication encryption is already enabled")
		return nil
	}

	// Initialize encryption
	if err := authEnc.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize auth encryption: %w", err)
	}

	fmt.Println("✅ Authentication encryption enabled successfully")
	fmt.Println("🔑 New authentication tokens will be encrypted")
	fmt.Println("💡 Use 'migrate' command to encrypt existing plaintext data")

	return nil
}

func runRotateAuthEncryption(cmd *cobra.Command, args []string) error {
	confirm, _ := cmd.Flags().GetBool("confirm")
	if !confirm {
		return fmt.Errorf("key rotation requires --confirm flag. This operation will re-encrypt all authentication data")
	}

	cfg, err := config.Load("")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	db, err := openDatabase(cfg)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	authEnc := encryption.NewAuthEncryption(&cfg.Storage.Encryption, ".", db)
	if err := authEnc.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize auth encryption: %w", err)
	}

	fmt.Println("🔄 Starting authentication encryption key rotation...")

	if err := authEnc.RotateAuthEncryption(); err != nil {
		return fmt.Errorf("failed to rotate auth encryption keys: %w", err)
	}

	fmt.Println("✅ Authentication encryption key rotation completed successfully")
	fmt.Println("🔑 All authentication data has been re-encrypted with new keys")

	return nil
}

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
	if err := authEnc.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize auth encryption: %w", err)
	}

	if dryRun {
		fmt.Println("🔍 DRY RUN: Analyzing authentication data for migration...")
	} else {
		fmt.Println("🔄 Migrating authentication data to encrypted storage...")
	}

	// Migrate API clients
	if err := migrateAPIClients(db, authEnc, dryRun); err != nil {
		return fmt.Errorf("failed to migrate API clients: %w", err)
	}

	// Migrate sessions
	if err := migrateSessions(db, authEnc, dryRun); err != nil {
		return fmt.Errorf("failed to migrate sessions: %w", err)
	}

	// Migrate API tokens
	if err := migrateAPITokens(db, authEnc, dryRun); err != nil {
		return fmt.Errorf("failed to migrate API tokens: %w", err)
	}

	// Migrate password reset tokens
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
	if err := authEnc.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize auth encryption: %w", err)
	}

	fmt.Println("🔍 Validating authentication encryption...")

	// Validate API clients
	if err := validateAPIClients(db, authEnc, verbose); err != nil {
		return fmt.Errorf("API client validation failed: %w", err)
	}

	// Validate sessions
	if err := validateSessions(db, authEnc, verbose); err != nil {
		return fmt.Errorf("session validation failed: %w", err)
	}

	// Validate API tokens
	if err := validateAPITokens(db, authEnc, verbose); err != nil {
		return fmt.Errorf("API token validation failed: %w", err)
	}

	// Validate password reset tokens
	if err := validatePasswordResetTokens(db, authEnc, verbose); err != nil {
		return fmt.Errorf("password reset token validation failed: %w", err)
	}

	fmt.Println("✅ All authentication encryption validation checks passed")

	return nil
}

// Helper functions

func openDatabase(cfg *config.Config) (*gorm.DB, error) {
	return gorm.Open(sqlite.Open(cfg.Storage.Database.Path), &gorm.Config{})
}

func showAuthEncryptionStats(db *gorm.DB, encryptionEnabled bool) error {
	fmt.Println("\n📊 Authentication Data Statistics")
	fmt.Println("-" + string(make([]rune, 32)))

	// API clients
	var apiClientCount int64
	var encryptedAPIClientCount int64
	db.Model(&models.APIClient{}).Count(&apiClientCount)
	if encryptionEnabled {
		db.Model(&models.APIClient{}).Where("encrypted_client_secret IS NOT NULL").Count(&encryptedAPIClientCount)
	}
	fmt.Printf("🔑 API Clients: %d total", apiClientCount)
	if encryptionEnabled {
		fmt.Printf(" (%d encrypted)", encryptedAPIClientCount)
	}
	fmt.Println()

	// Sessions
	var sessionCount int64
	var encryptedSessionCount int64
	db.Model(&models.Session{}).Count(&sessionCount)
	if encryptionEnabled {
		db.Model(&models.Session{}).Where("encrypted_session_token IS NOT NULL").Count(&encryptedSessionCount)
	}
	fmt.Printf("🎫 Sessions: %d total", sessionCount)
	if encryptionEnabled {
		fmt.Printf(" (%d encrypted)", encryptedSessionCount)
	}
	fmt.Println()

	// API tokens
	var apiTokenCount int64
	var encryptedAPITokenCount int64
	db.Model(&models.APIToken{}).Count(&apiTokenCount)
	if encryptionEnabled {
		db.Model(&models.APIToken{}).Where("encrypted_token IS NOT NULL").Count(&encryptedAPITokenCount)
	}
	fmt.Printf("🎟️  API Tokens: %d total", apiTokenCount)
	if encryptionEnabled {
		fmt.Printf(" (%d encrypted)", encryptedAPITokenCount)
	}
	fmt.Println()

	// Password reset tokens
	var resetTokenCount int64
	var encryptedResetTokenCount int64
	db.Model(&models.PasswordReset{}).Count(&resetTokenCount)
	if encryptionEnabled {
		db.Model(&models.PasswordReset{}).Where("encrypted_token IS NOT NULL").Count(&encryptedResetTokenCount)
	}
	fmt.Printf("🔄 Reset Tokens: %d total", resetTokenCount)
	if encryptionEnabled {
		fmt.Printf(" (%d encrypted)", encryptedResetTokenCount)
	}
	fmt.Println()

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
		encryptedSecret, metadata, err := authEnc.EncryptClientSecret(client.ClientSecret)
		if err != nil {
			return fmt.Errorf("failed to encrypt client secret for client %s: %w", client.ClientID, err)
		}

		updates := map[string]interface{}{
			"encrypted_client_secret": encryptedSecret,
			"client_secret_metadata":  metadata,
		}

		if err := db.Model(&client).Updates(updates).Error; err != nil {
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
		encryptedToken, metadata, err := authEnc.EncryptSessionToken(session.SessionToken)
		if err != nil {
			return fmt.Errorf("failed to encrypt session token for session %d: %w", session.ID, err)
		}

		updates := map[string]interface{}{
			"encrypted_session_token": encryptedToken,
			"session_token_metadata":  metadata,
		}

		if err := db.Model(&session).Updates(updates).Error; err != nil {
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
		encryptedToken, metadata, err := authEnc.EncryptAPIToken(token.Token)
		if err != nil {
			return fmt.Errorf("failed to encrypt API token %d: %w", token.ID, err)
		}

		updates := map[string]interface{}{
			"encrypted_token": encryptedToken,
			"token_metadata":  metadata,
		}

		if err := db.Model(&token).Updates(updates).Error; err != nil {
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
		encryptedToken, metadata, err := authEnc.EncryptPasswordResetToken(reset.Token)
		if err != nil {
			return fmt.Errorf("failed to encrypt password reset token %d: %w", reset.ID, err)
		}

		updates := map[string]interface{}{
			"encrypted_token": encryptedToken,
			"token_metadata":  metadata,
		}

		if err := db.Model(&reset).Updates(updates).Error; err != nil {
			return fmt.Errorf("failed to update password reset token %d: %w", reset.ID, err)
		}
	}

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
		_, err := authEnc.DecryptClientSecret(client.EncryptedClientSecret, []byte(client.ClientSecretMetadata))
		if err != nil {
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
		_, err := authEnc.DecryptSessionToken(session.EncryptedSessionToken, []byte(session.SessionTokenMetadata))
		if err != nil {
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
		_, err := authEnc.DecryptAPIToken(token.EncryptedToken, []byte(token.TokenMetadata))
		if err != nil {
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
		_, err := authEnc.DecryptPasswordResetToken(reset.EncryptedToken, []byte(reset.TokenMetadata))
		if err != nil {
			return fmt.Errorf("failed to decrypt password reset token %d: %w", reset.ID, err)
		}
		if verbose {
			fmt.Printf("  ✅ Reset Token %d: OK\n", reset.ID)
		}
	}

	return nil
}
