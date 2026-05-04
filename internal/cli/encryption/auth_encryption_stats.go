// auth_encryption_stats.go — openDatabase and showAuthEncryptionStats.
//
// Shared helpers used by auth_encryption.go, auth_encryption_migrate.go,
// and auth_encryption_validate.go.
package encryption

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func openDatabase(cfg *config.Config) (*gorm.DB, error) {
	return gorm.Open(sqlite.Open(cfg.Storage.Database.Path), &gorm.Config{})
}

func showAuthEncryptionStats(db *gorm.DB, encryptionEnabled bool) error {
	fmt.Println("\n📊 Authentication Data Statistics")
	fmt.Println("-" + string(make([]rune, 32)))

	var apiClientCount, encryptedAPIClientCount int64
	db.Model(&models.APIClient{}).Count(&apiClientCount)
	if encryptionEnabled {
		db.Model(&models.APIClient{}).Where("encrypted_client_secret IS NOT NULL").Count(&encryptedAPIClientCount)
	}
	fmt.Printf("🔑 API Clients: %d total", apiClientCount)
	if encryptionEnabled {
		fmt.Printf(" (%d encrypted)", encryptedAPIClientCount)
	}
	fmt.Println()

	var sessionCount, encryptedSessionCount int64
	db.Model(&models.Session{}).Count(&sessionCount)
	if encryptionEnabled {
		db.Model(&models.Session{}).Where("encrypted_session_token IS NOT NULL").Count(&encryptedSessionCount)
	}
	fmt.Printf("🎫 Sessions: %d total", sessionCount)
	if encryptionEnabled {
		fmt.Printf(" (%d encrypted)", encryptedSessionCount)
	}
	fmt.Println()

	var apiTokenCount, encryptedAPITokenCount int64
	db.Model(&models.APIToken{}).Count(&apiTokenCount)
	if encryptionEnabled {
		db.Model(&models.APIToken{}).Where("encrypted_token IS NOT NULL").Count(&encryptedAPITokenCount)
	}
	fmt.Printf("🎟️  API Tokens: %d total", apiTokenCount)
	if encryptionEnabled {
		fmt.Printf(" (%d encrypted)", encryptedAPITokenCount)
	}
	fmt.Println()

	var resetTokenCount, encryptedResetTokenCount int64
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
