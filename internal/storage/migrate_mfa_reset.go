package storage

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// createMFAResetRequests is one of migrateDatabase's ordered steps (factory.go):
// the two-admin MFA reset requests (RECOVERY-MFA-RESET-1), additive.
func createMFAResetRequests(db *gorm.DB, exists bool) error {
	if !exists {
		if err := db.AutoMigrate(&models.MFAResetRequest{}); err != nil {
			return fmt.Errorf("failed to migrate mfa_reset_requests table: %w", err)
		}
	}
	return nil
}
