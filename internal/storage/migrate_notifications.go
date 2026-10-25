package storage

// migrateDatabase steps for notifications.
// Called in order from migrateDatabase (factory.go); see the step lists there.

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// createNotifications is one of migrateDatabase's ordered steps (factory.go).
func createNotifications(db *gorm.DB, notificationsExists bool) error {
	// Notifications (ADR-024). Create the table if absent; otherwise add only the
	// newer ProjectID/Title/Link columns via the Migrator. We must NOT run a full
	// AutoMigrate on an already-existing table here — on Postgres that re-inspect
	// trips the pgx "insufficient arguments" prepared-statement bug mid-boot (the
	// same hazard handled for the other additive tables above).
	if !notificationsExists {
		if err := db.AutoMigrate(&models.Notification{}); err != nil {
			return fmt.Errorf("failed to migrate notifications table: %w", err)
		}
	} else {
		m := db.Migrator()
		for _, col := range []string{"ProjectID", "Title", "Link", "Severity"} {
			if !m.HasColumn(&models.Notification{}, col) {
				if err := m.AddColumn(&models.Notification{}, col); err != nil {
					return fmt.Errorf("failed to add notifications.%s column: %w", col, err)
				}
			}
		}
	}
	return nil
}
