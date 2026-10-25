package storage

// migrateDatabase steps for secret ACLs, access schedules and share records.
// Called in order from migrateDatabase (factory.go); see the step lists there.

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// createSecretACLs is one of migrateDatabase's ordered steps (factory.go).
func createSecretACLs(db *gorm.DB, secretACLExists bool) error {
	// Create the secret-ACL table if missing (RBAC Phase 3, additive).
	if !secretACLExists {
		if err := db.AutoMigrate(&models.SecretACL{}); err != nil {
			return fmt.Errorf("failed to migrate secret_acls table: %w", err)
		}
	}
	return nil
}

// createSecretAccessSchedules is one of migrateDatabase's ordered steps (factory.go).
func createSecretAccessSchedules(db *gorm.DB, scheduleExists bool) error {
	// Create secret_access_schedules if missing (temporal access policies, additive).
	if !scheduleExists {
		if err := db.AutoMigrate(&models.SecretAccessSchedule{}); err != nil {
			return fmt.Errorf("failed to migrate secret_access_schedules table: %w", err)
		}
	}
	return nil
}

// alterShareRecordIndex is one of migrateDatabase's ordered steps (factory.go).
func alterShareRecordIndex(db *gorm.DB) error {
	// Close the share-create race (#136): a partial unique index on live rows so two
	// concurrent CreateShareRecord calls for the same (secret, recipient, is_group)
	// can no longer both succeed as separate rows. Additive + idempotent; the full
	// AutoMigrate below covers fresh DBs (which get the index further down too).
	if tableExists(db, "share_records") {
		if err := ensureShareRecordUniqueIndex(db); err != nil {
			return err
		}
	}
	return nil
}
