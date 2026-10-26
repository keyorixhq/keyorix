package storage

// migrateDatabase steps for dynamic secrets.
// Called in order from migrateDatabase (factory.go); see the step lists there.

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// createDynamicSecretTables is one of migrateDatabase's ordered steps (factory.go).
func createDynamicSecretTables(db *gorm.DB, exec func(string) error, dynConfigExists, dynLeaseExists bool) error {
	// Create the dynamic-secrets tables if missing (ADR-035, additive); otherwise add
	// only the newer max-TTL column via the Migrator (same pgx hazard — never
	// full-AutoMigrate an existing table here).
	if !dynConfigExists {
		if err := db.AutoMigrate(&models.DynamicSecretConfig{}); err != nil {
			return fmt.Errorf("failed to migrate dynamic_secret_configs table: %w", err)
		}
	} else {
		m := db.Migrator()
		if !m.HasColumn(&models.DynamicSecretConfig{}, "MaxTTLSeconds") {
			if err := m.AddColumn(&models.DynamicSecretConfig{}, "MaxTTLSeconds"); err != nil {
				return fmt.Errorf("failed to add dynamic_secret_configs.max_ttl_seconds column: %w", err)
			}
		}
		// Data classification (ISO A.5.12). Additive ("" = unclassified).
		if tableExists(db, "dynamic_secret_configs") && !columnExists(db, "dynamic_secret_configs", "classification") {
			if err := exec("ALTER TABLE dynamic_secret_configs ADD COLUMN classification TEXT DEFAULT ''"); err != nil {
				return err
			}
		}
		// Companion index (models.DynamicSecretConfig.Classification is `gorm:"index"`);
		// this whole branch only runs when dynamic_secret_configs already existed (the
		// upgrade path — a fresh install's AutoMigrate call below already creates the
		// index), so it's safe to run unconditionally here rather than nesting inside
		// the ALTER guard above — see the secret_nodes.classification comment for why.
		if err := exec("CREATE INDEX IF NOT EXISTS idx_dynamic_secret_configs_classification ON dynamic_secret_configs (classification)"); err != nil {
			return err
		}
		// Disabled (#369): refuses new leases once the owning project is soft-deleted.
		// Additive (defaults false = every pre-existing config stays enabled).
		if !m.HasColumn(&models.DynamicSecretConfig{}, "Disabled") {
			if err := m.AddColumn(&models.DynamicSecretConfig{}, "Disabled"); err != nil {
				return fmt.Errorf("failed to add dynamic_secret_configs.disabled column: %w", err)
			}
		}
	}
	if !dynLeaseExists {
		if err := db.AutoMigrate(&models.DynamicSecretLease{}); err != nil {
			return fmt.Errorf("failed to migrate dynamic_secret_leases table: %w", err)
		}
	}
	// At most one dynamic-secret config may exist per (project, environment, name)
	// (#462), matching DynamicSecretConfig's own doc comment. The struct carries no
	// unique-index tag (same reason as the max-TTL/Disabled columns above: this table
	// is never re-AutoMigrated once it exists), so the index must be created
	// explicitly here to also reach pre-existing databases. Close the gap at the DB
	// layer regardless of whether the table pre-existed.
	if tableExists(db, "dynamic_secret_configs") {
		if err := ensureDynamicSecretConfigNameIndex(db); err != nil {
			return err
		}
	}
	return nil
}
