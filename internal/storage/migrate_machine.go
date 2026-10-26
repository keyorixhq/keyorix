package storage

// migrateDatabase steps for machine identities and their credentials, roles and OIDC bindings.
// Called in order from migrateDatabase (factory.go); see the step lists there.

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// createMachineIdentities is one of migrateDatabase's ordered steps (factory.go).
func createMachineIdentities(db *gorm.DB, exec func(string) error, machineExists bool) error {
	// Create machine_identities if missing (ADR-023, additive, safe on existing DBs).
	if !machineExists {
		if err := db.AutoMigrate(&models.MachineIdentity{}); err != nil {
			return fmt.Errorf("failed to migrate machine_identities table: %w", err)
		}
	} else {
		if !columnExists(db, "machine_identities", "classification") {
			// Data classification (ISO A.5.12). Additive ("" = unclassified).
			if err := exec("ALTER TABLE machine_identities ADD COLUMN classification TEXT DEFAULT ''"); err != nil {
				return err
			}
		}
		// Companion index (models.MachineIdentity.Classification is `gorm:"index"`);
		// this else branch only runs on the upgrade path (a fresh install's
		// AutoMigrate call above already creates the index) — see the
		// secret_nodes.classification comment for why this runs unconditionally
		// rather than nested inside the ALTER guard.
		if err := exec("CREATE INDEX IF NOT EXISTS idx_machine_identities_classification ON machine_identities (classification)"); err != nil {
			return err
		}
		// #3433: the project soft-delete cascade's suspension marker (schema epoch 4).
		// Additive; 0 / NULL = "not suspended by a cascade", which is what every
		// existing row is.
		if !columnExists(db, "machine_identities", "cascade_suspended_project_id") {
			if err := exec("ALTER TABLE machine_identities ADD COLUMN cascade_suspended_project_id BIGINT NOT NULL DEFAULT 0"); err != nil {
				return err
			}
		}
		if !columnExists(db, "machine_identities", "cascade_suspended_at") {
			// Per-dialect type for the reason given at secret_nodes.purge_at.
			ts := "DATETIME"
			if db.Dialector.Name() == "postgres" {
				ts = "TIMESTAMP WITH TIME ZONE"
			}
			if err := exec("ALTER TABLE machine_identities ADD COLUMN cascade_suspended_at " + ts); err != nil {
				return err
			}
		}
	}
	return nil
}

// createMachineIdentityCredentials is one of migrateDatabase's ordered steps (factory.go).
func createMachineIdentityCredentials(db *gorm.DB, exec func(string) error, machineCredExists bool) error {
	// Create machine-token tables if missing (ADR-030, additive, safe on existing DBs).
	if !machineCredExists {
		if err := db.AutoMigrate(&models.MachineIdentityCredential{}); err != nil {
			return fmt.Errorf("failed to migrate machine_identity_credentials table: %w", err)
		}
	} else {
		if !columnExists(db, "machine_identity_credentials", "classification") {
			if err := exec("ALTER TABLE machine_identity_credentials ADD COLUMN classification TEXT DEFAULT ''"); err != nil {
				return err
			}
		}
		// Companion index (models.MachineIdentityCredential.Classification is
		// `gorm:"index"`); see the machine_identities.classification comment above
		// for why this runs unconditionally in this (upgrade-only) branch.
		if err := exec("CREATE INDEX IF NOT EXISTS idx_machine_identity_credentials_classification ON machine_identity_credentials (classification)"); err != nil {
			return err
		}
	}
	return nil
}

// createMachineIdentityRoleTables is one of migrateDatabase's ordered steps (factory.go).
func createMachineIdentityRoleTables(db *gorm.DB, machineRoleExists, machineOIDCExists bool) error {
	if !machineRoleExists {
		if err := db.AutoMigrate(&models.MachineIdentityRole{}); err != nil {
			return fmt.Errorf("failed to migrate machine_identity_roles table: %w", err)
		}
	}
	// ADR-031: OIDC federation bindings.
	if !machineOIDCExists {
		if err := db.AutoMigrate(&models.MachineIdentityOIDCBinding{}); err != nil {
			return fmt.Errorf("failed to migrate machine_identity_oidc_bindings table: %w", err)
		}
	}
	return nil
}
