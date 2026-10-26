package storage

// migrateDatabase steps for Connect reference grants and connector project bindings.
// Called in order from migrateDatabase (factory.go); see the step lists there.

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// createConnectTables is one of migrateDatabase's ordered steps (factory.go).
func createConnectTables(db *gorm.DB, connectRefGrantExists, connectorProjectBindingsExists bool) error {
	// Create connect_ref_grants if missing (ADR-045 per-reference Connect RBAC,
	// additive, safe on existing DBs).
	if !connectRefGrantExists {
		if err := db.AutoMigrate(&models.ConnectRefGrant{}); err != nil {
			return fmt.Errorf("failed to migrate connect_ref_grants table: %w", err)
		}
	}

	// Create connector_project_bindings if missing (ADR-082 branch 2, additive, safe
	// on existing DBs) — pins each Connect connector to the Keyorix project it
	// resolved to at first boot, by ID, so a later project rename can't silently
	// reassign ownership (see ConnectorProjectBinding's own doc comment).
	if !connectorProjectBindingsExists {
		if err := db.AutoMigrate(&models.ConnectorProjectBinding{}); err != nil {
			return fmt.Errorf("failed to migrate connector_project_bindings table: %w", err)
		}
	}
	return nil
}
