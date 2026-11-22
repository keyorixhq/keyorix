package storage

// migrateDatabase steps for projects and project memberships.
// Called in order from migrateDatabase (factory.go); see the step lists there.

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// createProjectMemberships is one of migrateDatabase's ordered steps (factory.go).
func createProjectMemberships(db *gorm.DB, membershipExists bool) error {
	// Create project_memberships if missing (ADR-022 membership lifecycle, additive).
	if !membershipExists {
		if err := db.AutoMigrate(&models.ProjectMembership{}); err != nil {
			return fmt.Errorf("failed to migrate project_memberships table: %w", err)
		}
	} else if !db.Migrator().HasColumn(&models.ProjectMembership{}, "InvitedByMachineIdentityID") {
		// #1573, #4518: the machine-identity actor column a database first installed
		// before v0.92 never got.
		if err := db.Migrator().AddColumn(&models.ProjectMembership{}, "InvitedByMachineIdentityID"); err != nil {
			return fmt.Errorf("failed to add project_memberships.invited_by_machine_identity_id column: %w", err)
		}
	}
	if tableExists(db, "project_memberships") {
		if err := ensureProjectMembershipIndex(db); err != nil {
			return err
		}
	}
	return nil
}

// alterProjectNameIndex is one of migrateDatabase's ordered steps (factory.go).
func alterProjectNameIndex(db *gorm.DB, projectsExists bool) error {
	// Swap the plain unique index on projects.name for a case-insensitive, live-rows-
	// only partial one (#385): "Production"/"production" previously landed as two
	// distinct, all-succeeding rows, and the CLI's project name resolution
	// (resolveProjectID) is case-insensitive and returns the first match — so a
	// same-name-different-case shadow project the exact-match index didn't block could
	// silently hijack a later `keyorix secret import/export --project production`.
	// Additive + idempotent; the full AutoMigrate below covers fresh DBs.
	if projectsExists {
		if err := ensureProjectNameIndex(db); err != nil {
			return err
		}
	}
	return nil
}
