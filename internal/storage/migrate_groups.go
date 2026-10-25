package storage

// migrateDatabase steps for groups and group membership.
// Called in order from migrateDatabase (factory.go); see the step lists there.

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// alterGroups is one of migrateDatabase's ordered steps (factory.go).
func alterGroups(db *gorm.DB, exec func(string) error, groupsExists bool) error {
	// Groups gained soft-delete (DeletedAt) + a partial unique index on name. On an
	// existing DB add the column and swap the plain unique index for the partial one
	// (additive, idempotent); the full AutoMigrate below covers fresh DBs.
	if groupsExists {
		if m := db.Migrator(); !m.HasColumn(&models.Group{}, "DeletedAt") {
			if err := m.AddColumn(&models.Group{}, "DeletedAt"); err != nil {
				return fmt.Errorf("failed to add groups.deleted_at column: %w", err)
			}
		}
		// groups.name_folded (#1642) has exactly the same existing-DB problem
		// roles.name_folded had, and was missed because the reasoning stopped at
		// the wrong question. #1642's own note reads groups.name_folded as safe
		// because ensureGroupNameIndex is "called from both here AND the fresh-DB
		// tail" -- true, and irrelevant: ensureGroupNameIndex calls
		// backfillFoldedColumn, which only backfills and indexes an EXISTING
		// column and never ALTER TABLE ADD COLUMN it. The call site existed; the
		// column did not. On any database created before #1642, migrateDatabase
		// returns early (projectsExists) so AutoMigrate never adds it, and the
		// backfill's own SELECT is what fails:
		//
		//   failed to read groups for name_folded backfill:
		//   ERROR: column "name_folded" does not exist (SQLSTATE 42703)
		//
		// which aborts migrateDatabase and, through CreateStorage ->
		// server/main.go's log.Fatalf, prevents the server from booting at all.
		// Found by running v0.92.0 against the DAST rig's real Postgres volume,
		// 2026-09-11. Literal DDL rather than Migrator.AddColumn because the
		// model tags this column `not null`, and Postgres rejects ADD COLUMN ...
		// NOT NULL without a DEFAULT on a table that already has rows.
		if !columnExists(db, "groups", "name_folded") {
			if err := exec("ALTER TABLE groups ADD COLUMN name_folded TEXT NOT NULL DEFAULT ''"); err != nil {
				return err
			}
		}
		if err := ensureGroupNameIndex(db); err != nil {
			return err
		}
	}
	return nil
}

// alterUserGroupsProjectID is one of migrateDatabase's ordered steps (factory.go).
func alterUserGroupsProjectID(db *gorm.DB, exec func(string) error) error {
	// UserGroup.ProjectID scopes group membership to a project (0 = global).
	// The old PK was (user_id, group_id); the new PK is (user_id, group_id, project_id).
	// For SQLite (fresh DBs or test environments) AutoMigrate handles this; for
	// existing installs we add the column with a DEFAULT 0 so existing global
	// memberships are correctly mapped to project_id=0. The PK cannot be altered in
	// place on SQLite (no ADD COLUMN to PK), but GORM's AutoMigrate on a fresh DB
	// already creates the correct composite PK. For Postgres, the ALTER adds the
	// column first and we let GORM's AutoMigrate handle the rest on next fresh-DB
	// creation; upgraded installs get a best-effort column add so the application
	// can at least insert new scoped rows without breaking on old global ones.
	if tableExists(db, "user_groups") && !columnExists(db, "user_groups", "project_id") {
		if err := exec("ALTER TABLE user_groups ADD COLUMN project_id INTEGER NOT NULL DEFAULT 0"); err != nil {
			return err
		}
	}
	return nil
}
