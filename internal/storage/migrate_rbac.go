package storage

// migrateDatabase steps for roles, role assignments and separation-of-duties policies.
// Called in order from migrateDatabase (factory.go); see the step lists there.

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// alterRoleAssignmentScope is one of migrateDatabase's ordered steps (factory.go).
func alterRoleAssignmentScope(db *gorm.DB, exec func(string) error) error {
	// RBAC Phase 2: scope role assignments by environment as well as project.
	// project_id already exists (nullable on pre-008 DBs); add environment_id and
	// normalise NULL project_id rows to the 0 = global sentinel the queries expect.
	for _, m := range []struct{ tbl, addEnvID, nullPID string }{
		{"user_roles", "ALTER TABLE user_roles ADD COLUMN environment_id INTEGER NOT NULL DEFAULT 0", "UPDATE user_roles SET project_id = 0 WHERE project_id IS NULL"},
		{"group_roles", "ALTER TABLE group_roles ADD COLUMN environment_id INTEGER NOT NULL DEFAULT 0", "UPDATE group_roles SET project_id = 0 WHERE project_id IS NULL"},
	} {
		if !tableExists(db, m.tbl) {
			continue
		}
		if !columnExists(db, m.tbl, "environment_id") {
			if err := exec(m.addEnvID); err != nil {
				return err
			}
		}
		if columnExists(db, m.tbl, "project_id") {
			if err := exec(m.nullPID); err != nil {
				return err
			}
		}
	}
	return nil
}

// alterRoleFlags is one of migrateDatabase's ordered steps (factory.go).
func alterRoleFlags(db *gorm.DB, exec func(string) error) error {
	// ADR-084: structural admin-bypass flag, replacing roleSetContainsAdmin's old
	// name-based lookup. Additive column for existing installs (a fresh install
	// gets it via AutoMigrate's CREATE TABLE, so this is a no-op there); the
	// backfill runs exactly once, gated on the column having just been added —
	// a one-time SNAPSHOT of today's four reserved admin-tier names into the
	// new flag, using the same name list this migration retires as an ongoing
	// mechanism. After this, the flag is authoritative: renaming a role never
	// moves it, and no future role acquires it by matching a name.
	if tableExists(db, "roles") && !columnExists(db, "roles", "bypasses_permission_checks") {
		if err := exec("ALTER TABLE roles ADD COLUMN bypasses_permission_checks BOOLEAN NOT NULL DEFAULT false"); err != nil {
			return err
		}
		if err := exec("UPDATE roles SET bypasses_permission_checks = true " +
			"WHERE name IN ('super_admin', 'admin', 'system_admin', 'project_admin')"); err != nil {
			return err
		}
	}

	// GROUP-ROLE-SCOPE-1 Phase 2 (#3546): roles.assignable_scope. The column's
	// default is the NEW-role default (project); the one-time backfill sets every
	// EXISTING role to any (nothing that worked before breaks), then the built-ins
	// to their fixed scope. Column and backfill share one transaction: the
	// column's absence gates the backfill, so a crash between them must not leave
	// it unrun (every role, system_admin included, would read as project-only).
	if tableExists(db, "roles") && !columnExists(db, "roles", "assignable_scope") {
		if err := db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Migrator().AddColumn(&models.Role{}, "AssignableScope"); err != nil {
				return err
			}
			return backfillRoleAssignableScope(tx)
		}); err != nil {
			return fmt.Errorf("failed to add roles.assignable_scope: %w", err)
		}
	}
	return nil
}

// createSoDPolicies is one of migrateDatabase's ordered steps (factory.go).
func createSoDPolicies(db *gorm.DB, sodExists bool) error {
	// Create the separation-of-duties policy table if missing (additive).
	if !sodExists {
		if err := db.AutoMigrate(&models.SoDPolicy{}); err != nil {
			return fmt.Errorf("failed to migrate sod_policies table: %w", err)
		}
	}
	return nil
}

// alterRoleAndSecretNodeNames is one of migrateDatabase's ordered steps (factory.go).
func alterRoleAndSecretNodeNames(db *gorm.DB, exec func(string) error) error {
	// #1642: roles.name_folded and secret_nodes' NFC-normalized name were only
	// ever wired into the fresh-DB tail below, never into this additive,
	// existing-DB-safe path -- unlike every sibling *_folded/normalized column
	// above (groups.name_folded, users.username_folded/email_folded), which is
	// called from both here AND the fresh-DB tail. Since migrateDatabase
	// returns early below once projectsExists is true (an already-initialized
	// database), the fresh-DB-only call site never ran on any upgrade: the
	// roles table never gained name_folded, while models.Role and
	// CreateRole/UpdateRole unconditionally reference that column in every
	// generated INSERT/UPDATE -- breaking role creation/update outright on
	// every real upgrade the first time either is called. Mirrors
	// ensureUserNameIndex's tableExists guard above exactly. Additive +
	// idempotent; the full AutoMigrate below covers fresh DBs.
	if tableExists(db, "roles") {
		// ensureRoleNameIndex/backfillFoldedColumn assume name_folded already
		// exists (true on a fresh install, where AutoMigrate added it from
		// models.Role's struct tag) -- they only backfill and index an
		// EXISTING column, they never ALTER TABLE ADD COLUMN it themselves.
		// On an existing install AutoMigrate never runs, so this ADD COLUMN
		// step -- mirroring the groups.DeletedAt AddColumn immediately above
		// this comment block -- is what actually has to add it here.
		// Literal DDL, not Migrator.AddColumn. models.Role tags NameFolded
		// "not null", and GORM renders that straight into the ALTER with no
		// DEFAULT -- which every engine rejects against a table that already
		// has rows:
		//
		//   SQLite:   Cannot add a NOT NULL column with default value NULL
		//   Postgres: column "name_folded" of relation "roles" contains null values
		//
		// so #1642's roles guard only ever worked on an EMPTY roles table. It
		// went unnoticed because the one real database this was reproduced on
		// happened to have roles=0; any install with the seeded admin/operator/
		// viewer roles would have hit it. Caught by
		// TestMigrateDatabase_PreFoldedColumnsUpgrade, whose fixture inserts a
		// role -- the synthetic case was stronger than the real one here.
		// DEFAULT '' also matches what backfillFoldedColumn selects on, so the
		// backfill immediately below still picks every pre-existing row up.
		if !columnExists(db, "roles", "name_folded") {
			if err := exec("ALTER TABLE roles ADD COLUMN name_folded TEXT NOT NULL DEFAULT ''"); err != nil {
				return err
			}
		}
		if err := ensureRoleNameIndex(db); err != nil {
			return err
		}
	}
	if tableExists(db, "secret_nodes") {
		if err := ensureSecretNodeNameNFC(db); err != nil {
			return err
		}
	}
	return nil
}
