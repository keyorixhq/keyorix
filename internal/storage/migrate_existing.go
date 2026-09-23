package storage

import "gorm.io/gorm"

// MigrateExisting runs the production schema bootstrap -- exactly the
// migrateDatabase step CreateStorage runs, under the same in-process
// migration mutex (plus the Postgres advisory lock when db is Postgres) --
// against an already-open *gorm.DB.
//
// For callers that must choose their own connection shape but must still
// end up with every index and constraint production enforces, not just what
// GORM AutoMigrate derives from struct tags: test and fuzz fixtures using an
// in-memory SQLite DSN or a schema-scoped Postgres connection (#1947 --
// AutoMigrate alone never creates uniq_secret_versions_node_version, the
// partial unique indexes on users/projects/memberships/..., the
// account-state CHECK, etc.). Unlike CreateStorage it takes no SQLite
// cross-process file lock: the caller owns the connection and whatever file
// (if any) backs it.
func MigrateExisting(db *gorm.DB) error {
	return withMigrationLock(db, db.Dialector.Name() == "postgres", "", (&DefaultStorageFactory{}).migrateDatabase)
}
