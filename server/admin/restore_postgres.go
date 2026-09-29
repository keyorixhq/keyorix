// restore_postgres.go holds `admin restore`'s Postgres-TARGET-specific
// pieces (design-b3-backup-v2.md §4's "Postgres target restore" bullet):
// everything restore.go's SQLite-shaped helpers (readExistingDatabase
// AuditEventCount, destinationEventsNewerThan, removeStaleSQLiteSidecars,
// verifyRestoredAudit's OpenSQLiteReadOnly) cannot do against a Postgres
// target, because there is no single database FILE to stat/open directly.
package admin

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/config"
)

// postgresWitnessAnchorDir returns a stable, host-local directory to anchor
// the rollback-protection witness file against (design §6.3) when the
// restore target is Postgres, which has no single database FILE for
// auditverify.WitnessPath's usual "sibling to the database" convention to
// resolve against. Uses the FIRST key-material file's own directory --
// already the one piece of genuinely host-local state a Postgres deployment
// has (key files are always local filesystem paths regardless of storage
// backend), and already effectively "this deployment's identity" the same
// way a SQLite db path already is (one config file/key-material set per
// deployment in both cases).
func postgresWitnessAnchorDir(cfg *config.Config) (string, error) {
	paths, err := expectedKeyFilePaths(cfg)
	if err != nil {
		return "", err
	}
	if len(paths) == 0 {
		return "", fmt.Errorf("internal error: no key-material files to anchor the rollback-protection witness against")
	}
	return filepath.Dir(paths[0]), nil
}

// postgresTargetIdentityPath synthesizes the string restore.go's shared,
// backend-agnostic helpers (checkRollbackProtection, refuseNonEmptyExisting's
// SQLite sibling) treat as "dbPath" purely for ITS DIRECTORY COMPONENT (via
// auditverify.WitnessPath) -- never opened as a file itself for Postgres.
func postgresTargetIdentityPath(cfg *config.Config) (string, error) {
	dir, err := postgresWitnessAnchorDir(cfg)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "postgres-target"), nil
}

// postgresOpenSQL opens cfg's configured Postgres DSN via database/sql
// directly (the "pgx" driver, already registered process-wide by
// internal/auditverify's own blank import) -- a short-lived raw connection
// for the small existence/count queries below, independent of the
// REPEATABLE READ snapshot connection backup uses or the GORM connection
// migration/LoadArchive use.
func postgresOpenSQL(cfg *config.Config) (*sql.DB, error) {
	db, err := sql.Open("pgx", cfg.Storage.Database.DSN)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	return db, nil
}

// refuseNonEmptyPostgresTarget is refuseNonEmptyExisting's Postgres
// equivalent: refuses if the target database already has ANY user table
// (information_schema.tables, excluding Postgres/pg_catalog's own internal
// schemas) -- there is no single "does the database file exist and have
// content" check the way there is for SQLite, so this asks the same
// question ("is there already something here") the only way that's
// meaningful for a whole database/schema.
func refuseNonEmptyPostgresTarget(cfg *config.Config) error {
	if restoreOverwriteExisting {
		return nil
	}
	db, err := postgresOpenSQL(cfg)
	if err != nil {
		return nil // can't connect -- migrateDatabase will surface this loudly on its own; not this check's job
	}
	defer db.Close() //nolint:errcheck

	var count int
	const q = `SELECT COUNT(*) FROM information_schema.tables ` +
		`WHERE table_schema NOT IN ('pg_catalog', 'information_schema')`
	if err := db.QueryRow(q).Scan(&count); err != nil {
		return fmt.Errorf("check target Postgres database for existing tables: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("target Postgres database already has %d table(s) -- restore refuses to overwrite it "+
			"(pass --overwrite-existing if you are certain, e.g. this is a genuine disaster-recovery restore; "+
			"the normal flow is restoring into a fresh/empty database)", count)
	}
	return nil
}

// postgresAuditEventCount is readExistingDatabaseAuditEventCount's Postgres
// equivalent: MAX(id) from audit_events in the TARGET Postgres database, 0
// if the table doesn't exist yet (a fresh/pre-migration database) or the
// database can't be reached at all (nothing to compare against yet).
func postgresAuditEventCount(cfg *config.Config) (int64, error) {
	db, err := postgresOpenSQL(cfg)
	if err != nil {
		return 0, nil //nolint:nilerr // unreachable target has nothing to compare against, same as SQLite's os.IsNotExist case
	}
	defer db.Close() //nolint:errcheck

	var count sql.NullInt64
	err = db.QueryRow("SELECT MAX(id) FROM audit_events").Scan(&count)
	if err != nil {
		if isPostgresUndefinedTable(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read audit_events count from target Postgres database: %w", err)
	}
	return count.Int64, nil
}

// postgresAuditEventsNewerThan is destinationEventsNewerThan's Postgres
// equivalent.
func postgresAuditEventsNewerThan(cfg *config.Config, archiveHead int64) (int64, error) {
	db, err := postgresOpenSQL(cfg)
	if err != nil {
		return 0, nil //nolint:nilerr // unreachable target has nothing newer, same reasoning as postgresAuditEventCount
	}
	defer db.Close() //nolint:errcheck

	var n int64
	// Postgres placeholders are positional ($1, $2, ...), unlike SQLite's
	// "?" -- destinationEventsNewerThan's query text isn't reusable verbatim.
	q := "SELECT COUNT(*) FROM audit_events WHERE id > $1 AND event_type NOT IN ("
	args := []any{archiveHead}
	for i, et := range rollbackBookkeepingEventTypes {
		if i > 0 {
			q += ", "
		}
		q += fmt.Sprintf("$%d", i+2)
		args = append(args, et)
	}
	q += ")"
	if err := db.QueryRow(q, args...).Scan(&n); err != nil { // nosemgrep: go.lang.security.audit.sqli.gosql-sqli.gosql-sqli -- q's dynamic part is only a "$2,$3,..." placeholder run sized off len(rollbackBookkeepingEventTypes) (a package-level literal slice); every actual value is passed as a parameterized arg, never interpolated
		if isPostgresUndefinedTable(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("count newer audit events in target Postgres database: %w", err)
	}
	return n, nil
}

// isPostgresUndefinedTable reports whether err is Postgres's "relation does
// not exist" error (SQLSTATE 42P01) -- the fresh/pre-migration-database
// case, not a real error, mirroring the SQLite helpers' own
// strings.Contains(err.Error(), "no such table") check.
func isPostgresUndefinedTable(err error) bool {
	return strings.Contains(err.Error(), "42P01") || strings.Contains(err.Error(), "does not exist")
}

// verifyRestoredAuditPostgres is verifyRestoredAudit's Postgres equivalent,
// using auditverify.OpenPostgres (already existing, backend-neutral
// infrastructure -- internal/auditverify's own independence requirement
// means it already speaks both dialects) instead of OpenSQLiteReadOnly.
func verifyRestoredAuditPostgres(cfg *config.Config) error {
	db, err := auditverify.OpenPostgres(cfg.Storage.Database.DSN)
	if err != nil {
		return fmt.Errorf("open restored database for automatic verify-audit: %w", err)
	}
	defer db.Close() //nolint:errcheck
	return runVerifyRestoredAudit(cfg, db)
}
