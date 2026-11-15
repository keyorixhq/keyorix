// restore_populated_guard.go: `admin restore --overwrite-existing` on a target
// that holds data (MIGRATE-VERIFY-1 (b), KEY-ROTATION-SAFETY-1 item 1).
//
// --overwrite-existing exists for the re-run case: an interrupted restore's
// leftovers (an empty, migrated schema, a key set) or a 0-byte placeholder.
// The same flag also replaced a target that holds a working deployment: on
// PostgreSQL its tables are emptied inside the load transaction (the rows are
// gone; only the key files are kept aside), on SQLite the database is moved
// aside. Replacing real data is a different decision from re-running a
// restore, so it takes its own flag, --replace-existing-data.
//
// "Holds data" is any row in a table of the model registry other than
// system_metadata (the rows clearPostgresRestoreTarget would delete), except
// audit events written by host-side admin commands (actor admin_cli). A freshly
// migrated database has rows only in system_metadata (the schema epoch rows),
// and an admin command run on it adds only admin_cli events, so the re-run
// case passes. The check runs with the other refusals, before the archive is
// extracted and before any key file is staged.
package admin

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	"gorm.io/gorm/schema"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage"
)

// restoreReplaceExistingData is `admin restore --replace-existing-data`.
var restoreReplaceExistingData bool

// ErrRestoreTargetPopulated refuses an --overwrite-existing restore onto a
// database that holds data, without --replace-existing-data. Nothing was
// changed: no key file, manifest or row was touched.
var ErrRestoreTargetPopulated = errors.New("the restore target database holds data")

// refusePopulatedRestoreTarget is the --replace-existing-data guard. Without
// --overwrite-existing the non-empty refusals already stopped the restore.
func refusePopulatedRestoreTarget(cfg *config.Config, dbPath string) error {
	if restoreReplaceExistingData && !restoreOverwriteExisting {
		return fmt.Errorf("--replace-existing-data only applies together with --overwrite-existing")
	}
	if !restoreOverwriteExisting || restoreReplaceExistingData {
		return nil
	}
	tables, err := restoreTargetTablesWithRows(cfg, dbPath)
	if err != nil {
		return fmt.Errorf("check whether the restore target holds data (nothing was changed): %w", err)
	}
	if len(tables) == 0 {
		return nil
	}
	what := "its rows are deleted"
	if !isPostgresStorage(cfg) {
		what = "the database file is moved aside to <path>.pre-restore-<timestamp>"
	}
	return fmt.Errorf("%w (tables with rows: %s) -- restore refuses to replace it with --overwrite-existing alone, "+
		"and nothing was changed: the key files, the key-set manifest and the database are as they were. "+
		"--overwrite-existing is for re-running an interrupted restore into an empty database. To replace a "+
		"deployment's data on purpose (%s; the key files are kept aside), take a backup of it first, then pass "+
		"--replace-existing-data as well", ErrRestoreTargetPopulated, strings.Join(tables, ", "), what)
}

// restoreTargetTablesWithRows names the registry tables (system_metadata
// excluded) that hold at least one row in the restore target. A missing
// database or table holds nothing.
func restoreTargetTablesWithRows(cfg *config.Config, dbPath string) ([]string, error) {
	var db *sql.DB
	var undefined func(error) bool
	if isPostgresStorage(cfg) {
		var err error
		if db, err = postgresOpenSQL(cfg); err != nil {
			return nil, err
		}
		undefined = isPostgresUndefinedTable
	} else {
		info, err := os.Stat(dbPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("stat %q: %w", dbPath, err)
		}
		if info.Size() == 0 {
			return nil, nil
		}
		if db, err = sql.Open("sqlite", "file:"+dbPath+"?mode=ro"); err != nil {
			return nil, fmt.Errorf("open %q read-only: %w", dbPath, err)
		}
		undefined = func(err error) bool { return strings.Contains(err.Error(), "no such table") }
	}
	defer db.Close() //nolint:errcheck

	var out []string
	for _, m := range storage.AllModels() {
		s, err := schema.Parse(m, &postgresResyncSchemaCache, schema.NamingStrategy{})
		if err != nil {
			return nil, fmt.Errorf("parse schema for %T: %w", m, err)
		}
		if s.Table == "system_metadata" {
			continue
		}
		var one int
		if s.Table == "audit_events" {
			// The admin commands an operator runs on a fresh host before a
			// restore (init, migrate, encryption init, a rolled-back
			// restore --recover) each record an admin_cli event: bookkeeping
			// of this host, not deployment data.
			q := "SELECT 1 FROM audit_events WHERE actor_type IS NULL OR actor_type <> ? LIMIT 1"
			if isPostgresStorage(cfg) {
				q = "SELECT 1 FROM audit_events WHERE actor_type IS NULL OR actor_type <> $1 LIMIT 1"
			}
			err = db.QueryRow(q, adminActorType).Scan(&one)
		} else {
			// #nosec G202 -- s.Table comes from storage.AllModels()'s compiled-in Go structs, quoted by quoteIdentPG
			err = db.QueryRow("SELECT 1 FROM " + quoteIdentPG(s.Table) + " LIMIT 1").Scan(&one) // nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query -- registry table name, never archive or request content
		}
		switch {
		case err == nil:
			out = append(out, s.Table)
		case errors.Is(err, sql.ErrNoRows), undefined(err):
		default:
			return nil, fmt.Errorf("read table %q: %w", s.Table, err)
		}
	}
	return out, nil
}
