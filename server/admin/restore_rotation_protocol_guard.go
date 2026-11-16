// restore_rotation_protocol_guard.go: `admin restore` refuses a target whose
// database records a DEK rotation protocol newer than this binary's
// (KEY-ROTATION-TAILS-NOV-1 item 3, internal/encryption/rotation_protocol.go).
//
// Every server start with encryption enabled on a local database records the
// protocol it implements (PostgreSQL and SQLite). A restore by an older admin binary over that target replaces key
// files and rows with a binary that predates part of the protocol the
// deployment's servers rely on, the same hazard `admin encryption rotate`
// already refuses. The check runs with the other target refusals, before the
// archive is extracted and before any key file is staged. A target without a
// database, without system_metadata or without the marker passes.
package admin

import (
	"database/sql"
	"errors"
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
)

func refuseNewerRotationProtocolAtRestoreTarget(cfg *config.Config, dbPath string) error {
	isPG := isPostgresStorage(cfg)
	var db *sql.DB
	if isPG {
		var err error
		if db, err = postgresOpenSQL(cfg); err != nil {
			return fmt.Errorf("read the restore target's DEK rotation protocol (nothing was changed): %w", err)
		}
	} else {
		info, err := os.Stat(dbPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("stat %q: %w", dbPath, err)
		}
		if info.Size() == 0 {
			return nil
		}
		if db, err = openExistingSQLiteReadOnly(dbPath); err != nil {
			return err
		}
	}
	defer db.Close() //nolint:errcheck

	existsQ := "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'system_metadata'"
	valueQ := "SELECT value FROM system_metadata WHERE key = ?"
	if isPG {
		existsQ = "SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'system_metadata'"
		valueQ = "SELECT value FROM system_metadata WHERE key = $1"
	}
	var one int
	if err := db.QueryRow(existsQ).Scan(&one); errors.Is(err, sql.ErrNoRows) {
		return nil
	} else if err != nil {
		return fmt.Errorf("read the restore target's DEK rotation protocol (nothing was changed): %w", err)
	}
	var value string
	if err := db.QueryRow(valueQ, encryption.DEKRotationProtocolKey).Scan(&value); errors.Is(err, sql.ErrNoRows) {
		return nil
	} else if err != nil {
		return fmt.Errorf("read the restore target's DEK rotation protocol (nothing was changed): %w", err)
	}
	if err := encryption.CheckRecordedRotationProtocol(value, "restore over it", "admin restore"); err != nil {
		return fmt.Errorf("%w (nothing was changed)", err)
	}
	return nil
}
