package backupfmt

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"gorm.io/gorm"
)

// legacyColumn names one archive column the CURRENT model no longer maps
// but whose value an upgrade backfill still reads from the raw column of
// that name. An in-place upgrade keeps such a column in the database (no
// migration drops it) and the backfill moves its value into the current
// columns; restore must leave the same input for the same backfill, not
// refuse the archive (#3452) and not drop the value (design §3.5).
//
// Adding an entry is a decision: the named backfill must exist, read
// exactly Column, and run on every restored database before it is served
// (server/admin runs it right after the restore commits). Every other
// unmapped column is still refused by checkSchemaDelta.
type legacyColumn struct {
	Model  string // registry type name, e.g. "NotificationChannel"
	Column string // DB column name in the archive's manifest
	// JSONKey is the row's NDJSON key for the value: rows are keyed by the
	// Go field name of the binary that wrote them (row_codec.go).
	JSONKey string
	SQLType string // column type to add when the target lacks it
	// Backfill names the function that consumes the carried value.
	Backfill string
}

var legacyColumns = []legacyColumn{
	{
		// Before #2468 (v0.95.x) the webhook URL was stored in plaintext in
		// notification_channels.url; it is now url_enc/url_meta (AAD-bound
		// to the channel id), and the model's URL field is gorm:"-".
		Model: "NotificationChannel", Column: "url", JSONKey: "URL", SQLType: "TEXT",
		Backfill: "store.(*LocalStorage).MigrateNotificationChannelURLsToEncrypted",
	},
}

func isLegacyColumn(modelName, column string) bool {
	for _, lc := range legacyColumns {
		if lc.Model == modelName && lc.Column == column {
			return true
		}
	}
	return false
}

// carryLegacyColumns writes every archived legacyColumns value of entry's
// table into the raw column of the same name in db (the load transaction),
// adding the column first when the freshly-migrated target lacks it. Runs
// after loadTable inserted the rows, so it updates by id. Streams the
// staged NDJSON file a second time; nothing is held per row beyond the
// current line. A row whose value is absent, null or empty is left alone
// (the backfill treats a missing value and an empty one alike).
func carryLegacyColumns(db *gorm.DB, modelName string, entry TableEntry, stagingDir string) error {
	for _, lc := range legacyColumns {
		if lc.Model != modelName || !slices.Contains(entry.Columns, lc.Column) {
			continue
		}
		if err := carryLegacyColumn(db, lc, entry, stagingDir); err != nil {
			return fmt.Errorf("table %q: carry legacy column %q for %s: %w", entry.Name, lc.Column, lc.Backfill, err)
		}
	}
	return nil
}

func carryLegacyColumn(db *gorm.DB, lc legacyColumn, entry TableEntry, stagingDir string) error {
	f, err := os.Open(filepath.Join(stagingDir, entry.TarName)) // #nosec G304 -- this package's own generated name, matched against the manifest by ExtractArchive
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck

	columnReady := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<30) // same per-line ceiling as loadTable
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(line, &raw); err != nil {
			return fmt.Errorf("decode row: %w", err)
		}
		v, ok := raw[lc.JSONKey]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			continue
		}
		var value string
		if err := json.Unmarshal(v, &value); err != nil {
			return fmt.Errorf("decode %s: %w", lc.JSONKey, err)
		}
		if value == "" {
			continue
		}
		var id uint
		if err := json.Unmarshal(raw["ID"], &id); err != nil || id == 0 {
			return fmt.Errorf("row has no usable ID (%v)", err)
		}
		if !columnReady {
			if err := ensureRawColumn(db, entry.Name, lc.Column, lc.SQLType); err != nil {
				return err
			}
			columnReady = true
		}
		res := db.Table(entry.Name).Where("id = ?", id).UpdateColumn(lc.Column, value)
		if res.Error != nil {
			return fmt.Errorf("update row %d: %w", id, res.Error)
		}
		if res.RowsAffected != 1 {
			return fmt.Errorf("update row %d: %d rows affected, expected 1", id, res.RowsAffected)
		}
	}
	return sc.Err()
}

// ensureRawColumn adds column (not mapped by any model field) to table when
// it is missing. ColumnTypes, not HasColumn: HasColumn resolves a struct
// field name, and these columns have none.
func ensureRawColumn(db *gorm.DB, table, column, sqlType string) error {
	cols, err := db.Migrator().ColumnTypes(table)
	if err != nil {
		return fmt.Errorf("read columns: %w", err)
	}
	for _, c := range cols {
		if c.Name() == column {
			return nil
		}
	}
	q := db.Statement.Quote
	// #nosec G201 -- table/column/type come from legacyColumns and the manifest's table name, which
	// LoadArchive only reaches for a table of the current model registry; all are quoted identifiers.
	return db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", q(table), q(column), sqlType)).Error
}
