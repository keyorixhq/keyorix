package storage

import (
	"errors"
	"fmt"
	"strconv"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// CheckSchemaEpoch exposes checkSchemaEpoch (ADR-097) for `keyorix-server
// admin diagnose`, which needs to report migration state WITHOUT applying
// any migration (OpenGormDB's own doc comment: raw open, no schema changes
// as a side effect). It is exactly the read-only comparison
// migrateDatabase itself runs first, before touching anything -- reusing it
// here keeps that comparison defined in exactly one place rather than
// duplicating the read logic in the admin package.
func CheckSchemaEpoch(db *gorm.DB) error {
	return checkSchemaEpoch(db)
}

// InspectMigrationState reports, read-only, whether db's schema is up to
// date with this binary (upToDate) and a human-readable detail. It is the
// read-only counterpart to migrateDatabase for `keyorix-server admin
// diagnose`: migrateDatabase's individual ALTER-gated-on-column-existence
// steps have no single formal "migration version" beyond schema_epoch, so
// "behind" here means exactly what migrateDatabase itself would find
// changed to apply -- not a stronger claim about which specific columns are
// missing. Returns a non-nil error only when the check ITSELF cannot be
// answered (this binary is older than the database, or the recorded epoch
// is corrupt) -- a database that is simply behind and needs `admin migrate`
// is reported via upToDate=false, not an error, since that is the expected
// state of a freshly-initialized or not-yet-upgraded database, not a
// failure of the check.
func InspectMigrationState(db *gorm.DB) (upToDate bool, detail string, err error) {
	if err := checkSchemaEpoch(db); err != nil {
		return false, "", err
	}
	if !tableExists(db, "system_metadata") {
		if !tableExists(db, "users") {
			return false, "database has no tables yet -- run `keyorix-server admin migrate` to create the schema", nil
		}
		return false, "database predates schema-epoch tracking -- migrations are pending; run `keyorix-server admin migrate`", nil
	}
	var m models.SystemMetadata
	dberr := db.Where("key = ?", schemaEpochMetadataKey).Take(&m).Error
	if dberr != nil {
		if errors.Is(dberr, gorm.ErrRecordNotFound) {
			return false, "schema epoch not recorded yet -- migrations are pending; run `keyorix-server admin migrate`", nil
		}
		return false, "", fmt.Errorf("failed to read schema epoch: %w", dberr)
	}
	dbEpoch, perr := strconv.Atoi(m.Value)
	if perr != nil {
		return false, "", fmt.Errorf("stored schema epoch %q is not a valid integer", m.Value)
	}
	if dbEpoch < currentSchemaEpoch {
		return false, fmt.Sprintf("database schema epoch %d is behind this binary's %d -- migrations are pending; run `keyorix-server admin migrate`", dbEpoch, currentSchemaEpoch), nil
	}
	return true, fmt.Sprintf("database schema epoch %d matches this binary", dbEpoch), nil
}
