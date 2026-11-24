package storage

import (
	"fmt"
	"strconv"

	"gorm.io/gorm"
)

// SchemaEpochIsCurrent reports whether db already records exactly this
// binary's schema epoch (ADR-097), read without migrating anything. A caller
// that must not change the schema as a side effect (CreateStorage migrates on
// open) opens storage only when this is true: the migration is then the
// idempotent no-op every later admin command and server start runs. False with
// a nil error when the schema is absent, older, newer or unrecorded; an error
// only when the read itself fails or the recorded value is not a number.
//
// Its caller is `admin backup`'s refusal audit (#4105): an operator who
// upgrades the binary and takes a backup first must not have the database
// migrated by a backup that was refused.
func SchemaEpochIsCurrent(db *gorm.DB) (bool, error) {
	if !tableExists(db, "system_metadata") {
		return false, nil
	}
	m, found, err := readSchemaMetadata(db, schemaEpochMetadataKey)
	if err != nil {
		return false, fmt.Errorf("read schema epoch: %w", err)
	}
	if !found {
		return false, nil
	}
	epoch, err := strconv.Atoi(m.Value)
	if err != nil {
		return false, fmt.Errorf("stored schema epoch %q is not a valid integer", m.Value)
	}
	return epoch == currentSchemaEpoch, nil
}
