package storage

// migrateDatabase step that records whether the legacy service-account tables are
// empty (#2541, ADR-113). Called from migrateDatabase (factory.go) right before
// recordSchemaEpoch, on both the established and the fresh-install path.

import (
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// legacyServiceAccountsEmptyMarkerKey is the system_metadata key recording that
// api_clients and api_tokens held no rows at this database's last migration.
// #nosec G101 -- metadata key name, not a credential.
const legacyServiceAccountsEmptyMarkerKey = "service_accounts_purge_v1"

// legacyServiceAccountsEmptyMarkerValue is the marker's only value.
const legacyServiceAccountsEmptyMarkerValue = "empty"

// recordLegacyServiceAccountsState is stage 1 of #2541: it counts the rows of
// api_clients and api_tokens and records the answer, so the later removal of the
// models and tables can be gated on evidence from real installs, not a date.
//
// No released binary from v0.87.0 (#552) on inserts into either table, and no
// authentication path ever accepted their tokens; a row can only come from a
// database that ran v0.86.0 or older and issued a service account, or from a
// restored archive that carried one (the I6 old-release fixtures do). Both
// counts zero: the marker is written (idempotent upsert). Any row: the marker
// is removed, so it never outlives the state it records, and a warning names
// the counts. Neither case fails the boot or changes a row of either table:
// this step observes, it does not purge.
//
// Existence comes from migrateDatabase's up-front snapshot, never a fresh
// tableExists here: this runs after steps that may create tables, which can make
// a later existence query on Postgres return a spurious false
// (INV-STORAGE-migration-existence-snapshot-before-create), and a spurious false
// would record a false "empty". A table absent from the snapshot was created
// empty by this same migration (createU1Tables), and nothing in the migration
// inserts into it, so it counts as zero.
func recordLegacyServiceAccountsState(db *gorm.DB, apiClientExists, apiTokenExists bool) error {
	counts := make(map[string]int64, 2)
	var total int64
	for t, exists := range map[string]bool{"api_clients": apiClientExists, "api_tokens": apiTokenExists} {
		if !exists {
			continue
		}
		var n int64
		if err := db.Table(t).Count(&n).Error; err != nil {
			return fmt.Errorf("count rows in legacy table %s: %w", t, err)
		}
		counts[t] = n
		total += n
	}
	if total > 0 {
		if err := db.Where("key = ?", legacyServiceAccountsEmptyMarkerKey).Delete(&models.SystemMetadata{}).Error; err != nil {
			return fmt.Errorf("clear %s marker: %w", legacyServiceAccountsEmptyMarkerKey, err)
		}
		log.Printf("WARNING: legacy service-account tables are not empty (api_clients: %d rows, api_tokens: %d rows). "+
			"No authentication path has accepted these credentials since v0.87.0, and removing both tables is "+
			"planned (#2541, ADR-113). Review the rows and, after taking a backup, delete them "+
			"(DELETE FROM api_tokens; DELETE FROM api_clients;)",
			counts["api_clients"], counts["api_tokens"])
		return nil
	}
	now := time.Now().UTC() // GORM keeps a non-zero UpdatedAt, so NowFunc's UTC would not apply (#3914)
	if err := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value"}),
	}).Create(&models.SystemMetadata{
		Key: legacyServiceAccountsEmptyMarkerKey, Value: legacyServiceAccountsEmptyMarkerValue, UpdatedAt: now,
	}).Error; err != nil {
		return fmt.Errorf("record %s marker: %w", legacyServiceAccountsEmptyMarkerKey, err)
	}
	return nil
}
