// dek_created_at.go — when the database's current DEK became its DEK
// (RD-CBOM-TAILS-1, read by the crypto inventory).
package encryption

import (
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// dekCreatedAtKey is the system_metadata key recording when a DEK became the
// database's DEK, as "<fingerprint> <RFC 3339 time>". Not secret. It is written
// only where a DEK becomes current: when this server seeds the epoch, and in the
// rotation sweep's transaction next to the epoch compare-and-set. Lifting a
// rotation fence (a failed or interrupted rotation, at rotation or at startup)
// rewrites the epoch row and its updated_at but never this row, so the old DEK is
// not re-dated by a rotation that did not happen. PostgreSQL only, like the epoch.
const dekCreatedAtKey = "dek.created_at"

// DEKCreatedAtMetadataKey is dekCreatedAtKey for callers outside the package.
const DEKCreatedAtMetadataKey = dekCreatedAtKey

// recordDEKCreatedAt records at as the time the DEK with this fingerprint became
// the database's DEK, replacing any earlier DEK's row.
func recordDEKCreatedAt(db *gorm.DB, fingerprint string, at time.Time) error {
	at = at.UTC()
	v := fingerprint + " " + at.Format(time.RFC3339Nano)
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.Assignments(map[string]any{"value": v, "updated_at": at}),
	}).Create(&models.SystemMetadata{Key: dekCreatedAtKey, Value: v, UpdatedAt: at}).Error
}

// DEKCreatedAt returns the time a dek.created_at value records, only when it
// records the DEK named by epoch (the dek.epoch value). A rotation fence as the
// epoch, a row for another DEK (a deployment seeded before this key existed and
// rotated by an older binary) or a malformed value returns ok=false: the caller
// then has no recorded time.
func DEKCreatedAt(epoch, recorded string) (time.Time, bool) {
	fp, ts, ok := strings.Cut(recorded, " ")
	if !ok || fp == "" || fp != epoch || strings.HasPrefix(epoch, dekEpochRotatingPrefix) {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil || t.IsZero() {
		return time.Time{}, false
	}
	return t.UTC(), true
}
