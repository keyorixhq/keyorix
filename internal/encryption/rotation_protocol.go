// rotation_protocol.go — refuse a DEK rotation by an admin binary older than
// the database's servers (DEK-ROTATE-SAFETY-1 item 3, DEK-EPOCH-N1-ROTATION).
//
// A rotation run by a binary that predates part of the rotation protocol does
// that part wrong without knowing it. The case that happened: an N-1 admin
// image without the DEK epoch (#3337) sweeps every row to a new DEK but leaves
// dek.epoch naming the old one, so replicas holding the new key set refuse to
// start while replicas still holding the old key set start and write rows
// under the retired DEK.
//
// The database therefore records the newest rotation protocol any binary that
// served or rotated it implements: system_metadata[dekRotationProtocolKey], an
// integer only ever raised (StartDEKEpochGuard on PostgreSQL, and every
// rotation's sweep transaction on any database). RotateDEKWithSweep refuses
// when the recorded protocol is newer than its own (or unreadable), before it
// writes a key file or a row.
//
// Bump dekRotationProtocol whenever a change to the rotation (sweep, fence,
// epoch, redo marker, key-file promotion) would be unsafe if an older binary
// rotated a database a newer one serves. The protocols so far:
//
//	1 (implicit, no marker): rotation without the DEK epoch (v0.96.x and older).
//	2: DEK epoch fence and compare-and-set (#3337), pre-commit decrypt check.
//
// Not covered: binaries that predate this file never read the marker, so this
// cannot stop a v0.96.x (protocol 1) admin binary; for those the rule "never
// rotate with an older admin binary than the servers" is documented in
// docs/operator/key-rotation-runbook.md.
package encryption

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// dekRotationProtocolKey is the system_metadata key of the recorded rotation
// protocol. Not secret.
const dekRotationProtocolKey = "dek.rotation_protocol"

// dekRotationProtocol is the rotation protocol this binary implements. See the
// file comment before changing it.
const dekRotationProtocol = 2

// ErrRotationProtocolTooOld refuses a rotation by a binary whose rotation
// protocol is older than the one the database records.
var ErrRotationProtocolTooOld = errors.New("this binary's DEK rotation is older than the one this database's servers use")

// recordDEKRotationProtocol raises the recorded protocol to this binary's; it
// never lowers it (the comparison is in SQL, as in the schema epoch).
func recordDEKRotationProtocol(db *gorm.DB) error {
	keepHigher := gorm.Expr("CASE WHEN CAST(system_metadata.value AS INTEGER) >= CAST(excluded.value AS INTEGER) " +
		"THEN system_metadata.value ELSE excluded.value END")
	if err := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.Assignments(map[string]any{"value": keepHigher, "updated_at": time.Now().UTC()}),
	}).Create(&models.SystemMetadata{Key: dekRotationProtocolKey, Value: strconv.Itoa(dekRotationProtocol), UpdatedAt: time.Now().UTC()}).Error; err != nil {
		return fmt.Errorf("record DEK rotation protocol: %w", err)
	}
	return nil
}

// refuseNewerRotationProtocol fails when the database records a rotation
// protocol newer than this binary's, or one that does not parse (fail closed).
func refuseNewerRotationProtocol(db *gorm.DB) error {
	var rows []models.SystemMetadata
	if err := db.Where("key = ?", dekRotationProtocolKey).Limit(1).Find(&rows).Error; err != nil {
		return fmt.Errorf("read the recorded DEK rotation protocol: %w", err)
	}
	if len(rows) == 0 {
		return nil
	}
	recorded, err := strconv.Atoi(rows[0].Value)
	if err != nil {
		return fmt.Errorf("%w: the recorded DEK rotation protocol %q is not an integer; refusing to rotate rather than guess", ErrRotationProtocolTooOld, rows[0].Value)
	}
	if recorded > dekRotationProtocol {
		return fmt.Errorf("%w: this database records DEK rotation protocol %d (written by a newer Keyorix server or admin command), this binary implements %d. "+
			"Rotating with it could leave the database in a state the newer servers refuse or misread. Run `admin encryption rotate` with the same version as the servers, never an older admin image",
			ErrRotationProtocolTooOld, recorded, dekRotationProtocol)
	}
	return nil
}
