package encryption

import (
	"errors"
	"strconv"
	"testing"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func recordedRotationProtocol(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var rows []models.SystemMetadata
	if err := db.Where("key = ?", dekRotationProtocolKey).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		return ""
	}
	return rows[0].Value
}

// A completed rotation records its protocol, and recording never lowers a
// newer one already there.
func TestRotationProtocol_RecordedByRotationAndNeverLowered(t *testing.T) {
	db := newTestDB(t)
	svc, _ := newTestService(t, "rotation-protocol")
	defer svc.Shutdown()
	if _, err := svc.RotateDEKWithSweep("rotation-protocol", db); err != nil {
		t.Fatal(err)
	}
	if got, want := recordedRotationProtocol(t, db), strconv.Itoa(dekRotationProtocol); got != want {
		t.Fatalf("recorded protocol after a rotation = %q, want %q", got, want)
	}
	higher := strconv.Itoa(dekRotationProtocol + 1)
	if err := db.Model(&models.SystemMetadata{}).Where("key = ?", dekRotationProtocolKey).Update("value", higher).Error; err != nil {
		t.Fatal(err)
	}
	if err := recordDEKRotationProtocol(db); err != nil {
		t.Fatal(err)
	}
	if got := recordedRotationProtocol(t, db); got != higher {
		t.Fatalf("recording lowered the protocol from %s to %s", higher, got)
	}
	if err := refuseNewerRotationProtocol(db); !errors.Is(err, ErrRotationProtocolTooOld) {
		t.Fatalf("want ErrRotationProtocolTooOld, got %v", err)
	}
}

// No record (a database last served by a binary that predates the marker) and
// an equal record both allow the rotation.
func TestRotationProtocol_AbsentOrEqualAllows(t *testing.T) {
	db := newTestDB(t)
	if err := refuseNewerRotationProtocol(db); err != nil {
		t.Fatalf("no record: %v", err)
	}
	if err := recordDEKRotationProtocol(db); err != nil {
		t.Fatal(err)
	}
	if err := refuseNewerRotationProtocol(db); err != nil {
		t.Fatalf("equal record: %v", err)
	}
}
