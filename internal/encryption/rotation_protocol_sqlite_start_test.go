package encryption

import (
	"errors"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
)

// KEY-ROTATION-TAILS-NOV-1 item 3: a SQLite server start records the rotation
// protocol (StartDEKEpochGuard), as a PostgreSQL one does, without starting
// the epoch guard; it never lowers a newer recorded value, and a database it
// served refuses a rotation by an older binary.
func TestStartDEKEpochGuard_SQLiteRecordsRotationProtocol(t *testing.T) {
	db := fuzzworld.OpenSQLite(t, "file:"+filepath.Join(t.TempDir(), "p.db"), 1)
	fuzzworld.Bootstrap(t, db)
	svc := newEpochTestService(t, t.TempDir())
	defer svc.Shutdown()

	if got := recordedRotationProtocol(t, db); got != "" {
		t.Fatalf("fixture already records protocol %q", got)
	}
	released := false
	if err := svc.StartDEKEpochGuard(db, func() { released = true }); err != nil {
		t.Fatalf("StartDEKEpochGuard on SQLite: %v", err)
	}
	if got, want := recordedRotationProtocol(t, db), strconv.Itoa(dekRotationProtocol); got != want {
		t.Fatalf("recorded protocol after a SQLite start = %q, want %s", got, want)
	}
	if svc.DEKEpochGuardRunning() || released {
		t.Fatalf("guard running=%v released=%v on SQLite, want neither", svc.DEKEpochGuardRunning(), released)
	}
	if v, found := epochValue(t, db); found {
		t.Fatalf("a SQLite start wrote a DEK epoch %q", v)
	}

	newer := strconv.Itoa(dekRotationProtocol + 1)
	if err := db.Model(&models.SystemMetadata{}).Where("key = ?", dekRotationProtocolKey).Update("value", newer).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.StartDEKEpochGuard(db, nil); err != nil {
		t.Fatalf("second StartDEKEpochGuard on SQLite: %v", err)
	}
	if got := recordedRotationProtocol(t, db); got != newer {
		t.Fatalf("a SQLite start lowered the recorded protocol from %s to %q", newer, got)
	}
	if _, err := svc.RotateDEKWithSweep("epoch-test-passphrase", db); !errors.Is(err, ErrRotationProtocolTooOld) {
		t.Fatalf("rotation by a binary older than the recorded protocol: want ErrRotationProtocolTooOld, got %v", err)
	}
}

func TestCheckRecordedRotationProtocol(t *testing.T) {
	for _, c := range []struct {
		value  string
		refuse bool
	}{
		{strconv.Itoa(dekRotationProtocol), false},
		{strconv.Itoa(dekRotationProtocol - 1), false},
		{strconv.Itoa(dekRotationProtocol + 1), true},
		{"not-a-number", true},
	} {
		err := CheckRecordedRotationProtocol(c.value, "restore over it", "admin restore")
		if c.refuse != errors.Is(err, ErrRotationProtocolTooOld) || (!c.refuse && err != nil) {
			t.Errorf("CheckRecordedRotationProtocol(%q) = %v, want refuse=%v", c.value, err, c.refuse)
		}
	}
}
