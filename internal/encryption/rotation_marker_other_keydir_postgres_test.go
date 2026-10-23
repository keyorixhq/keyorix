package encryption

// rotation_marker_other_keydir_postgres_test.go (HA-SECRET-KEYS-1): with several
// key directories on one PostgreSQL database (key_dir_lock: database, the Helm
// chart's Secret mode, per-host key copies), the DEK-rotation redo marker is
// global but dek.key.pending lives in ONE directory: the one the rotation ran
// in. Recovery in any other directory must leave the marker alone, or the
// rotating directory's next recovery discards the only copy of the new DEK.
// Skips when KEYORIX_TEST_PG_DSN is unset (pg-gated).

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

func redoMarkerPresent(t *testing.T, db *gorm.DB) bool {
	t.Helper()
	var n int64
	if err := db.Model(&models.SystemMetadata{}).Where("key = ?", dekRotationPromotePendingKey).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// bootLike runs the server's key start-up order on dir: rotation crash
// recovery, Initialize, the DEK epoch guard.
func bootLike(t *testing.T, db *gorm.DB, dir string) (*Service, error) {
	t.Helper()
	svc := NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "keys/dek.key", SaltPath: "keys/kek.salt", KeyDirLock: config.KeyDirLockDatabase}, dir)
	if err := svc.RecoverInterruptedRotation(db); err != nil {
		return nil, err
	}
	if err := svc.Initialize(epochPass); err != nil {
		return nil, err
	}
	if err := svc.StartDEKEpochGuard(db, nil); err != nil {
		svc.Shutdown()
		return nil, err
	}
	t.Cleanup(svc.Shutdown)
	return svc, nil
}

// interruptedRotationIn rotates in dirA, then puts dirA and the database into
// the state a crash between the sweep commit and the pending -> active rename
// leaves: rows and epoch under the new DEK, the redo marker committed,
// dek.key.pending the only copy of the new DEK.
func interruptedRotationIn(t *testing.T, db *gorm.DB, dirA string, a *Service) {
	t.Helper()
	active := filepath.Join(dirA, "keys", "dek.key")
	oldWrapped, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.RotateDEKWithSweep(epochPass, db); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	a.Shutdown()
	if err := os.Rename(active, active+".pending"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(active, oldWrapped, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.SystemMetadata{Key: dekRotationPromotePendingKey, Value: "v-interrupted"}).Error; err != nil {
		t.Fatal(err)
	}
}

// A replica with its own key directory starts while a rotation elsewhere is
// interrupted after its commit. It is refused (its DEK is stale), and it must
// not consume the redo marker: the rotating directory's recovery then still
// promotes its pending DEK and every row stays readable.
func TestDEKRotation_Postgres_RecoveryInAnotherKeyDirKeepsTheRedoMarker(t *testing.T) {
	db := epochPGDB(t)
	dirA, dirB, a, b, node := epochReplicas(t, db)
	b.Shutdown()
	for v := 1; v <= 3; v++ {
		if err := epochWrite(t, a, db, node, v); err != nil {
			t.Fatal(err)
		}
	}
	interruptedRotationIn(t, db, dirA, a)

	if _, err := bootLike(t, db, dirB); !errors.Is(err, ErrDEKEpochMismatch) {
		t.Fatalf("replica on the old key set: got %v, want ErrDEKEpochMismatch", err)
	}
	if !redoMarkerPresent(t, db) {
		t.Fatal("a replica whose key directory has no dek.key.pending removed the redo marker")
	}

	// The rotation's own directory (the admin workspace, or the host it ran on)
	// recovers: the pending DEK must be promoted, not discarded.
	recovered, err := bootLike(t, db, dirA)
	if err != nil {
		t.Fatalf("recovery in the rotating key directory: %v", err)
	}
	if bad := epochUndecryptable(t, recovered, db, node); len(bad) != 0 {
		t.Fatalf("versions %v are undecryptable after recovery: the new DEK was lost", bad)
	}
	if _, err := os.Stat(filepath.Join(dirA, "keys", "dek.key.pending")); !os.IsNotExist(err) {
		t.Fatalf("dek.key.pending still present after recovery: %v", err)
	}
	if redoMarkerPresent(t, db) {
		t.Fatal("redo marker left after the rotating directory finished the promotion")
	}
}

// A rotation that renamed its pending DEK but crashed before clearing the
// marker leaves the marker with no pending file anywhere. The next start in
// that directory proves its DEK is the database's current one (epoch) and
// clears the marker; a later rotation then starts from a clean state.
func TestDEKRotation_Postgres_CompletedRotationMarkerClearedOnceEpochMatches(t *testing.T) {
	db := epochPGDB(t)
	dirA, _, a, _, node := epochReplicas(t, db)
	if err := epochWrite(t, a, db, node, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RotateDEKWithSweep(epochPass, db); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	a.Shutdown()
	if err := db.Create(&models.SystemMetadata{Key: dekRotationPromotePendingKey, Value: "v-left-behind"}).Error; err != nil {
		t.Fatal(err)
	}
	svc, err := bootLike(t, db, dirA)
	if err != nil {
		t.Fatalf("start after a completed rotation: %v", err)
	}
	if redoMarkerPresent(t, db) {
		t.Fatal("the leftover redo marker of a completed rotation was not cleared once the epoch matched")
	}
	if bad := epochUndecryptable(t, svc, db, node); len(bad) != 0 {
		t.Fatalf("versions %v undecryptable", bad)
	}
}

// A leftover marker must not survive into the next rotation of a current key
// directory: had that rotation crashed after staging dek.key.pending but before
// its commit, recovery would have promoted the uncommitted DEK. Checked in the
// rotation's fence wait, when the pending DEK is already staged.
func TestDEKRotation_Postgres_RotationClearsALeftoverMarkerBeforeStaging(t *testing.T) {
	db := epochPGDB(t)
	dirA, _, a, _, node := epochReplicas(t, db)
	if err := epochWrite(t, a, db, node, 1); err != nil {
		t.Fatal(err)
	}
	if err := a.StartDEKEpochGuard(db, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.SystemMetadata{Key: dekRotationPromotePendingKey, Value: "v-left-behind"}).Error; err != nil {
		t.Fatal(err)
	}
	old := fingerprintOf(t, a)
	done := make(chan error, 1)
	go func() { _, err := a.RotateDEKWithSweep(epochPass, db); done <- err }()
	waitFor(t, "the rotation fence", func() bool { v, _ := epochValue(t, db); return v == dekEpochRotatingPrefix+old })
	if _, err := os.Stat(filepath.Join(dirA, "keys", "dek.key.pending")); err != nil {
		t.Fatalf("pending DEK not staged during the fence wait: %v", err)
	}
	if redoMarkerPresent(t, db) {
		t.Error("a leftover redo marker is still present while the rotation's uncommitted pending DEK is staged")
	}
	if err := <-done; err != nil {
		t.Fatalf("rotate: %v", err)
	}
}

// A rotation started from a key directory that is not the current one (a stale
// workspace) while another directory holds the interrupted rotation's pending
// DEK is refused, and does not remove that rotation's redo marker on its way.
func TestDEKRotation_Postgres_RotateFromStaleKeyDirKeepsTheRedoMarker(t *testing.T) {
	db := epochPGDB(t)
	dirA, dirB, a, b, node := epochReplicas(t, db)
	b.Shutdown()
	if err := epochWrite(t, a, db, node, 1); err != nil {
		t.Fatal(err)
	}
	interruptedRotationIn(t, db, dirA, a)

	stale := NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "keys/dek.key", SaltPath: "keys/kek.salt", KeyDirLock: config.KeyDirLockDatabase}, dirB)
	if err := stale.RecoverInterruptedRotation(db); err != nil {
		t.Fatal(err)
	}
	if err := stale.Initialize(epochPass); err != nil {
		t.Fatal(err)
	}
	defer stale.Shutdown()
	if _, err := stale.RotateDEKWithSweep(epochPass, db); !errors.Is(err, ErrDEKEpochMismatch) {
		t.Fatalf("rotate from the stale key directory: got %v, want ErrDEKEpochMismatch", err)
	}
	if !redoMarkerPresent(t, db) {
		t.Fatal("a rotation from a stale key directory removed another directory's redo marker")
	}
	recovered, err := bootLike(t, db, dirA)
	if err != nil {
		t.Fatalf("recovery in the rotating key directory: %v", err)
	}
	if bad := epochUndecryptable(t, recovered, db, node); len(bad) != 0 {
		t.Fatalf("versions %v undecryptable: the new DEK was lost", bad)
	}
}
