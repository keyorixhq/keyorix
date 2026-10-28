package encryption

// dek_created_at_postgres_test.go: dek.created_at (dek_created_at.go) on real
// PostgreSQL. Skips when KEYORIX_TEST_PG_DSN is unset (pg-gated).

import (
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

func recordedCreatedAt(t *testing.T, db *gorm.DB) (time.Time, bool) {
	t.Helper()
	epoch, _ := epochValue(t, db)
	var rows []models.SystemMetadata
	if err := db.Where("key = ?", dekCreatedAtKey).Limit(1).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		return time.Time{}, false
	}
	return DEKCreatedAt(epoch, rows[0].Value)
}

// Seeding the epoch dates the DEK; a rotation re-dates it to the new DEK.
func TestDEKCreatedAt_Postgres_SeedAndRotation(t *testing.T) {
	db := epochPGDB(t)
	_, _, a, b, _ := epochReplicas(t, db)
	before := time.Now().UTC().Add(-time.Second)
	if err := b.StartDEKEpochGuard(db, nil); err != nil {
		t.Fatal(err)
	}
	seeded, ok := recordedCreatedAt(t, db)
	if !ok || seeded.Before(before) {
		t.Fatalf("after seeding: created_at = %v, %v; want a time after %v", seeded, ok, before)
	}
	if _, err := a.RotateDEKWithSweep(epochPass, db); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	rotated, ok := recordedCreatedAt(t, db)
	if !ok || !rotated.After(seeded) {
		t.Fatalf("after rotation: created_at = %v, %v; want the new DEK dated after %v", rotated, ok, seeded)
	}
}

// Review finding (#3754): lifting a failed rotation's fence rewrites the epoch
// row (and its updated_at) with the old DEK; the old DEK's recorded time must not
// move.
func TestDEKCreatedAt_Postgres_FailedRotationKeepsTheOldDEKsTime(t *testing.T) {
	db := epochPGDB(t)
	_, _, a, b, node := epochReplicas(t, db)
	if err := b.StartDEKEpochGuard(db, nil); err != nil {
		t.Fatal(err)
	}
	seeded, ok := recordedCreatedAt(t, db)
	if !ok {
		t.Fatal("no created_at after seeding")
	}
	if err := db.Create(&models.SecretVersion{SecretNodeID: node.ID, VersionNumber: 99, EncryptedValue: []byte(`{"ciphertext":"AA==","nonce":"AAAAAAAAAAAAAAAA","metadata":{"algorithm":"AES-256-GCM","aad_version":"v2"}}`), EncryptionMetadata: models.JSON(`{"algorithm":"AES-256-GCM"}`)}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := a.RotateDEKWithSweep(epochPass, db); err == nil {
		t.Fatal("rotation over an undecryptable row succeeded")
	}
	if v, _ := epochValue(t, db); v != fingerprintOf(t, b) {
		t.Fatalf("epoch after the failed rotation = %q, want the old fingerprint", v)
	}
	got, ok := recordedCreatedAt(t, db)
	if !ok || !got.Equal(seeded) {
		t.Fatalf("after the failed rotation: created_at = %v, %v; want the seed time %v unchanged", got, ok, seeded)
	}
}

// The startup lift of an interrupted rotation's fence keeps the old DEK's time.
func TestDEKCreatedAt_Postgres_StartupLiftKeepsTheOldDEKsTime(t *testing.T) {
	db := epochPGDB(t)
	_, _, _, b, _ := epochReplicas(t, db)
	own := fingerprintOf(t, b)
	old := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
	if err := recordDEKCreatedAt(db, own, old); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.SystemMetadata{Key: dekEpochKey, Value: dekEpochRotatingPrefix + own}).Error; err != nil {
		t.Fatal(err)
	}
	if err := b.StartDEKEpochGuard(db, nil); err != nil {
		t.Fatalf("start over a stale fence: %v", err)
	}
	got, ok := recordedCreatedAt(t, db)
	if !ok || !got.Equal(old) {
		t.Fatalf("after the startup lift: created_at = %v, %v; want %v", got, ok, old)
	}
}
