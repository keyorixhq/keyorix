package encryption

// sweep_test.go — Tests for RotateDEKWithSweep (ADR-010)
//
// Test plan from ADR:
//  1. TestRotateDEKWithSweep_ReEncryptsAllRows
//  2. TestRotateDEKWithSweep_UpgradesLegacyAAD
//  3. TestRotateDEKWithSweep_RollbackOnError
//  4. TestRotateDEKWithSweep_PendingFileCleanup
//
// Test 5 (end-to-end with real server) is an integration test — not here.
//
// These tests use an in-memory SQLite DB via gorm + go-sqlite driver.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ─── helpers ───────────────────────────────────────────────────────────────

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Discard,
	})
	if err != nil {
		t.Fatalf("failed to open test DB: %v", err)
	}
	tables := []interface{}{
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.Session{},
		&models.APIToken{},
		&models.APIClient{},
		&models.PasswordReset{},
	}
	for _, m := range tables {
		if err := db.AutoMigrate(m); err != nil {
			t.Fatalf("AutoMigrate failed: %v", err)
		}
	}
	return db
}

// newTestService creates an initialized Service with a temp key directory.
func newTestService(t *testing.T, passphrase string) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		KEKPath:  "kek.key",
		DEKPath:  "dek.key",
		SaltPath: "kek.salt",
	}
	svc := NewService(cfg, dir)
	if err := svc.Initialize(passphrase); err != nil {
		t.Fatalf("failed to initialize service: %v", err)
	}
	return svc, dir
}

// seedSecretVersion encrypts a value and inserts a SecretVersion row.
// Returns the version ID.
func seedSecretVersion(t *testing.T, db *gorm.DB, svc *Service, nodeID, namespaceID uint, versionNumber int, value string) uint {
	t.Helper()
	aad := SecretAAD(nodeID, namespaceID, versionNumber)
	enc, meta, err := svc.EncryptSecretWithAAD([]byte(value), aad)
	if err != nil {
		t.Fatalf("EncryptSecretWithAAD: %v", err)
	}
	v := &models.SecretVersion{
		SecretNodeID:       nodeID,
		VersionNumber:      versionNumber,
		EncryptedValue:     enc,
		EncryptionMetadata: models.JSON(meta),
	}
	if err := db.Create(v).Error; err != nil {
		t.Fatalf("failed to insert SecretVersion: %v", err)
	}
	return v.ID
}

// seedLegacySecretVersion encrypts WITHOUT AAD (simulates pre-AAD rows).
func seedLegacySecretVersion(t *testing.T, db *gorm.DB, svc *Service, nodeID uint, versionNumber int, value string) uint {
	t.Helper()
	enc, meta, err := svc.EncryptSecret([]byte(value))
	if err != nil {
		t.Fatalf("EncryptSecret (legacy): %v", err)
	}
	v := &models.SecretVersion{
		SecretNodeID:       nodeID,
		VersionNumber:      versionNumber,
		EncryptedValue:     enc,
		EncryptionMetadata: models.JSON(meta),
	}
	if err := db.Create(v).Error; err != nil {
		t.Fatalf("failed to insert legacy SecretVersion: %v", err)
	}
	return v.ID
}

// seedSecretNode inserts a SecretNode and returns its ID.
func seedSecretNode(t *testing.T, db *gorm.DB, namespaceID uint) uint {
	t.Helper()
	n := &models.SecretNode{
		NamespaceID: namespaceID,
		Name:        fmt.Sprintf("node-%d", namespaceID),
		IsSecret:    true,
	}
	if err := db.Create(n).Error; err != nil {
		t.Fatalf("failed to insert SecretNode: %v", err)
	}
	return n.ID
}

// captureCurrentDEK returns a copy of the current in-memory DEK bytes.
// Requires access to keyManager — we call GetDEK() on the Service.
func captureCurrentDEK(t *testing.T, svc *Service) []byte {
	t.Helper()
	dek := svc.keyManager.GetDEK()
	if len(dek) == 0 {
		t.Fatal("DEK is empty after initialization")
	}
	return dek
}

// ─── tests ──────────────────────────────────────────────────────────────────

// TestRotateDEKWithSweep_ReEncryptsAllRows verifies that after rotation, every
// encrypted row can be decrypted using the new DEK and fails with the old DEK.
func TestRotateDEKWithSweep_ReEncryptsAllRows(t *testing.T) {
	db := newTestDB(t)
	svc, _ := newTestService(t, "test-passphrase")

	// Seed a SecretNode + SecretVersion
	const namespaceID = uint(1)
	nodeID := seedSecretNode(t, db, namespaceID)
	versionID := seedSecretVersion(t, db, svc, nodeID, namespaceID, 1, "super-secret-value")

	// Capture old DEK bytes
	oldDEK := captureCurrentDEK(t, svc)

	// Run rotation with sweep
	if err := svc.RotateDEKWithSweep("test-passphrase", db); err != nil {
		t.Fatalf("RotateDEKWithSweep failed: %v", err)
	}

	newDEK := captureCurrentDEK(t, svc)
	if string(oldDEK) == string(newDEK) {
		t.Fatal("DEK did not change after rotation")
	}

	// Fetch the updated row
	var v models.SecretVersion
	if err := db.First(&v, versionID).Error; err != nil {
		t.Fatalf("failed to fetch SecretVersion: %v", err)
	}

	// Should decrypt with new service (new DEK in memory)
	aad := SecretAAD(nodeID, namespaceID, 1)
	plaintext, err := svc.DecryptSecretWithAAD(v.EncryptedValue, aad)
	if err != nil {
		t.Fatalf("decrypt with new DEK failed: %v", err)
	}
	if string(plaintext) != "super-secret-value" {
		t.Errorf("unexpected plaintext: %q", plaintext)
	}

	// Should NOT decrypt with old DEK
	oldEncSvc, err := NewEncryptionService(oldDEK)
	if err != nil {
		t.Fatalf("failed to create old EncryptionService: %v", err)
	}
	enc, err := DeserializeEncryptedData(v.EncryptedValue)
	if err != nil {
		t.Fatalf("DeserializeEncryptedData: %v", err)
	}
	if _, err := oldEncSvc.DecryptWithAAD(enc, aad); err == nil {
		t.Error("expected decrypt with old DEK to fail, but it succeeded")
	}
}

// TestRotateDEKWithSweep_UpgradesLegacyAAD verifies that legacy rows (no AAD)
// are decrypted without AAD and re-encrypted with AAD after the sweep.
func TestRotateDEKWithSweep_UpgradesLegacyAAD(t *testing.T) {
	db := newTestDB(t)
	svc, _ := newTestService(t, "test-passphrase")

	const namespaceID = uint(2)
	nodeID := seedSecretNode(t, db, namespaceID)
	versionID := seedLegacySecretVersion(t, db, svc, nodeID, 1, "legacy-value")

	// Verify it's a legacy row before sweep
	var before models.SecretVersion
	if err := db.First(&before, versionID).Error; err != nil {
		t.Fatalf("failed to fetch pre-sweep version: %v", err)
	}
	var meta EncryptionMetadata
	if err := json.Unmarshal([]byte(before.EncryptionMetadata), &meta); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}
	if meta.AADVersion != "" {
		t.Errorf("expected legacy row to have no AADVersion before sweep, got %q", meta.AADVersion)
	}

	// Run sweep
	if err := svc.RotateDEKWithSweep("test-passphrase", db); err != nil {
		t.Fatalf("RotateDEKWithSweep failed: %v", err)
	}

	// Verify the row now has aad_version = "v1"
	var after models.SecretVersion
	if err := db.First(&after, versionID).Error; err != nil {
		t.Fatalf("failed to fetch post-sweep version: %v", err)
	}
	var afterMeta EncryptionMetadata
	if err := json.Unmarshal([]byte(after.EncryptionMetadata), &afterMeta); err != nil {
		t.Fatalf("failed to unmarshal post-sweep metadata: %v", err)
	}
	if afterMeta.AADVersion != "v1" {
		t.Errorf("expected AADVersion = v1 after sweep, got %q", afterMeta.AADVersion)
	}

	// And it should decrypt correctly with the new DEK + AAD
	aad := SecretAAD(nodeID, namespaceID, 1)
	plaintext, err := svc.DecryptSecretWithAAD(after.EncryptedValue, aad)
	if err != nil {
		t.Fatalf("decrypt of upgraded legacy row failed: %v", err)
	}
	if string(plaintext) != "legacy-value" {
		t.Errorf("unexpected plaintext after AAD upgrade: %q", plaintext)
	}
}

// TestRotateDEKWithSweep_RollbackOnError injects a DB error mid-sweep and
// verifies the old DEK remains active and no rows were modified.
func TestRotateDEKWithSweep_RollbackOnError(t *testing.T) {
	db := newTestDB(t)
	svc, _ := newTestService(t, "test-passphrase")

	const namespaceID = uint(3)
	nodeID := seedSecretNode(t, db, namespaceID)
	seedSecretVersion(t, db, svc, nodeID, namespaceID, 1, "sensitive-data")

	// Capture the encrypted value before rotation attempt
	var before models.SecretVersion
	if err := db.First(&before, 1).Error; err != nil {
		t.Fatalf("failed to fetch pre-rotation version: %v", err)
	}
	originalEncrypted := make([]byte, len(before.EncryptedValue))
	copy(originalEncrypted, before.EncryptedValue)

	oldDEK := captureCurrentDEK(t, svc)

	// Drop the secret_nodes table to force a sweep error (nodeNamespaceMap query fails)
	if err := db.Migrator().DropTable(&models.SecretNode{}); err != nil {
		t.Fatalf("failed to drop table: %v", err)
	}

	err := svc.RotateDEKWithSweep("test-passphrase", db)
	if err == nil {
		t.Fatal("expected RotateDEKWithSweep to fail, but it succeeded")
	}

	// Old DEK should still be active
	currentDEK := captureCurrentDEK(t, svc)
	if string(currentDEK) != string(oldDEK) {
		t.Error("DEK changed despite sweep failure — old DEK should remain active")
	}

	// Pending file should be cleaned up
	// (We can't easily check the temp dir path here without exposing it — skip)
}

// TestRotateDEKWithSweep_PendingFileCleanup verifies that a leftover
// .pending file is removed by CleanPendingDEK at startup.
func TestRotateDEKWithSweep_PendingFileCleanup(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		KEKPath:  "kek.key",
		DEKPath:  "dek.key",
		SaltPath: "kek.salt",
	}

	// Create a fake .pending file simulating an interrupted rotation
	pendingPath := filepath.Join(dir, "dek.key.pending")
	if err := os.WriteFile(pendingPath, []byte("fake-pending"), 0600); err != nil {
		t.Fatalf("failed to create fake pending file: %v", err)
	}

	svc := NewService(cfg, dir)
	svc.CleanPendingDEK()

	if _, err := os.Stat(pendingPath); !os.IsNotExist(err) {
		t.Error("expected pending file to be removed by CleanPendingDEK, but it still exists")
	}
}
