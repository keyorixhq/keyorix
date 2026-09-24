package main

// admin_encryption_integration_postgres_test.go covers the same `keyorix-server
// admin encryption` workflow as admin_encryption_integration_test.go's
// TestAdminEncryptionWorkflow_SQLite, but against a real PostgreSQL backend --
// gated on KEYORIX_TEST_PG_DSN (see admin_integration_postgres_test.go's own
// header for the convention). Skips (not fails) when unset.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func encryptionPostgresYAML(dir, dsn string) error {
	content := fmt.Sprintf(`storage:
  type: postgres
  database:
    dsn: %q
  encryption:
    enabled: true
    dek_path: keys/dek.key
    salt_path: keys/kek.salt
server:
  http:
    enabled: true
    port: "8090"
  grpc:
    enabled: false
`, dsn)
	return os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(content), 0600)
}

func openTestSecretsDBPostgres(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open postgres secrets db directly: %v", err)
	}
	if err := db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}); err != nil {
		t.Fatalf("automigrate secret tables: %v", err)
	}
	return db
}

func seedProbeSecretPostgres(t *testing.T, dir, dsn, passphrase, plaintext string) (db *gorm.DB, versionID uint, aad []byte) {
	t.Helper()
	db = openTestSecretsDBPostgres(t, dsn)
	node := &models.SecretNode{ProjectID: 1, Name: "probe-node-pg", IsSecret: true}
	if err := db.Create(node).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}
	svc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "keys/dek.key", SaltPath: "keys/kek.salt"}, dir)
	if err := svc.Initialize(passphrase); err != nil {
		t.Fatalf("seed service Initialize: %v", err)
	}
	defer svc.Shutdown()
	aad = encryption.SecretAAD(node.ID, node.ProjectID, 1)
	enc, meta, err := svc.EncryptSecretWithAAD([]byte(plaintext), aad)
	if err != nil {
		t.Fatalf("seed EncryptSecretWithAAD: %v", err)
	}
	v := &models.SecretVersion{SecretNodeID: node.ID, VersionNumber: 1, EncryptedValue: enc, EncryptionMetadata: models.JSON(meta)}
	if err := db.Create(v).Error; err != nil {
		t.Fatalf("seed SecretVersion: %v", err)
	}
	return db, v.ID, aad
}

func decryptProbeSecretPostgres(t *testing.T, dir, passphrase string, db *gorm.DB, versionID uint, aad []byte) (string, error) {
	t.Helper()
	var v models.SecretVersion
	if err := db.First(&v, versionID).Error; err != nil {
		t.Fatalf("fetch probe row: %v", err)
	}
	svc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "keys/dek.key", SaltPath: "keys/kek.salt"}, dir)
	if err := svc.Initialize(passphrase); err != nil {
		return "", fmt.Errorf("Initialize: %w", err)
	}
	defer svc.Shutdown()
	pt, err := svc.DecryptSecretWithAAD(v.EncryptedValue, aad)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// TestAdminEncryptionWorkflow_Postgres mirrors TestAdminEncryptionWorkflow_SQLite's
// happy path (init through auth-encryption rotate) against a real, isolated
// Postgres database, confirming the encryption family's admin commands work
// identically regardless of storage backend.
func TestAdminEncryptionWorkflow_Postgres(t *testing.T) {
	base := adminPgTestDSN(t)
	dsn := adminPgIsolatedDatabaseDSN(t, base)

	bin := buildServerBinary(t)
	dir := t.TempDir()
	const passphrase = "test-passphrase-enc-postgres"
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+passphrase)

	if err := encryptionPostgresYAML(dir, dsn); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0750); err != nil {
		t.Fatalf("mkdir keys: %v", err)
	}

	// encryption init unconditionally treats storage.database.path as a local
	// SQLite file to create (a pre-existing gap in the ported-near-verbatim
	// logic, same one admin_integration_postgres_test.go's TestAdminWorkflow_Postgres
	// works around) -- derive the KEK directly via `status`, which triggers
	// the same first-boot key generation without touching storage.database.path.
	out, err := runAdmin(t, bin, dir, env, "encryption", "status", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption status (first-boot key derivation) failed: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "keys", "dek.key")); statErr != nil {
		t.Fatalf("expected dek.key to be created by status's first-boot derivation: %v", statErr)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "validate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption validate failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Encryption setup is valid") {
		t.Errorf("expected validate to pass, got:\n%s", out)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "fix-perms", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption fix-perms failed: %v\n%s", err, out)
	}

	db, versionID, aad := seedProbeSecretPostgres(t, dir, dsn, passphrase, "rotate-me-probe-value-pg")

	out, err = runAdmin(t, bin, dir, env, "encryption", "rotate", "--dry-run", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption rotate --dry-run failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "no changes were made") {
		t.Errorf("expected dry-run to report no changes, got:\n%s", out)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "rotate", "--confirm", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption rotate --confirm failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "DEK rotated successfully") {
		t.Errorf("expected rotate to report success, got:\n%s", out)
	}
	got, derr := decryptProbeSecretPostgres(t, dir, passphrase, db, versionID, aad)
	if derr != nil {
		t.Fatalf("DATA LOSS: probe secret unreadable after rotate (postgres): %v", derr)
	}
	if got != "rotate-me-probe-value-pg" {
		t.Fatalf("VALUE CORRUPTION: probe secret changed after rotate (postgres): got %q", got)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "upgrade-aad", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption upgrade-aad failed: %v\n%s", err, out)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "auth-encryption", "status", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("auth-encryption status failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Authentication Encryption Status") {
		t.Errorf("expected auth-encryption status header, got:\n%s", out)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "auth-encryption", "enable", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("auth-encryption enable failed: %v\n%s", err, out)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "auth-encryption", "migrate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("auth-encryption migrate failed: %v\n%s", err, out)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "auth-encryption", "validate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("auth-encryption validate failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "validation checks passed") {
		t.Errorf("expected auth-encryption validate to pass, got:\n%s", out)
	}

	// auth-encryption rotate (S13's fix point) must still preserve the probe
	// secret against the Postgres backend too.
	out, err = runAdmin(t, bin, dir, env, "encryption", "auth-encryption", "rotate", "--confirm", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("auth-encryption rotate failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "rotation completed successfully") {
		t.Errorf("expected auth-encryption rotate to report success, got:\n%s", out)
	}
	got, derr = decryptProbeSecretPostgres(t, dir, passphrase, db, versionID, aad)
	if derr != nil || got != "rotate-me-probe-value-pg" {
		t.Fatalf("probe secret unreadable or changed after auth-encryption rotate (postgres): got=%q err=%v", got, derr)
	}
}

// TestAdminEncryptionRotate_RefusedWhileExclusiveLockHeld_Postgres is the
// Postgres counterpart of the SQLite lock-guard regression test.
func TestAdminEncryptionRotate_RefusedWhileExclusiveLockHeld_Postgres(t *testing.T) {
	base := adminPgTestDSN(t)
	dsn := adminPgIsolatedDatabaseDSN(t, base)

	bin := buildServerBinary(t)
	dir := t.TempDir()
	const passphrase = "test-passphrase-enc-lock-postgres"
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+passphrase)

	if err := encryptionPostgresYAML(dir, dsn); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0750); err != nil {
		t.Fatalf("mkdir keys: %v", err)
	}
	if out, err := runAdmin(t, bin, dir, env, "encryption", "status", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("encryption status (key derivation) failed: %v\n%s", err, out)
	}

	hook := startLockHolderHook(t, bin, dir, env)
	defer hook.release(t)

	out, err := runAdmin(t, bin, dir, env, "encryption", "rotate", "--confirm", "--config", "./keyorix.yaml")
	if err == nil || !strings.Contains(out, "admin commands must not run concurrently") {
		t.Fatalf("expected encryption rotate to refuse while the exclusive lock is held, got (err=%v):\n%s", err, out)
	}
}
