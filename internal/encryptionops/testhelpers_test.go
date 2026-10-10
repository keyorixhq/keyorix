// testhelpers_test.go — shared fixtures for this package's tests: a chdir'd
// temp dir (every *WithConfig function here resolves DEKPath/SaltPath/the
// sqlite DB path against os.Getwd(), not an injected baseDir), a *gorm.DB
// with every table the DEK-rotation sweep and auth-encryption migration
// touch, and stdout capture for asserting the no-secret-leakage property.
package encryptionops

import (
	"io"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

const (
	testBaselinePassphrase = "encops-test-baseline-passphrase-123"
	testNewPassphrase      = "encops-test-NEW-passphrase-456"
	testWrongPassphrase    = "encops-test-WRONG-passphrase-789"
	testDBFile             = "keyorix-test.db"
)

// chdirTemp creates a fresh temp dir and chdirs into it, restoring the
// original working directory when the test ends.
func chdirTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("os.Chdir(%s): %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
	return dir
}

// testConfig builds a minimal local-storage config with encryption enabled
// (unless encEnabled is false), dek.key/kek.salt as relative paths (resolved
// against the chdir'd cwd by every function under test).
func testConfig(encEnabled bool) *config.Config {
	return &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: testDBFile},
			Encryption: config.EncryptionConfig{
				Enabled:  encEnabled,
				DEKPath:  "dek.key",
				SaltPath: "kek.salt",
			},
		},
	}
}

// migrateEncOpsTables opens dbPath and creates every table the DEK-rotation
// sweep (RotateDEKWithSweep/PreviewRotationSweep/UpgradeAuthAAD) and the
// auth-encryption migration touch. The caller must close the returned DB.
func migrateEncOpsTables(t *testing.T, dbPath string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: gormlogger.Discard})
	if err != nil {
		t.Fatalf("gorm.Open(%s): %v", dbPath, err)
	}
	if err := db.AutoMigrate(
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.APIToken{},
		&models.APIClient{},
		&models.PasswordReset{},
		&models.MFASecret{},
		&models.DynamicSecretConfig{},
		&models.DynamicSecretLease{},
		&models.NotificationChannel{},
		&models.SystemMetadata{},
	); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	return db
}

func closeTestDB(db *gorm.DB) {
	if db == nil {
		return
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}

// zeroPassSrc is a PassphraseSource with every field unset, so
// ResolvePassphrase falls back to the env var — the same minimal-ceremony
// path server/admin/fuzz_encryption_command_fault_test.go uses.
func zeroPassSrc() crypto.PassphraseSource { return crypto.PassphraseSource{} }

func setPassphraseEnv(t *testing.T, value string) {
	t.Helper()
	t.Setenv(MasterPassphraseEnvVar, value)
}

func setNewPassphraseEnv(t *testing.T, value string) {
	t.Helper()
	t.Setenv(NewMasterPassphraseEnvVar, value)
}

// captureOutput redirects os.Stdout for fn's duration and returns everything
// written to it plus fn's own return value. Not safe under t.Parallel (global
// process state) — nothing in this package's tests uses it in parallel.
func captureOutput(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	runErr := fn()
	os.Stdout = orig
	_ = w.Close()
	data, _ := io.ReadAll(r)
	_ = r.Close()
	return string(data), runErr
}

// fileMode returns the permission bits of path, failing the test if it
// cannot be stat'd.
func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}
