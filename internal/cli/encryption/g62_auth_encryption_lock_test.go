package encryption

// g62_auth_encryption_lock_test.go — regression tests for G62 member 3:
// auth-encryption status/enable/migrate/validate never took the cross-process
// key-lock the sibling DEK commands (status/validate/fix-perms/upgrade-aad,
// see local_key_lock_test.go) and the sibling encryption commands
// (migrate-provider, rotate) were deliberately built to require — letting a
// concurrent migrate-provider/rotate race them. `auth-encryption rotate` is
// deliberately NOT covered here: it delegates straight to
// Service.RotateDEKWithSweep, which already acquires the exclusive lock itself.
//
// Follows the exact structure of TestValidateWithConfig_RefusedWhileServerHoldsLock
// / TestValidateWithConfig_SucceedsWithNoServerOrRotationRunning in
// local_key_lock_test.go: a "server" Service acquires the exclusive dek.lock
// first, and the *WithConfig testable core under test must be refused while it
// holds it, then succeed once released.

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	enc "github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const authLockTestPassphrase = "auth-encryption-lock-test-passphrase-123"

// newAuthLockTestConfig builds a cfg pointing at workDir for both the key
// directory (AuthEncryption's baseDir is "." — the CLI always resolves it from
// cwd, so callers must t.Chdir(workDir) first) and a local sqlite database
// file, and sets KEYORIX_MASTER_PASSWORD so masterPassphrase() succeeds.
func newAuthLockTestConfig(t *testing.T, workDir string) *config.Config {
	t.Helper()
	t.Setenv("KEYORIX_MASTER_PASSWORD", authLockTestPassphrase)
	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(workDir, "secrets.db")
	cfg.Storage.Encryption = config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "kek.salt",
	}
	return cfg
}

// provisionAuthLockTestDB creates the sqlite file at cfg's configured path and
// migrates the tables migrate/validate query, mirroring an already-initialized
// production database. Opened and closed independently of the *WithConfig call
// under test, which opens its own connection via openDatabase(cfg).
func provisionAuthLockTestDB(t *testing.T, cfg *config.Config) {
	t.Helper()
	db, err := storage.OpenGormDB(cfg)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	if err := db.AutoMigrate(&models.APIClient{}, &models.Session{}, &models.APIToken{}, &models.PasswordReset{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}

// provisionAuthLockTestKeys generates the key material up front (mirrors
// `keyorix encryption init`/a prior `auth-encryption enable` run having
// already happened against this directory).
func provisionAuthLockTestKeys(t *testing.T, cfg *config.Config, workDir string) {
	t.Helper()
	setup := enc.NewService(&cfg.Storage.Encryption, workDir)
	if err := setup.Initialize(authLockTestPassphrase); err != nil {
		t.Fatalf("failed to provision key material: %v", err)
	}
	setup.Shutdown()
}

// acquireSimulatedServerLock starts a Service against workDir and has it take
// the exclusive dek.lock, simulating a live server (or an in-progress
// rotation/migrate-provider — all three hold the identical lock). Callers must
// defer the returned Service's Shutdown() to release it.
func acquireSimulatedServerLock(t *testing.T, cfg *config.Config, workDir string) *enc.Service {
	t.Helper()
	serverSvc := enc.NewService(&cfg.Storage.Encryption, workDir)
	if err := serverSvc.Initialize(authLockTestPassphrase); err != nil {
		t.Fatalf("failed to initialize simulated server: %v", err)
	}
	if err := serverSvc.AcquireExclusiveKeyLock(); err != nil {
		t.Fatalf("simulated server failed to acquire the exclusive key lock: %v", err)
	}
	return serverSvc
}

// ─── migrate ───────────────────────────────────────────────────────────────

// TestMigrateAuthDataWithConfig_RefusedWhileServerHoldsLock is the direct
// regression test for G62 member 3's detection idea: `auth-encryption migrate`
// must be refused, not silently proceed, while a live server (or an
// in-progress rotation/migrate-provider) holds the exclusive key lock.
func TestMigrateAuthDataWithConfig_RefusedWhileServerHoldsLock(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)
	cfg := newAuthLockTestConfig(t, workDir)
	provisionAuthLockTestDB(t, cfg)
	provisionAuthLockTestKeys(t, cfg, workDir)

	serverSvc := acquireSimulatedServerLock(t, cfg, workDir)
	defer serverSvc.Shutdown()

	err := migrateAuthDataWithConfig(cfg, false)
	if err == nil {
		t.Fatal("expected auth-encryption migrate to be refused while a live server holds the exclusive key lock")
	}
	if !strings.Contains(err.Error(), "exclusively") {
		t.Errorf("expected a clear, actionable error mentioning the exclusive holder, got: %v", err)
	}
}

// TestMigrateAuthDataWithConfig_SucceedsWithNoServerOrRotationRunning is the
// non-regression control: ordinary, single-invocation `auth-encryption
// migrate` usage (no server running, no rotation in progress) must not be
// broken by requiring a lock that's never actually contended in that case.
func TestMigrateAuthDataWithConfig_SucceedsWithNoServerOrRotationRunning(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)
	cfg := newAuthLockTestConfig(t, workDir)
	provisionAuthLockTestDB(t, cfg)
	provisionAuthLockTestKeys(t, cfg, workDir)

	if err := migrateAuthDataWithConfig(cfg, false); err != nil {
		t.Fatalf("expected auth-encryption migrate to succeed with no server/rotation running, got: %v", err)
	}
}

// ─── validate ──────────────────────────────────────────────────────────────

func TestValidateAuthEncryptionWithConfig_RefusedWhileServerHoldsLock(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)
	cfg := newAuthLockTestConfig(t, workDir)
	provisionAuthLockTestDB(t, cfg)
	provisionAuthLockTestKeys(t, cfg, workDir)

	serverSvc := acquireSimulatedServerLock(t, cfg, workDir)
	defer serverSvc.Shutdown()

	err := validateAuthEncryptionWithConfig(cfg, false)
	if err == nil {
		t.Fatal("expected auth-encryption validate to be refused while a live server holds the exclusive key lock")
	}
	if !strings.Contains(err.Error(), "exclusively") {
		t.Errorf("expected a clear, actionable error mentioning the exclusive holder, got: %v", err)
	}
}

func TestValidateAuthEncryptionWithConfig_SucceedsWithNoServerOrRotationRunning(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)
	cfg := newAuthLockTestConfig(t, workDir)
	provisionAuthLockTestDB(t, cfg)
	provisionAuthLockTestKeys(t, cfg, workDir)

	if err := validateAuthEncryptionWithConfig(cfg, false); err != nil {
		t.Fatalf("expected auth-encryption validate to succeed with no server/rotation running, got: %v", err)
	}
}

// ─── status ────────────────────────────────────────────────────────────────

func TestAuthStatusWithConfig_RefusedWhileServerHoldsLock(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)
	cfg := newAuthLockTestConfig(t, workDir)
	provisionAuthLockTestDB(t, cfg)
	provisionAuthLockTestKeys(t, cfg, workDir)

	serverSvc := acquireSimulatedServerLock(t, cfg, workDir)
	defer serverSvc.Shutdown()

	err := authStatusWithConfig(cfg)
	if err == nil {
		t.Fatal("expected auth-encryption status to be refused while a live server holds the exclusive key lock")
	}
	if !strings.Contains(err.Error(), "exclusively") {
		t.Errorf("expected a clear, actionable error mentioning the exclusive holder, got: %v", err)
	}
}

func TestAuthStatusWithConfig_SucceedsWithNoServerOrRotationRunning(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)
	cfg := newAuthLockTestConfig(t, workDir)
	provisionAuthLockTestDB(t, cfg)
	provisionAuthLockTestKeys(t, cfg, workDir)

	if err := authStatusWithConfig(cfg); err != nil {
		t.Fatalf("expected auth-encryption status to succeed with no server/rotation running, got: %v", err)
	}
}

// ─── enable ────────────────────────────────────────────────────────────────

func TestEnableAuthEncryptionWithConfig_RefusedWhileServerHoldsLock(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)
	cfg := newAuthLockTestConfig(t, workDir)
	provisionAuthLockTestDB(t, cfg)
	provisionAuthLockTestKeys(t, cfg, workDir)

	serverSvc := acquireSimulatedServerLock(t, cfg, workDir)
	defer serverSvc.Shutdown()

	err := enableAuthEncryptionWithConfig(cfg, false)
	if err == nil {
		t.Fatal("expected auth-encryption enable to be refused while a live server holds the exclusive key lock")
	}
	if !strings.Contains(err.Error(), "exclusively") {
		t.Errorf("expected a clear, actionable error mentioning the exclusive holder, got: %v", err)
	}
}

func TestEnableAuthEncryptionWithConfig_SucceedsWithNoServerOrRotationRunning(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)
	cfg := newAuthLockTestConfig(t, workDir)
	provisionAuthLockTestDB(t, cfg)
	provisionAuthLockTestKeys(t, cfg, workDir)

	if err := enableAuthEncryptionWithConfig(cfg, false); err != nil {
		t.Fatalf("expected auth-encryption enable to succeed with no server/rotation running, got: %v", err)
	}
}
