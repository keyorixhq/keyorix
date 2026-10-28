package admin

// REVIEW-SERVERGUARD-RECOVERYKEY-1 F7: acquireDatabaseLock's refusal names the
// real cause on each of its three non-force branches. An unreadable or
// foreign-owned SQLite <db>.server.lock used to be reported as "cannot connect
// to the database", which sent operators to the database instead of the file.
// Every branch still fails closed without --force.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/serverguard"
)

func sqliteLockCfg(dir string) *config.Config {
	return &config.Config{Storage: config.StorageConfig{
		Type:     "local",
		Database: config.DatabaseConfig{Path: filepath.Join(dir, "secrets.db")},
	}}
}

const (
	lockFileMsg = "cannot open the server lock file: "
	connectMsg  = "cannot connect to the database to check for a running server"
	heldMsg     = "appears to be using this database"
)

// Branch 1: the lock file cannot be opened (a 0000 file stands in for a
// foreign-owned one: the same EACCES).
func TestAcquireDatabaseLock_LockFileOpenErrorNamesTheFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens a mode-0000 file, so EACCES cannot be produced")
	}
	forceFlag = false
	dir := t.TempDir()
	cfg := sqliteLockCfg(dir)
	lockPath := filepath.Join(dir, "secrets.db.server.lock")
	if err := os.WriteFile(lockPath, nil, 0o000); err != nil {
		t.Fatal(err)
	}

	lock, err := acquireDatabaseLock(cfg)
	if err == nil {
		_ = lock.Release()
		t.Fatal("acquireDatabaseLock succeeded although the server lock file cannot be opened")
	}
	msg := err.Error()
	if !strings.Contains(msg, lockFileMsg+lockPath+": permission denied") {
		t.Fatalf("expected %q naming %s and the OS error, got: %v", lockFileMsg, lockPath, err)
	}
	if strings.Contains(msg, connectMsg) || strings.Contains(msg, heldMsg) {
		t.Fatalf("a lock-file open error must not be reported as a connection failure or a held lock, got: %v", err)
	}
	if !strings.Contains(msg, "--force") {
		t.Fatalf("the refusal must still say how to override it, got: %v", err)
	}
}

// Branch 2: the lock is held by another process.
func TestAcquireDatabaseLock_HeldLockIsNotALockFileError(t *testing.T) {
	forceFlag = false
	setInContainer(t, false)
	cfg := sqliteLockCfg(t.TempDir())
	first, err := serverguard.AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("first AcquireExclusive: %v", err)
	}
	defer first.Release() //nolint:errcheck

	_, err = acquireDatabaseLock(cfg)
	if err == nil || !strings.Contains(err.Error(), heldMsg) || strings.Contains(err.Error(), lockFileMsg) {
		t.Fatalf("expected only the held-lock message, got: %v", err)
	}
}

// Branch 3: PostgreSQL cannot be reached.
func TestAcquireDatabaseLock_ConnectFailureIsNotALockFileError(t *testing.T) {
	forceFlag = false
	cfg := &config.Config{Storage: config.StorageConfig{
		Type: "postgres",
		Database: config.DatabaseConfig{
			Host: "127.0.0.1", Port: "1", Name: "nonexistent", User: "nouser", SSLMode: "disable",
		},
	}}
	_, err := acquireDatabaseLock(cfg)
	if err == nil || !strings.Contains(err.Error(), connectMsg) || strings.Contains(err.Error(), lockFileMsg) {
		t.Fatalf("expected only the connect-failure message, got: %v", err)
	}
}
