package admin

// admin_test.go covers acquireDatabaseLock's two distinct failure messages (#2362): a
// connect-level failure (bad credentials, unreachable host -- presence was never actually
// determined) must say so plainly, not claim a server is using the database; a genuinely
// held lock keeps the original "appears to be using this database" message. Both still fail
// closed without --force.

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/serverguard"
)

func TestAcquireDatabaseLock_ConnectFailureSurfacesRealError(t *testing.T) {
	forceFlag = false
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "postgres",
			Database: config.DatabaseConfig{
				Host: "127.0.0.1", Port: "1", Name: "nonexistent", User: "nouser", SSLMode: "disable",
			},
		},
	}
	_, err := acquireDatabaseLock(cfg)
	if err == nil {
		t.Fatal("expected acquireDatabaseLock to fail against an unreachable Postgres host")
	}
	if !strings.Contains(err.Error(), "cannot connect to the database to check for a running server") {
		t.Fatalf("expected the real-connect-error message, got: %v", err)
	}
	if strings.Contains(err.Error(), "appears to be using this database") {
		t.Fatalf("connect failure must not be misreported as a held lock, got: %v", err)
	}
}

func TestAcquireDatabaseLock_ActuallyHeldLockSurfacesPresenceMessage(t *testing.T) {
	forceFlag = false
	dir := t.TempDir()
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: filepath.Join(dir, "secrets.db")},
		},
	}
	first, err := serverguard.AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("first AcquireExclusive: %v", err)
	}
	defer first.Release() //nolint:errcheck

	_, err = acquireDatabaseLock(cfg)
	if err == nil {
		t.Fatal("expected acquireDatabaseLock to fail while another exclusive lock is held")
	}
	if !strings.Contains(err.Error(), "appears to be using this database") {
		t.Fatalf("expected the held-lock message, got: %v", err)
	}
	if strings.Contains(err.Error(), "cannot connect to the database to check for a running server") {
		t.Fatalf("a genuine held lock must not be reported as a connect failure, got: %v", err)
	}
}

func TestAcquireDatabaseLock_ForceProceedsOnAnyFailure(t *testing.T) {
	forceFlag = true
	defer func() { forceFlag = false }()
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "postgres",
			Database: config.DatabaseConfig{
				Host: "127.0.0.1", Port: "1", Name: "nonexistent", User: "nouser", SSLMode: "disable",
			},
		},
	}
	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		t.Fatalf("expected --force to proceed despite the connect failure, got error: %v", err)
	}
	if lock != nil {
		t.Fatalf("expected a nil lock when --force bypasses a failed acquisition, got: %v", lock)
	}
}
