package admin

// SERVERGUARD-LOCK-TAILS-1 item 1: an admin command on SQLite whose
// <database>.server.lock sidecar is deleted while it runs must stop (exit 1),
// like one whose PostgreSQL lock connection died, and no server may attach
// before it has. Not gated: SQLite only.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/serverguard"
)

func sqliteLockLossAdminCfg(t *testing.T) (*config.Config, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "secrets.db")
	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = dbPath
	old, oldForce := config.PinnedLockPingInterval, forceFlag
	config.PinnedLockPingInterval = 20 * time.Millisecond
	forceFlag = false
	t.Cleanup(func() { config.PinnedLockPingInterval, forceFlag = old, oldForce })
	return cfg, dbPath + ".server.lock"
}

func TestAcquireDatabaseLock_SQLiteSidecarDeleted_StopsTheCommand(t *testing.T) {
	cfg, lockPath := sqliteLockLossAdminCfg(t)
	exited := observeLostLockExit(t)

	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		t.Fatalf("acquireDatabaseLock: %v", err)
	}
	defer lock.Release() //nolint:errcheck
	select {
	case <-exited:
		t.Fatal("the command was stopped while its sidecar was intact")
	case <-time.After(10 * config.PinnedLockPingInterval):
	}

	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("the admin command's SQLite sidecar was deleted, but the command was not stopped")
	}
	// The command is stopping (in production os.Exit follows at once): until
	// its lock is gone with the process, no server may attach.
	if p, err := serverguard.AcquirePresence(cfg); err == nil {
		_ = p.Release()
		t.Fatal("a server attached beside the stopping admin command after its sidecar was deleted")
	}
}

func TestAcquireDatabaseLock_SQLiteReleasedLockNeverStopsTheCommand(t *testing.T) {
	cfg, _ := sqliteLockLossAdminCfg(t)
	exited := observeLostLockExit(t)

	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		t.Fatalf("acquireDatabaseLock: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	select {
	case <-exited:
		t.Fatal("a command that released its lock normally was stopped")
	case <-time.After(20 * config.PinnedLockPingInterval):
	}
}
