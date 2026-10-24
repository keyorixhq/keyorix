package admin

// An admin command whose exclusive database lock is lost while it runs must
// stop (POOLER-LOCKLOSS-1, stopOnLostDatabaseLock). Gated on
// KEYORIX_TEST_PG_DSN.

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

// serverPresenceLockKeyForTest is internal/serverguard's serverPresenceLockKey,
// the key AcquireExclusive takes.
const serverPresenceLockKeyForTest = 872342

func lockLossAdminCfg(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = pgAdminTestDSN(t)
	old := config.PinnedLockPingInterval
	config.PinnedLockPingInterval = 100 * time.Millisecond
	t.Cleanup(func() { config.PinnedLockPingInterval = old })
	return cfg
}

func observeLostLockExit(t *testing.T) <-chan struct{} {
	t.Helper()
	exited := make(chan struct{}, 1)
	old := exitOnLostDatabaseLock
	exitOnLostDatabaseLock = func() { exited <- struct{}{} }
	t.Cleanup(func() { exitOnLostDatabaseLock = old })
	return exited
}

func TestAcquireDatabaseLock_LostLockStopsTheCommand(t *testing.T) {
	cfg := lockLossAdminCfg(t)
	exited := observeLostLockExit(t)

	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		t.Fatalf("acquireDatabaseLock: %v", err)
	}
	defer lock.Release() //nolint:errcheck
	select {
	case <-exited:
		t.Fatal("the command was stopped while its lock connection was alive")
	case <-time.After(400 * time.Millisecond):
	}

	direct, err := sql.Open("pgx", cfg.Storage.Database.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = direct.Close() }()
	var killed int
	if err := direct.QueryRowContext(context.Background(), `SELECT count(*) FROM (
			SELECT pg_terminate_backend(pid) FROM pg_locks
			WHERE locktype = 'advisory' AND granted AND objsubid = 1 AND classid = 0 AND objid = $1
			  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())) k`,
		serverPresenceLockKeyForTest).Scan(&killed); err != nil || killed != 1 {
		t.Fatalf("terminate the admin lock backend: killed=%d err=%v", killed, err)
	}

	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("the admin command's exclusive lock was lost, but the command was not stopped")
	}
}

func TestAcquireDatabaseLock_ReleasedLockNeverStopsTheCommand(t *testing.T) {
	cfg := lockLossAdminCfg(t)
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
	case <-time.After(500 * time.Millisecond):
	}
}
