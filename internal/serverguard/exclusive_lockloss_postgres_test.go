package serverguard

import (
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

// Lock loss for the exclusive lock every state-changing admin command holds
// (POOLER-LOCKLOSS-1; it was not watched under
// INV-STORAGE-session-advisory-lock-loss). pg-gated; the TestPgBouncer_ variant
// runs the transaction shape on a direct connection and, under
// scripts/pgbouncer-matrix.sh, goes through PgBouncer. Helpers in
// keyinit_lockloss_postgres_test.go.

// TestPostgres_ServerGuard_LostExclusiveLockIsReported: an admin command's
// exclusive lock on a direct connection is a session lock. Its backend ending
// lets a server take the presence lock beside the still-running command (the
// condition this guards); Exclusive.Lost must then close, so the command can
// stop (server/admin stopOnLostDatabaseLock).
func TestPostgres_ServerGuard_LostExclusiveLockIsReported(t *testing.T) {
	cfg := pgCfg(t)
	if cfg.Storage.Database.TransactionPooling() {
		t.Fatal("this test is about the session shape")
	}
	assertLostExclusiveLockIsReported(t, cfg)
}

// TestPgBouncer_ServerGuard_LostExclusiveLockIsReported: the same for the
// transaction shape, and through PgBouncer under scripts/pgbouncer-matrix.sh.
func TestPgBouncer_ServerGuard_LostExclusiveLockIsReported(t *testing.T) {
	cfg, _ := poolerGuardCfg(t)
	assertLostExclusiveLockIsReported(t, cfg)
}

func assertLostExclusiveLockIsReported(t *testing.T, cfg *config.Config) {
	t.Helper()
	shortLockPing(t)

	x, err := AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("AcquireExclusive: %v", err)
	}
	defer func() { _ = x.Release() }()
	if x.Lost() == nil {
		t.Fatal("a PostgreSQL exclusive lock must be watchable (Lost returned nil)")
	}
	select {
	case <-x.Lost():
		t.Fatal("Lost closed while the exclusive lock connection was alive")
	case <-time.After(400 * time.Millisecond):
	}
	if p, err := AcquirePresence(cfg); err == nil {
		_ = p.Release()
		t.Fatal("a server took the presence lock while an admin command held it exclusively")
	}

	terminateLockHolder(t, serverPresenceLockKey)

	// The condition: nothing keeps a server out any more.
	p, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("after the exclusive lock's backend ended a server should get in (that is the hazard): %v", err)
	}
	_ = p.Release()

	select {
	case <-x.Lost():
	case <-time.After(5 * time.Second):
		t.Fatal("the exclusive lock was lost (backend terminated) but Exclusive.Lost never closed")
	}
	if err := x.Release(); err != nil {
		t.Logf("Release after loss: %v (fine: the connection is already gone)", err)
	}
}

// TestPostgres_ServerGuard_ReleasedExclusiveIsNeverLost: a normal Release stops
// the watch first, so Lost never closes for a command that finished (it would
// make the admin command exit 1 after succeeding).
func TestPostgres_ServerGuard_ReleasedExclusiveIsNeverLost(t *testing.T) {
	cfg := pgCfg(t)
	shortLockPing(t)
	x, err := AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("AcquireExclusive: %v", err)
	}
	if err := x.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	select {
	case <-x.Lost():
		t.Fatal("Lost closed after a normal Release")
	case <-time.After(500 * time.Millisecond):
	}
}
