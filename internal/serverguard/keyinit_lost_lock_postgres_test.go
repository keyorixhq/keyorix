package serverguard

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

// REVIEW-SERVERGUARD-RECOVERYKEY-1: the key-initialisation lock can end while
// fn runs (pg_terminate_backend, a PostgreSQL restart or failover, a pooler
// timeout) with no signal to the holder. A sibling replica then takes the lock
// and runs its own first-boot key generation beside this one, both past the
// "no wrapped DEK yet" check. WithKeyInitLock must report that loss instead of
// returning fn's success, so the server refuses to start rather than serve
// under a DEK a sibling may have overwritten on the shared key directory.

// TestPostgres_WithKeyInitLock_ReportsLockLostDuringFn: direct connection
// (session lock).
func TestPostgres_WithKeyInitLock_ReportsLockLostDuringFn(t *testing.T) {
	assertKeyInitLockLossReported(t, pgCfg(t))
}

// TestPgBouncer_WithKeyInitLock_ReportsLockLostDuringFn: pgbouncer-transaction
// (transaction-scoped lock inside the pinned transaction).
func TestPgBouncer_WithKeyInitLock_ReportsLockLostDuringFn(t *testing.T) {
	cfg, _ := poolerGuardCfg(t)
	assertKeyInitLockLossReported(t, cfg)
}

func assertKeyInitLockLossReported(t *testing.T, cfg *config.Config) {
	t.Helper()
	direct, err := sql.Open("pgx", pgTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = direct.Close() }()

	siblingRan := false
	err = WithKeyInitLock(cfg, 10*time.Second, func() error {
		var killed int
		if err := direct.QueryRowContext(context.Background(), `SELECT count(*) FROM (
				SELECT pg_terminate_backend(pid) FROM pg_locks
				WHERE locktype = 'advisory' AND granted AND objsubid = 1 AND classid = $1 AND objid = $2
				  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())) k`,
			keyInitLockKey>>32, keyInitLockKey&0xFFFFFFFF).Scan(&killed); err != nil || killed != 1 {
			t.Fatalf("terminate the key-initialisation lock backend: killed=%d err=%v", killed, err)
		}
		// The exclusion is gone: a sibling gets in while this holder is still
		// "inside". This is the state the holder must not report as success.
		deadline := time.Now().Add(5 * time.Second)
		for !siblingRan && time.Now().Before(deadline) {
			_ = WithKeyInitLock(cfg, 500*time.Millisecond, func() error { siblingRan = true; return nil })
		}
		return nil
	})
	if !siblingRan {
		t.Fatal("precondition: a sibling never got the lock after the holder's backend was terminated")
	}
	if err == nil {
		t.Fatal("WithKeyInitLock returned success although its lock was lost while fn ran and a sibling held it meanwhile")
	}
	if !strings.Contains(err.Error(), "lost") {
		t.Fatalf("want a lock-lost error, got %v", err)
	}
}
