package serverguard

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

// Lock loss for the key-initialisation lock (POOLER-LOCKLOSS-1; it was not
// watched under INV-STORAGE-session-advisory-lock-loss). pg-gated.

func shortLockPing(t *testing.T) {
	t.Helper()
	old := config.PinnedLockPingInterval
	config.PinnedLockPingInterval = 100 * time.Millisecond
	t.Cleanup(func() { config.PinnedLockPingInterval = old })
}

// terminateLockHolder ends the backend holding advisory lock key (single bigint
// form) in this database, the way a failover, a pg_terminate_backend or a
// PgBouncer restart would, and fails unless exactly one backend held it.
func terminateLockHolder(t *testing.T, key int64) {
	t.Helper()
	direct, err := sql.Open("pgx", pgTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = direct.Close() }()
	var killed int
	err = direct.QueryRowContext(context.Background(), `SELECT count(*) FROM (
			SELECT pg_terminate_backend(pid) FROM pg_locks
			WHERE locktype = 'advisory' AND granted AND objsubid = 1 AND classid = $1 AND objid = $2
			  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())) k`,
		key>>32, key&0xFFFFFFFF).Scan(&killed)
	if err != nil || killed != 1 {
		t.Fatalf("terminate the backend holding advisory lock %d: killed=%d err=%v", key, killed, err)
	}
}

// TestPostgres_WithKeyInitLock_LostLockFailsTheHolder: the key-initialisation
// lock's backend ends while fn writes the key files; a sibling replica can then
// take the lock and write them too. fn itself succeeds, so without the check
// the first replica would start with keys that may not be the ones on disk.
// WithKeyInitLock must return errKeyInitLockLost. Both lock shapes.
func TestPostgres_WithKeyInitLock_LostLockFailsTheHolder(t *testing.T) {
	for _, pooler := range []string{config.PoolerNone, config.PoolerPgBouncerTransaction} {
		t.Run(pooler, func(t *testing.T) {
			cfg := pgCfg(t)
			setTestPooler(&cfg.Storage.Database, pooler)
			shortLockPing(t)

			siblingGotIn := false
			err := WithKeyInitLock(cfg, 5*time.Second, func() error {
				terminateLockHolder(t, keyInitLockKey)
				// The overlap this reports: a sibling now gets the lock while
				// this holder is still inside fn.
				return WithKeyInitLock(cfg, time.Second, func() error {
					siblingGotIn = true
					return nil
				})
			})
			if !siblingGotIn {
				t.Fatal("the sibling did not get the lock after the holder's backend ended (test premise)")
			}
			// Not errors.Is(err, errKeyInitLockLost), so the test compiles on the
			// base commit and shows a behavioural red there (redproof.sh).
			if err == nil || !strings.Contains(err.Error(), "key-initialisation lock was lost") {
				t.Fatalf("WithKeyInitLock after its lock was lost = %v, want the lost-lock refusal", err)
			}
		})
	}
}

// TestPostgres_WithKeyInitLock_HeldLockIsNotLost: the check must not fire on a
// healthy lock, including fn running longer than a watch interval.
func TestPostgres_WithKeyInitLock_HeldLockIsNotLost(t *testing.T) {
	cfg := pgCfg(t)
	shortLockPing(t)
	err := WithKeyInitLock(cfg, 5*time.Second, func() error {
		time.Sleep(350 * time.Millisecond)
		return nil
	})
	if err != nil {
		t.Fatalf("WithKeyInitLock with a healthy lock: %v", err)
	}
}
