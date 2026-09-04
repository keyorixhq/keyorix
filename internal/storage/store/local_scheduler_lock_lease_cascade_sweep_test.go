// local_scheduler_lock_lease_cascade_sweep_test.go — partial-coverage sweep
// for local_scheduler_lock_lease.go's TryAcquireSchedulerLock: the three
// SQLite-reachable DB-error branches (the ON CONFLICT Create itself, the
// existing-row Take, and the renew Updates). The `tx.Dialector.Name() ==
// "postgres"` FOR UPDATE clause (line 85-87) is out of scope (Postgres-only).
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestTryAcquireSchedulerLock_CreateFails(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.TryAcquireSchedulerLock(context.Background(), 1, "holder-a", time.Minute)
	require.Error(t, err)
}

func TestTryAcquireSchedulerLock_TakeFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SchedulerLockLease{})
	require.NoError(t, ls.db.Create(&models.SchedulerLockLease{
		Key: 1, Holder: "holder-a", ExpiresAt: time.Now().Add(time.Hour),
	}).Error)

	// The ON CONFLICT Create hits the existing row (RowsAffected 0) and falls
	// through to Take; drop the table right before that Take runs.
	require.NoError(t, ls.db.Callback().Query().Before("gorm:query").Register("drop-lease-before-take", func(tx *gorm.DB) {
		tx.Exec("DROP TABLE IF EXISTS scheduler_lock_leases")
	}))

	_, err := ls.TryAcquireSchedulerLock(context.Background(), 1, "holder-b", time.Minute)
	require.Error(t, err)
}

func TestTryAcquireSchedulerLock_RenewUpdatesFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SchedulerLockLease{})
	require.NoError(t, ls.db.Create(&models.SchedulerLockLease{
		Key: 1, Holder: "holder-a", ExpiresAt: time.Now().Add(time.Hour),
	}).Error)

	// Same holder renewing its own still-live lease: Take succeeds, falls
	// through to the renew Updates; drop the table right before that Updates.
	require.NoError(t, ls.db.Callback().Update().Before("gorm:update").Register("drop-lease-before-update", func(tx *gorm.DB) {
		tx.Exec("DROP TABLE IF EXISTS scheduler_lock_leases")
	}))

	_, err := ls.TryAcquireSchedulerLock(context.Background(), 1, "holder-a", time.Minute)
	require.Error(t, err)
}
