package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestDeleteAuditLogsBefore_InvertedPair_Postgres is the real-Postgres variant of
// the INV-STORE-22 guard (#2633): the inverted-pair purge must leave a chain that
// verifies, in the production call shape (inside WithTransaction). pg-gated.
func TestDeleteAuditLogsBefore_InvertedPair_Postgres(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	db := pgOpen(t, dsn)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
	ls := NewLocalStorage(db)

	assertInvertedPairPurgeKeepsChainVerifiable(t, ls, func(cutoff time.Time) (n int64, a *storage.AuditChainAnchor, err error) {
		txErr := ls.WithTransaction(context.Background(), func(tx storage.Storage) error {
			n, a, err = tx.DeleteAuditLogsBefore(context.Background(), cutoff)
			return err
		})
		if err == nil {
			err = txErr
		}
		return n, a, err
	})
}

// TestDeleteAuditLogsBefore_WaitsForKeyauditAdvisoryLock_Postgres guards the
// cross-process half of INV-STORE-22's lock: while another connection (a
// different replica, its own LocalStorage and mutex) holds the KEYAUDIT
// transaction-scoped advisory lock that LogAuditEvent takes, a purge — in the
// production call shape, inside WithTransaction, where auditChainMu is not
// taken — must block until that transaction ends. pg-gated.
func TestDeleteAuditLogsBefore_WaitsForKeyauditAdvisoryLock_Postgres(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	holderDB := pgOpen(t, dsn)
	require.NoError(t, holderDB.AutoMigrate(&models.AuditEvent{}))
	ls := NewLocalStorage(pgOpen(t, dsn))
	cutoff := seedInvertedPairTrail(t, ls)

	locked := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- holderDB.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", int64(auditAdvisoryLockKey)).Error; err != nil {
				return err
			}
			close(locked)
			<-release
			return nil
		})
	}()
	<-locked

	done := make(chan error, 1)
	go func() {
		done <- ls.WithTransaction(context.Background(), func(tx storage.Storage) error {
			_, _, err := tx.DeleteAuditLogsBefore(context.Background(), cutoff)
			return err
		})
	}()
	select {
	case err := <-done:
		close(release)
		t.Fatalf("DeleteAuditLogsBefore ran while another connection held the KEYAUDIT advisory lock (err=%v)", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	require.NoError(t, <-holderDone)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("DeleteAuditLogsBefore did not complete after the KEYAUDIT advisory lock was released")
	}
}
