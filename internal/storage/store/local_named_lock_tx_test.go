package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// SQLite: LockNamedKeyInTx takes nothing (write transactions are already
// serialized, BEGIN IMMEDIATE in one process), so per-key waiting cannot be
// observed here; the PostgreSQL tests in local_named_lock_tx_postgres_test.go
// are the contention proof. What SQLite does check is the contract every
// caller depends on: inside a transaction it succeeds, outside one it is
// refused, and a WithNamedLock holder can take its own key in its transaction.
func TestLockNamedKeyInTx_SQLite_InsideTransaction(t *testing.T) {
	ls := newNamedLockTestStore(t)
	err := ls.WithTransaction(context.Background(), func(tx storage.Storage) error {
		if err := tx.LockNamedKeyInTx(context.Background(), "k"); err != nil {
			return err
		}
		return tx.LockNamedKeyInTx(context.Background(), "k") // re-entrant
	})
	require.NoError(t, err)
}

func TestLockNamedKeyInTx_SQLite_OutsideTransactionIsRefused(t *testing.T) {
	ls := newNamedLockTestStore(t)
	require.ErrorIs(t, ls.LockNamedKeyInTx(context.Background(), "k"), errNamedKeyOutsideTx)
}

func TestLockNamedKeyInTx_SQLite_InsideOwnNamedLock(t *testing.T) {
	ls := newNamedLockTestStore(t)
	done := make(chan error, 1)
	go func() {
		done <- ls.WithNamedLock(context.Background(), "k", func(ctx context.Context) error {
			return ls.WithTransaction(ctx, func(tx storage.Storage) error {
				return tx.LockNamedKeyInTx(ctx, "k")
			})
		})
	}()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("LockNamedKeyInTx inside its own WithNamedLock section deadlocked")
	}
}

// The transaction key space is derived from, but disjoint from, the session
// key: same hash, split into the two halves PostgreSQL's two-int4 form takes.
func TestNamedLockXactKey_IsTheSessionKeyHashSplit(t *testing.T) {
	for _, k := range []string{"last-admin-guard", "project-admin-guard:7", "sod-grant:user:42"} {
		hi, lo := namedLockXactKey(k)
		whole := uint64(namedLockKey(k))
		require.Equal(t, whole, uint64(uint32(hi))<<32|uint64(uint32(lo)), k)
	}
	ahi, alo := namedLockXactKey("project-admin-guard:7")
	bhi, blo := namedLockXactKey("project-admin-guard:8")
	require.False(t, ahi == bhi && alo == blo, "two keys must not share a transaction lock")
}
