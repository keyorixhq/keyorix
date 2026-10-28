package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// xactKeyHolder opens a write transaction on ls, takes key with
// LockNamedKeyInTx, reports that on locked, and keeps the transaction open
// until release is closed; it then commits (or rolls back when rollback).
type xactKeyHolder struct {
	locked  chan struct{}
	release chan struct{}
	done    chan error
}

func holdXactKey(ls *LocalStorage, key string, rollback bool) *xactKeyHolder {
	h := &xactKeyHolder{locked: make(chan struct{}), release: make(chan struct{}), done: make(chan error, 1)}
	go func() {
		h.done <- ls.WithTransaction(context.Background(), func(tx storage.Storage) error {
			if err := tx.LockNamedKeyInTx(context.Background(), key); err != nil {
				return err
			}
			close(h.locked)
			<-h.release
			if rollback {
				return errors.New("roll back")
			}
			return nil
		})
	}()
	return h
}

// xactLockKey is unique per test and process: advisory locks are
// database-wide, not per schema, and other packages' tests may share the
// database.
func xactLockKey(t *testing.T, suffix string) string {
	return fmt.Sprintf("named-lock-tx-test:%d:%s:%s", os.Getpid(), t.Name(), suffix)
}

// The second transaction on the same key, on another replica's pool, waits
// until the first ends, whether the first commits or rolls back.
func TestLockNamedKeyInTx_Postgres_SameKeyWaitsForFirstTransaction(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	for _, rollback := range []bool{false, true} {
		t.Run(fmt.Sprintf("first_rolls_back=%v", rollback), func(t *testing.T) {
			key := xactLockKey(t, "same")
			first := holdXactKey(NewLocalStorage(pgOpen(t, dsn)), key, rollback)
			select {
			case <-first.locked:
			case err := <-first.done:
				t.Fatalf("first transaction failed: %v", err)
			case <-time.After(10 * time.Second):
				t.Fatal("first transaction did not take the key")
			}

			second := holdXactKey(NewLocalStorage(pgOpen(t, dsn)), key, false)
			select {
			case <-second.locked:
				t.Fatal("the second transaction took the key while the first transaction still held it")
			case err := <-second.done:
				t.Fatalf("second transaction ended while waiting: %v", err)
			case <-time.After(750 * time.Millisecond):
			}

			close(first.release)
			if rollback {
				require.Error(t, <-first.done)
			} else {
				require.NoError(t, <-first.done)
			}
			select {
			case <-second.locked:
			case <-time.After(10 * time.Second):
				t.Fatal("the second transaction did not take the key after the first ended")
			}
			close(second.release)
			require.NoError(t, <-second.done)
		})
	}
}

// Two different keys never wait on each other.
func TestLockNamedKeyInTx_Postgres_DifferentKeyDoesNotWait(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	first := holdXactKey(NewLocalStorage(pgOpen(t, dsn)), xactLockKey(t, "a"), false)
	defer func() {
		close(first.release)
		require.NoError(t, <-first.done)
	}()
	select {
	case <-first.locked:
	case <-time.After(10 * time.Second):
		t.Fatal("first transaction did not take its key")
	}

	second := holdXactKey(NewLocalStorage(pgOpen(t, dsn)), xactLockKey(t, "b"), false)
	select {
	case <-second.locked:
	case <-time.After(10 * time.Second):
		t.Fatal("a transaction on a different key waited for the first one")
	}
	close(second.release)
	require.NoError(t, <-second.done)
}

// A WithNamedLock holder takes the same key in its own write transaction (the
// shape every NAMEDLOCK-OVERLAP-2 fence has). The session lock and the
// transaction lock are on different backends, so on one shared advisory key
// this would wait forever; namedLockXactKey's separate key space is what
// prevents that. Run with and without a dedicated lock pool.
func TestLockNamedKeyInTx_Postgres_InsideOwnNamedLockDoesNotSelfDeadlock(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	for _, lockPool := range []bool{false, true} {
		t.Run(fmt.Sprintf("lock_pool=%v", lockPool), func(t *testing.T) {
			ls := NewLocalStorage(pgOpen(t, dsn))
			if lockPool {
				sqlDB, err := pgOpen(t, dsn).DB()
				require.NoError(t, err)
				ls.SetNamedLockDB(sqlDB)
			}
			key := xactLockKey(t, "own")
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			err := ls.WithNamedLock(ctx, key, func(ctx context.Context) error {
				return ls.WithTransaction(ctx, func(tx storage.Storage) error {
					return tx.LockNamedKeyInTx(ctx, key)
				})
			})
			require.NoError(t, err, "a holder's own transaction must not wait on its own session lock")
		})
	}
}

// The premise of namedLockXactKey: had LockNamedKeyInTx used WithNamedLock's
// own bigint key, the holder's transaction would wait on the holder's session
// lock. Without this, InsideOwnNamedLockDoesNotSelfDeadlock could pass for a
// reason other than the key split.
func TestNamedLockXactKey_Postgres_SharedBigintKeyWouldSelfDeadlock(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	ls := NewLocalStorage(pgOpen(t, dsn))
	key := xactLockKey(t, "bigint")
	err := ls.WithNamedLock(context.Background(), key, func(ctx context.Context) error {
		waitCtx, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
		defer cancel()
		return ls.WithTransaction(waitCtx, func(tx storage.Storage) error {
			return tx.(*LocalStorage).db.WithContext(waitCtx).Exec("SELECT pg_advisory_xact_lock(?)", namedLockKey(key)).Error
		})
	})
	require.Error(t, err, "the bigint form inside the holder's own section must block on the holder's session lock")
}

// A waiter whose ctx ends stops waiting and its transaction rolls back.
func TestLockNamedKeyInTx_Postgres_WaiterHonoursContext(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	key := xactLockKey(t, "ctx")
	first := holdXactKey(NewLocalStorage(pgOpen(t, dsn)), key, false)
	defer func() {
		close(first.release)
		require.NoError(t, <-first.done)
	}()
	<-first.locked

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	err := NewLocalStorage(pgOpen(t, dsn)).WithTransaction(ctx, func(tx storage.Storage) error {
		return tx.LockNamedKeyInTx(ctx, key)
	})
	require.Error(t, err, "a waiter whose context ended must give up, not take the key")
}

// Outside a transaction the lock would end with its own statement: refused.
func TestLockNamedKeyInTx_Postgres_OutsideTransactionIsRefused(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	err := NewLocalStorage(pgOpen(t, dsn)).LockNamedKeyInTx(context.Background(), xactLockKey(t, "out"))
	require.ErrorIs(t, err, errNamedKeyOutsideTx)
}
