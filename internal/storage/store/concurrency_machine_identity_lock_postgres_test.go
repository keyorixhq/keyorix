package store

// concurrency_machine_identity_lock_postgres_test.go — INV-STORE-15 (#2511):
// LockMachineIdentityForUpdate takes SELECT ... FOR UPDATE on Postgres only,
// and the lock is only meaningful when taken inside the same WithTransaction
// as the write it guards.
//
// The Postgres half is asserted directly at the lock, not through a race
// outcome: a holder takes the lock inside a transaction and parks; a
// contender on an independent connection (separate *gorm.DB, separate
// backend) tries to take the same lock and must still be blocked after a
// grace window, then must read the holder's COMMITTED write once released.
// That is deterministic — dropping the FOR UPDATE clause makes the contender
// return immediately with the pre-write state, every run.
//
// Two calibration cases run the same harness where the contender is expected
// NOT to block, proving the harness can observe a non-blocking contender (so
// the blocking assertion is not passing because of the harness itself):
// a plain unlocked read, and a holder that takes the lock outside any
// transaction (Postgres releases a FOR UPDATE at the end of its autocommit
// statement — the historical test-only defect CLAUDE.md describes).
//
// The end-to-end race through the real core caller (transitionMachineInTx) is
// internal/core's TestConcurrency_TransitionMachineIdentity_MultiInstancePostgres_RevokedIsTerminal;
// that one is probabilistic, this one is not.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// lockContentionGrace is how long the contender must stay blocked while the
// holder parks on the lock. Generous by design: a slow runner only makes a
// non-locking contender take longer to return, never makes a blocked one
// return early, so a large value cannot produce a false "blocked".
const lockContentionGrace = 750 * time.Millisecond

type contenderResult struct {
	state string
	err   error
}

// runHolderContender seeds one machine identity in state "suspended", has the
// holder lock it (inside WithTransaction when holderInTx, else as a standalone
// autocommit statement) and park, then starts contend on an independent
// connection. It reports whether contend returned while the holder was still
// parked, and what state contend finally read. The holder always revokes the
// row before finishing, via the same conditional write production uses.
func runHolderContender(t *testing.T, holderInTx bool, contend func(ctx context.Context, tx storage.Storage) (string, error)) (returnedWhileHeld bool, final contenderResult) {
	t.Helper()
	ctx := context.Background()
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))

	setup := pgOpen(t, dsn)
	require.NoError(t, setup.AutoMigrate(&models.MachineIdentity{}))
	require.NoError(t, setup.Create(&models.MachineIdentity{ID: 1, ProjectID: 1, Name: "ci-runner", State: "suspended"}).Error)

	holder := NewLocalStorage(pgOpen(t, dsn))
	contender := NewLocalStorage(pgOpen(t, dsn))

	locked := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan error, 1)
	holdAndRevoke := func(s storage.Storage) error {
		m, err := s.LockMachineIdentityForUpdate(ctx, 1)
		if err != nil {
			return err
		}
		close(locked)
		<-release
		now := time.Now().UTC()
		m.State, m.UpdatedAt, m.RevokedAt = "revoked", now, &now
		matched, err := s.TransitionMachineIdentityState(ctx, m, "suspended")
		if err != nil {
			return err
		}
		if !matched {
			return errors.New("holder's conditional write matched 0 rows")
		}
		return nil
	}
	go func() {
		if holderInTx {
			holderDone <- holder.WithTransaction(ctx, holdAndRevoke)
		} else {
			holderDone <- holdAndRevoke(holder)
		}
	}()
	<-locked

	contenderDone := make(chan contenderResult, 1)
	go func() {
		var state string
		err := contender.WithTransaction(ctx, func(tx storage.Storage) error {
			var err error
			state, err = contend(ctx, tx)
			return err
		})
		contenderDone <- contenderResult{state: state, err: err}
	}()

	select {
	case final = <-contenderDone:
		returnedWhileHeld = true
	case <-time.After(lockContentionGrace):
	}
	close(release)
	require.NoError(t, <-holderDone)
	if !returnedWhileHeld {
		select {
		case final = <-contenderDone:
		case <-time.After(30 * time.Second):
			t.Fatal("contender never returned after the holder committed")
		}
	}
	require.NoError(t, final.err)
	return returnedWhileHeld, final
}

func lockAndReadState(ctx context.Context, tx storage.Storage) (string, error) {
	m, err := tx.LockMachineIdentityForUpdate(ctx, 1)
	if err != nil {
		return "", err
	}
	return m.State, nil
}

func TestLockMachineIdentityForUpdate_Postgres_HoldsRowLockUntilCommit(t *testing.T) {
	returnedWhileHeld, final := runHolderContender(t, true, lockAndReadState)
	assert.False(t, returnedWhileHeld,
		"a second LockMachineIdentityForUpdate on the same row must block while another transaction holds it — it returned (state=%q), so FOR UPDATE was not taken", final.state)
	assert.Equal(t, "revoked", final.state,
		"once released, the contender must read the holder's committed write, not the pre-lock value")
}

func TestLockMachineIdentityForUpdate_Postgres_HarnessCalibration(t *testing.T) {
	t.Run("unlocked_read_does_not_block", func(t *testing.T) {
		returnedWhileHeld, final := runHolderContender(t, true, func(ctx context.Context, tx storage.Storage) (string, error) {
			m, err := tx.GetMachineIdentity(ctx, 1)
			if err != nil {
				return "", err
			}
			return m.State, nil
		})
		assert.True(t, returnedWhileHeld, "a plain read must not wait on a row lock — if it did, the blocking assertion above would prove nothing")
		assert.Equal(t, "suspended", final.state)
	})

	t.Run("standalone_lock_outside_transaction_does_not_hold", func(t *testing.T) {
		returnedWhileHeld, final := runHolderContender(t, false, lockAndReadState)
		assert.True(t, returnedWhileHeld,
			"FOR UPDATE outside an explicit transaction releases when its autocommit statement ends — callers must take the lock inside the same WithTransaction as the write")
		assert.Equal(t, "suspended", final.state)
	})
}

// TestLockMachineIdentityForUpdate_SQLite_NoRowLockClauseInsideTransaction is
// the SQLite half: the lock is taken inside a transaction (the way
// transitionMachineInTx calls it) and the statement that reaches the database
// carries no FOR UPDATE, which SQLite does not support. Note this half holds
// even without LockMachineIdentityForUpdate's own dialect check — the SQLite
// dialector drops a clause.Locking itself — so this pins the observable
// contract, not that specific line.
func TestLockMachineIdentityForUpdate_SQLite_NoRowLockClauseInsideTransaction(t *testing.T) {
	ctx := context.Background()
	ls := newMachineStore(t)
	require.NoError(t, ls.db.Create(&models.MachineIdentity{ID: 1, ProjectID: 1, Name: "ci-runner", State: "active"}).Error)

	var queries []string
	require.NoError(t, ls.db.Callback().Query().After("gorm:query").Register("test:capture_machine_lock_sql", func(db *gorm.DB) {
		queries = append(queries, db.Statement.SQL.String())
	}))

	require.NoError(t, ls.WithTransaction(ctx, func(tx storage.Storage) error {
		m, err := tx.LockMachineIdentityForUpdate(ctx, 1)
		if err != nil {
			return err
		}
		assert.Equal(t, "active", m.State)
		return nil
	}))

	require.Len(t, queries, 1)
	assert.NotContains(t, strings.ToUpper(queries[0]), "FOR UPDATE", "SQLite has no row lock; the clause must not reach it")
}
