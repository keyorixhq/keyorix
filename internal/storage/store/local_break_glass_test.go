// local_break_glass_test.go — pins that the partial unique index on
// break_glass_activations (project_id, user_id) WHERE state='active' actually closes
// the concurrent-activation race: at most one row for a given (project, user) can be
// 'active' at a time, even when two callers race the insert.
package store

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newBreakGlassStore(t *testing.T) *LocalStorage {
	t.Helper()
	db := concurrentDB(t)
	require.NoError(t, db.AutoMigrate(&models.BreakGlassActivation{}))
	// Mirrors ensureBreakGlassActiveIndex (internal/storage/factory.go) — this is the
	// actual race gate under test, so create it exactly as the real migration does.
	require.NoError(t, db.Exec(
		"CREATE UNIQUE INDEX uniq_break_glass_active_project_user ON break_glass_activations (project_id, user_id) WHERE state = 'active'",
	).Error)
	return NewLocalStorage(db)
}

// A second active activation for the same (project_id, user_id) is rejected with
// storage.ErrBreakGlassAlreadyActive, not a raw driver error — proving the sentinel
// wiring works end to end (index → OnConflict DoNothing → RowsAffected check).
func TestCreateBreakGlassActivation_RejectsSecondActiveForSameProjectUser(t *testing.T) {
	ls := newBreakGlassStore(t)
	ctx := context.Background()

	first, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 2, UserID: 10, RoleID: 3, RoleName: "editor", State: "active",
	})
	require.NoError(t, err)
	assert.NotZero(t, first.ID)

	_, err = ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 2, UserID: 10, RoleID: 3, RoleName: "editor", State: "active",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, storage.ErrBreakGlassAlreadyActive), "got %v", err)
}

// The index is scoped to state='active' (a PARTIAL unique index), not a plain unique
// index: a second row for the same (project_id, user_id) is fine once the first is no
// longer active (revoked/expired) — that's how re-activation after revoke works.
func TestCreateBreakGlassActivation_AllowsReactivationAfterPriorIsInactive(t *testing.T) {
	ls := newBreakGlassStore(t)
	ctx := context.Background()

	first, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 2, UserID: 10, RoleID: 3, RoleName: "editor", State: "active",
	})
	require.NoError(t, err)

	first.State = "revoked"
	require.NoError(t, ls.UpdateBreakGlassActivation(ctx, first))

	second, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 2, UserID: 10, RoleID: 3, RoleName: "editor", State: "active",
	})
	require.NoError(t, err, "a fresh activation must be allowed once the prior one is no longer active")
	assert.NotEqual(t, first.ID, second.ID)
}

// A DIFFERENT user or project is unaffected by another (project, user)'s active
// activation — the index is scoped to the exact pair, not global.
func TestCreateBreakGlassActivation_DifferentProjectOrUserUnaffected(t *testing.T) {
	ls := newBreakGlassStore(t)
	ctx := context.Background()

	_, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 2, UserID: 10, RoleID: 3, RoleName: "editor", State: "active",
	})
	require.NoError(t, err)

	_, err = ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 2, UserID: 11, RoleID: 3, RoleName: "editor", State: "active",
	})
	require.NoError(t, err, "a different user on the same project is unaffected")

	_, err = ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 3, UserID: 10, RoleID: 3, RoleName: "editor", State: "active",
	})
	require.NoError(t, err, "the same user on a different project is unaffected")
}

// The actual concurrency claim: N goroutines racing to activate break-glass for the
// SAME (project, user) must yield exactly one winner — the DB constraint, not
// application-level sequencing, is what closes the race. Uses a real file-backed
// SQLite DB with WAL + a busy timeout (concurrentDB) so connections genuinely
// contend; a single shared in-memory connection would serialize every statement and
// mask the race this test exists to catch.
func TestCreateBreakGlassActivation_ConcurrentRaceYieldsExactlyOneWinner(t *testing.T) {
	ls := newBreakGlassStore(t)

	const racers = 16
	var successes, conflicts, otherErrs atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := ls.CreateBreakGlassActivation(context.Background(), &models.BreakGlassActivation{
				ProjectID: 2, UserID: 10, RoleID: 3, RoleName: "editor", State: "active",
			})
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, storage.ErrBreakGlassAlreadyActive):
				conflicts.Add(1)
			default:
				otherErrs.Add(1)
			}
		}()
	}
	close(start) // release all racers at once
	wg.Wait()

	assert.Zero(t, otherErrs.Load(), "every losing racer must fail with the sentinel, not some other error")
	assert.EqualValues(t, 1, successes.Load(), "exactly one concurrent activation must win, regardless of goroutine scheduling")
	assert.EqualValues(t, racers-1, conflicts.Load())

	// And the database agrees: exactly one 'active' row exists for this (project, user).
	var count int64
	require.NoError(t, ls.db.Model(&models.BreakGlassActivation{}).
		Where("project_id = ? AND user_id = ? AND state = ?", 2, 10, "active").
		Count(&count).Error)
	assert.EqualValues(t, 1, count)
}

// TestBreakGlassReads_NeverPersistState is #1653's durable guard, rewritten
// for the new target state (2026-09-02): the original guard question was "no
// authorization decision reads BreakGlassActivation.State" -- correct
// question, and the answer turned out to be no (core.RevokeBreakGlass's own
// guard, and its remote-storage-proxy mirror, both did). The actual defect
// was upstream of that: ListBreakGlassActivations, a read path, computed a
// wall-clock transition and PERSISTED it -- a list/get endpoint writing
// access-control-adjacent state is a defect on its own terms, independent of
// clocks, because it means a benign read by anyone who can list/get
// activations is what triggers the write. Once State is a genuine read-time
// projection (projectEffectiveBreakGlassState), the durable invariant this
// fix establishes -- the one a future change would break -- is: neither
// GetBreakGlassActivation nor ListBreakGlassActivations EVER writes. This
// test proves it directly: seed a TTL-lapsed 'active' row, call both read
// functions, then re-query the row's raw persisted state and assert it is
// UNCHANGED. See ReconcileExpiredBreakGlassActivation for the one place
// (a mutating operation, ActivateBreakGlass) a TTL-lapse transition is ever
// actually written.
func TestBreakGlassReads_NeverPersistState(t *testing.T) {
	ls := newBreakGlassStore(t)
	ctx := context.Background()
	past := time.Now().Add(-time.Hour)

	seeded, err := ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 2, UserID: 10, RoleID: 3, RoleName: "editor", State: "active", ExpiresAt: &past,
	})
	require.NoError(t, err)

	got, err := ls.GetBreakGlassActivation(ctx, seeded.ID)
	require.NoError(t, err)
	assert.Equal(t, "expired", got.State, "GetBreakGlassActivation must project the TTL-lapse for the caller")

	list, err := ls.ListBreakGlassActivations(ctx, 2)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "expired", list[0].State, "ListBreakGlassActivations must project the TTL-lapse for the caller")

	var stored models.BreakGlassActivation
	require.NoError(t, ls.db.First(&stored, seeded.ID).Error)
	assert.Equal(t, "active", stored.State,
		"neither read above may have persisted the projection -- the row's real, stored state must be unchanged")
}
