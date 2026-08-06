// local_secrets_transition_status_test.go — SQLite integration test for
// LocalStorage.TransitionSecretStatus, proving the CAS guard the
// StateTransitionMissingCAS fix (secret_suspend.go's SuspendSecret/
// ResumeSecret TOCTOU race) relies on: a conditional UPDATE that only applies
// when the row's CURRENTLY persisted status still matches fromStatus. Mirrors
// TestTransitionMachineIdentityState_S25_NoMatchReturnsFalse's shape, but
// against a real row (not a not-found ID) so it actually exercises the WHERE
// clause's status comparison, not just the id comparison.
package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newTransitionSecretStatusStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}))
	return NewLocalStorage(db)
}

// TestTransitionSecretStatus_ClosesRace proves the exact race
// StateTransitionMissingCAS flags: two callers both observe the secret's
// status as "active" (e.g. a suspend and a resume-that-never-should-have-
// applied racing off the same stale read), then both attempt to persist their
// own mutation conditioned on that same observed fromStatus. Only the FIRST
// write may land; the second must be rejected (matched=false) rather than
// silently clobbering the first — which is exactly what a plain
// UpdateSecret(ctx, secret) full-row Save could not detect.
func TestTransitionSecretStatus_ClosesRace(t *testing.T) {
	ls := newTransitionSecretStatusStore(t)
	ctx := context.Background()

	node := &models.SecretNode{ID: 1, Name: "db-password", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active"}
	require.NoError(t, ls.db.Create(node).Error)

	// Two independent in-memory copies, both starting from the same
	// "active" read — modeling two concurrent callers (a suspend and a
	// resume, or two racing suspends) that each observed the row before
	// either write landed.
	winner := &models.SecretNode{ID: 1, Name: "db-password", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "suspended"}
	loser := &models.SecretNode{ID: 1, Name: "db-password", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active"}

	// The first writer's conditional UPDATE succeeds: the row's persisted
	// status was still "active" when this write ran.
	matched, err := ls.TransitionSecretStatus(ctx, winner, "active")
	require.NoError(t, err)
	assert.True(t, matched, "the first writer must win the race")

	var afterFirst models.SecretNode
	require.NoError(t, ls.db.First(&afterFirst, 1).Error)
	assert.Equal(t, "suspended", afterFirst.Status, "the winner's status must be persisted")

	// The second writer's conditional UPDATE — still conditioned on the
	// SAME stale "active" fromStatus it originally observed — must now be
	// rejected: the row has already moved to "suspended".
	matched, err = ls.TransitionSecretStatus(ctx, loser, "active")
	require.NoError(t, err)
	assert.False(t, matched, "a second writer racing off the same stale read must lose, not clobber the winner")

	var afterSecond models.SecretNode
	require.NoError(t, ls.db.First(&afterSecond, 1).Error)
	assert.Equal(t, "suspended", afterSecond.Status, "the loser's rejected write must not have altered the row")
}

// TestTransitionSecretStatus_NoMatchReturnsFalse mirrors
// TestTransitionMachineIdentityState_S25_NoMatchReturnsFalse: a transition
// against a nonexistent row reports matched=false, no error.
func TestTransitionSecretStatus_NoMatchReturnsFalse(t *testing.T) {
	ls := newTransitionSecretStatusStore(t)
	matched, err := ls.TransitionSecretStatus(context.Background(), &models.SecretNode{ID: 9999}, "active")
	require.NoError(t, err)
	assert.False(t, matched)
}

// TestTransitionSecretStatus_ClosedDB_ReturnsError verifies the error branch:
// when the underlying SQLite connection is closed, TransitionSecretStatus
// must propagate the storage error rather than silently returning
// matched=false.
func TestTransitionSecretStatus_ClosedDB_ReturnsError(t *testing.T) {
	ls := newTransitionSecretStatusStore(t)
	sqlDB, err := ls.db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	_, err = ls.TransitionSecretStatus(context.Background(), &models.SecretNode{ID: 1}, "active")
	assert.Error(t, err)
}
