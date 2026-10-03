package store

// state_transition_cas_test.go — INV-STORE-14 (#2510): TransitionMachineIdentityState
// and TransitionSecretStatus persist via ONE conditional UPDATE
// (`WHERE id = ? AND state/status = ?` + `Select("*")` + `Updates(m)`). Two
// properties, each tested separately because each half can regress on its own:
//
//   - the fromState predicate: a writer acting on a stale read affects 0 rows
//     and leaves the winner's row untouched (TestTransitionSecretStatus_ClosesRace
//     already covers the secret half; the machine-identity half is here);
//   - Select("*"): the caller's FULL mutated row lands in that same statement,
//     including fields it set to their zero value — a plain struct Updates
//     skips zero values, so dropping Select("*") would silently keep stale
//     columns while still reporting matched=true.
//
// What these do not cover: real concurrency. They interleave two writers
// deterministically on one SQLite connection; the predicate is what makes
// the outcome order-independent, and that is what is asserted. Cross-replica
// serialization of the lock-then-write sequence is INV-STORE-15
// (concurrency_machine_identity_lock_postgres_test.go).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestTransitionMachineIdentityState_StaleFromStateAffectsZeroRows: two
// callers both read the identity as "suspended"; one revokes it, the other
// then tries to reactivate it off the same stale read. The reactivation must
// match 0 rows and the row must stay revoked — "revoked is terminal" (#388)
// would otherwise be silently undone.
func TestTransitionMachineIdentityState_StaleFromStateAffectsZeroRows(t *testing.T) {
	ctx := context.Background()
	ls := newMachineStore(t)
	created := time.Date(2026, 6, 5, 9, 0, 0, 0, time.UTC)
	require.NoError(t, ls.db.Create(&models.MachineIdentity{
		ID: 1, ProjectID: 1, Name: "ci-runner", State: "suspended", CreatedAt: created, UpdatedAt: created,
	}).Error)

	revokedAt := created.Add(time.Hour)
	revoker := &models.MachineIdentity{ID: 1, ProjectID: 1, Name: "ci-runner", State: "revoked",
		CreatedAt: created, UpdatedAt: revokedAt, RevokedAt: &revokedAt}
	reactivator := &models.MachineIdentity{ID: 1, ProjectID: 1, Name: "ci-runner", State: "active",
		CreatedAt: created, UpdatedAt: revokedAt.Add(time.Minute)}

	matched, err := ls.TransitionMachineIdentityState(ctx, revoker, "suspended")
	require.NoError(t, err)
	require.True(t, matched, "the first writer's fromState still matches the row")

	matched, err = ls.TransitionMachineIdentityState(ctx, reactivator, "suspended")
	require.NoError(t, err)
	assert.False(t, matched, "a writer acting on a stale fromState must affect 0 rows")

	got, err := ls.GetMachineIdentity(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, "revoked", got.State, "the rejected write must not have reverted the revoke")
	require.NotNil(t, got.RevokedAt, "the rejected write must not have cleared revoked_at")
	assert.True(t, got.RevokedAt.Equal(revokedAt))
}

// TestTransitionMachineIdentityState_PersistsFullRowIncludingZeroValues pins
// the Select("*") half: fields the caller cleared (Description,
// Classification) must be written as cleared, and fields it set (RevokedAt)
// must be written, all in the one conditional statement.
func TestTransitionMachineIdentityState_PersistsFullRowIncludingZeroValues(t *testing.T) {
	ctx := context.Background()
	ls := newMachineStore(t)
	created := time.Date(2026, 6, 5, 9, 0, 0, 0, time.UTC)
	require.NoError(t, ls.db.Create(&models.MachineIdentity{
		ID: 1, ProjectID: 1, Name: "ci-runner", State: "active", Description: "old description",
		Classification: "restricted", CreatedAt: created, UpdatedAt: created,
	}).Error)

	m, err := ls.GetMachineIdentity(ctx, 1)
	require.NoError(t, err)
	revokedAt := created.Add(time.Hour)
	m.State = "revoked"
	m.UpdatedAt = revokedAt
	m.RevokedAt = &revokedAt
	m.Description = ""
	m.Classification = ""

	matched, err := ls.TransitionMachineIdentityState(ctx, m, "active")
	require.NoError(t, err)
	require.True(t, matched)

	got, err := ls.GetMachineIdentity(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, "revoked", got.State)
	require.NotNil(t, got.RevokedAt, "revoked_at must be persisted in the same statement as the state change")
	assert.True(t, got.RevokedAt.Equal(revokedAt))
	assert.Empty(t, got.Description, "a field the caller cleared must be persisted as cleared (Select(\"*\")), not left stale")
	assert.Empty(t, got.Classification, "a field the caller cleared must be persisted as cleared (Select(\"*\")), not left stale")
}

// TestTransitionSecretStatus_PersistsFullRowIncludingZeroValues is the same
// Select("*") check for TransitionSecretStatus.
func TestTransitionSecretStatus_PersistsFullRowIncludingZeroValues(t *testing.T) {
	ctx := context.Background()
	ls := newTransitionSecretStatusStore(t)
	require.NoError(t, ls.db.Create(&models.SecretNode{
		ID: 1, Name: "db-password", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active",
		Description: "old description", Classification: "restricted",
	}).Error)

	var secret models.SecretNode
	require.NoError(t, ls.db.First(&secret, 1).Error)
	secret.Status = "suspended"
	secret.Description = ""
	secret.Classification = ""

	matched, err := ls.TransitionSecretStatus(ctx, &secret, "active")
	require.NoError(t, err)
	require.True(t, matched)

	var got models.SecretNode
	require.NoError(t, ls.db.First(&got, 1).Error)
	assert.Equal(t, "suspended", got.Status)
	assert.Empty(t, got.Description, "a field the caller cleared must be persisted as cleared (Select(\"*\")), not left stale")
	assert.Empty(t, got.Classification, "a field the caller cleared must be persisted as cleared (Select(\"*\")), not left stale")
}
