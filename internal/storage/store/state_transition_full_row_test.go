package store

// state_transition_full_row_test.go — INV-STORE-14 (#2510), the Select("*") half.
// TransitionMachineIdentityState and TransitionSecretStatus persist the caller's
// FULL mutated row in the same conditional UPDATE as the state change, including
// fields set to their zero value. A plain struct Updates skips zero values, so
// dropping Select("*") would silently keep stale columns while still reporting
// matched=true. The fromState predicate and real-Postgres concurrency halves of
// INV-STORE-14/15 are covered by local_state_transition_cas_test.go and the
// concurrency_*_postgres_test.go files.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

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
