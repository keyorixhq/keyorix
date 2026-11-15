package store

// full_row_writer_cascade_interleave_test.go — STORE-STALE-NOV-2 item 3.
//
// full_row_writer_interleave_test.go (#4179) races each exempt full-row writer against a
// competing call of the SAME writer (revoke, reject, close). These race two exempt
// writers against the OTHER writers of their tables, the ones that change a
// security-relevant column without going through the exempt primitive:
//
//   - machine_identities: the project-delete cascade (SuspendMachineIdentitiesForDeletedProject,
//     state + cascade marker) and its restore (ReactivateMachineIdentitiesForRestoredProject,
//     an A->B->A on state), against ClassifyMachineIdentity's unlocked read + full-row
//     TransitionMachineIdentityState. (Every other caller re-reads under
//     LockMachineIdentityForUpdate inside the write transaction, so it holds no stale struct.)
//   - access_requests: the secret-delete close of an approval (closeApprovedSecretAccessRequests,
//     approved -> expired) against a stale approve through UpdateAccessRequest.
//
// Same harness and ordering as the #4179 file: two replicas, one database, steps forced
// sequentially, on SQLite and Postgres.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// deletedProject seeds a soft-deleted project (the state the cascade runs in).
func (env *interleaveEnv) deletedProject(t *testing.T, at time.Time) *models.Project {
	t.Helper()
	require.NoError(t, env.db.AutoMigrate(&models.Project{}, &models.MachineIdentityRole{}))
	p := &models.Project{Name: "cascade-" + t.Name(), DeletedAt: gorm.DeletedAt{Time: at, Valid: true}}
	require.NoError(t, env.db.Create(p).Error)
	return p
}

// A stale classify must lose to the project-delete cascade: the identity stays
// suspended with its cascade marker (which the restore needs to re-activate it, and
// nothing else), and the classify leaves no column behind.
func TestFullRowWriters_CascadeSuspendSurvivesStaleClassify_TransitionMachineIdentityState(t *testing.T) {
	forEachInterleaveBackend(t, func(t *testing.T, env *interleaveEnv) {
		ctx := context.Background()
		p := env.deletedProject(t, interleaveNow())
		seed := &models.MachineIdentity{ProjectID: p.ID, Name: "ci", State: "active", CreatedAt: interleaveNow(), UpdatedAt: interleaveNow()}
		require.NoError(t, env.db.Create(seed).Error)

		stale, err := env.a.GetMachineIdentity(ctx, seed.ID) // A: classify reads it active, unlocked
		require.NoError(t, err)

		suspended, err := env.b.SuspendMachineIdentitiesForDeletedProject(ctx, p.ID) // B: the cascade
		require.NoError(t, err)
		require.Len(t, suspended, 1)

		stale.Classification, stale.UpdatedAt = "restricted", interleaveNow().Add(time.Minute)
		ok, err := env.a.TransitionMachineIdentityState(ctx, stale, "active")
		require.NoError(t, err)
		assert.False(t, ok, "a classify built on a pre-cascade read must lose the state CAS")

		got, err := env.b.GetMachineIdentity(ctx, seed.ID)
		require.NoError(t, err)
		assert.Equal(t, "suspended", got.State, "the cascade suspend was reverted: the identity of a deleted project is active again")
		assert.Equal(t, p.ID, got.CascadeSuspendedProjectID, "the cascade marker was cleared by a stale write")
		require.NotNil(t, got.CascadeSuspendedAt)
		assert.Empty(t, got.Classification)
	})
}

// The A->B->A case: the cascade suspends and the restore re-activates before A's
// stale classify lands, so A's CAS on 'active' matches again. It may only add its
// label: state stays active, the marker stays cleared, nothing is re-suspended or
// re-marked (a re-marked active row would make a later restore of the same
// project re-activate it as if the cascade had suspended it).
func TestFullRowWriters_CascadeSuspendAndRestoreThenStaleClassify_TransitionMachineIdentityState(t *testing.T) {
	forEachInterleaveBackend(t, func(t *testing.T, env *interleaveEnv) {
		ctx := context.Background()
		p := env.deletedProject(t, interleaveNow())
		seed := &models.MachineIdentity{ProjectID: p.ID, Name: "ci", State: "active", CreatedAt: interleaveNow(), UpdatedAt: interleaveNow()}
		require.NoError(t, env.db.Create(seed).Error)

		stale, err := env.a.GetMachineIdentity(ctx, seed.ID)
		require.NoError(t, err)

		_, err = env.b.SuspendMachineIdentitiesForDeletedProject(ctx, p.ID)
		require.NoError(t, err)
		reactivated, err := env.b.ReactivateMachineIdentitiesForRestoredProject(ctx, p.ID, interleaveNow().Add(time.Minute))
		require.NoError(t, err)
		require.Len(t, reactivated, 1)

		stale.Classification, stale.UpdatedAt = "restricted", interleaveNow().Add(2*time.Minute)
		ok, err := env.a.TransitionMachineIdentityState(ctx, stale, "active")
		require.NoError(t, err)
		require.True(t, ok, "fixture: after the restore the row is active again, so the classify matches")

		got, err := env.b.GetMachineIdentity(ctx, seed.ID)
		require.NoError(t, err)
		assert.Equal(t, "active", got.State)
		assert.Zero(t, got.CascadeSuspendedProjectID, "a stale classify re-marked an active identity as cascade-suspended")
		assert.Nil(t, got.CascadeSuspendedAt)
		assert.Nil(t, got.RevokedAt)
		assert.Equal(t, "restricted", got.Classification)
	})
}

// A stale approve must lose to an approval that was already granted and then
// closed by the secret's delete (approved -> expired, #2797): the close is the
// revoke of that approval and must survive, or a restore of the secret would
// revive it with no re-authorisation.
func TestFullRowWriters_SecretDeleteCloseSurvivesStaleApprove_UpdateAccessRequest(t *testing.T) {
	forEachInterleaveBackend(t, func(t *testing.T, env *interleaveEnv) {
		ctx := context.Background()
		secret := &models.SecretNode{Name: "db-password", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active"}
		require.NoError(t, env.db.Create(secret).Error)
		seed := &models.AccessRequest{ProjectID: 1, UserID: 7, SecretID: &secret.ID, State: "pending", CreatedAt: interleaveNow()}
		require.NoError(t, env.db.Create(seed).Error)

		var stale models.AccessRequest // A: approver 1 reads it pending
		require.NoError(t, env.a.db.First(&stale, seed.ID).Error)

		// B: approver 9 approves, then the secret is deleted, which closes the approval.
		var fresh models.AccessRequest
		require.NoError(t, env.b.db.First(&fresh, seed.ID).Error)
		resolvedAt := interleaveNow().Add(time.Minute)
		fresh.State, fresh.ResolvedBy, fresh.ResolvedAt = "approved", 9, &resolvedAt
		ok, err := env.b.UpdateAccessRequest(ctx, &fresh)
		require.NoError(t, err)
		require.True(t, ok)
		require.NoError(t, closeApprovedSecretAccessRequests(env.b.db.WithContext(ctx), "secret_id = ?", secret.ID))

		later := interleaveNow().Add(2 * time.Minute)
		stale.State, stale.ResolvedBy, stale.ResolvedAt = "approved", 1, &later
		ok, err = env.a.UpdateAccessRequest(ctx, &stale)
		require.NoError(t, err)
		assert.False(t, ok, "an approve built on a pre-approval read must lose the pending CAS")

		var got models.AccessRequest
		require.NoError(t, env.db.First(&got, seed.ID).Error)
		assert.Equal(t, "expired", got.State, "the secret-delete close was reverted: a restore would revive the approval")
		assert.Equal(t, uint(9), got.ResolvedBy)
	})
}
