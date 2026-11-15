package store

// full_row_writer_aba_interleave_test.go — STORE-STALE-NOV-3 item 1.
//
// The #4179 and STORE-STALE-NOV-2 files race each exempt full-row writer against a
// competing write that moves the row OFF the state the stale struct was read in, so the
// stale write's CAS misses. The one exempt writer whose table has a cycle back to an
// earlier state is TransitionMachineIdentityState (active <-> suspended): there a stale
// struct's CAS can match again after A->B->A, and the full-row write then lands. This
// file pins what such a write can carry back and why none of it matters.
//
// Same harness and ordering as the #4179 file: two replicas, one database, steps forced
// sequentially, on SQLite and Postgres.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// A classify that read a CASCADE-suspended identity (marker set) lands after the
// restore re-activated it and an admin suspended it again. Its CAS on 'suspended'
// matches, so it writes the stale cascade marker back onto an admin-suspended row.
// That marker must stay inert: a later delete + restore of the same project must not
// re-activate the identity the admin suspended. It cannot, because the restore also
// requires the marker to equal the project's CURRENT deleted_at and updated_at to
// still equal the marker; the classify stamps its own updated_at and the second
// deletion has a new deleted_at.
func TestFullRowWriters_StaleClassifyAfterRestoreAndAdminSuspend_MarkerStaysInert_TransitionMachineIdentityState(t *testing.T) {
	forEachInterleaveBackend(t, func(t *testing.T, env *interleaveEnv) {
		ctx := context.Background()
		firstDelete := interleaveNow()
		p := env.deletedProject(t, firstDelete)
		seed := &models.MachineIdentity{ProjectID: p.ID, Name: "ci", State: "active", CreatedAt: interleaveNow(), UpdatedAt: interleaveNow()}
		require.NoError(t, env.db.Create(seed).Error)

		suspended, err := env.b.SuspendMachineIdentitiesForDeletedProject(ctx, p.ID) // B: the cascade
		require.NoError(t, err)
		require.Len(t, suspended, 1)

		stale, err := env.a.GetMachineIdentity(ctx, seed.ID) // A: classify reads it cascade-suspended
		require.NoError(t, err)
		require.Equal(t, p.ID, stale.CascadeSuspendedProjectID, "fixture: A's read carries the cascade marker")

		// B: the project is restored (identity re-activated, marker cleared) ...
		reactivated, err := env.b.ReactivateMachineIdentitiesForRestoredProject(ctx, p.ID, interleaveNow().Add(time.Minute))
		require.NoError(t, err)
		require.Len(t, reactivated, 1)
		require.NoError(t, env.db.Unscoped().Model(&models.Project{}).Where("id = ?", p.ID).Update("deleted_at", nil).Error)
		// ... and an admin suspends it (transitionMachineInTx clears the marker).
		fresh, err := env.b.GetMachineIdentity(ctx, seed.ID)
		require.NoError(t, err)
		fresh.State, fresh.UpdatedAt = "suspended", interleaveNow().Add(2*time.Minute)
		fresh.CascadeSuspendedProjectID, fresh.CascadeSuspendedAt = 0, nil
		ok, err := env.b.TransitionMachineIdentityState(ctx, fresh, "active")
		require.NoError(t, err)
		require.True(t, ok)

		// A: its classify lands; the row is 'suspended' again, so the CAS matches.
		stale.Classification, stale.UpdatedAt = "restricted", interleaveNow().Add(3*time.Minute)
		ok, err = env.a.TransitionMachineIdentityState(ctx, stale, "suspended")
		require.NoError(t, err)
		require.True(t, ok, "fixture: after A->B->A the stale classify's CAS matches")

		got, err := env.b.GetMachineIdentity(ctx, seed.ID)
		require.NoError(t, err)
		assert.Equal(t, "suspended", got.State, "the admin suspend was reverted by a stale classify")
		assert.Nil(t, got.RevokedAt)
		// The residual this test is about: the full-row write put the marker the
		// admin's transition cleared back. (If classify ever writes only its own
		// columns, this precondition is gone and so is the exempt row.)
		require.Equal(t, p.ID, got.CascadeSuspendedProjectID, "fixture: the stale write carried the cascade marker back")
		require.NotEqual(t, got.UpdatedAt.UTC(), got.CascadeSuspendedAt.UTC(), "fixture: the classify stamped its own updated_at")

		// The project is deleted again and restored: the admin-suspended identity
		// must stay suspended, whatever marker the stale write left on it.
		secondDelete := interleaveNow().Add(time.Hour)
		require.NoError(t, env.db.Unscoped().Model(&models.Project{}).Where("id = ?", p.ID).Update("deleted_at", secondDelete).Error)
		again, err := env.b.SuspendMachineIdentitiesForDeletedProject(ctx, p.ID)
		require.NoError(t, err)
		assert.Empty(t, again, "the cascade touches only active identities")
		reactivated, err = env.b.ReactivateMachineIdentitiesForRestoredProject(ctx, p.ID, secondDelete.Add(time.Minute))
		require.NoError(t, err)
		assert.Empty(t, reactivated, "a restore re-activated an identity an admin had suspended, through a stale cascade marker")

		got, err = env.b.GetMachineIdentity(ctx, seed.ID)
		require.NoError(t, err)
		assert.Equal(t, "suspended", got.State)
	})
}
