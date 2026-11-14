// cta_review_suspend_marker_old_binary_cases_test.go — STORE-STALE-NOV-2 item 2 (#3362).
//
// The four-step sequence of #3362, driven to the place the harm happens: the
// SecretSuspended refusal a new replica serves, whose ClearSyncedCopies tells the
// operator and k8s-sync to empty the synced Kubernetes copies.
//
//  1. a new replica suspends S with clear_synced_copies=true;
//  2. an old (pre-#3215) replica resumes S: it writes status and updated_at only;
//  3. an old replica suspends S again, a plain suspend: status and updated_at only;
//  4. a new replica reads S. Its refusal must NOT ask for the copies to be cleared:
//     the suspension in force (3) never asked for that.
//
// The old binary is simulated by a raw UPDATE of exactly those two columns, on the
// setup connection (a third pool, neither replica's). On PostgreSQL the marker is
// bound to its suspension by trg_secret_nodes_suspend_marker (HA-READY-1): every
// status change away from suspended clears it, whoever writes it, so the marker in
// force during a suspension was set by that suspension. The schema-epoch floor (3)
// refuses to start a pre-#3215 binary at all once the database is migrated
// (TestOpenRefusesV096BinaryOnMigratedDatabase family). SQLite has no older binary
// beside this one (one process, the same floor), so its twin runs the steps with
// this binary's own resume and plain suspend.
package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// suspendMarkerStep moves secret id to status as the given writer would.
type suspendMarkerStep func(f *ctaReview, id uint, status string)

// oldBinaryStatusWrite is a pre-#3215 replica's TransitionSecretStatus: it knows
// only status and updated_at.
func oldBinaryStatusWrite(f *ctaReview, id uint, status string) {
	f.t.Helper()
	require.NoError(f.t, f.setupDB.Exec("UPDATE secret_nodes SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", status, id).Error)
}

// newBinaryStatusWrite is this binary's own resume / plain suspend on replica B.
func newBinaryStatusWrite(f *ctaReview, id uint, status string) {
	f.t.Helper()
	var err error
	if status == SecretStatusActive {
		_, err = f.coreB.ResumeSecret(f.ctx, id, f.adminID)
	} else {
		_, err = f.coreB.SuspendSecret(f.ctx, id, f.adminID, "plain")
	}
	require.NoError(f.t, err)
}

func runSuspendMarkerFourSteps(t *testing.T, f *ctaReview, step suspendMarkerStep) {
	s := f.secret("marker-3362", f.adminID)
	refusal := func(c *KeyorixCore) SecretReadRefusal {
		t.Helper()
		return suspendedRefusal(t, c, s.ID)
	}
	marker := func() bool {
		t.Helper()
		var got models.SecretNode
		require.NoError(t, f.setupDB.First(&got, s.ID).Error)
		return got.SuspendClearSyncedCopies
	}

	// 1. New replica A: suspend with clear-copies.
	_, err := f.coreA.SuspendSecretWithOptions(f.ctx, s.ID, f.adminID, "leaked", SuspendOptions{ClearSyncedCopies: true})
	require.NoError(t, err)
	require.True(t, refusal(f.coreB).ClearSyncedCopies, "fixture: the clear-copies suspension must reach the refusal")

	// 2. Resume (old or new writer).
	step(f, s.ID, SecretStatusActive)
	assert.False(t, marker(), "the marker outlived the suspension it belongs to")

	// 3. Plain suspend (old or new writer).
	step(f, s.ID, SecretStatusSuspended)

	// 4. New replica B serves the refusal.
	assert.False(t, refusal(f.coreB).ClearSyncedCopies,
		"a plain suspend after a resume told the operator and k8s-sync to empty the synced copies (#3362)")
	assert.False(t, refusal(f.coreA).ClearSyncedCopies)

	// The new resume clears it too, and a new clear-copies suspend still sets it.
	_, err = f.coreA.SuspendSecretWithOptions(f.ctx, s.ID, f.adminID, "leaked again", SuspendOptions{ClearSyncedCopies: true})
	require.NoError(t, err)
	require.True(t, refusal(f.coreB).ClearSyncedCopies)
	_, err = f.coreB.ResumeSecret(f.ctx, s.ID, f.adminID)
	require.NoError(t, err)
	assert.False(t, marker(), "the new resume must clear the marker")
}
