// cta_review_stepup_grant_vs_delete_postgres_test.go — AUTH-AUDIT-2, the
// DeleteUser half of cta_review_stepup_grant_vs_suspend_postgres_test.go (see
// that file for the interleaving and the stepUpUser fixture).
package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// DeleteUser soft-deletes the row: a re-check that only refused an existing
// blocked owner would read the deleted user as absent and let the grant through.
func TestCTAReview_StepUpGrant_vs_DeleteUser_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	u, code := f.stepUpUser("stepup-delete")

	var deleteErr error
	fired := f.beforeA("create", "mfa_step_up_grants", func() {
		deleteErr = f.coreB.DeleteUser(f.ctx, f.adminID, u.ID)
	})

	stepUpErr := f.coreA.VerifyMFAStepUp(f.ctx, u.ID, code)

	require.True(t, fired(), "replica A never reached its grant INSERT — the interleaving under test never happened")
	require.NoError(t, deleteErr, "replica B's delete must report success; the whole point is that it did")
	assert.Error(t, stepUpErr, "the step-up must be refused: its owner was deleted before the grant committed")
	assert.Zero(t, f.countLive(&models.MFAStepUpGrant{}, "user_id = ? AND consumed_at IS NULL", u.ID),
		"a delete that returned success must leave no live step-up grant — otherwise "+
			"delete → restore → reactivate hands back the elevation (step-up err: %v)", stepUpErr)
}
