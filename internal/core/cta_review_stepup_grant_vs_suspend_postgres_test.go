// cta_review_stepup_grant_vs_suspend_postgres_test.go — AUTH-AUDIT-2.
// The DeleteUser half is cta_review_stepup_grant_vs_delete_postgres_test.go;
// stepUpUser below is shared by both.
//
// VerifyMFAStepUp checks the account (active, not login-blocked) before it
// checks the code, then writes an MFAStepUpGrant. The grant write used to be a
// bare INSERT, so a suspend or delete committing on another replica between
// that check and the insert left a live grant behind: the sweep's own
// post-commit purge (purgeStepUpGrants) had already run and found nothing.
// Same class as #2701 (sessions and PATs), now the third credential table.
//
// Reuses the two-replica ctaReview fixture
// (concurrency_check_then_act_exempt_review_postgres_test.go): beforeA runs
// replica B's complete SuspendUser/DeleteUser, on B's own connection, right
// before replica A's grant INSERT — after A's account check passed.
package core

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// stepUpUser creates a user with TOTP MFA active and returns one unused
// recovery code (a recovery code rather than a TOTP code, so the step-up is not
// refused as a replay of the activation's TOTP step).
func (f *ctaReview) stepUpUser(name string) (*models.User, string) {
	f.t.Helper()
	u := f.user(name, "")
	_, secret, err := f.setup.BeginMFAEnrollment(f.ctx, u.ID)
	require.NoError(f.t, err)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(f.t, err)
	recovery, err := f.setup.ActivateMFA(f.ctx, u.ID, code, "UserPass123!xyz-long-enough", "")
	require.NoError(f.t, err)
	require.NotEmpty(f.t, recovery)
	return u, recovery[0]
}

func TestCTAReview_StepUpGrant_vs_SuspendUser_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	u, code := f.stepUpUser("stepup-suspend")

	var suspendErr error
	fired := f.beforeA("create", "mfa_step_up_grants", func() {
		suspendErr = f.coreB.SuspendUser(f.ctx, f.adminID, u.ID)
	})

	stepUpErr := f.coreA.VerifyMFAStepUp(f.ctx, u.ID, code)

	require.True(t, fired(), "replica A never reached its grant INSERT — the interleaving under test never happened")
	require.NoError(t, suspendErr, "replica B's suspend must report success; the whole point is that it did")
	assert.Error(t, stepUpErr, "the step-up must be refused: its owner was suspended before the grant committed")
	assert.Zero(t, f.countLive(&models.MFAStepUpGrant{}, "user_id = ? AND consumed_at IS NULL", u.ID),
		"a suspend that returned success must leave no live step-up grant — otherwise "+
			"suspend → reactivate hands back an elevation minted for a blocked account (step-up err: %v)", stepUpErr)
}
