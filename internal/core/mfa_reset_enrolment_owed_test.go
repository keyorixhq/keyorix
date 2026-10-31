package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #3799: users.mfa_enrolment_required is an input of the account-setup gate.
// The enrol_mfa step is owed by an interactive session of a factor-less account
// when the deployment requires MFA OR an administrator MFA reset left an
// enrolment owed; PATs stay exempt and a second factor discharges it.
func TestPendingAccountSetupSteps_MFAEnrolmentOwed(t *testing.T) {
	for _, tc := range []struct {
		name                                                 string
		restricted, hasFactor, interactive, requireMFA, owed bool
		want                                                 []string
	}{
		{"reset, require_mfa off, restricted", true, false, true, false, true, []string{SetupStepChangePassword, SetupStepEnrollMFA}},
		{"reset, require_mfa off, password changed", false, false, true, false, true, []string{SetupStepEnrollMFA}},
		{"reset, enrolled", false, true, true, false, true, nil},
		{"reset, PAT", false, false, false, false, true, nil},
		{"never reset, require_mfa off", false, false, true, false, false, nil},
		{"never reset, require_mfa on", false, false, true, true, false, []string{SetupStepEnrollMFA}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, PendingAccountSetupSteps(tc.restricted, tc.hasFactor, tc.interactive, tc.requireMFA, tc.owed))
		})
	}
}

// The approved reset leaves the target owing an enrolment that the setup gate
// sees with require_mfa off, and the target's own TOTP activation clears it.
func TestMFAReset_EnrolmentOwedUntilEnrolled(t *testing.T) {
	f := newMFAResetFixture(t)
	f.c.SetRequireMFA(false)
	req := f.request(t)
	approval, err := f.c.ApproveMFAReset(context.Background(), f.b.ID, false, req.ID, f.code(t, f.b.ID))
	require.NoError(t, err)

	u := f.reload(t, f.target.ID)
	require.True(t, u.MFAEnrolmentRequired)
	assert.True(t, MFAEnrolmentOwed(u))
	assert.Equal(t, []string{SetupStepChangePassword, SetupStepEnrollMFA}, f.c.pendingSetupStepsFor(u))
	assert.True(t, f.c.needsSetupSession(u), "a reset user owes both steps: a setup-only session")

	f.enrol(t, f.target.ID, approval.OneTimePassword)
	u = f.reload(t, f.target.ID)
	assert.False(t, u.MFAEnrolmentRequired, "TOTP activation must clear mfa_enrolment_required")
	assert.False(t, MFAEnrolmentOwed(u))
	assert.Equal(t, []string{SetupStepChangePassword}, f.c.pendingSetupStepsFor(u))
}
