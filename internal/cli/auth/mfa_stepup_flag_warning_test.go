// mfa_stepup_flag_warning_test.go — #G58: 'auth mfa stepup --code' must warn on
// stderr when the code is passed on the command line (ps/proc + shell-history
// exposure), matching the same property already covered for --api-key in
// login_flag_warning_test.go.
package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunMFAStepUp_CodeFlagWarnsWhenExplicitlySet(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	require.NoError(t, mfaStepUpCmd.Flags().Set("code", "123456"))
	t.Cleanup(func() {
		_ = mfaStepUpCmd.Flags().Set("code", "")
		mfaStepUpCmd.Flags().Lookup("code").Changed = false
	})

	out := captureStderr(t, func() {
		// No remote session configured, so this returns an error after the
		// warning fires — only the warning itself is under test here.
		_ = runMFAStepUp(mfaStepUpCmd, nil)
	})
	assert.Contains(t, out, "--code")
	assert.Contains(t, out, "ps/proc")
}
