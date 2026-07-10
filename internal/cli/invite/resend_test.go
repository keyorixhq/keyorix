package invite

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInviteResendRequiredFlags(t *testing.T) {
	for _, name := range []string{"id", "by"} {
		f := resendCmd.Flags().Lookup(name)
		require.NotNil(t, f, "resend should have --%s", name)
		assert.NotEmpty(t, f.Annotations[cobraRequired], "--%s should be required", name)
	}
}

func TestInviteResendIDRequired(t *testing.T) {
	orig := resendID
	defer func() { resendID = orig }()
	resendID = 0
	resendBy = "admin@example.com"
	err := resendCmd.RunE(resendCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invitation id is required")
}

func TestInviteResendByRequired(t *testing.T) {
	origID, origBy := resendID, resendBy
	defer func() { resendID = origID; resendBy = origBy }()
	resendID = 1
	resendBy = ""
	err := resendCmd.RunE(resendCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acting admin email is required")
}

func TestInviteHasResendSubcommand(t *testing.T) {
	names := make([]string, 0)
	for _, c := range InviteCmd.Commands() {
		names = append(names, c.Use)
	}
	assert.Contains(t, names, "resend")
}
