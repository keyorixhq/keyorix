package migrate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunUserToMachine_ByRequired(t *testing.T) {
	// Calling runUserToMachine directly bypasses cobra's MarkFlagRequired so we
	// can exercise the defensive guard inside the function body.
	orig := u2mBy
	defer func() { u2mBy = orig }()
	u2mBy = ""

	err := runUserToMachine(userToMachineCmd, []string{"ci-bot"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acting admin email is required")
}
