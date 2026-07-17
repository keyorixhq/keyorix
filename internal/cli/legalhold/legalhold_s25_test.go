package legalhold

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLiftCmd_NotConnected verifies that liftCmd returns "not connected" when
// no server is configured — even after the reason check and (if needed) the
// interactive confirmation pass.
func TestLiftCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	origR, origY := liftReason, liftYes
	defer func() { liftReason = origR; liftYes = origY }()

	liftReason = "test lift reason"
	liftYes = false

	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("yes\n"))

	err := liftCmd.RunE(cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}
